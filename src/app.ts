import fs from 'node:fs';
import path from 'node:path';
import { Readable } from 'node:stream';
import type { ReadableStream as NodeReadableStream } from 'node:stream/web';
import { setTimeout as sleep } from 'node:timers/promises';
import type { HttpBindings } from '@hono/node-server';
import { Hono, type Context } from 'hono';
import { bodyLimit } from 'hono/body-limit';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import { createMiddleware } from 'hono/factory';
import { HTTPException } from 'hono/http-exception';
import { secureHeaders } from 'hono/secure-headers';
import type { ContentfulStatusCode } from 'hono/utils/http-status';
import { createAccessVerifier, type AccessVerifier } from './access.js';
import { Audit } from './audit.js';
import {
  LoginGate,
  LoginLimiter,
  RequestLimiter,
  Sessions,
  TotpVerifier,
  verifyPassword,
} from './auth.js';
import { ROOT, type Config } from './config.js';
import { HttpError } from './errors.js';
import { deriveMasterKey } from './seal.js';
import { Store } from './store.js';

const SESSION_COOKIE = 'transit_session';
const CSRF_HEADER_VALUE = 'transit';
const MIN_TTL_SECONDS = 10;
const JSON_LIMIT_BYTES = 8192;

interface Env {
  Bindings: HttpBindings;
  Variables: { masterKey: Buffer };
}

type Ctx = Context<Env>;

interface Asset {
  body: string;
  type: string;
}

function loadAssets(): Map<string, Asset> {
  const read = (...parts: string[]): string => fs.readFileSync(path.join(ROOT, ...parts), 'utf8');
  return new Map<string, Asset>([
    ['/', { body: read('web', 'index.html'), type: 'text/html; charset=utf-8' }],
    ['/style.css', { body: read('web', 'style.css'), type: 'text/css; charset=utf-8' }],
    ['/app.js', { body: read('dist', 'web', 'app.js'), type: 'text/javascript; charset=utf-8' }],
    ['/e2ee.js', { body: read('dist', 'web', 'e2ee.js'), type: 'text/javascript; charset=utf-8' }],
  ]);
}

/** Strips characters that are unsafe in file names; the result is display-only. */
export function cleanName(raw: unknown): string {
  const name = String(raw ?? '')
    .normalize('NFC')
    .replace(/[\x00-\x1f\x7f<>:"/\\|?*]/g, '_')
    .replace(/^[.\s]+|[\s.]+$/g, '')
    .slice(0, 200);
  return name || 'file';
}

const ENVELOPE_RE = /^[A-Za-z0-9+/=_-]{1,2048}$/;

/** The envelope is opaque ciphertext produced by the browser; only its shape is checked. */
function parseEnvelope(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string' || !ENVELOPE_RE.test(value)) throw new HttpError(400, 'Invalid encryption envelope');
  return value;
}

function contentDisposition(name: string): string {
  const fallback = name.replace(/[^\x20-\x7e]|["\\%]/g, '_');
  return `attachment; filename="${fallback}"; filename*=UTF-8''${encodeURIComponent(name)}`;
}

const isLoopback = (addr: string | undefined): boolean =>
  addr === '127.0.0.1' || addr === '::1' || addr === '::ffff:127.0.0.1';

async function jsonBody(c: Ctx): Promise<Record<string, unknown>> {
  try {
    const value: unknown = await c.req.json();
    if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error('not an object');
    return value as Record<string, unknown>;
  } catch {
    throw new HttpError(400, 'Invalid JSON');
  }
}

export interface AppOptions {
  /** Overrides the Cloudflare Access verifier (used by tests). */
  verifyAccess?: AccessVerifier;
}

export interface App {
  app: Hono<Env>;
  store: Store;
  /** Stops timers and wipes session keys from memory. */
  dispose(): void;
}

export async function createApp(cfg: Config, options: AppOptions = {}): Promise<App> {
  const store = new Store(cfg);
  await store.init();
  const audit = new Audit(cfg.auditLog ? path.join(cfg.dataDir, 'audit.log') : null);
  const sessions = new Sessions({
    idleMs: cfg.sessionIdleSeconds * 1000,
    maxMs: cfg.sessionMaxSeconds * 1000,
    maxSessions: cfg.maxSessions,
  });
  const loginLimiter = new LoginLimiter();
  const loginGate = new LoginGate(4);
  const requestLimiter = new RequestLimiter(600, 60_000);
  const totp = cfg.totpSecret ? new TotpVerifier(cfg.totpSecret) : null;
  const verifyAccess = options.verifyAccess ?? (cfg.access ? createAccessVerifier(cfg.access) : null);
  const assets = loadAssets();

  const ipOf = (c: Ctx): string => {
    const peer = c.env.incoming.socket.remoteAddress;
    const forwarded = c.req.header('cf-connecting-ip');
    if (cfg.trustProxy && isLoopback(peer) && forwarded) return forwarded;
    return peer ?? 'unknown';
  };

  const isSecure = (c: Ctx): boolean =>
    cfg.trustProxy && isLoopback(c.env.incoming.socket.remoteAddress) && c.req.header('x-forwarded-proto') === 'https';

  const readToken = (c: Ctx): string | undefined =>
    isSecure(c) ? getCookie(c, SESSION_COOKIE, 'host') : getCookie(c, SESSION_COOKIE);

  const clampTtlSeconds = (value: unknown): number => {
    if (typeof value !== 'number' || !Number.isFinite(value)) return cfg.defaultTtlSeconds;
    return Math.min(Math.max(Math.round(value), MIN_TTL_SECONDS), cfg.maxTtlSeconds);
  };

  const limits = () => ({
    ttlChoices: cfg.ttlChoices,
    defaultTtlSeconds: cfg.defaultTtlSeconds,
    maxFileBytes: cfg.maxFileBytes,
    maxTotalBytes: cfg.maxTotalBytes,
    e2ee: { salt: cfg.e2eeSalt, iterations: cfg.e2eeIterations, required: cfg.requireClientEncryption },
  });

  const app = new Hono<Env>();

  // ---- Global guards -------------------------------------------------

  app.use(
    secureHeaders({
      contentSecurityPolicy: {
        defaultSrc: ["'none'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        connectSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
        baseUri: ["'none'"],
      },
      crossOriginResourcePolicy: 'same-origin',
      crossOriginOpenerPolicy: 'same-origin',
      referrerPolicy: 'no-referrer',
      xFrameOptions: 'DENY',
      strictTransportSecurity: 'max-age=63072000',
    }),
  );

  app.use(async (c, next) => {
    c.header('Cache-Control', 'no-store');
    c.header('X-Robots-Tag', 'noindex, nofollow');

    if (cfg.allowedHosts.length > 0) {
      const host = (c.req.header('host') ?? '').toLowerCase().replace(/:\d+$/, '');
      if (!cfg.allowedHosts.includes(host)) throw new HttpError(421, 'Misdirected request');
    }
    if (verifyAccess && !(await verifyAccess(c.req.header('cf-access-jwt-assertion')))) {
      audit.log('access_denied', { ip: ipOf(c) });
      throw new HttpError(403, 'Forbidden');
    }
    if (!requestLimiter.allow(ipOf(c))) {
      throw new HttpError(429, 'Too many requests', { headers: { 'Retry-After': '60' } });
    }
    await next();
  });

  // ---- Static assets -------------------------------------------------

  for (const [route, asset] of assets) {
    app.get(route, (c) => c.body(asset.body, 200, { 'Content-Type': asset.type }));
  }

  // ---- API -----------------------------------------------------------

  const api = new Hono<Env>();

  // Mutations must carry a custom header (not sendable cross-origin without CORS) and,
  // when an Origin header is present, it must match the Host.
  api.use(async (c, next) => {
    if (c.req.method !== 'GET') {
      if (c.req.header('x-requested-with') !== CSRF_HEADER_VALUE) throw new HttpError(403, 'Forbidden');
      const origin = c.req.header('origin');
      if (origin) {
        let originHost: string | null = null;
        try {
          originHost = new URL(origin).host;
        } catch {
          originHost = null;
        }
        if (originHost !== c.req.header('host')) throw new HttpError(403, 'Forbidden');
      }
    }
    await next();
  });

  const requireAuth = createMiddleware<Env>(async (c, next) => {
    const key = sessions.unlock(readToken(c));
    if (!key) throw new HttpError(401, 'Not signed in');
    c.set('masterKey', key);
    await next();
  });

  const tooLarge = (c: Ctx) => c.json({ error: 'Body too large' }, 413);

  api.get('/session', (c) => {
    const authenticated = sessions.unlock(readToken(c)) !== null;
    return c.json({ authenticated, totp: totp !== null, ...(authenticated ? { limits: limits() } : {}) });
  });

  api.post('/login', bodyLimit({ maxSize: JSON_LIMIT_BYTES, onError: tooLarge }), async (c) => {
    const ip = ipOf(c);
    const locked = loginLimiter.lockedFor(ip);
    if (locked > 0) {
      throw new HttpError(429, 'Too many attempts. Try again later.', {
        headers: { 'Retry-After': String(Math.ceil(locked / 1000)) },
      });
    }
    const body = await jsonBody(c);
    const password = typeof body.password === 'string' ? body.password.slice(0, 1024) : '';
    const code = typeof body.code === 'string' ? body.code.trim() : '';

    const masterKey = await loginGate.run(async () => {
      await sleep(loginLimiter.globalDelayMs());
      const ok = (await verifyPassword(password, cfg.passwordHash)) && (totp ? totp.verify(code) : true);
      return ok ? deriveMasterKey(password, cfg.kdfSalt) : null;
    });
    if (!masterKey) {
      loginLimiter.fail(ip);
      audit.log('login_fail', { ip });
      throw new HttpError(401, 'Invalid credentials');
    }

    loginLimiter.success(ip);
    audit.log('login_ok', { ip });
    const secure = isSecure(c);
    setCookie(c, SESSION_COOKIE, sessions.create(masterKey), {
      httpOnly: true,
      sameSite: 'Strict',
      path: '/',
      secure,
      ...(secure ? { prefix: 'host' as const } : {}),
    });
    return c.json({ ok: true });
  });

  const clearCookie = (c: Ctx): void => {
    const secure = isSecure(c);
    deleteCookie(c, SESSION_COOKIE, { path: '/', secure, ...(secure ? { prefix: 'host' as const } : {}) });
  };

  api.post('/logout', (c) => {
    sessions.destroy(readToken(c));
    clearCookie(c);
    audit.log('logout', { ip: ipOf(c) });
    return c.json({ ok: true });
  });

  api.post('/panic', requireAuth, async (c) => {
    const deleted = await store.wipeAll();
    sessions.destroyAll();
    clearCookie(c);
    audit.log('panic', { ip: ipOf(c), deleted });
    return c.json({ ok: true, deleted });
  });

  api.get('/files', requireAuth, (c) => {
    const key = c.get('masterKey');
    return c.json({
      files: store.list().map((f) => store.describe(f, key)),
      usedBytes: store.usedBytes(),
      now: Date.now(),
    });
  });

  api.get('/files/:id', requireAuth, (c) => {
    const key = c.get('masterKey');
    const meta = store.get(c.req.param('id'));
    if (!meta) throw new HttpError(404, 'File not found or expired');

    const name = store.describe(meta, key).name;
    const stream = store.openDecrypted(meta, key);
    audit.log('download', { id: meta.id, ip: ipOf(c) });

    const outgoing = c.env.outgoing;
    outgoing.once('close', () => {
      stream.destroy();
      if (meta.burn && outgoing.writableFinished) {
        void store.remove(meta.id).then(() => audit.log('burned', { id: meta.id }));
      }
    });

    return new Response(Readable.toWeb(stream) as unknown as ReadableStream, {
      headers: {
        'Content-Type': 'application/octet-stream',
        'Content-Length': String(meta.size),
        'Content-Disposition': contentDisposition(name),
      },
    });
  });

  api.delete('/files/:id', requireAuth, async (c) => {
    const id = c.req.param('id');
    if (!store.get(id)) throw new HttpError(404, 'File not found');
    await store.remove(id);
    audit.log('delete', { id, ip: ipOf(c) });
    return c.json({ ok: true });
  });

  api.post('/uploads', requireAuth, bodyLimit({ maxSize: JSON_LIMIT_BYTES, onError: tooLarge }), async (c) => {
    const body = await jsonBody(c);
    const size = typeof body.size === 'number' ? body.size : Number.NaN;
    const envelope = parseEnvelope(body.e2ee);
    if (cfg.requireClientEncryption && envelope === null) {
      throw new HttpError(400, 'Files must be encrypted in the browser');
    }
    const uploadId = await store.beginUpload(
      {
        // With client-side encryption the real name only exists inside the envelope.
        name: envelope ? 'encrypted' : cleanName(body.name),
        envelope,
        size,
        ttlMs: clampTtlSeconds(body.ttl) * 1000,
        burn: body.burn === true,
      },
      c.get('masterKey'),
    );
    audit.log('upload_begin', { id: uploadId, size, ip: ipOf(c) });
    return c.json({ uploadId, chunkBytes: cfg.chunkBytes }, 201);
  });

  api.get('/uploads/:id', requireAuth, (c) => c.json({ received: store.uploadProgress(c.req.param('id')) }));

  api.put('/uploads/:id', requireAuth, async (c) => {
    const length = Number(c.req.header('content-length'));
    if (!Number.isSafeInteger(length)) throw new HttpError(411, 'Content-Length required');
    const offset = Number(c.req.query('offset'));
    if (!Number.isSafeInteger(offset) || offset < 0) throw new HttpError(400, 'Invalid offset');
    const body = c.req.raw.body;
    if (!body) throw new HttpError(400, 'Empty body');

    const result = await store.appendChunk(
      c.req.param('id'),
      offset,
      Readable.fromWeb(body as unknown as NodeReadableStream),
      length,
    );
    if (!result.done) return c.json(result);
    audit.log('upload_done', { id: result.file.id, size: result.file.size });
    return c.json({ done: true, file: store.describe(result.file, c.get('masterKey')) });
  });

  api.delete('/uploads/:id', requireAuth, async (c) => {
    await store.cancelUpload(c.req.param('id'));
    return c.json({ ok: true });
  });

  app.route('/api', api);

  // ---- Errors --------------------------------------------------------

  app.notFound((c) => c.json({ error: 'Not found' }, 404));

  app.onError((err, c) => {
    if (err instanceof HttpError) {
      for (const [name, value] of Object.entries(err.headers)) c.header(name, value);
      return c.json({ error: err.message, ...err.extra }, err.status as ContentfulStatusCode);
    }
    if (err instanceof HTTPException) return err.getResponse();
    console.error(err);
    return c.json({ error: 'Internal error' }, 500);
  });

  // ---- Housekeeping --------------------------------------------------

  const timer = setInterval(() => {
    sessions.sweep();
    loginLimiter.sweep();
    requestLimiter.sweep();
    store
      .purge()
      .then((expired) => {
        for (const id of expired) audit.log('expired', { id });
      })
      .catch((err: unknown) => console.error('purge failed', err));
  }, 15_000);
  timer.unref();

  return {
    app,
    store,
    dispose: () => {
      clearInterval(timer);
      sessions.destroyAll();
    },
  };
}
