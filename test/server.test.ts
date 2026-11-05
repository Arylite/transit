import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import type { Server } from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import { after, before, describe, it } from 'node:test';
import { serve } from '@hono/node-server';
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT, type JWK } from 'jose';
import { createAccessVerifier } from '../src/access.js';
import { createApp, type App } from '../src/app.js';
import {
  base32Decode,
  generateTotpSecret,
  hashPassword,
  hotp,
  LoginGate,
  Sessions,
  TotpVerifier,
} from '../src/auth.js';
import { DEFAULTS, resolve, type Config } from '../src/config.js';
import { HttpError } from '../src/errors.js';
import {
  createEnvelope,
  decryptUnit,
  deriveMasterKey,
  encryptedLength,
  encryptUnit,
  keyCheckCode,
  openEnvelope,
  PLAIN_SEGMENT_BYTES,
  segmentCount,
  UNIT_BYTES,
} from '../web/e2ee.js';
import {
  newFileKey,
  newSalt,
  open,
  seal,
  SEGMENT_BYTES,
  SegmentDecryptor,
  SegmentEncryptor,
  encryptedSize,
} from '../src/seal.js';

const PASSWORD = 'correct horse battery staple';
const H = { 'X-Requested-With': 'transit' };

async function collect(stream: Readable): Promise<Buffer> {
  const parts: Buffer[] = [];
  for await (const part of stream) parts.push(part as Buffer);
  return Buffer.concat(parts);
}

async function encrypt(key: Buffer, data: Buffer, chunk = data.length): Promise<Buffer> {
  const parts: Buffer[] = [];
  for (let offset = 0; offset < data.length; offset += chunk) {
    const enc = new SegmentEncryptor(key, data.length, offset / SEGMENT_BYTES);
    parts.push(await collect(Readable.from([data.subarray(offset, offset + chunk)]).pipe(enc)));
  }
  return Buffer.concat(parts);
}

const decrypt = (key: Buffer, blob: Buffer, size: number): Promise<Buffer> =>
  collect(Readable.from([blob]).pipe(new SegmentDecryptor(key, size)));

describe('segment encryption', () => {
  const key = newFileKey();

  for (const size of [1, 100, SEGMENT_BYTES - 1, SEGMENT_BYTES, SEGMENT_BYTES + 1, 3 * SEGMENT_BYTES + 5]) {
    it(`round-trips ${size} bytes`, async () => {
      const data = crypto.randomBytes(size);
      const blob = await encrypt(key, data);
      assert.equal(blob.length, encryptedSize(size));
      assert.deepEqual(await decrypt(key, blob, size), data);
    });
  }

  it('produces identical output when encrypted in aligned chunks', async () => {
    const data = crypto.randomBytes(3 * SEGMENT_BYTES + 77);
    assert.deepEqual(await encrypt(key, data, 2 * SEGMENT_BYTES), await encrypt(key, data));
  });

  it('detects a flipped bit', async () => {
    const data = crypto.randomBytes(2 * SEGMENT_BYTES);
    const blob = await encrypt(key, data);
    blob[1000] = (blob[1000] ?? 0) ^ 1;
    await assert.rejects(decrypt(key, blob, data.length));
  });

  it('detects truncation at a segment boundary', async () => {
    const data = crypto.randomBytes(3 * SEGMENT_BYTES);
    const blob = await encrypt(key, data);
    await assert.rejects(decrypt(key, blob.subarray(0, encryptedSize(2 * SEGMENT_BYTES)), data.length));
  });

  it('detects swapped segments', async () => {
    const data = crypto.randomBytes(3 * SEGMENT_BYTES);
    const blob = await encrypt(key, data);
    const unit = SEGMENT_BYTES + 16;
    const swapped = Buffer.concat([blob.subarray(unit, 2 * unit), blob.subarray(0, unit), blob.subarray(2 * unit)]);
    await assert.rejects(decrypt(key, swapped, data.length));
  });

  it('rejects the wrong key', async () => {
    const data = crypto.randomBytes(500);
    await assert.rejects(decrypt(newFileKey(), await encrypt(key, data), data.length));
  });

  it('seals and opens small values, and fails on tampering', () => {
    const sealed = seal(key, Buffer.from('hello'));
    assert.equal(open(key, sealed).toString(), 'hello');
    const raw = Buffer.from(sealed, 'base64');
    raw[raw.length - 1] = (raw[raw.length - 1] ?? 0) ^ 1;
    assert.throws(() => open(key, raw.toString('base64')));
  });
});

describe('sessions and login gate', () => {
  it('zeroes the master key when a session ends', () => {
    const sessions = new Sessions({ idleMs: 1000, maxMs: 1000, maxSessions: 3 });
    const key = Buffer.alloc(32, 7);
    const token = sessions.create(key);
    assert.equal(sessions.unlock(token), key);
    sessions.destroy(token);
    assert.ok(key.every((b) => b === 0));
    assert.equal(sessions.unlock(token), null);
  });

  it('evicts the oldest session beyond the cap and zeroes its key', () => {
    const sessions = new Sessions({ idleMs: 1000, maxMs: 1000, maxSessions: 2 });
    const first = Buffer.alloc(32, 1);
    const firstToken = sessions.create(first);
    sessions.create(Buffer.alloc(32, 2));
    sessions.create(Buffer.alloc(32, 3));
    assert.equal(sessions.unlock(firstToken), null);
    assert.ok(first.every((b) => b === 0));
  });

  it('expires idle sessions', () => {
    const sessions = new Sessions({ idleMs: 1000, maxMs: 100_000, maxSessions: 3 });
    const token = sessions.create(Buffer.alloc(32, 1));
    assert.equal(sessions.unlock(token, Date.now() + 5000), null);
  });

  it('runs password checks one at a time and caps the queue', async () => {
    const gate = new LoginGate(2);
    let running = 0;
    let peak = 0;
    const slow = async (): Promise<void> => {
      running += 1;
      peak = Math.max(peak, running);
      await new Promise((r) => setTimeout(r, 20));
      running -= 1;
    };
    const results = await Promise.allSettled([gate.run(slow), gate.run(slow), gate.run(slow), gate.run(slow)]);
    assert.equal(peak, 1);
    const rejected = results.filter((r) => r.status === 'rejected');
    assert.equal(rejected.length, 2);
    assert.ok(rejected.every((r) => (r.reason as HttpError).status === 429));
  });
});

function testConfig(dataDir: string, extra: Partial<Config> = {}): Config {
  return resolve({
    ...DEFAULTS,
    passwordHash: hashPassword(PASSWORD),
    kdfSalt: newSalt(),
    e2eeSalt: newSalt(),
    requireClientEncryption: false,
    e2eeIterations: 1000,
    dataDir,
    chunkBytes: 2 * SEGMENT_BYTES,
    maxFileBytes: 1_000_000,
    maxTotalBytes: 2_000_000,
    ...extra,
  });
}

async function listen(app: App): Promise<{ server: Server; base: string }> {
  return new Promise((resolveListen) => {
    const server = serve({ fetch: app.app.fetch, hostname: '127.0.0.1', port: 0 }, (info) =>
      resolveListen({ server: server as Server, base: `http://127.0.0.1:${info.port}` }),
    );
  });
}

describe('transit server', () => {
  let app: App;
  let server: Server;
  let base = '';
  let dataDir = '';
  let cookie = '';

  async function call(
    method: string,
    url: string,
    init: { json?: unknown; body?: Buffer; ip?: string } = {},
  ): Promise<Response> {
    const headers: Record<string, string> = { ...H };
    if (cookie) headers.Cookie = cookie;
    if (init.ip) headers['CF-Connecting-IP'] = init.ip;
    let body: Buffer | string | undefined = init.body;
    if (init.json !== undefined) {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(init.json);
    }
    return fetch(base + url, { method, headers, body: body as RequestInit['body'] });
  }

  async function login(): Promise<void> {
    const res = await fetch(`${base}/api/login`, {
      method: 'POST',
      headers: { ...H, 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: PASSWORD }),
    });
    assert.equal(res.status, 200);
    cookie = (res.headers.getSetCookie()[0] ?? '').split(';')[0] ?? '';
    assert.match(cookie, /^transit_session=/);
  }

  before(async () => {
    dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'transit-test-'));
    app = await createApp(testConfig(dataDir));
    ({ server, base } = await listen(app));
  });

  after(async () => {
    app.dispose();
    server.closeAllConnections();
    await new Promise((r) => server.close(r));
    await fs.rm(dataDir, { recursive: true, force: true });
  });

  async function upload(name: string, data: Buffer, opts: { ttl?: number; burn?: boolean } = {}) {
    const begin = await call('POST', '/api/uploads', {
      json: { name, size: data.length, ttl: opts.ttl ?? 60, burn: opts.burn ?? false },
    });
    assert.equal(begin.status, 201);
    const { uploadId, chunkBytes } = (await begin.json()) as { uploadId: string; chunkBytes: number };
    let last: { done: boolean; file: { id: string; name: string } } | undefined;
    for (let offset = 0; offset < data.length; offset += chunkBytes) {
      const res = await call('PUT', `/api/uploads/${uploadId}?offset=${offset}`, {
        body: data.subarray(offset, offset + chunkBytes),
      });
      assert.equal(res.status, 200);
      last = (await res.json()) as typeof last;
    }
    assert.ok(last?.done);
    return last.file;
  }

  it('serves the page with strict security headers', async () => {
    const res = await fetch(`${base}/`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-security-policy') ?? '', /default-src 'none'/);
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(res.headers.get('cache-control'), 'no-store');
  });

  it('refuses unauthenticated API access', async () => {
    assert.equal((await call('GET', '/api/files')).status, 401);
  });

  it('rejects mutations without the CSRF header', async () => {
    const res = await fetch(`${base}/api/login`, { method: 'POST', body: '{}' });
    assert.equal(res.status, 403);
  });

  it('rejects a wrong password, then accepts the right one', async () => {
    const bad = await call('POST', '/api/login', { json: { password: 'nope' }, ip: '203.0.113.1' });
    assert.equal(bad.status, 401);
    await login();
  });

  it('uploads in chunks, lists, downloads identical bytes', async () => {
    const data = crypto.randomBytes(2 * 2 * SEGMENT_BYTES + 4321);
    const file = await upload('a/b:c.bin', data);
    assert.equal(file.name, 'a_b_c.bin');

    const list = (await (await call('GET', '/api/files')).json()) as { files: { id: string; name: string }[] };
    assert.ok(list.files.some((f) => f.id === file.id && f.name === 'a_b_c.bin'));

    const dl = await call('GET', `/api/files/${file.id}`);
    assert.equal(dl.status, 200);
    assert.match(dl.headers.get('content-disposition') ?? '', /^attachment;/);
    assert.deepEqual(Buffer.from(await dl.arrayBuffer()), data);
  });

  it('stores nothing readable on disk', async () => {
    const marker = Buffer.from('TOP-SECRET-MARKER-'.repeat(2000));
    await upload('payroll-2026.xlsx', marker);
    const dir = path.join(dataDir, 'files');
    for (const name of await fs.readdir(dir)) {
      const content = await fs.readFile(path.join(dir, name));
      assert.equal(content.includes('TOP-SECRET-MARKER'), false, `${name} leaks content`);
      assert.equal(content.includes('payroll'), false, `${name} leaks the file name`);
    }
  });

  it('refuses to serve a blob that was modified on disk', async () => {
    const data = crypto.randomBytes(3 * SEGMENT_BYTES);
    const file = await upload('tamper.bin', data);
    const blob = path.join(dataDir, 'files', `${file.id}.bin`);
    const bytes = await fs.readFile(blob);
    bytes[5000] = (bytes[5000] ?? 0) ^ 1;
    await fs.writeFile(blob, bytes);

    let delivered: Buffer | null = null;
    try {
      const res = await call('GET', `/api/files/${file.id}`);
      delivered = Buffer.from(await res.arrayBuffer());
    } catch {
      delivered = null;
    }
    assert.ok(delivered === null || !delivered.equals(data));
  });

  it('resyncs on a wrong offset and rejects misaligned chunks', async () => {
    const begin = await call('POST', '/api/uploads', { json: { name: 'x', size: 400_000, ttl: 60 } });
    const { uploadId } = (await begin.json()) as { uploadId: string };
    const wrong = await call('PUT', `/api/uploads/${uploadId}?offset=1024`, { body: Buffer.alloc(SEGMENT_BYTES) });
    assert.equal(wrong.status, 409);
    assert.equal(((await wrong.json()) as { received: number }).received, 0);
    const misaligned = await call('PUT', `/api/uploads/${uploadId}?offset=0`, { body: Buffer.alloc(1000) });
    assert.equal(misaligned.status, 400);
    await call('DELETE', `/api/uploads/${uploadId}`);
  });

  it('enforces size limits', async () => {
    const res = await call('POST', '/api/uploads', { json: { name: 'big', size: 1_000_001, ttl: 60 } });
    assert.equal(res.status, 413);
  });

  it('deletes one-time files after the first download', async () => {
    const file = await upload('once.bin', crypto.randomBytes(300), { burn: true });
    await (await call('GET', `/api/files/${file.id}`)).arrayBuffer();
    await new Promise((r) => setTimeout(r, 150));
    assert.equal((await call('GET', `/api/files/${file.id}`)).status, 404);
  });

  it('expires files on purge', async () => {
    const file = await upload('short.bin', crypto.randomBytes(300), { ttl: 30 });
    await app.store.purge(Date.now() + 31_000);
    assert.equal((await call('GET', `/api/files/${file.id}`)).status, 404);
    const leftovers = (await fs.readdir(path.join(dataDir, 'files'))).filter((n) => n.startsWith(file.id));
    assert.deepEqual(leftovers, []);
  });

  it('cannot read names with a different key', async () => {
    const file = await upload('keyed.bin', crypto.randomBytes(300));
    const stored = app.store.get(file.id);
    assert.ok(stored);
    assert.equal(app.store.describe(stored, newFileKey()).name, '(unreadable)');
  });

  it('rejects malformed ids', async () => {
    assert.equal((await call('GET', '/api/files/..%2f..%2fconfig')).status, 404);
    assert.equal((await call('DELETE', '/api/files/not-an-id')).status, 404);
  });

  it('locks an IP out after repeated failures', async () => {
    const ip = '198.51.100.7';
    for (let i = 0; i < 5; i += 1) {
      assert.equal((await call('POST', '/api/login', { json: { password: 'wrong' }, ip })).status, 401);
    }
    const locked = await call('POST', '/api/login', { json: { password: PASSWORD }, ip });
    assert.equal(locked.status, 429);
    assert.ok(Number(locked.headers.get('retry-after')) > 0);
  });

  it('writes an audit log without file names', async () => {
    const log = await fs.readFile(path.join(dataDir, 'audit.log'), 'utf8');
    assert.match(log, /"event":"login_ok"/);
    assert.match(log, /"event":"upload_done"/);
    assert.equal(log.includes('payroll'), false);
    assert.equal(log.includes('a_b_c'), false);
  });

  it('wipes everything and signs out with the panic action', async () => {
    await upload('p1.bin', crypto.randomBytes(100));
    const res = await call('POST', '/api/panic');
    assert.equal(res.status, 200);
    assert.equal((await call('GET', '/api/files')).status, 401);
    await login();
    const list = (await (await call('GET', '/api/files')).json()) as { files: unknown[] };
    assert.equal(list.files.length, 0);
    assert.deepEqual((await fs.readdir(path.join(dataDir, 'files'))).filter((n) => n.endsWith('.bin')), []);
  });

  it('signs out', async () => {
    await call('POST', '/api/logout');
    assert.equal((await call('GET', '/api/files')).status, 401);
  });
});

describe('client-side encryption', () => {
  let master: CryptoKey;

  before(async () => {
    master = await deriveMasterKey('a long passphrase for tests', newSalt(), 1000);
  });

  async function encryptAll(key: CryptoKey, plain: Buffer): Promise<Buffer> {
    const total = segmentCount(plain.length);
    const parts: Buffer[] = [];
    for (let i = 0; i < total; i += 1) {
      const seg = new Uint8Array(plain.subarray(i * PLAIN_SEGMENT_BYTES, (i + 1) * PLAIN_SEGMENT_BYTES));
      parts.push(Buffer.from(await encryptUnit(key, i, i === total - 1, seg)));
    }
    return Buffer.concat(parts);
  }

  async function decryptAll(key: CryptoKey, cipher: Buffer): Promise<Buffer> {
    const units = Math.ceil(cipher.length / UNIT_BYTES);
    const parts: Buffer[] = [];
    for (let i = 0; i < units; i += 1) {
      const unit = new Uint8Array(cipher.subarray(i * UNIT_BYTES, (i + 1) * UNIT_BYTES));
      parts.push(Buffer.from(await decryptUnit(key, i, i === units - 1, unit)));
    }
    return Buffer.concat(parts);
  }

  it('round-trips the envelope and rejects a wrong passphrase', async () => {
    const { envelope } = await createEnvelope(master, 'Q3 payroll.xlsx');
    assert.equal((await openEnvelope(master, envelope)).name, 'Q3 payroll.xlsx');
    const other = await deriveMasterKey('another passphrase entirely', newSalt(), 1000);
    await assert.rejects(openEnvelope(other, envelope));
  });

  it('gives the same key check code only for the same passphrase and salt', async () => {
    const salt = newSalt();
    const a = await keyCheckCode(await deriveMasterKey('same passphrase', salt, 1000));
    const b = await keyCheckCode(await deriveMasterKey('same passphrase', salt, 1000));
    const c = await keyCheckCode(await deriveMasterKey('same passphrase!', salt, 1000));
    assert.equal(a, b);
    assert.notEqual(a, c);
  });

  it('round-trips and detects tampering, truncation and reordering', async () => {
    const { key } = await createEnvelope(master, 'x');
    const plain = crypto.randomBytes(2 * PLAIN_SEGMENT_BYTES + 99);
    const cipher = await encryptAll(key, plain);
    assert.equal(cipher.length, encryptedLength(plain.length));
    assert.deepEqual(await decryptAll(key, cipher), plain);

    const flipped = Buffer.from(cipher);
    flipped[10] = (flipped[10] ?? 0) ^ 1;
    await assert.rejects(decryptAll(key, flipped));
    await assert.rejects(decryptAll(key, cipher.subarray(0, 2 * UNIT_BYTES)));
    const swapped = Buffer.concat([cipher.subarray(UNIT_BYTES, 2 * UNIT_BYTES), cipher.subarray(0, UNIT_BYTES), cipher.subarray(2 * UNIT_BYTES)]);
    await assert.rejects(decryptAll(key, swapped));
  });

  describe('through the server', () => {
    let app: App;
    let server: Server;
    let base = '';
    let dataDir = '';
    let cookie = '';

    const call = (method: string, url: string, init: { json?: unknown; body?: Buffer } = {}): Promise<Response> => {
      const headers: Record<string, string> = { ...H, Cookie: cookie };
      let body: Buffer | string | undefined = init.body;
      if (init.json !== undefined) {
        headers['Content-Type'] = 'application/json';
        body = JSON.stringify(init.json);
      }
      return fetch(base + url, { method, headers, body: body as RequestInit['body'] });
    };

    before(async () => {
      dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'transit-e2ee-'));
      app = await createApp(
        testConfig(dataDir, { requireClientEncryption: true, chunkBytes: 2 * UNIT_BYTES, maxFileBytes: 10_000_000, maxTotalBytes: 20_000_000 }),
      );
      ({ server, base } = await listen(app));
      const res = await fetch(`${base}/api/login`, {
        method: 'POST',
        headers: { ...H, 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: PASSWORD }),
      });
      cookie = (res.headers.getSetCookie()[0] ?? '').split(';')[0] ?? '';
    });

    after(async () => {
      app.dispose();
      server.closeAllConnections();
      await new Promise((r) => server.close(r));
      await fs.rm(dataDir, { recursive: true, force: true });
    });

    it('refuses plaintext uploads and malformed envelopes', async () => {
      const plain = await call('POST', '/api/uploads', { json: { name: 'x', size: 100, ttl: 60 } });
      assert.equal(plain.status, 400);
      const bad = await call('POST', '/api/uploads', { json: { name: 'x', size: 100, ttl: 60, e2ee: '<script>' } });
      assert.equal(bad.status, 400);
    });

    it('stores only ciphertext and a hidden name, and the browser can decrypt it back', async () => {
      const plain = Buffer.concat([Buffer.from('CLIENT-SIDE-SECRET-'.repeat(5000)), crypto.randomBytes(PLAIN_SEGMENT_BYTES)]);
      const { envelope, key } = await createEnvelope(master, 'board-minutes.docx');
      const cipher = await encryptAll(key, plain);

      const begin = await call('POST', '/api/uploads', {
        json: { name: 'board-minutes.docx', size: cipher.length, ttl: 60, e2ee: envelope },
      });
      assert.equal(begin.status, 201);
      const { uploadId } = (await begin.json()) as { uploadId: string };
      for (let offset = 0; offset < cipher.length; offset += UNIT_BYTES) {
        const res = await call('PUT', `/api/uploads/${uploadId}?offset=${offset}`, {
          body: cipher.subarray(offset, offset + UNIT_BYTES),
        });
        assert.equal(res.status, 200);
      }

      const list = (await (await call('GET', '/api/files')).json()) as {
        files: { id: string; name: string; envelope: string | null }[];
      };
      const entry = list.files[0];
      assert.ok(entry);
      assert.equal(entry.name, 'encrypted');
      assert.equal((await openEnvelope(master, entry.envelope ?? '')).name, 'board-minutes.docx');

      const download = Buffer.from(await (await call('GET', `/api/files/${entry.id}`)).arrayBuffer());
      assert.deepEqual(download, cipher);
      assert.deepEqual(await decryptAll(key, download), plain);

      for (const name of await fs.readdir(path.join(dataDir, 'files'))) {
        const content = await fs.readFile(path.join(dataDir, 'files', name));
        assert.equal(content.includes('CLIENT-SIDE-SECRET'), false, `${name} leaks content`);
        assert.equal(content.includes('board-minutes'), false, `${name} leaks the name`);
      }
    });
  });
});

describe('cloudflare access (optional extra layer)', () => {
  const issuer = 'team.cloudflareaccess.com';
  let dataDir = '';
  let app: App;
  let server: Server;
  let base = '';
  let sign: (opts?: { aud?: string; exp?: string | number; email?: string }) => Promise<string>;

  before(async () => {
    const { publicKey, privateKey } = await generateKeyPair('RS256');
    const jwk: JWK = { ...(await exportJWK(publicKey)), alg: 'RS256', kid: 'k1' };
    sign = (opts = {}) =>
      new SignJWT({ email: opts.email ?? 'me@example.com' })
        .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
        .setIssuer(`https://${issuer}`)
        .setAudience(opts.aud ?? 'aud123')
        .setIssuedAt()
        .setExpirationTime(opts.exp ?? '5m')
        .sign(privateKey);

    dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'transit-access-'));
    const verifier = createAccessVerifier(
      { teamDomain: issuer, audience: 'aud123', emails: ['me@example.com'] },
      createLocalJWKSet({ keys: [jwk] }),
    );
    app = await createApp(testConfig(dataDir), { verifyAccess: verifier });
    ({ server, base } = await listen(app));
  });

  after(async () => {
    app.dispose();
    server.closeAllConnections();
    await new Promise((r) => server.close(r));
    await fs.rm(dataDir, { recursive: true, force: true });
  });

  const get = (token?: string) =>
    fetch(`${base}/`, { headers: token ? { 'Cf-Access-Jwt-Assertion': token } : {} });

  it('blocks requests without a token', async () => {
    assert.equal((await get()).status, 403);
  });

  it('accepts a valid token', async () => {
    assert.equal((await get(await sign())).status, 200);
  });

  it('blocks a token for another audience, an expired one and another email', async () => {
    assert.equal((await get(await sign({ aud: 'other' }))).status, 403);
    assert.equal((await get(await sign({ exp: Math.floor(Date.now() / 1000) - 120 }))).status, 403);
    assert.equal((await get(await sign({ email: 'intruder@example.com' }))).status, 403);
  });

  it('blocks a token signed by an unknown key', async () => {
    const other = await generateKeyPair('RS256');
    const forged = await new SignJWT({ email: 'me@example.com' })
      .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
      .setIssuer(`https://${issuer}`)
      .setAudience('aud123')
      .setExpirationTime('5m')
      .sign(other.privateKey);
    assert.equal((await get(forged)).status, 403);
  });
});

describe('totp', () => {
  it('accepts the current code once and rejects replay', () => {
    const secret = generateTotpSecret();
    const verifier = new TotpVerifier(secret);
    const now = 1_700_000_000_000;
    const code = hotp(base32Decode(secret), Math.floor(now / 30000));
    assert.equal(verifier.verify(code, now), true);
    assert.equal(verifier.verify(code, now), false);
  });

  it('matches the RFC 6238 SHA-1 test vector', () => {
    assert.equal(hotp(Buffer.from('12345678901234567890'), Math.floor(59 / 30)), '287082');
  });
});
