import crypto from 'node:crypto';
import { promisify } from 'node:util';
import { HttpError } from './errors.js';

const scrypt = promisify(crypto.scrypt) as (
  password: string,
  salt: Buffer,
  keylen: number,
  options: crypto.ScryptOptions,
) => Promise<Buffer>;

const SCRYPT = { N: 1 << 15, r: 8, p: 1, maxmem: 128 * 1024 * 1024 } satisfies crypto.ScryptOptions;

/** Hashes a password as "scrypt$N$salt$hash" (base64 parts). */
export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 32, SCRYPT);
  return `scrypt$${SCRYPT.N}$${salt.toString('base64')}$${hash.toString('base64')}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [alg, n, saltB64, hashB64] = stored.split('$');
  if (alg !== 'scrypt' || !n || !saltB64 || !hashB64) return false;
  const expected = Buffer.from(hashB64, 'base64');
  const actual = await scrypt(password, Buffer.from(saltB64, 'base64'), expected.length, {
    ...SCRYPT,
    N: Number(n),
  });
  return crypto.timingSafeEqual(actual, expected);
}

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buf: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(str: string): Buffer {
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of str.replace(/=+$/, '').toUpperCase()) {
    const idx = B32.indexOf(ch);
    if (idx < 0) throw new Error('Invalid base32 secret');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export function generateTotpSecret(): string {
  return base32Encode(crypto.randomBytes(20));
}

export function hotp(secret: Buffer, counter: number): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', secret).update(msg).digest();
  const o = h[19]! & 15;
  const code = (((h[o]! & 0x7f) << 24) | (h[o + 1]! << 16) | (h[o + 2]! << 8) | h[o + 3]!) % 1e6;
  return String(code).padStart(6, '0');
}

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}

/** RFC 6238 verifier (SHA-1, 30 s, 6 digits, +/-1 step) that rejects code replay. */
export class TotpVerifier {
  private readonly secret: Buffer;
  private lastStep = 0;

  constructor(secretBase32: string) {
    this.secret = base32Decode(secretBase32);
  }

  verify(code: string, now: number = Date.now()): boolean {
    if (!/^\d{6}$/.test(code)) return false;
    const step = Math.floor(now / 30000);
    for (const delta of [-1, 0, 1]) {
      const s = step + delta;
      if (s > this.lastStep && safeEqual(hotp(this.secret, s), code)) {
        this.lastStep = s;
        return true;
      }
    }
    return false;
  }
}

const sha256 = (s: string): string => crypto.createHash('sha256').update(s).digest('hex');

interface SessionEntry {
  created: number;
  last: number;
  /** Master encryption key derived at login. Zeroed when the session ends. */
  masterKey: Buffer;
}

/**
 * In-memory sessions with idle and absolute timeouts and a cap on concurrent sessions.
 * Tokens are stored hashed. Each session owns a copy of the master key, so once the
 * last session is gone nothing in memory can decrypt the stored files.
 */
export class Sessions {
  private readonly map = new Map<string, SessionEntry>();
  private readonly idleMs: number;
  private readonly maxMs: number;
  private readonly maxSessions: number;

  constructor(options: { idleMs: number; maxMs: number; maxSessions: number }) {
    this.idleMs = options.idleMs;
    this.maxMs = options.maxMs;
    this.maxSessions = options.maxSessions;
  }

  create(masterKey: Buffer): string {
    while (this.map.size >= this.maxSessions) {
      const oldest = this.map.keys().next();
      if (oldest.done) break;
      this.drop(oldest.value);
    }
    const token = crypto.randomBytes(32).toString('base64url');
    const now = Date.now();
    this.map.set(sha256(token), { created: now, last: now, masterKey });
    return token;
  }

  /** Returns the session's master key if the token is valid, and refreshes its idle timer. */
  unlock(token: string | undefined, now: number = Date.now()): Buffer | null {
    if (!token) return null;
    const id = sha256(token);
    const s = this.map.get(id);
    if (!s) return null;
    if (this.isStale(s, now)) {
      this.drop(id);
      return null;
    }
    s.last = now;
    return s.masterKey;
  }

  destroy(token: string | undefined): void {
    if (token) this.drop(sha256(token));
  }

  destroyAll(): void {
    for (const id of [...this.map.keys()]) this.drop(id);
  }

  sweep(now: number = Date.now()): void {
    for (const [id, s] of this.map) {
      if (this.isStale(s, now)) this.drop(id);
    }
  }

  private drop(id: string): void {
    this.map.get(id)?.masterKey.fill(0);
    this.map.delete(id);
  }

  private isStale(s: SessionEntry, now: number): boolean {
    return now - s.last > this.idleMs || now - s.created > this.maxMs;
  }
}

interface LimiterEntry {
  fails: number;
  until: number;
  last: number;
}

/**
 * Per-IP exponential lockout after 5 failures, plus a global slowdown that
 * grows with recent failures (never a hard lock, so it cannot lock the owner out).
 */
export class LoginLimiter {
  private readonly byIp = new Map<string, LimiterEntry>();
  private recent: number[] = [];

  lockedFor(ip: string, now: number = Date.now()): number {
    const e = this.byIp.get(ip);
    return e && e.until > now ? e.until - now : 0;
  }

  fail(ip: string, now: number = Date.now()): void {
    const e = this.byIp.get(ip) ?? { fails: 0, until: 0, last: now };
    e.fails += 1;
    e.last = now;
    if (e.fails >= 5) e.until = now + Math.min(30000 * 2 ** (e.fails - 5), 3600000);
    this.byIp.set(ip, e);
    this.recent.push(now);
  }

  success(ip: string): void {
    this.byIp.delete(ip);
  }

  globalDelayMs(now: number = Date.now()): number {
    this.recent = this.recent.filter((t) => now - t < 600000);
    return Math.min(this.recent.length * 100, 5000);
  }

  sweep(now: number = Date.now()): void {
    for (const [ip, e] of this.byIp) {
      if (e.until < now && now - e.last > 3600000) this.byIp.delete(ip);
    }
  }
}

/**
 * Runs password checks strictly one at a time and refuses to queue more than
 * `maxWaiting`, so guessing cannot be parallelised however many IPs are used.
 */
export class LoginGate {
  private tail: Promise<unknown> = Promise.resolve();
  private waiting = 0;
  private readonly maxWaiting: number;

  constructor(maxWaiting: number) {
    this.maxWaiting = maxWaiting;
  }

  async run<T>(task: () => Promise<T>): Promise<T> {
    if (this.waiting >= this.maxWaiting) {
      throw new HttpError(429, 'Too many sign-in attempts in progress', { headers: { 'Retry-After': '10' } });
    }
    this.waiting += 1;
    const result = this.tail.then(task);
    this.tail = result.catch(() => undefined);
    try {
      return await result;
    } finally {
      this.waiting -= 1;
    }
  }
}

/** Fixed-window request cap per IP. */
export class RequestLimiter {
  private readonly hits = new Map<string, { count: number; resetAt: number }>();
  private readonly limit: number;
  private readonly windowMs: number;

  constructor(limit: number, windowMs: number) {
    this.limit = limit;
    this.windowMs = windowMs;
  }

  allow(ip: string, now: number = Date.now()): boolean {
    const e = this.hits.get(ip);
    if (!e || e.resetAt <= now) {
      this.hits.set(ip, { count: 1, resetAt: now + this.windowMs });
      return true;
    }
    e.count += 1;
    return e.count <= this.limit;
  }

  sweep(now: number = Date.now()): void {
    for (const [ip, e] of this.hits) {
      if (e.resetAt <= now) this.hits.delete(ip);
    }
  }
}
