import crypto from 'node:crypto';
import { Transform, type TransformCallback } from 'node:stream';
import { promisify } from 'node:util';

/** Plaintext bytes per encrypted segment. Upload chunks must be a multiple of this. */
export const SEGMENT_BYTES = 64 * 1024;
const TAG_BYTES = 16;
const NONCE_BYTES = 12;
const KEY_BYTES = 32;
const UNIT_BYTES = SEGMENT_BYTES + TAG_BYTES;
const ALGORITHM = 'aes-256-gcm';

const scrypt = promisify(crypto.scrypt) as (
  password: string,
  salt: Buffer,
  keylen: number,
  options: crypto.ScryptOptions,
) => Promise<Buffer>;

export const segmentCount = (plainSize: number): number => Math.ceil(plainSize / SEGMENT_BYTES);

/** Size of the stored blob for a plaintext of `plainSize` bytes. */
export const encryptedSize = (plainSize: number): number => plainSize + segmentCount(plainSize) * TAG_BYTES;

/** Blob offset of the segment that starts at the (segment-aligned) plaintext offset. */
export const blobOffset = (plainOffset: number): number => (plainOffset / SEGMENT_BYTES) * UNIT_BYTES;

export function newSalt(): string {
  return crypto.randomBytes(16).toString('base64');
}

/** Derives the 256-bit master key from the password. It only ever lives in memory. */
export function deriveMasterKey(password: string, saltBase64: string): Promise<Buffer> {
  return scrypt(password, Buffer.from(saltBase64, 'base64'), KEY_BYTES, {
    N: 1 << 15,
    r: 8,
    p: 1,
    maxmem: 128 * 1024 * 1024,
  });
}

export const newFileKey = (): Buffer => crypto.randomBytes(KEY_BYTES);

/** AES-256-GCM seal of a small value, encoded as base64(iv | ciphertext | tag). */
export function seal(key: Buffer, plain: Buffer): string {
  const iv = crypto.randomBytes(NONCE_BYTES);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, { authTagLength: TAG_BYTES });
  const body = Buffer.concat([cipher.update(plain), cipher.final()]);
  return Buffer.concat([iv, body, cipher.getAuthTag()]).toString('base64');
}

export function open(key: Buffer, sealed: string): Buffer {
  const raw = Buffer.from(sealed, 'base64');
  if (raw.length < NONCE_BYTES + TAG_BYTES) throw new Error('Sealed value is too short');
  const decipher = crypto.createDecipheriv(ALGORITHM, key, raw.subarray(0, NONCE_BYTES), {
    authTagLength: TAG_BYTES,
  });
  decipher.setAuthTag(raw.subarray(raw.length - TAG_BYTES));
  return Buffer.concat([decipher.update(raw.subarray(NONCE_BYTES, raw.length - TAG_BYTES)), decipher.final()]);
}

function segmentNonce(index: number): Buffer {
  const nonce = Buffer.alloc(NONCE_BYTES);
  nonce.writeBigUInt64BE(BigInt(index), NONCE_BYTES - 8);
  return nonce;
}

/**
 * Splits a byte stream into fixed-size units and transforms each one.
 * Each file has its own random key, so the segment index alone is a unique nonce.
 * The "last segment" flag is authenticated, which makes truncation detectable.
 */
abstract class SegmentStream extends Transform {
  protected readonly key: Buffer;
  protected readonly lastIndex: number;
  protected index: number;
  private pending: Buffer = Buffer.alloc(0);
  private readonly unitBytes: number;

  protected constructor(key: Buffer, plainSize: number, unitBytes: number, firstIndex: number) {
    super();
    this.key = key;
    this.lastIndex = segmentCount(plainSize) - 1;
    this.unitBytes = unitBytes;
    this.index = firstIndex;
  }

  protected abstract process(unit: Buffer, index: number, isLast: boolean): Buffer;

  override _transform(chunk: Buffer, _encoding: BufferEncoding, callback: TransformCallback): void {
    try {
      this.pending = this.pending.length ? Buffer.concat([this.pending, chunk]) : chunk;
      let pos = 0;
      while (this.pending.length - pos >= this.unitBytes) {
        this.emit_(this.pending.subarray(pos, pos + this.unitBytes));
        pos += this.unitBytes;
      }
      this.pending = this.pending.subarray(pos);
      callback();
    } catch (err) {
      callback(err as Error);
    }
  }

  override _flush(callback: TransformCallback): void {
    try {
      if (this.pending.length > 0) this.emit_(this.pending);
      this.pending = Buffer.alloc(0);
      this.finalCheck();
      callback();
    } catch (err) {
      callback(err as Error);
    }
  }

  protected finalCheck(): void {}

  private emit_(unit: Buffer): void {
    if (this.index > this.lastIndex) throw new Error('More data than the declared size');
    const index = this.index;
    this.index += 1;
    this.push(this.process(unit, index, index === this.lastIndex));
  }
}

/** Encrypts plaintext that starts at a segment boundary (`firstSegment`). */
export class SegmentEncryptor extends SegmentStream {
  constructor(key: Buffer, plainSize: number, firstSegment: number) {
    super(key, plainSize, SEGMENT_BYTES, firstSegment);
  }

  protected override process(unit: Buffer, index: number, isLast: boolean): Buffer {
    const cipher = crypto.createCipheriv(ALGORITHM, this.key, segmentNonce(index), { authTagLength: TAG_BYTES });
    cipher.setAAD(Buffer.from([isLast ? 1 : 0]));
    return Buffer.concat([cipher.update(unit), cipher.final(), cipher.getAuthTag()]);
  }
}

/** Decrypts a whole blob; fails on any tampering, reordering or truncation. */
export class SegmentDecryptor extends SegmentStream {
  constructor(key: Buffer, plainSize: number) {
    super(key, plainSize, UNIT_BYTES, 0);
  }

  protected override process(unit: Buffer, index: number, isLast: boolean): Buffer {
    if (unit.length <= TAG_BYTES) throw new Error('Corrupt segment');
    const decipher = crypto.createDecipheriv(ALGORITHM, this.key, segmentNonce(index), {
      authTagLength: TAG_BYTES,
    });
    decipher.setAAD(Buffer.from([isLast ? 1 : 0]));
    decipher.setAuthTag(unit.subarray(unit.length - TAG_BYTES));
    return Buffer.concat([decipher.update(unit.subarray(0, unit.length - TAG_BYTES)), decipher.final()]);
  }

  protected override finalCheck(): void {
    if (this.index !== this.lastIndex + 1) throw new Error('File is truncated');
  }
}
