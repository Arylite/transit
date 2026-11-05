import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pipeline as pipelineCb, Transform, type Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import type { Config } from './config.js';
import { HttpError } from './errors.js';
import {
  blobOffset,
  encryptedSize,
  newFileKey,
  open,
  seal,
  SEGMENT_BYTES,
  SegmentDecryptor,
  SegmentEncryptor,
} from './seal.js';

const fsp = fs.promises;
const ID_RE = /^[a-f0-9]{32}$/;
const UPLOAD_IDLE_MS = 60 * 60 * 1000;
const MAX_PARALLEL_UPLOADS = 20;

const newId = (): string => crypto.randomBytes(16).toString('hex');

/** What is persisted. The name and the file key are only stored sealed. */
export interface StoredFile {
  id: string;
  size: number;
  createdAt: number;
  expiresAt: number;
  /** Delete the file after its first complete download. */
  burn: boolean;
  /** Per-file key, sealed with the master key. Deleting this record shreds the blob. */
  wrappedKey: string;
  /** File name, sealed with the per-file key. */
  encName: string;
  /** Opaque client-side encryption envelope (real name, salt); null for server-only encryption. */
  envelope: string | null;
}

/** What the API shows to a signed-in user. */
export interface FileView {
  id: string;
  name: string;
  size: number;
  createdAt: number;
  expiresAt: number;
  burn: boolean;
  envelope: string | null;
}

export interface UploadRequest {
  name: string;
  size: number;
  ttlMs: number;
  burn: boolean;
  envelope: string | null;
}

interface Upload {
  id: string;
  size: number;
  ttlMs: number;
  burn: boolean;
  envelope: string | null;
  fileKey: Buffer;
  wrappedKey: string;
  encName: string;
  received: number;
  busy: boolean;
  touched: number;
  tmpPath: string;
}

export type ChunkResult =
  | { done: false; received: number }
  | { done: true; file: StoredFile };

/**
 * Disk-backed encrypted file store.
 *
 * Blobs live at files/<id>.bin (AES-256-GCM, 64 KiB segments, random per-file key),
 * metadata at files/<id>.json. The original name is never used as a path and is only
 * stored encrypted. Uploads are sequential, resumable chunk streams assembled in tmp/.
 */
export class Store {
  private readonly cfg: Config;
  private readonly filesDir: string;
  private readonly tmpDir: string;
  private readonly files = new Map<string, StoredFile>();
  private readonly uploads = new Map<string, Upload>();
  private readonly pendingRemoval = new Set<string>();

  constructor(cfg: Config) {
    this.cfg = cfg;
    this.filesDir = path.join(cfg.dataDir, 'files');
    this.tmpDir = path.join(cfg.dataDir, 'tmp');
  }

  static isValidId(id: string): boolean {
    return ID_RE.test(id);
  }

  async init(): Promise<void> {
    await fsp.mkdir(this.filesDir, { recursive: true });
    await fsp.rm(this.tmpDir, { recursive: true, force: true });
    await fsp.mkdir(this.tmpDir, { recursive: true });

    const names = await fsp.readdir(this.filesDir);
    for (const name of names) {
      if (!name.endsWith('.json')) continue;
      const id = name.slice(0, -5);
      if (!ID_RE.test(id)) continue;
      try {
        const meta = JSON.parse(await fsp.readFile(this.metaPath(id), 'utf8')) as StoredFile;
        const stat = await fsp.stat(this.blobPath(id));
        if (meta.id === id && stat.size === encryptedSize(meta.size)) {
          this.files.set(id, { ...meta, envelope: meta.envelope ?? null });
        }
      } catch {
        // Unreadable or incomplete entry: removed below.
      }
    }
    for (const name of names) {
      const id = name.split('.')[0] ?? '';
      if (!this.files.has(id)) await fsp.rm(path.join(this.filesDir, name), { force: true });
    }
    await this.purge();
  }

  usedBytes(): number {
    let total = 0;
    for (const f of this.files.values()) total += f.size;
    for (const u of this.uploads.values()) total += u.size;
    return total;
  }

  list(now: number = Date.now()): StoredFile[] {
    return [...this.files.values()]
      .filter((f) => f.expiresAt > now)
      .sort((a, b) => b.createdAt - a.createdAt);
  }

  get(id: string, now: number = Date.now()): StoredFile | null {
    const f = ID_RE.test(id) ? this.files.get(id) : undefined;
    return f && f.expiresAt > now ? f : null;
  }

  /** Decrypts the file name for display. Never throws: a wrong key yields a placeholder. */
  describe(file: StoredFile, masterKey: Buffer): FileView {
    let name = '(unreadable)';
    try {
      const fileKey = open(masterKey, file.wrappedKey);
      try {
        name = open(fileKey, file.encName).toString('utf8');
      } finally {
        fileKey.fill(0);
      }
    } catch {
      // Stored under a different password; the file can only expire.
    }
    return {
      id: file.id,
      name,
      size: file.size,
      createdAt: file.createdAt,
      expiresAt: file.expiresAt,
      burn: file.burn,
      envelope: file.envelope,
    };
  }

  /** Streams the decrypted file. The stream errors if the blob was altered or truncated. */
  openDecrypted(file: StoredFile, masterKey: Buffer): Readable {
    const fileKey = open(masterKey, file.wrappedKey);
    const decryptor = new SegmentDecryptor(fileKey, file.size);
    pipelineCb(fs.createReadStream(this.blobPath(file.id)), decryptor, () => fileKey.fill(0));
    return decryptor;
  }

  /** Reserves quota and creates the tmp file for a new upload. */
  async beginUpload(req: UploadRequest, masterKey: Buffer): Promise<string> {
    if (!Number.isSafeInteger(req.size) || req.size <= 0) throw new HttpError(400, 'Invalid or empty file');
    if (req.size > this.cfg.maxFileBytes) throw new HttpError(413, 'File exceeds the size limit');
    if (this.usedBytes() + req.size > this.cfg.maxTotalBytes) throw new HttpError(507, 'Storage quota exceeded');
    if (this.uploads.size >= MAX_PARALLEL_UPLOADS) throw new HttpError(429, 'Too many uploads in progress');

    const id = newId();
    const fileKey = newFileKey();
    const up: Upload = {
      id,
      size: req.size,
      ttlMs: req.ttlMs,
      burn: req.burn,
      envelope: req.envelope,
      fileKey,
      wrappedKey: seal(masterKey, fileKey),
      encName: seal(fileKey, Buffer.from(req.name, 'utf8')),
      received: 0,
      busy: false,
      touched: Date.now(),
      tmpPath: path.join(this.tmpDir, id),
    };
    this.uploads.set(id, up);
    try {
      await fsp.writeFile(up.tmpPath, '', { flag: 'wx', mode: 0o600 });
    } catch (err) {
      this.uploads.delete(id);
      fileKey.fill(0);
      throw err;
    }
    return id;
  }

  uploadProgress(id: string): number {
    return this.getUpload(id).received;
  }

  /**
   * Encrypts and writes one chunk at `offset`. `received` only advances once the whole
   * chunk arrived, so a failed chunk can simply be sent again. Every chunk except the
   * last must be a multiple of the segment size so segments never straddle chunks.
   */
  async appendChunk(id: string, offset: number, body: Readable, length: number): Promise<ChunkResult> {
    const up = this.getUpload(id);
    if (up.busy) throw new HttpError(409, 'Chunk already in progress', { extra: { received: up.received } });
    if (offset !== up.received) throw new HttpError(409, 'Offset mismatch', { extra: { received: up.received } });
    const isFinal = up.received + length === up.size;
    const sizeOk = length > 0 && length <= this.cfg.chunkBytes && up.received + length <= up.size;
    if (!sizeOk || (!isFinal && length % SEGMENT_BYTES !== 0)) throw new HttpError(400, 'Invalid chunk length');

    up.busy = true;
    try {
      let n = 0;
      const counter = new Transform({
        transform(chunk: Buffer, _enc, cb) {
          n += chunk.length;
          if (n > length) cb(new HttpError(400, 'Body longer than Content-Length'));
          else cb(null, chunk);
        },
      });
      const encryptor = new SegmentEncryptor(up.fileKey, up.size, offset / SEGMENT_BYTES);
      const out = fs.createWriteStream(up.tmpPath, { flags: 'r+', start: blobOffset(offset) });
      await pipeline(body, counter, encryptor, out);
      if (n !== length) throw new HttpError(400, 'Body shorter than Content-Length');
      if (this.uploads.get(id) !== up) throw new HttpError(404, 'Upload was cancelled');

      up.received += n;
      up.touched = Date.now();
      if (up.received < up.size) return { done: false, received: up.received };
      return { done: true, file: await this.finish(up) };
    } finally {
      up.busy = false;
    }
  }

  async cancelUpload(id: string): Promise<void> {
    const up = this.getUpload(id);
    this.uploads.delete(id);
    up.fileKey.fill(0);
    await fsp.rm(up.tmpPath, { force: true }).catch(() => undefined);
  }

  /** Deletes the metadata first (destroying the sealed key), then the blob. */
  async remove(id: string): Promise<void> {
    this.files.delete(id);
    try {
      await fsp.rm(this.metaPath(id), { force: true });
      await fsp.rm(this.blobPath(id), { force: true });
      this.pendingRemoval.delete(id);
    } catch {
      this.pendingRemoval.add(id);
    }
  }

  /** Removes every file and abandoned upload. Returns how many files were deleted. */
  async wipeAll(): Promise<number> {
    const ids = [...this.files.keys()];
    for (const id of ids) await this.remove(id);
    for (const id of [...this.uploads.keys()]) await this.cancelUpload(id);
    return ids.length;
  }

  /** Deletes expired files and abandoned uploads, and retries failed deletions. Returns expired ids. */
  async purge(now: number = Date.now()): Promise<string[]> {
    const expired: string[] = [];
    for (const [id, f] of this.files) {
      if (f.expiresAt > now) continue;
      expired.push(id);
      await this.remove(id);
    }
    for (const id of [...this.pendingRemoval]) await this.remove(id);
    for (const [id, up] of this.uploads) {
      if (!up.busy && now - up.touched > UPLOAD_IDLE_MS) await this.cancelUpload(id);
    }
    return expired;
  }

  private async finish(up: Upload): Promise<StoredFile> {
    const stat = await fsp.stat(up.tmpPath);
    if (stat.size !== encryptedSize(up.size)) throw new HttpError(500, 'Stored size mismatch');
    const createdAt = Date.now();
    const meta: StoredFile = {
      id: up.id,
      size: up.size,
      createdAt,
      expiresAt: createdAt + up.ttlMs,
      burn: up.burn,
      wrappedKey: up.wrappedKey,
      encName: up.encName,
      envelope: up.envelope,
    };
    await fsp.rename(up.tmpPath, this.blobPath(up.id));
    await fsp.writeFile(this.metaPath(up.id), JSON.stringify(meta), { mode: 0o600 });
    this.files.set(up.id, meta);
    this.uploads.delete(up.id);
    up.fileKey.fill(0);
    return meta;
  }

  private getUpload(id: string): Upload {
    const up = ID_RE.test(id) ? this.uploads.get(id) : undefined;
    if (!up) throw new HttpError(404, 'Unknown upload');
    return up;
  }

  private blobPath(id: string): string {
    return path.join(this.filesDir, `${id}.bin`);
  }

  private metaPath(id: string): string {
    return path.join(this.filesDir, `${id}.json`);
  }
}
