/**
 * Client-side encryption, run in the browser with Web Crypto. The server only ever
 * receives ciphertext and an opaque envelope; the passphrase never leaves the page.
 *
 * Key hierarchy:
 *   passphrase --PBKDF2-SHA256 (server-supplied salt)--> master key (HKDF key)
 *   master key --HKDF (random per-file salt)--> per-file AES-256-GCM key
 *
 * File body: AES-256-GCM in 1 MiB units (1 MiB - 16 bytes of plaintext + 16-byte tag).
 * The nonce is the unit index and the authenticated data flags the last unit, so
 * reordering and truncation are detected. Each file has its own key, so nonces never repeat.
 *
 * Envelope (base64): version(1) | file salt(16) | iv(12) | AES-GCM(name).
 */

const TAG_BYTES = 16;
const NONCE_BYTES = 12;
const SALT_BYTES = 16;
const ENVELOPE_VERSION = 1;

/** Ciphertext bytes per unit. A multiple of 64 KiB, which the server requires for chunking. */
export const UNIT_BYTES = 1024 * 1024;
export const PLAIN_SEGMENT_BYTES = UNIT_BYTES - TAG_BYTES;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export const segmentCount = (plainSize: number): number => Math.ceil(plainSize / PLAIN_SEGMENT_BYTES);

/** Size of the encrypted body for a plaintext of `plainSize` bytes. */
export const encryptedLength = (plainSize: number): number => plainSize + segmentCount(plainSize) * TAG_BYTES;

export function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function fromBase64(text: string): Uint8Array<ArrayBuffer> {
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

const randomBytes = (length: number): Uint8Array<ArrayBuffer> => crypto.getRandomValues(new Uint8Array(length));

/** Derives the master key from the passphrase. Deliberately slow; do it once per unlock. */
export async function deriveMasterKey(passphrase: string, saltBase64: string, iterations: number): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey('raw', encoder.encode(passphrase.normalize('NFKC')), 'PBKDF2', false, [
    'deriveBits',
  ]);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: fromBase64(saltBase64), iterations },
    material,
    256,
  );
  return crypto.subtle.importKey('raw', bits, 'HKDF', false, ['deriveKey', 'deriveBits']);
}

/** Short code derived from the master key, to compare by eye that two machines typed the same passphrase. */
export async function keyCheckCode(master: CryptoKey): Promise<string> {
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: encoder.encode('transit/check/v1') },
    master,
    24,
  );
  return [...new Uint8Array(bits)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function deriveFileKey(master: CryptoKey, salt: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: encoder.encode('transit/file/v1') },
    master,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export interface OpenedFile {
  name: string;
  key: CryptoKey;
}

/** Creates a new random file key and the envelope that carries the encrypted name. */
export async function createEnvelope(master: CryptoKey, name: string): Promise<{ envelope: string; key: CryptoKey }> {
  const salt = randomBytes(SALT_BYTES);
  const iv = randomBytes(NONCE_BYTES);
  const key = await deriveFileKey(master, salt);
  const sealedName = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: encoder.encode('name'), tagLength: 128 },
      key,
      encoder.encode(name),
    ),
  );
  const out = new Uint8Array(1 + SALT_BYTES + NONCE_BYTES + sealedName.length);
  out[0] = ENVELOPE_VERSION;
  out.set(salt, 1);
  out.set(iv, 1 + SALT_BYTES);
  out.set(sealedName, 1 + SALT_BYTES + NONCE_BYTES);
  return { envelope: toBase64(out), key };
}

/** Recovers the file name and key. Throws if the passphrase is wrong or the envelope was altered. */
export async function openEnvelope(master: CryptoKey, envelope: string): Promise<OpenedFile> {
  const raw = fromBase64(envelope);
  if (raw[0] !== ENVELOPE_VERSION || raw.length < 1 + SALT_BYTES + NONCE_BYTES + TAG_BYTES) {
    throw new Error('Unsupported envelope');
  }
  const salt = raw.slice(1, 1 + SALT_BYTES);
  const iv = raw.slice(1 + SALT_BYTES, 1 + SALT_BYTES + NONCE_BYTES);
  const key = await deriveFileKey(master, salt);
  const name = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, additionalData: encoder.encode('name'), tagLength: 128 },
    key,
    raw.slice(1 + SALT_BYTES + NONCE_BYTES),
  );
  return { name: decoder.decode(name), key };
}

interface GcmParams {
  name: 'AES-GCM';
  iv: Uint8Array<ArrayBuffer>;
  additionalData: Uint8Array<ArrayBuffer>;
  tagLength: 128;
}

function unitParams(index: number, isLast: boolean): GcmParams {
  const iv = new Uint8Array(NONCE_BYTES);
  new DataView(iv.buffer).setBigUint64(NONCE_BYTES - 8, BigInt(index));
  return { name: 'AES-GCM', iv, additionalData: Uint8Array.of(isLast ? 1 : 0), tagLength: 128 };
}

export async function encryptUnit(
  key: CryptoKey,
  index: number,
  isLast: boolean,
  plain: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.encrypt(unitParams(index, isLast), key, plain));
}

export async function decryptUnit(
  key: CryptoKey,
  index: number,
  isLast: boolean,
  unit: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.decrypt(unitParams(index, isLast), key, unit));
}
