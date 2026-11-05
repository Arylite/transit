import {
  createEnvelope,
  decryptUnit,
  deriveMasterKey,
  encryptUnit,
  encryptedLength,
  keyCheckCode,
  openEnvelope,
  PLAIN_SEGMENT_BYTES,
  segmentCount,
  UNIT_BYTES,
  type OpenedFile,
} from './e2ee.js';

interface FileInfo {
  id: string;
  name: string;
  size: number;
  createdAt: number;
  expiresAt: number;
  burn: boolean;
  envelope: string | null;
}

interface Limits {
  ttlChoices: number[];
  defaultTtlSeconds: number;
  maxFileBytes: number;
  maxTotalBytes: number;
  e2ee: { salt: string; iterations: number; required: boolean };
}

interface SessionInfo {
  authenticated: boolean;
  totp: boolean;
  limits?: Limits;
}

interface FilesResponse {
  files: FileInfo[];
  usedBytes: number;
  now: number;
}

interface BeginResponse {
  uploadId: string;
  chunkBytes: number;
}

type ChunkResponse = { done: false; received: number } | { done: true; file: FileInfo };

class ApiError extends Error {
  readonly status: number;
  readonly data: Record<string, unknown>;
  readonly network: boolean;
  readonly cancelled: boolean;

  constructor(
    message: string,
    options: { status?: number; data?: Record<string, unknown>; network?: boolean; cancelled?: boolean } = {},
  ) {
    super(message);
    this.status = options.status ?? 0;
    this.data = options.data ?? {};
    this.network = options.network ?? false;
    this.cancelled = options.cancelled ?? false;
  }
}

const CSRF_HEADERS = { 'X-Requested-With': 'transit' } as const;
const MAX_RETRIES = 5;
const TTL_STORAGE_KEY = 'transit.ttl';

function $<T extends HTMLElement>(selector: string): T {
  const element = document.querySelector<T>(selector);
  if (!element) throw new Error(`Missing element: ${selector}`);
  return element;
}

function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Partial<HTMLElementTagNameMap[K]> = {},
  ...children: (Node | string)[]
): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  Object.assign(element, props);
  element.append(...children);
  return element;
}

const loginView = $<HTMLElement>('#login-view');
const vaultView = $<HTMLElement>('#vault-view');
const loginForm = $<HTMLFormElement>('#login-form');
const passwordInput = $<HTMLInputElement>('#password');
const codeField = $<HTMLElement>('#code-field');
const codeInput = $<HTMLInputElement>('#code');
const loginError = $<HTMLElement>('#login-error');
const usageLabel = $<HTMLElement>('#usage');
const logoutButton = $<HTMLButtonElement>('#logout');
const panicButton = $<HTMLButtonElement>('#panic');
const notice = $<HTMLElement>('#notice');
const unlockForm = $<HTMLFormElement>('#unlock-form');
const passphraseInput = $<HTMLInputElement>('#passphrase');
const unlockButton = $<HTMLButtonElement>('#unlock');
const lockButton = $<HTMLButtonElement>('#lock');
const keyStatus = $<HTMLElement>('#key-status');
const dropZone = $<HTMLElement>('#drop');
const fileInput = $<HTMLInputElement>('#file-input');
const ttlSelect = $<HTMLSelectElement>('#ttl');
const burnCheckbox = $<HTMLInputElement>('#burn');
const transfersList = $<HTMLUListElement>('#transfers');
const filesTable = $<HTMLTableElement>('#files-table');
const filesBody = $<HTMLTableSectionElement>('#files-body');
const emptyLabel = $<HTMLElement>('#empty');

let limits: Limits | null = null;
let files: FileInfo[] = [];
let clockOffset = 0;
let pollTimer: number | undefined;
let tickTimer: number | undefined;
let noticeTimer: number | undefined;
let master: CryptoKey | null = null;
const opened = new Map<string, OpenedFile | null>();
const countdownCells = new Map<string, { cell: HTMLElement; expiresAt: number }>();

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

function showNotice(message: string): void {
  notice.textContent = message;
  notice.hidden = false;
  window.clearTimeout(noticeTimer);
  noticeTimer = window.setTimeout(() => {
    notice.hidden = true;
  }, 10000);
}

function formatBytes(bytes: number): string {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${unit === 0 || value >= 100 ? Math.round(value) : value.toFixed(1)} ${units[unit]}`;
}

function formatRemaining(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000));
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const seconds = total % 60;
  if (hours > 0) return `${hours}h ${String(minutes).padStart(2, '0')}m`;
  if (minutes > 0) return `${minutes}m ${String(seconds).padStart(2, '0')}s`;
  return `${seconds}s`;
}

function formatDuration(seconds: number): string {
  if (seconds % 86400 === 0) return `${seconds / 86400} day${seconds === 86400 ? '' : 's'}`;
  if (seconds % 3600 === 0) return `${seconds / 3600} hour${seconds === 3600 ? '' : 's'}`;
  if (seconds % 60 === 0) return `${seconds / 60} minutes`;
  return `${seconds} seconds`;
}

function concat(a: Uint8Array<ArrayBuffer>, b: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> {
  if (a.length === 0) return b;
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

async function api<T>(method: string, url: string, body?: unknown): Promise<T> {
  let res: Response;
  try {
    res = await fetch(url, {
      method,
      credentials: 'same-origin',
      headers: body === undefined ? CSRF_HEADERS : { ...CSRF_HEADERS, 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError('Network error', { network: true });
  }
  const data = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (!res.ok) {
    if (res.status === 401 && url !== '/api/login') showLogin(false);
    throw new ApiError(typeof data.error === 'string' ? data.error : `HTTP ${res.status}`, {
      status: res.status,
      data,
    });
  }
  return data as T;
}

function sendChunk(
  uploadId: string,
  offset: number,
  blob: Blob,
  onProgress: (loaded: number) => void,
  abortRef: { abort: () => void },
): Promise<ChunkResponse> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    abortRef.abort = () => xhr.abort();
    xhr.open('PUT', `/api/uploads/${uploadId}?offset=${offset}`);
    xhr.setRequestHeader('X-Requested-With', 'transit');
    xhr.setRequestHeader('Content-Type', 'application/octet-stream');
    xhr.upload.onprogress = (e) => onProgress(e.loaded);
    xhr.onload = () => {
      let data: Record<string, unknown> = {};
      try {
        data = JSON.parse(xhr.responseText) as Record<string, unknown>;
      } catch {
        data = {};
      }
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(data as unknown as ChunkResponse);
        return;
      }
      if (xhr.status === 401) showLogin(false);
      reject(new ApiError(typeof data.error === 'string' ? data.error : `HTTP ${xhr.status}`, { status: xhr.status, data }));
    };
    xhr.onerror = () => reject(new ApiError('Network error', { network: true }));
    xhr.onabort = () => reject(new ApiError('Cancelled', { cancelled: true }));
    xhr.send(blob);
  });
}

// ---- Views -----------------------------------------------------------

function showLogin(totp: boolean | null): void {
  stopPolling();
  lock();
  limits = null;
  vaultView.hidden = true;
  loginView.hidden = false;
  if (totp !== null) {
    codeField.hidden = !totp;
    codeInput.required = totp;
  }
  passwordInput.focus();
}

function showVault(info: Limits): void {
  limits = info;
  loginView.hidden = true;
  vaultView.hidden = false;
  renderLockState();

  ttlSelect.replaceChildren(
    ...info.ttlChoices.map((s) => h('option', { value: String(s), textContent: formatDuration(s) })),
  );
  let preferred = info.defaultTtlSeconds;
  try {
    const stored = Number(localStorage.getItem(TTL_STORAGE_KEY));
    if (info.ttlChoices.includes(stored)) preferred = stored;
  } catch {
    // Storage may be unavailable; the default is fine.
  }
  ttlSelect.value = String(preferred);

  void refreshFiles();
  pollTimer = window.setInterval(() => void refreshFiles(), 10000);
  tickTimer = window.setInterval(tick, 1000);
}

function stopPolling(): void {
  window.clearInterval(pollTimer);
  window.clearInterval(tickTimer);
}

// ---- Client-side encryption key ---------------------------------------

function renderLockState(code?: string): void {
  const unlocked = master !== null;
  fileInput.disabled = !unlocked;
  dropZone.classList.toggle('locked', !unlocked);
  passphraseInput.hidden = unlocked;
  unlockButton.hidden = unlocked;
  lockButton.hidden = !unlocked;
  keyStatus.textContent = unlocked ? `Unlocked, key check ${code ?? ''}` : 'Locked';
  if (!unlocked) passphraseInput.value = '';
}

function lock(): void {
  master = null;
  opened.clear();
  renderLockState();
  renderFiles();
}

/** Opens the envelope of every listed file with the current key. Returns false if one fails. */
async function resolveNames(): Promise<boolean> {
  if (!master) return true;
  let allOk = true;
  for (const file of files) {
    if (!file.envelope || opened.has(file.id)) continue;
    try {
      opened.set(file.id, await openEnvelope(master, file.envelope));
    } catch {
      opened.set(file.id, null);
      allOk = false;
    }
  }
  return allOk;
}

async function unlock(passphrase: string): Promise<void> {
  if (!limits) return;
  if (!window.isSecureContext || !crypto.subtle) {
    showNotice('Client-side encryption needs HTTPS (or localhost).');
    return;
  }
  unlockButton.disabled = true;
  keyStatus.textContent = 'Deriving key...';
  try {
    const key = await deriveMasterKey(passphrase, limits.e2ee.salt, limits.e2ee.iterations);
    master = key;
    opened.clear();
    if (!(await resolveNames())) {
      master = null;
      opened.clear();
      renderLockState();
      showNotice('Wrong passphrase: it cannot open the files already stored here.');
      return;
    }
    renderLockState(await keyCheckCode(key));
    renderFiles();
  } finally {
    unlockButton.disabled = false;
  }
}

// ---- Files list -------------------------------------------------------

function displayName(file: FileInfo): string {
  if (!file.envelope) return file.name;
  if (!master) return '(locked)';
  return opened.get(file.id)?.name ?? '(cannot decrypt)';
}

async function refreshFiles(): Promise<void> {
  try {
    const data = await api<FilesResponse>('GET', '/api/files');
    clockOffset = data.now - Date.now();
    files = data.files;
    const live = new Set(files.map((f) => f.id));
    for (const id of opened.keys()) if (!live.has(id)) opened.delete(id);
    await resolveNames();
    renderFiles();
    const max = limits?.maxTotalBytes ?? 0;
    usageLabel.textContent = max ? `${formatBytes(data.usedBytes)} of ${formatBytes(max)} used` : '';
  } catch {
    // A 401 already switched to the login view; other errors retry on the next poll.
  }
}

function renderFiles(): void {
  countdownCells.clear();
  emptyLabel.hidden = files.length > 0;
  filesTable.hidden = files.length === 0;

  filesBody.replaceChildren(
    ...files.map((file) => {
      const countdown = h('td', { className: 'num' });
      countdownCells.set(file.id, { cell: countdown, expiresAt: file.expiresAt });

      const name = displayName(file);
      const nameCell = h('td', { className: 'file-name', title: name }, name);
      if (file.burn) nameCell.append(h('span', { className: 'badge', textContent: 'one-time' }));

      const remove = h('button', { type: 'button', className: 'danger', textContent: 'Delete' });
      remove.addEventListener('click', () => {
        remove.disabled = true;
        void api('DELETE', `/api/files/${file.id}`).then(refreshFiles, () => {
          remove.disabled = false;
        });
      });

      let download: HTMLElement;
      const key = opened.get(file.id);
      if (!file.envelope) {
        download = h('a', { className: 'button', href: `/api/files/${file.id}`, textContent: 'Download' });
      } else {
        const button = h('button', { type: 'button', textContent: 'Download', disabled: !key });
        if (!key) button.title = 'Unlock with your passphrase first';
        button.addEventListener('click', () => {
          if (key) void downloadEncrypted(file, key, button);
        });
        download = button;
      }

      return h(
        'tr',
        {},
        nameCell,
        h('td', { className: 'num', textContent: formatBytes(plainSizeOf(file)) }),
        countdown,
        h('td', { className: 'actions' }, download, remove),
      );
    }),
  );
  tick();
}

/** Stored size minus the encryption overhead, for display. */
function plainSizeOf(file: FileInfo): number {
  if (!file.envelope) return file.size;
  return Math.max(0, file.size - Math.ceil(file.size / UNIT_BYTES) * 16);
}

function tick(): void {
  const now = Date.now() + clockOffset;
  let expired = false;
  for (const { cell, expiresAt } of countdownCells.values()) {
    const remaining = expiresAt - now;
    cell.textContent = formatRemaining(remaining);
    if (remaining <= 0) expired = true;
  }
  if (expired) void refreshFiles();
}

// ---- Downloads --------------------------------------------------------

interface SaveSink {
  write(data: Uint8Array<ArrayBuffer>): Promise<void>;
  close(): Promise<void>;
  abort(): Promise<void>;
}

interface SaveHandle {
  createWritable(): Promise<{
    write(data: Uint8Array<ArrayBuffer>): Promise<void>;
    close(): Promise<void>;
    abort(): Promise<void>;
  }>;
}

type SaveFilePicker = (options: { suggestedName: string }) => Promise<SaveHandle>;

/**
 * Streams to disk with the File System Access API when the browser has it (Chrome, Edge),
 * so large files never sit in memory. Otherwise falls back to an in-memory Blob.
 */
async function openSink(name: string): Promise<SaveSink> {
  const picker = (window as unknown as { showSaveFilePicker?: SaveFilePicker }).showSaveFilePicker;
  if (picker) {
    const handle = await picker.call(window, { suggestedName: name });
    const writable = await handle.createWritable();
    return {
      write: (data) => writable.write(data),
      close: () => writable.close(),
      abort: () => writable.abort(),
    };
  }
  const parts: Uint8Array<ArrayBuffer>[] = [];
  return {
    write: async (data) => {
      parts.push(data);
    },
    close: async () => {
      const url = URL.createObjectURL(new Blob(parts));
      const link = h('a', { href: url, download: name });
      document.body.append(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 60000);
    },
    abort: async () => {
      parts.length = 0;
    },
  };
}

async function downloadEncrypted(file: FileInfo, key: OpenedFile, button: HTMLButtonElement): Promise<void> {
  const label = button.textContent;
  button.disabled = true;
  let sink: SaveSink | null = null;
  try {
    // The save dialog must open inside the click, before any await that takes time.
    sink = await openSink(key.name);
    const res = await fetch(`/api/files/${file.id}`, { credentials: 'same-origin' });
    if (res.status === 401) showLogin(false);
    if (!res.ok || !res.body) throw new Error(`Download failed (HTTP ${res.status})`);

    const units = Math.ceil(file.size / UNIT_BYTES);
    const reader = res.body.getReader();
    let pending: Uint8Array<ArrayBuffer> = new Uint8Array(0);
    let index = 0;
    let received = 0;

    const emit = async (unit: Uint8Array<ArrayBuffer>): Promise<void> => {
      if (!sink || index >= units) throw new Error('Unexpected extra data');
      await sink.write(await decryptUnit(key.key, index, index === units - 1, unit));
      index += 1;
      button.textContent = `${Math.floor((index / units) * 100)}%`;
    };

    for (;;) {
      const { done, value } = await reader.read();
      if (value) {
        received += value.length;
        pending = concat(pending, value);
        while (pending.length >= UNIT_BYTES) {
          await emit(pending.slice(0, UNIT_BYTES));
          pending = pending.slice(UNIT_BYTES);
        }
      }
      if (done) break;
    }
    if (pending.length > 0) await emit(pending);
    if (index !== units || received !== file.size) throw new Error('The file is incomplete or was altered');

    await sink.close();
    sink = null;
  } catch (err) {
    if (sink) await sink.abort().catch(() => undefined);
    if (!(err instanceof DOMException && err.name === 'AbortError')) {
      showNotice(err instanceof Error ? err.message : 'Download failed');
    }
  } finally {
    button.disabled = false;
    button.textContent = label;
  }
}

// ---- Uploads ----------------------------------------------------------

interface Transfer {
  cancelled: boolean;
  uploadId: string | null;
  abortRef: { abort: () => void };
}

function addTransferRow(file: File, transfer: Transfer) {
  const status = h('span', { className: 'status', textContent: 'Encrypting' });
  const bar = h('progress', { max: 100, value: 0 });
  const cancel = h('button', { type: 'button', textContent: 'Cancel' });
  const row = h(
    'li',
    {},
    h('span', { className: 'name', textContent: file.name, title: file.name }),
    h('span', {}, status, ' ', cancel),
    bar,
  );
  cancel.addEventListener('click', () => {
    transfer.cancelled = true;
    transfer.abortRef.abort();
    if (transfer.uploadId) void api('DELETE', `/api/uploads/${transfer.uploadId}`).catch(() => undefined);
    row.remove();
  });
  transfersList.append(row);

  return {
    progress(sent: number, total: number) {
      const percent = (sent / total) * 100;
      bar.value = percent;
      status.textContent = `${Math.floor(percent)}%`;
    },
    done() {
      row.remove();
    },
    fail(message: string) {
      row.className = 'failed';
      status.textContent = message;
      bar.hidden = true;
      cancel.textContent = 'Dismiss';
      cancel.onclick = () => row.remove();
    },
  };
}

/** Encrypts the plaintext units that make up ciphertext bytes [offset, offset + length). */
async function buildChunk(file: File, key: CryptoKey, offset: number, length: number): Promise<Blob> {
  const firstUnit = offset / UNIT_BYTES;
  const unitCount = Math.ceil(length / UNIT_BYTES);
  const plainStart = firstUnit * PLAIN_SEGMENT_BYTES;
  const plainEnd = Math.min(file.size, plainStart + unitCount * PLAIN_SEGMENT_BYTES);
  const data = new Uint8Array(await file.slice(plainStart, plainEnd).arrayBuffer());
  const totalUnits = segmentCount(file.size);

  const parts: Uint8Array<ArrayBuffer>[] = [];
  for (let i = 0; i < unitCount; i += 1) {
    const index = firstUnit + i;
    const plain = data.slice(i * PLAIN_SEGMENT_BYTES, (i + 1) * PLAIN_SEGMENT_BYTES);
    parts.push(await encryptUnit(key, index, index === totalUnits - 1, plain));
  }
  return new Blob(parts);
}

async function uploadFile(file: File, ttl: number, burn: boolean): Promise<void> {
  const transfer: Transfer = { cancelled: false, uploadId: null, abortRef: { abort: () => undefined } };
  const row = addTransferRow(file, transfer);

  if (!master || !limits) {
    row.fail('Unlock first');
    return;
  }
  if (file.size === 0) {
    row.fail('Empty file');
    return;
  }
  const cipherSize = encryptedLength(file.size);
  if (cipherSize > limits.maxFileBytes) {
    row.fail(`Too large (max ${formatBytes(limits.maxFileBytes)})`);
    return;
  }

  try {
    const { envelope, key } = await createEnvelope(master, file.name);
    const begin = await api<BeginResponse>('POST', '/api/uploads', {
      name: 'encrypted',
      size: cipherSize,
      ttl,
      burn,
      e2ee: envelope,
    });
    transfer.uploadId = begin.uploadId;

    const unitsPerChunk = Math.floor(begin.chunkBytes / UNIT_BYTES);
    if (unitsPerChunk < 1) throw new Error('Server chunk size is too small for client-side encryption');
    const chunkSize = unitsPerChunk * UNIT_BYTES;

    let offset = 0;
    let attempts = 0;
    for (;;) {
      if (transfer.cancelled) return;
      const length = Math.min(chunkSize, cipherSize - offset);
      const base = offset;
      try {
        const blob = await buildChunk(file, key, offset, length);
        const result = await sendChunk(
          begin.uploadId,
          offset,
          blob,
          (loaded) => row.progress(base + loaded, cipherSize),
          transfer.abortRef,
        );
        attempts = 0;
        if (result.done) break;
        offset = result.received;
        row.progress(offset, cipherSize);
      } catch (err) {
        if (!(err instanceof ApiError) || err.cancelled || transfer.cancelled) throw err;
        const retryable = err.network || err.status === 409 || err.status >= 500;
        if (!retryable || ++attempts > MAX_RETRIES) throw err;
        await sleep(1000 * attempts);
        const state = await api<{ received: number }>('GET', `/api/uploads/${begin.uploadId}`);
        offset = state.received;
      }
    }
    row.done();
    await refreshFiles();
  } catch (err) {
    if (transfer.cancelled || (err instanceof ApiError && err.cancelled)) return;
    row.fail(err instanceof Error ? err.message : 'Upload failed');
  }
}

function startUploads(list: FileList | File[]): void {
  const ttl = Number(ttlSelect.value);
  const burn = burnCheckbox.checked;
  for (const file of Array.from(list)) void uploadFile(file, ttl, burn);
}

// ---- Wiring -----------------------------------------------------------

loginForm.addEventListener('submit', (event) => {
  event.preventDefault();
  loginError.hidden = true;
  const submit = loginForm.querySelector<HTMLButtonElement>('button[type="submit"]');
  if (submit) submit.disabled = true;

  api('POST', '/api/login', { password: passwordInput.value, code: codeInput.value })
    .then(init)
    .catch((err: unknown) => {
      loginError.textContent = err instanceof Error ? err.message : 'Sign-in failed';
      loginError.hidden = false;
      codeInput.value = '';
    })
    .finally(() => {
      passwordInput.value = '';
      if (submit) submit.disabled = false;
    });
});

unlockForm.addEventListener('submit', (event) => {
  event.preventDefault();
  const passphrase = passphraseInput.value;
  passphraseInput.value = '';
  if (passphrase) void unlock(passphrase);
});

lockButton.addEventListener('click', lock);

logoutButton.addEventListener('click', () => {
  void api('POST', '/api/logout').finally(() => void init());
});

panicButton.addEventListener('click', () => {
  if (!window.confirm('Delete every file now and sign out everywhere?')) return;
  void api('POST', '/api/panic').finally(() => void init());
});

fileInput.addEventListener('change', () => {
  if (fileInput.files) startUploads(fileInput.files);
  fileInput.value = '';
});

ttlSelect.addEventListener('change', () => {
  try {
    localStorage.setItem(TTL_STORAGE_KEY, ttlSelect.value);
  } catch {
    // Not critical.
  }
});

for (const type of ['dragenter', 'dragover'] as const) {
  dropZone.addEventListener(type, (event) => {
    event.preventDefault();
    if (master) dropZone.classList.add('over');
  });
}
for (const type of ['dragleave', 'drop'] as const) {
  dropZone.addEventListener(type, () => dropZone.classList.remove('over'));
}
dropZone.addEventListener('drop', (event) => {
  event.preventDefault();
  if (master && event.dataTransfer?.files.length) startUploads(event.dataTransfer.files);
});

// Stop the browser from navigating to a file dropped outside the drop zone.
for (const type of ['dragover', 'drop'] as const) {
  window.addEventListener(type, (event) => event.preventDefault());
}

async function init(): Promise<void> {
  stopPolling();
  try {
    const info = await api<SessionInfo>('GET', '/api/session');
    if (info.authenticated && info.limits) showVault(info.limits);
    else showLogin(info.totp);
  } catch {
    loginError.textContent = 'Cannot reach the server.';
    loginError.hidden = false;
    showLogin(null);
  }
}

void init();
