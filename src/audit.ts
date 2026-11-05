import fs from 'node:fs';
import path from 'node:path';

const MAX_BYTES = 2 * 1024 * 1024;

type Fields = Record<string, string | number | boolean>;

/**
 * Append-only JSON-lines log of security-relevant events.
 * It never records file names, passwords or tokens, only ids, sizes and IPs.
 */
export class Audit {
  private readonly file: string | null;

  constructor(file: string | null) {
    this.file = file;
    if (file) fs.mkdirSync(path.dirname(file), { recursive: true });
  }

  log(event: string, fields: Fields = {}): void {
    if (!this.file) return;
    try {
      const line = `${JSON.stringify({ t: new Date().toISOString(), event, ...fields })}\n`;
      if (fs.existsSync(this.file) && fs.statSync(this.file).size > MAX_BYTES) {
        fs.renameSync(this.file, `${this.file}.1`);
      }
      fs.appendFileSync(this.file, line, { mode: 0o600 });
    } catch (err) {
      console.error('audit log write failed', err);
    }
  }
}
