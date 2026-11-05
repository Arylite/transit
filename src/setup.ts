import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import readline from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import { generateTotpSecret, hashPassword } from './auth.js';
import { CONFIG_PATH, DEFAULTS, loadRaw, ROOT, save, type Config } from './config.js';
import { newSalt } from './seal.js';

const MIN_PASSWORD_LENGTH = 16;

function askHidden(question: string): Promise<string> {
  return new Promise((resolve, reject) => {
    if (!stdin.isTTY) {
      reject(new Error('An interactive terminal is required (or set TRANSIT_PASSWORD).'));
      return;
    }
    stdout.write(question);
    let buffer = '';
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    const onData = (input: string): void => {
      for (const ch of input) {
        if (ch === '\r' || ch === '\n') {
          stdin.setRawMode(false);
          stdin.pause();
          stdin.off('data', onData);
          stdout.write('\n');
          resolve(buffer);
          return;
        }
        if (ch === '\u0003') process.exit(130);
        buffer = ch === '\u007f' || ch === '\b' ? buffer.slice(0, -1) : buffer + ch;
      }
    };
    stdin.on('data', onData);
  });
}

async function ask(question: string): Promise<string> {
  const rl = readline.createInterface({ input: stdin, output: stdout });
  try {
    return (await rl.question(question)).trim();
  } finally {
    rl.close();
  }
}

/** 27 random URL-safe characters, about 160 bits. */
const generatePassword = (): string => crypto.randomBytes(20).toString('base64url');

async function readPassword(): Promise<string> {
  const fromEnv = process.env.TRANSIT_PASSWORD;
  if (fromEnv) return fromEnv;

  const generate = (await ask('Generate a strong random password for you? [Y/n] ')).toLowerCase() !== 'n';
  if (generate) {
    const password = generatePassword();
    console.log(`\nYour password (shown once, store it in a password manager):\n\n  ${password}\n`);
    return password;
  }
  for (;;) {
    const first = await askHidden(`Password (min ${MIN_PASSWORD_LENGTH} characters, a long passphrase is fine): `);
    if (first.length < MIN_PASSWORD_LENGTH) {
      console.log(`Too short, use at least ${MIN_PASSWORD_LENGTH} characters.`);
      continue;
    }
    if (first !== (await askHidden('Repeat password: '))) {
      console.log('Passwords differ, try again.');
      continue;
    }
    return first;
  }
}

async function main(): Promise<void> {
  const next: Partial<Config> = { ...loadRaw() };

  const password = await readPassword();
  if (password.length < MIN_PASSWORD_LENGTH) throw new Error(`Password must have ${MIN_PASSWORD_LENGTH}+ characters.`);
  next.passwordHash = hashPassword(password);
  next.kdfSalt = newSalt();
  next.e2eeSalt = newSalt();

  const wantTotp = (await ask('Add an authenticator-app code (TOTP) as a second factor? Recommended. [Y/n] ')).toLowerCase() !== 'n';
  if (wantTotp) {
    next.totpSecret = generateTotpSecret();
    console.log('\nAdd this to your authenticator app (manual entry, time-based, SHA-1, 6 digits):');
    console.log(`  Secret : ${next.totpSecret}`);
    console.log(`  URI    : otpauth://totp/Transit?secret=${next.totpSecret}&issuer=Transit\n`);
  } else {
    next.totpSecret = null;
  }

  const hostname = (
    process.env.TRANSIT_HOSTNAME ?? (await ask('Public hostname if you use a named tunnel (empty to skip): '))
  )
    .trim()
    .toLowerCase();
  next.allowedHosts = hostname ? [hostname, 'localhost', '127.0.0.1'] : [];

  next.host ??= DEFAULTS.host;
  next.port ??= DEFAULTS.port;
  save(next);

  // The encryption key is derived from the password, so files stored under the old one are unreadable.
  const dataDir = path.resolve(ROOT, next.dataDir ?? DEFAULTS.dataDir);
  await fs.rm(path.join(dataDir, 'files'), { recursive: true, force: true });
  await fs.rm(path.join(dataDir, 'tmp'), { recursive: true, force: true });

  console.log(`Saved ${CONFIG_PATH}`);
  console.log('Previously stored files were deleted (their key changed with the password).');
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
