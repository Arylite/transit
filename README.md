# Transit

Private file drop for moving files between two machines when USB and cloud storage are blocked.
Runs on your own PC (Hono on Node), exposed through a Cloudflare Tunnel. Free to host.

The tunnel runs on the PC that hosts Transit. The other machine only needs a browser:
no Cloudflare account, client or login is involved there. Access control is the password.

## Security model

| Layer | What it does |
| --- | --- |
| Password | Long password required (16+ chars, or a generated 160-bit one). Stored as scrypt hash. |
| TOTP (optional, recommended) | Second factor from an authenticator app on your phone. Codes cannot be replayed. |
| Login hardening | Password checks run one at a time (no parallel guessing), global slowdown that grows with failures, per-IP lockout with exponential back-off, uniform error message. |
| Client-side encryption | Files are encrypted in the browser (Web Crypto, AES-256-GCM, 1 MiB units, key from an encryption passphrase via PBKDF2-SHA256, 1,000,000 iterations) before they leave the page, and decrypted in the browser on download. File names are encrypted too. The server, Cloudflare and a network proxy only see ciphertext. The passphrase is never sent anywhere and is forgotten on lock, sign-out or page reload. |
| Encryption at rest | On top of that, the server encrypts everything again (AES-256-GCM, per-file random key) so names and metadata are protected even for uploads that bypass the browser. Truncation, reordering and tampering are detected on download. |
| Key handling | The master key is derived from your password at login and exists only in memory, one copy per live session, zeroed when the session ends. Nothing on disk can decrypt the files. Restarting the server or signing out locks them. |
| Crypto-shredding | Deleting or expiring a file destroys its sealed key first, so leftover disk blocks are unreadable even if they are never overwritten. |
| Expiry | Per-upload lifetime (hard cap in config). Optional delete after first download. "Delete all" wipes everything and signs out every session. |
| Sessions | HttpOnly, SameSite=Strict cookie (`__Host-` prefixed over HTTPS), idle and absolute timeouts, at most 3 concurrent sessions. |
| Web hardening | Strict CSP (no inline script/style), CSRF header + Origin check, Host allow-list, security headers, no caching, request-rate cap, downloads always `attachment` + `nosniff`. |
| Network | Binds to loopback only (refuses anything else). Only the tunnel can reach it. |
| Audit log | `data/audit.log`: logins, uploads, downloads, deletions with ids, sizes and IPs. Never names or secrets. |

Not covered, so be aware:

- Someone who controls this PC while you are signed in can read the key from memory. Use disk encryption (BitLocker) and lock the machine.
- Client-side encryption protects against passive observers: Cloudflare, a logging proxy, a stolen disk. It does **not** protect against an active attacker who can modify the page in transit (for example a TLS-intercepting corporate proxy that rewrites the JavaScript): such a party could serve a script that steals the passphrase. If your employer's proxy inspects HTTPS, also encrypt the file yourself (7-Zip, AES-256) before uploading, or assume it can see the content.
- Pick a long encryption passphrase (5+ random words). Anyone who obtains the ciphertext can try to guess it offline; PBKDF2 slows that down but does not stop a weak passphrase. Use the same passphrase on both machines and compare the "key check" code shown after unlocking.
- The passphrase is separate from the login password on purpose. Do not reuse it.
- Downloads stream straight to disk in Chrome and Edge (File System Access API). Other browsers decrypt into memory first, so very large files can fail there.
- The password is the only gate to the server (plus TOTP if enabled). Use a random one from a password manager.

## Setup

Requires Node 22+.

```bash
npm ci
npm run build
npm run setup     # generates or asks for the password, optional TOTP, optional hostname
npm start         # http://127.0.0.1:8787
```

Running `setup` again changes the password and deletes stored files (their key was derived from the old one).

`config.json` (created by setup, git-ignored) can be edited by hand. All keys are optional:

| Key | Default | Meaning |
| --- | --- | --- |
| `ttlChoices` | 5 min, 15 min, 1 h, 6 h, 24 h (seconds) | Durations offered in the UI |
| `defaultTtlSeconds` | 3600 | Preselected duration |
| `maxTtlSeconds` | 86400 | Hard cap, enforced by the server |
| `sessionIdleSeconds` | 900 | Sign-out after inactivity |
| `sessionMaxSeconds` | 28800 | Sign-out regardless of activity |
| `maxSessions` | 3 | Concurrent sessions |
| `maxFileBytes` / `maxTotalBytes` | 2 GiB / 10 GiB | Per-file and total storage limits |
| `allowedHosts` | `[]` | Reject any other Host header (set by setup when you give a hostname) |
| `auditLog` | `true` | Write `data/audit.log` |
| `access` | `null` | Optional Cloudflare Access JWT validation (`teamDomain`, `audience`, `emails`) |

Restart after editing.

## Tunnel (on the PC that hosts Transit)

Install `cloudflared` (`winget install Cloudflare.cloudflared`).

**Quick tunnel**: no account, random `*.trycloudflare.com` URL on each start.

```bash
cloudflared tunnel --url http://127.0.0.1:8787
```

**Named tunnel**: stable hostname, needs a free Cloudflare account and a domain on it, on your own PC only.

```bash
cloudflared tunnel login
cloudflared tunnel create transit
cloudflared tunnel route dns transit files.example.com
cloudflared tunnel run --url http://127.0.0.1:8787 transit
```

Give that hostname to `npm run setup` so `allowedHosts` is set.

Only run the tunnel while you need it. Stop it (and Transit) when you are done.

## Raspberry Pi 3B+

Transit has no native dependencies, so it runs on a Pi as is. Notes for the 3B+ (1 GB RAM, no AES hardware acceleration):

- Use **64-bit Raspberry Pi OS Lite** and Node 22+ (NodeSource or nvm). 32-bit images are not recommended.
- Expect a sign-in to take 1 to 2 seconds (two scrypt runs) and roughly 20 to 40 MB/s of encryption throughput, more than a home uplink delivers. Memory stays low because everything is streamed.
- Keep the clock right: the Pi has no battery clock, and TOTP and file expiry depend on time. `systemd-timesyncd` is enabled by default, the units below wait for time sync.
- An SD card is slow and wears out with repeated large writes. Prefer a USB SSD or stick and point `dataDir` at it in `config.json` (absolute path, owned by the `transit` user, also listed in `ReadWritePaths` of the unit).
- Use disk encryption for that drive if the Pi can be physically taken. Files are already encrypted, but the audit log and metadata are not.

### Installer script

`setup.sh` installs and maintains Transit on Debian-based systems (Raspberry Pi OS, Debian, Ubuntu). Run `npm run build` on another machine first if you want to ship a prebuilt `dist/`.

```bash
sudo ./setup.sh                                   # install (default command)
sudo ./setup.sh install --data-dir /mnt/usb/transit
sudo ./setup.sh update                            # new code, keeps config and files, rolls back on failure
sudo ./setup.sh status
sudo ./setup.sh doctor                            # security and health checks, changes nothing
sudo ./setup.sh uninstall [--purge]
```

| Command | What it does |
| --- | --- |
| `install` | Checks the system (architecture, disk, memory, clock), installs Node 22 from nodejs.org with a verified checksum, creates the `transit` user, copies the project to `/opt/transit`, builds or reuses `dist/`, runs the interactive configuration, installs and starts the hardened systemd units, optionally installs `cloudflared` from Cloudflare's signed apt repository. |
| `update` | Saves the current version, deploys the new code, rebuilds, restarts and checks health. On any failure it restores the saved version automatically. |
| `tunnel` | Connects an existing named Cloudflare tunnel (see below) and restricts Transit to its hostname. |
| `status` | Version, service and tunnel state, health, data size, TOTP and clock state, tunnel URL if open. |
| `doctor` | Verifies loopback-only listening, file permissions, TOTP, `allowedHosts`, Node version, clock and the systemd exposure score. Exits non-zero on failure. |
| `uninstall` | Removes the services. `--purge` also deletes code, configuration, stored files and the user (asks for confirmation). |

Options: `--dry-run` prints every change without making it, `--verbose` shows command output, `--yes` answers confirmation questions, `--rebuild` forces a compile, `--no-cloudflared`, `--no-color`. Every run is logged to `/var/log/transit-setup.log`.

### Using a named tunnel you created as root

If you ran `cloudflared tunnel login` and `cloudflared tunnel create` as root, the credentials are in `/root/.cloudflared`, which the `transit` service user cannot read. Let the installer wire it up:

```bash
sudo ./setup.sh tunnel --tunnel NAME --hostname files.example.com
```

It copies the tunnel credentials to `/etc/transit` (readable by the service user only), writes the ingress config, creates the DNS record, sets `allowedHosts` and switches `transit-tunnel` to the named tunnel. Use `--cloudflared-dir` if the credentials are elsewhere. Then `sudo systemctl start transit-tunnel` opens it and `stop` closes it.

### Manual install

```bash
sudo useradd --system --home /opt/transit --shell /usr/sbin/nologin transit
sudo mkdir -p /opt/transit && sudo chown transit:transit /opt/transit
# copy the project (without node_modules) to /opt/transit, then as user transit:
sudo -u transit npm ci --omit=dev
sudo -u transit node dist/src/setup.js
sudo cp deploy/transit.service deploy/transit-tunnel.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now transit
```

Install `cloudflared` for arm64 from Cloudflare's package repository, then open the tunnel only when you need it:

```bash
sudo systemctl start transit-tunnel
journalctl -u transit-tunnel -n 20     # shows the https://....trycloudflare.com URL
sudo systemctl stop transit-tunnel     # when you are done
```

## Development

```bash
npm run typecheck
npm test
```

Server code is in `src/`, browser code in `web/` (compiled to `dist/web`).
