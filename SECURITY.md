# Security policy

Transit handles sensitive files, so security reports are welcome.

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's private vulnerability reporting
("Security" tab, "Report a vulnerability") and include steps to reproduce.

## Scope

In scope: authentication and session handling, the encryption format (browser and server),
file storage and deletion, the installer and the systemd units.

Out of scope: attacks that require control of the machine hosting Transit while a session is
unlocked, and weaknesses in third-party services (Cloudflare, your browser, your OS).

The security model and its known limits are described in the README.
