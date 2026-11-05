import { serve } from '@hono/node-server';
import { createApp } from './app.js';
import { load } from './config.js';

const LOOPBACK_HOSTS = new Set(['127.0.0.1', '::1', 'localhost']);

const cfg = load();
if (!LOOPBACK_HOSTS.has(cfg.host)) {
  // The tunnel connects from this machine; nothing else should ever reach the app directly.
  throw new Error(`Refusing to listen on "${cfg.host}". Use a loopback address and expose it with the tunnel.`);
}

const { app, dispose } = await createApp(cfg);

const server = serve(
  {
    fetch: app.fetch,
    hostname: cfg.host,
    port: cfg.port,
    serverOptions: { requestTimeout: 10 * 60 * 1000 },
  },
  (info) => {
    console.log(`Transit listening on http://${info.address}:${info.port}`);
    console.log(`Storage: ${cfg.dataDir}`);
    if (cfg.allowedHosts.length === 0) console.log('Note: allowedHosts is empty, any Host header is accepted.');
    if (!cfg.totpSecret) console.log('Note: TOTP is off, the password is the only secret.');
  },
);

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    dispose();
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 3000).unref();
  });
}
