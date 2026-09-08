import 'dotenv/config';
import { createApp } from './app.js';
import { loadConfig } from './config.js';
import { createStore } from './db.js';

const config = loadConfig();
const store = createStore(config);

await store.init();

if (store.kind === 'memory') {
  console.warn('WARNING: DATABASE_URL is not set. Using a non-persistent in-memory store for local development.');
}

const app = createApp({ store, config });
const server = app.listen(config.port, '0.0.0.0', () => {
  console.log(`BotAstra FamPay API listening on 0.0.0.0:${config.port} (${store.kind})`);
});

async function shutdown(signal) {
  console.log(`${signal} received; shutting down.`);
  server.close(async () => {
    try {
      await store.close();
    } finally {
      process.exit(0);
    }
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
