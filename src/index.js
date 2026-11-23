import { mkdir, chmod, readdir, rm } from 'node:fs/promises';
import path from 'node:path';
import { app } from './app.js';
import { config, validateConfig } from './config.js';
import { initializeDatabase, closeDatabase } from './db.js';
import { getMasterKey } from './security.js';
import { startBackgroundWorker, stopBackgroundWorker } from './worker.js';

async function clearStaleWorkDirectories() {
  await mkdir(config.tempDir, { recursive: true, mode: 0o700 });
  await chmod(config.tempDir, 0o700);
  await mkdir(config.directUploadDir, { recursive: true, mode: 0o700 });
  await chmod(config.directUploadDir, 0o700);
  const entries = await readdir(config.tempDir, { withFileTypes: true });
  await Promise.all(entries.map((entry) => rm(path.join(config.tempDir, entry.name), { recursive: true, force: true })));
}

async function main() {
  validateConfig();
  getMasterKey();
  await clearStaleWorkDirectories();
  await initializeDatabase();

  const server = app.listen(config.port, '0.0.0.0', () => {
    console.info(`Xsign API listening on port ${config.port}.`);
  });
  server.requestTimeout = 10 * 60 * 1000;

  const workerPromise = startBackgroundWorker();
  workerPromise.catch((error) => {
    console.error(`Xsign background worker stopped unexpectedly: ${String(error?.message || 'unknown error').slice(0, 180)}`);
    process.exitCode = 1;
  });

  let shuttingDown = false;
  const shutdown = async (signal) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.info(`Xsign received ${signal}; beginning graceful shutdown.`);
    stopBackgroundWorker();

    const httpClosed = new Promise((resolve) => server.close(() => resolve()));
    const workerStopped = Promise.race([
      workerPromise.then(() => true, () => false),
      new Promise((resolve) => setTimeout(() => resolve(false), 110000)),
    ]);

    const [workerFinished] = await Promise.all([workerStopped, httpClosed]);
    if (!workerFinished) {
      console.warn('Xsign worker did not finish before the shutdown deadline; any active job will be retried after its database lease expires.');
    }
    await closeDatabase().catch(() => {});
    process.exit(workerFinished ? 0 : 1);
  };

  process.once('SIGTERM', () => { void shutdown('SIGTERM'); });
  process.once('SIGINT', () => { void shutdown('SIGINT'); });
}

main().catch((error) => {
  console.error(`Xsign could not start: ${String(error?.message || 'configuration or database error').slice(0, 220)}`);
  process.exit(1);
});
