import os from 'node:os';
import { randomUUID } from 'node:crypto';
import { mkdir, rm } from 'node:fs/promises';
import path from 'node:path';
import { config } from './config.js';
import { pool } from './db.js';
import { deleteObjects } from './storage.js';
import { processSigningJob } from './job-runner.js';

const workerId = `${os.hostname()}-${process.pid}-${randomUUID()}`;
let stopping = false;
let lastCleanup = 0;

const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

async function claimNextJob() {
  const client = await pool.connect();
  let transactionOpen = false;
  try {
    await client.query('BEGIN');
    transactionOpen = true;
    const selected = await client.query(
      `SELECT * FROM signing_jobs
       WHERE status = 'queued'
          OR (status = 'running' AND locked_until IS NOT NULL AND locked_until < NOW())
       ORDER BY created_at ASC
       LIMIT 1
       FOR UPDATE SKIP LOCKED`,
    );
    const job = selected.rows[0];
    if (!job) {
      await client.query('COMMIT');
      transactionOpen = false;
      return null;
    }
    const updated = await client.query(
      `UPDATE signing_jobs
       SET status='running', stage='Starting signing worker', updated_at=NOW(),
           locked_until=NOW() + INTERVAL '4 minutes', worker_id=$2
       WHERE id=$1 RETURNING *`,
      [job.id, workerId],
    );
    await client.query('COMMIT');
    transactionOpen = false;
    return updated.rows[0];
  } catch (error) {
    if (transactionOpen) await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function cleanupExpired() {
  const expiredJobs = await pool.query(
    `SELECT id, result FROM signing_jobs
     WHERE status='completed' AND expires_at IS NOT NULL AND expires_at <= NOW()
     ORDER BY expires_at ASC LIMIT 100`,
  );
  for (const job of expiredJobs.rows) {
    const keys = Array.isArray(job.result?._storageKeys) ? job.result._storageKeys : [];
    try {
      await deleteObjects(keys);
      await pool.query(
        `UPDATE signing_jobs SET status='expired', stage='Signed IPA expired',
         error='The signed IPA has expired. Please submit a new signing job.',
         result=NULL, updated_at=NOW() WHERE id=$1 AND status='completed'`,
        [job.id],
      );
    } catch {
      // Retry object deletion on the next cleanup cycle rather than dropping its key list.
    }
  }

  const abandoned = await pool.query(
    `SELECT u.object_key FROM uploads u
     LEFT JOIN signing_jobs j ON j.id = u.job_id
     WHERE (u.used_at IS NULL AND u.expires_at <= NOW())
        OR (u.used_at IS NOT NULL AND j.status IN ('completed','failed','expired'))
        OR (u.used_at IS NOT NULL AND u.created_at < NOW() - INTERVAL '1 day')
     ORDER BY u.created_at ASC LIMIT 500`,
  );
  if (abandoned.rows.length) {
    const keys = abandoned.rows.map((row) => row.object_key);
    try {
      await deleteObjects(keys);
      await pool.query('DELETE FROM uploads WHERE object_key = ANY($1::text[])', [keys]);
    } catch {
      // Keep the rows so deletion is retried.
    }
  }

  const abandonedDirect = await pool.query(
    `SELECT d.id FROM direct_ipa_uploads d
     LEFT JOIN signing_jobs j ON j.id = d.job_id
     WHERE (d.used_at IS NULL AND d.expires_at <= NOW())
        OR (d.used_at IS NOT NULL AND j.status IN ('completed','failed','expired'))
        OR (d.used_at IS NOT NULL AND d.created_at < NOW() - INTERVAL '1 day')
     ORDER BY d.created_at ASC LIMIT 100`,
  );
  for (const upload of abandonedDirect.rows) {
    try {
      await rm(path.join(config.directUploadDir, `${upload.id}.ipa`), { force: true });
      await pool.query('DELETE FROM direct_ipa_uploads WHERE id = $1', [upload.id]);
    } catch {
      // Keep the database row so the local-file cleanup can be retried.
    }
  }

  await pool.query(
    `DELETE FROM signing_jobs
     WHERE status IN ('expired','failed') AND created_at < NOW() - INTERVAL '30 days'`,
  );
}

export async function startBackgroundWorker() {
  await mkdir(config.tempDir, { recursive: true, mode: 0o700 });
  console.info('Xsign signing worker started.');
  while (!stopping) {
    try {
      if (Date.now() - lastCleanup > 60000) {
        await cleanupExpired();
        lastCleanup = Date.now();
      }
      const job = await claimNextJob();
      if (job) {
        await processSigningJob(job, workerId);
        continue;
      }
    } catch (error) {
      console.error(`Signing worker cycle failed: ${String(error?.message || 'database or storage error').slice(0, 180)}`);
    }
    await sleep(config.workerPollMs);
  }
}

export function stopBackgroundWorker() {
  stopping = true;
}
