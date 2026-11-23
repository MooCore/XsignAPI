import pg from 'pg';
import { config } from './config.js';

const { Pool } = pg;

export const pool = new Pool({
  connectionString: config.databaseUrl,
  max: 8,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
  keepAlive: true,
});

pool.on('error', () => {
  console.error('PostgreSQL pool reported an idle-client error.');
});

export async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS signing_jobs (
      id UUID PRIMARY KEY,
      status TEXT NOT NULL CHECK (status IN ('queued','running','completed','failed','expired')),
      progress INTEGER NOT NULL DEFAULT 0 CHECK (progress >= 0 AND progress <= 100),
      stage TEXT NOT NULL DEFAULT 'Queued for signing',
      error TEXT,
      input_objects JSONB NOT NULL DEFAULT '{}'::jsonb,
      options JSONB NOT NULL DEFAULT '{}'::jsonb,
      password_ciphertext TEXT,
      password_nonce TEXT,
      password_tag TEXT,
      result JSONB,
      ip_hash TEXT NOT NULL,
      worker_id TEXT,
      locked_until TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      finished_at TIMESTAMPTZ,
      expires_at TIMESTAMPTZ
    );

    CREATE INDEX IF NOT EXISTS signing_jobs_queue_idx
      ON signing_jobs (status, created_at);
    CREATE INDEX IF NOT EXISTS signing_jobs_expiry_idx
      ON signing_jobs (status, expires_at);

    CREATE TABLE IF NOT EXISTS uploads (
      object_key TEXT PRIMARY KEY,
      purpose TEXT NOT NULL,
      expected_size BIGINT NOT NULL,
      ip_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL,
      used_at TIMESTAMPTZ,
      job_id UUID REFERENCES signing_jobs(id) ON DELETE SET NULL
    );
    CREATE INDEX IF NOT EXISTS uploads_expiry_idx ON uploads (expires_at);
  `);
}

export async function closeDatabase() {
  await pool.end();
}
