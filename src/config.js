import 'dotenv/config';

function integer(name, fallback, min, max) {
  const value = Number.parseInt(process.env[name] ?? '', 10);
  if (!Number.isFinite(value)) return fallback;
  return Math.max(min, Math.min(max, value));
}

function commaList(value) {
  return String(value || '')
    .split(',')
    .map((item) => item.trim().replace(/\/$/, ''))
    .filter(Boolean);
}

export const config = {
  nodeEnv: process.env.NODE_ENV || 'development',
  port: integer('PORT', 10000, 1, 65535),
  databaseUrl: process.env.DATABASE_URL || '',
  appMasterKey: process.env.APP_MASTER_KEY || '',
  frontendOrigins: commaList(process.env.FRONTEND_ORIGIN || process.env.CORS_ORIGINS),
  s3Endpoint: process.env.AWS_ENDPOINT_URL_S3 || process.env.TIGRIS_STORAGE_ENDPOINT || 'https://t3.storage.dev',
  s3Region: process.env.AWS_REGION || 'auto',
  s3AccessKeyId: process.env.AWS_ACCESS_KEY_ID || process.env.TIGRIS_STORAGE_ACCESS_KEY_ID || '',
  s3SecretAccessKey: process.env.AWS_SECRET_ACCESS_KEY || process.env.TIGRIS_STORAGE_SECRET_ACCESS_KEY || '',
  bucket: process.env.TIGRIS_BUCKET || 'ipa-signer',
  retentionMinutes: integer('FILE_RETENTION_MINUTES', 10, 5, 1440),
  uploadUrlTtlSeconds: integer('UPLOAD_URL_TTL_SECONDS', 900, 60, 3600),
  downloadUrlTtlSeconds: integer('DOWNLOAD_URL_TTL_SECONDS', integer('FILE_RETENTION_MINUTES', 10, 5, 1440) * 60, 60, 3600),
  maxIpaBytes: integer('MAX_IPA_MB', 500, 10, 4096) * 1024 * 1024,
  directIpaUploadEnabled: String(process.env.DIRECT_IPA_UPLOAD_ENABLED ?? 'true').toLowerCase() !== 'false',
  directIpaUploadMaxBytes: integer('DIRECT_IPA_UPLOAD_MAX_MB', 100, 10, 2048) * 1024 * 1024,
  directIpaMinFreeDiskBytes: integer('DIRECT_IPA_MIN_FREE_DISK_MB', 256, 64, 4096) * 1024 * 1024,
  directUploadDir: process.env.DIRECT_IPA_UPLOAD_DIR || '/tmp/xsign-direct-uploads',
  directUploadTtlMinutes: integer('DIRECT_IPA_UPLOAD_TTL_MINUTES', 30, 5, 240),
  maxP12Bytes: integer('MAX_P12_MB', 10, 1, 100) * 1024 * 1024,
  maxProfileBytes: integer('MAX_PROFILE_MB', 5, 1, 50) * 1024 * 1024,
  maxIconBytes: integer('MAX_ICON_MB', 20, 1, 100) * 1024 * 1024,
  maxTweakBytes: integer('MAX_TWEAK_MB', 100, 1, 500) * 1024 * 1024,
  maxTweakFiles: integer('MAX_TWEAK_FILES', 8, 0, 20),
  maxTotalJobBytes: integer('MAX_TOTAL_JOB_MB', 900, 50, 4096) * 1024 * 1024,
  jobTimeoutMs: integer('JOB_TIMEOUT_SECONDS', 1200, 60, 7200) * 1000,
  workerPollMs: integer('WORKER_POLL_MS', 1500, 500, 15000),
  tempDir: process.env.SIGNING_TEMP_DIR || '/tmp/xsign',
  maxRemoteRedirects: 3,
  maxRemoteDownloadMs: 120000,
};

export function validateConfig() {
  const missing = [];
  if (!config.databaseUrl) missing.push('DATABASE_URL');
  if (!config.appMasterKey) missing.push('APP_MASTER_KEY');
  if (!config.frontendOrigins.length) missing.push('FRONTEND_ORIGIN');
  if (!config.s3AccessKeyId) missing.push('AWS_ACCESS_KEY_ID');
  if (!config.s3SecretAccessKey) missing.push('AWS_SECRET_ACCESS_KEY');
  if (!config.bucket) missing.push('TIGRIS_BUCKET');
  if (missing.length) throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  if (config.bucket !== 'ipa-signer') {
    console.warn('TIGRIS_BUCKET is not ipa-signer; check that this is intentional.');
  }
}
