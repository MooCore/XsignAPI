import { Router } from 'express';
import { randomUUID } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import { mkdir, rm, stat, statfs } from 'node:fs/promises';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import path from 'node:path';
import { pool } from './db.js';
import { config } from './config.js';
import { encryptSecret, hashClientIp } from './security.js';
import { createUploadUrl, getObjectInfo } from './storage.js';
import {
  validateObjectKey,
  validateOptions,
  validateRemoteIpaUrl,
  validateUploadRequest,
  sanitizeFileName,
} from './validation.js';

export const router = Router();

function clientHash(req) {
  return hashClientIp(req.ip || req.socket.remoteAddress || 'unknown');
}

function httpError(status, message) {
  const error = new Error(message);
  error.statusCode = status;
  return error;
}

function safeJobResult(result) {
  if (!result || typeof result !== 'object') return null;
  return {
    installUrl: result.installUrl,
    downloadUrl: result.downloadUrl,
    manifestUrl: result.manifestUrl,
    appName: result.appName,
    bundleId: result.bundleId,
    appVersion: result.appVersion,
  };
}

router.get('/', (_req, res) => {
  res.json({ name: 'Xsign API', status: 'online', version: '1.0.0' });
});

router.get('/healthz', async (_req, res, next) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', service: 'xsign-api' });
  } catch (error) {
    next(error);
  }
});

router.get('/v1/capabilities', async (_req, res) => {
  let directLimit = config.directIpaUploadEnabled ? Math.min(config.directIpaUploadMaxBytes, config.maxIpaBytes) : 0;
  if (directLimit > 0) {
    try {
      const disk = await statfs(config.directUploadDir);
      const availableBytes = Number(disk.bavail) * Number(disk.bsize);
      directLimit = Math.min(directLimit, Math.max(0, availableBytes - config.directIpaMinFreeDiskBytes));
    } catch {
      directLimit = 0;
    }
  }
  res.set('Cache-Control', 'no-store');
  res.json({
    maxIpaBytes: config.maxIpaBytes,
    directIpaUploadEnabled: config.directIpaUploadEnabled && directLimit > 0,
    directIpaUploadMaxBytes: directLimit,
    largeFileFallback: 'tigris',
    maxTweakFiles: config.maxTweakFiles,
  });
});

router.post('/v1/uploads/ipa-direct', async (req, res) => {
  let filePath;
  let uploadId;
  try {
    if (!config.directIpaUploadEnabled) {
      return res.status(503).json({ message: 'Direct Render uploads are disabled. Use the large-file storage route.', code: 'DIRECT_UPLOAD_DISABLED' });
    }

    let fileName;
    try { fileName = sanitizeFileName(decodeURIComponent(String(req.headers['x-file-name'] || ''))); }
    catch { return res.status(400).json({ message: 'The IPA file name is invalid.' }); }
    if (path.extname(fileName).toLowerCase() !== '.ipa') {
      return res.status(400).json({ message: 'Only .ipa files can use the direct upload route.' });
    }

    const declaredSize = Number(req.headers['x-file-size']);
    const contentLength = req.headers['content-length'] ? Number(req.headers['content-length']) : null;
    if (!Number.isSafeInteger(declaredSize) || declaredSize <= 0) {
      return res.status(400).json({ message: 'The IPA file size could not be verified.' });
    }
    if (declaredSize > config.maxIpaBytes) {
      return res.status(413).json({ message: `This IPA exceeds the ${Math.floor(config.maxIpaBytes / (1024 * 1024))} MB maximum.`, code: 'IPA_MAX_SIZE_EXCEEDED' });
    }
    const directLimit = Math.min(config.directIpaUploadMaxBytes, config.maxIpaBytes);
    if (declaredSize > directLimit || (contentLength && contentLength > directLimit)) {
      req.resume();
      return res.status(413).json({ message: 'This IPA is too large for the configured Render upload route. Xsign will use Tigris instead.', code: 'DIRECT_UPLOAD_TOO_LARGE', fallback: 'tigris' });
    }
    if (contentLength && contentLength !== declaredSize) {
      return res.status(400).json({ message: 'The IPA upload size did not match the selected file.' });
    }

    uploadId = randomUUID();
    await mkdir(config.directUploadDir, { recursive: true, mode: 0o700 });
    const disk = await statfs(config.directUploadDir);
    const availableBytes = Number(disk.bavail) * Number(disk.bsize);
    if (availableBytes - declaredSize < config.directIpaMinFreeDiskBytes) {
      req.resume();
      return res.status(503).json({
        message: 'Render temporary storage is low. Xsign will use Tigris for this IPA instead.',
        code: 'DIRECT_UPLOAD_CAPACITY_LOW',
        fallback: 'tigris',
      });
    }
    filePath = path.join(config.directUploadDir, `${uploadId}.ipa`);
    let received = 0;
    const counter = new Transform({
      transform(chunk, _encoding, callback) {
        received += chunk.length;
        if (received > directLimit || received > declaredSize) {
          const error = httpError(413, 'The IPA exceeded the configured Render upload limit. Xsign can retry it through Tigris.');
          error.code = received > config.maxIpaBytes ? 'IPA_MAX_SIZE_EXCEEDED' : 'DIRECT_UPLOAD_TOO_LARGE';
          callback(error);
          return;
        }
        callback(null, chunk);
      },
    });

    await pipeline(req, counter, createWriteStream(filePath, { flags: 'wx', mode: 0o600 }));
    if (received !== declaredSize) throw httpError(400, 'The IPA upload was incomplete. Please try again.');
    const fileInfo = await stat(filePath);
    if (fileInfo.size !== declaredSize) throw httpError(400, 'The IPA upload could not be verified. Please try again.');

    await pool.query(
      `INSERT INTO direct_ipa_uploads (id, file_name, expected_size, ip_hash, expires_at)
       VALUES ($1, $2, $3, $4, NOW() + ($5 * INTERVAL '1 minute'))`,
      [uploadId, fileName, declaredSize, clientHash(req), config.directUploadTtlMinutes],
    );

    res.status(201).set('Cache-Control', 'no-store').json({
      uploadId, size: declaredSize, uploadMode: 'render', stage: 'IPA uploaded directly to Render',
    });
  } catch (error) {
    if (filePath) await rm(filePath, { force: true }).catch(() => {});
    if (res.headersSent || res.destroyed) return;
    const status = error.statusCode || (req.aborted ? 400 : 500);
    res.status(status).json({
      message: status >= 500 ? 'The direct IPA upload failed. Please retry or use Tigris storage.' : error.message,
      ...(error.code ? { code: error.code } : {}),
      ...(error.code === 'DIRECT_UPLOAD_TOO_LARGE' ? { fallback: 'tigris' } : {}),
    });
  }
});

router.post('/v1/uploads/presign', async (req, res, next) => {
  try {
    let request;
    try { request = validateUploadRequest(req.body || {}); }
    catch (error) { throw httpError(400, error.message); }
    const objectKey = `incoming/${request.purpose}/${randomUUID()}${request.extension}`;
    const presigned = await createUploadUrl({ objectKey, contentType: request.contentType });
    await pool.query(
      `INSERT INTO uploads (object_key, purpose, expected_size, ip_hash, expires_at)
       VALUES ($1, $2, $3, $4, NOW() + INTERVAL '1 hour')`,
      [objectKey, request.purpose, request.size, clientHash(req)],
    );
    res.status(200).json({
      uploadUrl: presigned.uploadUrl,
      objectKey,
      headers: presigned.headers,
    });
  } catch (error) {
    if (!error.statusCode) error.statusCode = 500;
    next(error);
  }
});

router.post('/v1/signing/jobs', async (req, res, next) => {
  let client;
  let transactionOpen = false;
  try {
    client = await pool.connect();
    const body = req.body || {};
    const inputs = body.inputs || {};
    let options;
    try { options = validateOptions(body.options || {}); }
    catch (error) { throw httpError(400, error.message); }

    const ipaObjectKey = inputs.ipaObjectKey || null;
    const ipaDirectUploadId = inputs.ipaDirectUploadId || null;
    let ipaUrl = null;
    if (inputs.ipaUrl) {
      try { ipaUrl = validateRemoteIpaUrl(String(inputs.ipaUrl).trim()); }
      catch (error) { throw httpError(400, error.message); }
    }
    const p12ObjectKey = inputs.p12ObjectKey;
    const mobileprovisionObjectKey = inputs.mobileprovisionObjectKey;
    const iconObjectKey = inputs.iconObjectKey || null;
    const tweakObjectKeys = inputs.tweakObjectKeys || [];
    const p12Password = body.p12Password ?? '';

    const ipaSources = [ipaObjectKey, ipaDirectUploadId, ipaUrl].filter(Boolean).length;
    if (ipaSources !== 1) {
      throw httpError(400, 'Choose one IPA file upload, direct Render upload, or IPA URL.');
    }
    if (ipaDirectUploadId && !/^[0-9a-f-]{36}$/i.test(ipaDirectUploadId)) {
      throw httpError(400, 'The direct IPA upload reference is invalid. Please upload the IPA again.');
    }
    if (!p12ObjectKey || !mobileprovisionObjectKey) {
      throw httpError(400, 'A P12 certificate and mobileprovision file are required.');
    }
    if (typeof p12Password !== 'string' || p12Password.length > 2048 || /[\r\n\0]/.test(p12Password)) {
      throw httpError(400, 'The P12 password is invalid or too long.');
    }
    if (!Array.isArray(tweakObjectKeys) || tweakObjectKeys.length > config.maxTweakFiles) {
      throw httpError(400, `You can upload up to ${config.maxTweakFiles} tweak files per signing job.`);
    }

    const requestedUploads = [];
    if (ipaObjectKey) requestedUploads.push({ key: ipaObjectKey, purpose: 'ipa' });
    requestedUploads.push({ key: p12ObjectKey, purpose: 'p12' });
    requestedUploads.push({ key: mobileprovisionObjectKey, purpose: 'mobileprovision' });
    if (iconObjectKey) requestedUploads.push({ key: iconObjectKey, purpose: 'app-icon' });
    for (const key of tweakObjectKeys) requestedUploads.push({ key, purpose: 'tweak' });

    const uniqueKeys = new Set();
    for (const upload of requestedUploads) {
      if (!validateObjectKey(upload.key, upload.purpose)) throw httpError(400, 'An upload reference is invalid. Please upload the file again.');
      if (uniqueKeys.has(upload.key)) throw httpError(400, 'A file was submitted more than once.');
      uniqueKeys.add(upload.key);
    }

    const ipHash = clientHash(req);
    await client.query('BEGIN');
    transactionOpen = true;
    let directIpaRecord = null;
    if (ipaDirectUploadId) {
      const directResult = await client.query(
        `SELECT id, expected_size, expires_at, used_at FROM direct_ipa_uploads WHERE id = $1 FOR UPDATE`,
        [ipaDirectUploadId],
      );
      directIpaRecord = directResult.rows[0] || null;
      if (!directIpaRecord || directIpaRecord.used_at || new Date(directIpaRecord.expires_at).getTime() <= Date.now()) {
        throw httpError(400, 'The direct IPA upload has expired or is no longer available. Please upload the IPA again.');
      }
      const directPath = path.join(config.directUploadDir, `${ipaDirectUploadId}.ipa`);
      const directStats = await stat(directPath).catch(() => null);
      if (!directStats || directStats.size !== Number(directIpaRecord.expected_size)) {
        throw httpError(400, 'The direct IPA upload is missing or incomplete. Please upload the IPA again.');
      }
    }

    const keys = requestedUploads.map((item) => item.key);
    const recordsResult = await client.query(
      `SELECT object_key, purpose, expected_size, expires_at, used_at
       FROM uploads
       WHERE object_key = ANY($1::text[])
       FOR UPDATE`,
      [keys],
    );
    if (recordsResult.rows.length !== requestedUploads.length) {
      throw httpError(400, 'One or more uploaded files are missing or belong to another upload session. Please upload them again.');
    }

    const recordMap = new Map(recordsResult.rows.map((row) => [row.object_key, row]));
    let totalInputBytes = directIpaRecord ? Number(directIpaRecord.expected_size) : 0;
    if (totalInputBytes > config.maxTotalJobBytes) {
      throw httpError(400, `The combined upload size cannot exceed ${Math.floor(config.maxTotalJobBytes / (1024 * 1024))} MB.`);
    }
    for (const upload of requestedUploads) {
      const record = recordMap.get(upload.key);
      if (!record || record.purpose !== upload.purpose || record.used_at || new Date(record.expires_at).getTime() <= Date.now()) {
        throw httpError(400, 'An upload has expired or has already been used. Please upload the files again.');
      }
      const actual = await getObjectInfo(upload.key);
      if (!actual.size || actual.size !== Number(record.expected_size)) {
        throw httpError(400, 'An uploaded file is incomplete or its size does not match. Please upload it again.');
      }
      totalInputBytes += actual.size;
      if (totalInputBytes > config.maxTotalJobBytes) {
        throw httpError(400, `The combined upload size cannot exceed ${Math.floor(config.maxTotalJobBytes / (1024 * 1024))} MB.`);
      }
    }

    const jobId = randomUUID();
    const encryptedPassword = encryptSecret(p12Password);
    const jobInputs = {
      ipaObjectKey,
      ipaDirectUploadId,
      ipaUrl,
      p12ObjectKey,
      mobileprovisionObjectKey,
      iconObjectKey,
      tweakObjectKeys,
    };
    await client.query(
      `INSERT INTO signing_jobs
       (id, status, progress, stage, input_objects, options, password_ciphertext, password_nonce, password_tag, ip_hash)
       VALUES ($1, 'queued', 20, 'Queued for signing', $2::jsonb, $3::jsonb, $4, $5, $6, $7)`,
      [jobId, JSON.stringify(jobInputs), JSON.stringify(options), encryptedPassword.ciphertext, encryptedPassword.nonce, encryptedPassword.tag, ipHash],
    );
    await client.query(
      `UPDATE uploads SET used_at = NOW(), job_id = $2 WHERE object_key = ANY($1::text[])`,
      [keys, jobId],
    );
    if (ipaDirectUploadId) {
      await client.query(
        `UPDATE direct_ipa_uploads SET used_at = NOW(), job_id = $2 WHERE id = $1`,
        [ipaDirectUploadId, jobId],
      );
    }
    await client.query('COMMIT');
    transactionOpen = false;

    res.status(202).json({ jobId, stage: 'Queued for signing' });
  } catch (error) {
    if (transactionOpen) await client.query('ROLLBACK').catch(() => {});
    if (!error.statusCode) error.statusCode = 500;
    next(error);
  } finally {
    client?.release();
  }
});

router.get('/v1/signing/jobs/:jobId', async (req, res, next) => {
  try {
    if (!/^[0-9a-f-]{36}$/i.test(req.params.jobId)) throw httpError(404, 'Signing job not found.');
    const result = await pool.query(
      `SELECT id, status, progress, stage, error, result, expires_at
       FROM signing_jobs WHERE id = $1`,
      [req.params.jobId],
    );
    const job = result.rows[0];
    if (!job) throw httpError(404, 'Signing job not found.');
    let status = job.status;
    let error = job.error;
    let jobResult = job.result;
    if (status === 'completed' && job.expires_at && new Date(job.expires_at).getTime() <= Date.now()) {
      status = 'failed';
      error = 'The signed IPA has expired. Please submit a new signing job.';
      jobResult = null;
    }
    res.set('Cache-Control', 'no-store');
    res.json({
      jobId: job.id,
      status,
      progress: status === 'completed' ? 100 : job.progress,
      stage: job.status === 'expired' ? 'Signed IPA expired' : job.stage,
      ...(error ? { error } : {}),
      ...(status === 'completed' && jobResult ? { result: safeJobResult(jobResult) } : {}),
    });
  } catch (error) {
    if (!error.statusCode) error.statusCode = 500;
    next(error);
  }
});
