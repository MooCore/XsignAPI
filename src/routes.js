import { Router } from 'express';
import { randomUUID } from 'node:crypto';
import { pool } from './db.js';
import { config } from './config.js';
import { encryptSecret, hashClientIp } from './security.js';
import { createUploadUrl, getObjectInfo } from './storage.js';
import {
  validateObjectKey,
  validateOptions,
  validateRemoteIpaUrl,
  validateUploadRequest,
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

    if (Boolean(ipaObjectKey) === Boolean(ipaUrl)) {
      throw httpError(400, 'Choose one IPA file upload or one IPA URL.');
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
    let totalInputBytes = 0;
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
      ipaUrl,
      p12ObjectKey,
      mobileprovisionObjectKey,
      iconObjectKey,
      tweakObjectKeys,
    };
    await client.query(
      `INSERT INTO signing_jobs
       (id, status, progress, stage, input_objects, options, password_ciphertext, password_nonce, password_tag, ip_hash)
       VALUES ($1, 'queued', 0, 'Queued for signing', $2::jsonb, $3::jsonb, $4, $5, $6, $7)`,
      [jobId, JSON.stringify(jobInputs), JSON.stringify(options), encryptedPassword.ciphertext, encryptedPassword.nonce, encryptedPassword.tag, ipHash],
    );
    await client.query(
      `UPDATE uploads SET used_at = NOW(), job_id = $2 WHERE object_key = ANY($1::text[])`,
      [keys, jobId],
    );
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
