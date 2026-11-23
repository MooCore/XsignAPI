import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  DeleteObjectCommand,
  DeleteObjectsCommand,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import { pipeline } from 'node:stream/promises';
import { createWriteStream } from 'node:fs';
import { config } from './config.js';

export const s3 = new S3Client({
  region: config.s3Region,
  endpoint: config.s3Endpoint,
  credentials: {
    accessKeyId: config.s3AccessKeyId,
    secretAccessKey: config.s3SecretAccessKey,
  },
  // Tigris supports S3 virtual-host addressing. Keep the SDK default (false).
  forcePathStyle: false,
  maxAttempts: 3,
});

export async function createUploadUrl({ objectKey, contentType }) {
  const command = new PutObjectCommand({
    Bucket: config.bucket,
    Key: objectKey,
    ContentType: contentType,
  });
  const uploadUrl = await getSignedUrl(s3, command, { expiresIn: config.uploadUrlTtlSeconds });
  return { uploadUrl, headers: { 'Content-Type': contentType } };
}

export async function getObjectInfo(objectKey) {
  const info = await s3.send(new HeadObjectCommand({ Bucket: config.bucket, Key: objectKey }));
  return { size: Number(info.ContentLength || 0), contentType: info.ContentType || '' };
}

export async function downloadObject(objectKey, destination, maximumBytes) {
  const response = await s3.send(new GetObjectCommand({ Bucket: config.bucket, Key: objectKey }));
  const size = Number(response.ContentLength || 0);
  if (size > maximumBytes) {
    response.Body?.destroy?.();
    throw new Error('A stored upload exceeds its allowed size.');
  }
  if (!response.Body) throw new Error('The uploaded file could not be read from storage.');
  let received = 0;
  response.Body.on('data', (chunk) => {
    received += chunk.length;
    if (received > maximumBytes) response.Body.destroy(new Error('File exceeds the allowed size.'));
  });
  await pipeline(response.Body, createWriteStream(destination, { mode: 0o600, flags: 'wx' }));
  if (received === 0) throw new Error('The uploaded file is empty.');
  return received;
}

export async function uploadFile(objectKey, filePath, contentType, cacheControl = 'private, no-store') {
  const details = await stat(filePath);
  await s3.send(new PutObjectCommand({
    Bucket: config.bucket,
    Key: objectKey,
    Body: createReadStream(filePath),
    ContentLength: details.size,
    ContentType: contentType,
    CacheControl: cacheControl,
  }));
  return details.size;
}

export async function createDownloadUrl(objectKey, contentType) {
  const command = new GetObjectCommand({
    Bucket: config.bucket,
    Key: objectKey,
    ResponseContentType: contentType,
    ResponseCacheControl: 'private, no-store',
  });
  return getSignedUrl(s3, command, { expiresIn: config.downloadUrlTtlSeconds });
}

export async function deleteObject(objectKey) {
  if (!objectKey) return;
  await s3.send(new DeleteObjectCommand({ Bucket: config.bucket, Key: objectKey }));
}

export async function deleteObjects(objectKeys = []) {
  const uniqueKeys = [...new Set(objectKeys.filter((key) => typeof key === 'string' && key.length))];
  for (let index = 0; index < uniqueKeys.length; index += 1000) {
    const batch = uniqueKeys.slice(index, index + 1000);
    if (!batch.length) continue;
    const response = await s3.send(new DeleteObjectsCommand({
      Bucket: config.bucket,
      Delete: { Objects: batch.map((Key) => ({ Key })), Quiet: true },
    }));
    if (response.Errors?.length) throw new Error('One or more Tigris objects could not be deleted.');
  }
}
