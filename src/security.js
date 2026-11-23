import { createCipheriv, createDecipheriv, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { config } from './config.js';

let cachedKey;

export function getMasterKey() {
  if (cachedKey) return cachedKey;
  const value = config.appMasterKey.trim();
  let key;
  if (/^[0-9a-fA-F]{64}$/.test(value)) key = Buffer.from(value, 'hex');
  else key = Buffer.from(value, 'base64');
  if (key.length !== 32) throw new Error('APP_MASTER_KEY must decode to exactly 32 bytes.');
  cachedKey = key;
  return key;
}

export function encryptSecret(plainText) {
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', getMasterKey(), nonce);
  const encrypted = Buffer.concat([cipher.update(String(plainText), 'utf8'), cipher.final()]);
  return {
    ciphertext: encrypted.toString('base64'),
    nonce: nonce.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
  };
}

export function decryptSecret(ciphertext, nonce, tag) {
  const decipher = createDecipheriv('aes-256-gcm', getMasterKey(), Buffer.from(nonce, 'base64'));
  decipher.setAuthTag(Buffer.from(tag, 'base64'));
  return Buffer.concat([
    decipher.update(Buffer.from(ciphertext, 'base64')),
    decipher.final(),
  ]);
}

export function hashClientIp(ip) {
  const normalized = String(ip || 'unknown').replace(/^::ffff:/, '');
  return createHmac('sha256', getMasterKey()).update(normalized).digest('hex');
}

export function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && timingSafeEqual(a, b);
}

export function redactErrorMessage(value) {
  return String(value || 'Unexpected error')
    .replace(/https?:\/\/\S+/gi, '[url]')
    .replace(/(?:tid|tsec)_[A-Za-z0-9_+/-]+/g, '[credential]')
    .replace(/\b[A-Za-z0-9+/]{40,}={0,2}\b/g, '[secret]')
    .slice(0, 500);
}
