import path from 'node:path';
import { URL } from 'node:url';
import { config } from './config.js';

const purposeExtensions = {
  ipa: new Set(['.ipa']),
  p12: new Set(['.p12', '.pfx']),
  mobileprovision: new Set(['.mobileprovision']),
  'app-icon': new Set(['.png', '.jpg', '.jpeg']),
  tweak: new Set(['.deb', '.dylib']),
};

export const purposeLimits = {
  ipa: config.maxIpaBytes,
  p12: config.maxP12Bytes,
  mobileprovision: config.maxProfileBytes,
  'app-icon': config.maxIconBytes,
  tweak: config.maxTweakBytes,
};

export function sanitizeFileName(value) {
  const base = path.basename(String(value || 'file')).normalize('NFKC');
  const cleaned = base.replace(/[^A-Za-z0-9._-]/g, '_').replace(/^\.+/, '').slice(0, 100);
  return cleaned || 'file';
}

export function validateUploadRequest(body) {
  const fileName = sanitizeFileName(body?.fileName);
  const purpose = String(body?.purpose || '');
  const contentType = String(body?.contentType || 'application/octet-stream').slice(0, 120);
  const size = Number(body?.size);
  if (!purposeExtensions[purpose]) throw new Error('Unsupported upload purpose.');
  if (!Number.isSafeInteger(size) || size <= 0 || size > purposeLimits[purpose]) {
    const maxMb = Math.floor(purposeLimits[purpose] / (1024 * 1024));
    throw new Error(`This ${purpose} upload must be between 1 byte and ${maxMb} MB.`);
  }
  const extension = path.extname(fileName).toLowerCase();
  if (!purposeExtensions[purpose].has(extension)) {
    throw new Error(`The selected file type is not valid for ${purpose}.`);
  }
  if (/[\r\n\0]/.test(contentType)) throw new Error('Invalid content type.');
  return { fileName, purpose, contentType, size, extension };
}

export function validateObjectKey(objectKey, expectedPurpose) {
  if (typeof objectKey !== 'string' || objectKey.length > 300) return false;
  const parts = objectKey.split('/');
  if (parts.length !== 3 || parts[0] !== 'incoming' || parts[1] !== expectedPurpose) return false;
  if (!/^[0-9a-f-]{36}\.[a-z0-9]+$/i.test(parts[2])) return false;
  return true;
}

export function validateOptions(raw = {}) {
  const text = (key, max) => {
    if (raw[key] === undefined || raw[key] === null || raw[key] === '') return null;
    if (typeof raw[key] !== 'string') throw new Error(`Invalid ${key} option.`);
    const value = raw[key].trim();
    if (!value) return null;
    if (value.length > max || /[\0\r\n]/.test(value)) throw new Error(`The ${key} option is too long or invalid.`);
    return value;
  };

  const appName = text('appName', 128);
  const bundleId = text('bundleId', 255);
  const appVersion = text('appVersion', 64);
  const buildNumber = text('buildNumber', 64);
  const minimumIOS = text('minimumIOS', 32);

  if (bundleId && !/^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/.test(bundleId)) {
    throw new Error('Enter a valid bundle identifier, such as com.example.app.');
  }
  if (appVersion && !/^[0-9A-Za-z][0-9A-Za-z.+_-]*$/.test(appVersion)) {
    throw new Error('The app version contains unsupported characters.');
  }
  if (buildNumber && !/^[0-9A-Za-z][0-9A-Za-z.+_-]*$/.test(buildNumber)) {
    throw new Error('The build number contains unsupported characters.');
  }
  if (minimumIOS && !/^\d{1,2}(?:\.\d{1,2}){0,2}$/.test(minimumIOS)) {
    throw new Error('Enter a valid minimum iOS version, such as 16.0.');
  }

  const boolean = (key) => {
    if (raw[key] === undefined) return false;
    if (typeof raw[key] !== 'boolean') throw new Error(`Invalid ${key} option.`);
    return raw[key];
  };

  return {
    appName,
    bundleId,
    appVersion,
    buildNumber,
    minimumIOS,
    proMotion: boolean('proMotion'),
    gameMode: boolean('gameMode'),
    removeExtensions: boolean('removeExtensions'),
    removeWatchApp: boolean('removeWatchApp'),
  };
}

export function validateRemoteIpaUrl(value) {
  if (typeof value !== 'string' || value.length > 2048) throw new Error('Enter a valid HTTP or HTTPS IPA URL.');
  let url;
  try { url = new URL(value); } catch { throw new Error('Enter a valid HTTP or HTTPS IPA URL.'); }
  if (!['http:', 'https:'].includes(url.protocol) || !url.hostname || url.username || url.password) {
    throw new Error('Only public HTTP or HTTPS IPA URLs are supported.');
  }
  if (url.port && !['80', '443'].includes(url.port)) throw new Error('IPA URLs must use the standard HTTP or HTTPS port.');
  return url.toString();
}
