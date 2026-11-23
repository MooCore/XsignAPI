import dns from 'node:dns/promises';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { createWriteStream } from 'node:fs';
import { pipeline } from 'node:stream/promises';
import ipaddr from 'ipaddr.js';
import { config } from './config.js';

function isPublicAddress(address) {
  try {
    const parsed = ipaddr.parse(address);
    return parsed.range() === 'unicast';
  } catch {
    return false;
  }
}

async function resolvePublicHost(hostname) {
  if (net.isIP(hostname)) throw new Error('IP-address IPA URLs are not accepted. Use a public hostname.');
  const records = await dns.lookup(hostname, { all: true, verbatim: true });
  if (!records.length || records.some((record) => !isPublicAddress(record.address))) {
    throw new Error('The IPA URL resolves to a restricted network address.');
  }
  // Pin the connection to the resolved public address to prevent DNS rebinding between validation and connect.
  return records[0];
}

function makePinnedLookup(record) {
  return (_hostname, options, callback) => {
    if (options && options.all) callback(null, [{ address: record.address, family: record.family }]);
    else callback(null, record.address, record.family);
  };
}

function requestOnce(url, record, destination, maximumBytes, timeoutMs) {
  return new Promise((resolve, reject) => {
    const transport = url.protocol === 'https:' ? https : http;
    const request = transport.request({
      protocol: url.protocol,
      hostname: url.hostname,
      port: url.port || undefined,
      method: 'GET',
      path: `${url.pathname}${url.search}`,
      headers: { Accept: 'application/octet-stream,*/*;q=0.8', 'Accept-Encoding': 'identity', 'User-Agent': 'Xsign-IPAFetch/1.0' },
      lookup: makePinnedLookup(record),
      servername: url.protocol === 'https:' ? url.hostname : undefined,
      timeout: Math.min(timeoutMs, 30000),
    }, (response) => {
      const status = response.statusCode || 0;
      if ([301, 302, 303, 307, 308].includes(status)) {
        const location = response.headers.location;
        response.resume();
        resolve({ redirect: location || null });
        return;
      }
      if (status < 200 || status >= 300) {
        response.resume();
        reject(new Error(`The IPA URL returned HTTP ${status}.`));
        return;
      }
      const declaredSize = Number(response.headers['content-length'] || 0);
      if (declaredSize > maximumBytes) {
        response.destroy();
        reject(new Error('The remote IPA exceeds the maximum allowed size.'));
        return;
      }
      let received = 0;
      const output = createWriteStream(destination, { flags: 'wx', mode: 0o600 });
      response.on('data', (chunk) => {
        received += chunk.length;
        if (received > maximumBytes) response.destroy(new Error('The remote IPA exceeds the maximum allowed size.'));
      });
      pipeline(response, output).then(() => {
        if (received === 0) reject(new Error('The remote IPA download was empty.'));
        else resolve({ bytes: received });
      }).catch((error) => reject(error));
    });

    const absoluteTimer = setTimeout(() => request.destroy(new Error('The remote IPA download timed out.')), timeoutMs);
    request.on('close', () => clearTimeout(absoluteTimer));
    request.on('timeout', () => request.destroy(new Error('The remote IPA download timed out.')));
    request.on('error', reject);
    request.end();
  });
}

export async function downloadRemoteIpa(rawUrl, destination, maximumBytes) {
  let current;
  try { current = new URL(rawUrl); } catch { throw new Error('The remote IPA URL is invalid.'); }
  for (let redirects = 0; redirects <= config.maxRemoteRedirects; redirects += 1) {
    if (!['http:', 'https:'].includes(current.protocol) || current.username || current.password) {
      throw new Error('The remote IPA URL must use HTTP or HTTPS without embedded credentials.');
    }
    if ((current.protocol === 'http:' && current.port && current.port !== '80')
      || (current.protocol === 'https:' && current.port && current.port !== '443')) {
      throw new Error('The remote IPA URL uses an unsupported port.');
    }
    const record = await resolvePublicHost(current.hostname);
    const remaining = config.maxRemoteDownloadMs;
    const response = await requestOnce(current, record, destination, maximumBytes, remaining);
    if (response.bytes) return response.bytes;
    if (!response.redirect) throw new Error('The remote IPA server returned an invalid redirect.');
    if (redirects === config.maxRemoteRedirects) throw new Error('The remote IPA URL redirected too many times.');
    current = new URL(response.redirect, current);
  }
  throw new Error('The remote IPA could not be downloaded.');
}
