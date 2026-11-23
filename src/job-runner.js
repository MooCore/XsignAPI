import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, readdir, rm, stat, copyFile, chmod, writeFile } from 'node:fs/promises';
import path from 'node:path';
import sharp from 'sharp';
import { config } from './config.js';
import { pool } from './db.js';
import { decryptSecret, redactErrorMessage } from './security.js';
import { downloadObject, uploadFile, createDownloadUrl, deleteObjects } from './storage.js';
import { downloadRemoteIpa } from './remote-download.js';

class PublicJobError extends Error {
  constructor(message) {
    super(message);
    this.name = 'PublicJobError';
  }
}

function runCommand(command, args, options = {}) {
  const {
    cwd,
    stdinText,
    timeoutMs = 120000,
    maxOutput = 256 * 1024,
    env = process.env,
  } = options;
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd, env, shell: false, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    let settled = false;
    const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs);
    const capture = (current, chunk) => (current + chunk.toString('utf8')).slice(-maxOutput);
    child.stdout.on('data', (chunk) => { stdout = capture(stdout, chunk); });
    child.stderr.on('data', (chunk) => { stderr = capture(stderr, chunk); });
    child.on('error', (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new Error(`${command} could not be started: ${error.message}`));
    });
    child.on('close', (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (code === 0) resolve({ stdout, stderr });
      else {
        const error = new Error(`${command} exited with code ${code ?? signal ?? 'unknown'}.`);
        error.command = command;
        error.stderr = stderr;
        error.stdout = stdout;
        error.timedOut = signal === 'SIGKILL';
        reject(error);
      }
    });
    if (stdinText !== undefined) child.stdin.end(stdinText);
    else child.stdin.end();
  });
}

async function runPython(args, options = {}) {
  const result = await runCommand('python3', [path.resolve('scripts/ipa_tools.py'), ...args], options);
  const lastLine = result.stdout.trim().split('\n').at(-1) || '{}';
  try { return JSON.parse(lastLine); }
  catch { throw new PublicJobError('The uploaded IPA could not be processed.'); }
}

async function updateStage(jobId, workerId, progress, stage) {
  await pool.query(
    `UPDATE signing_jobs
     SET progress = $3, stage = $4, updated_at = NOW(), locked_until = NOW() + INTERVAL '4 minutes'
     WHERE id = $1 AND worker_id = $2 AND status = 'running'`,
    [jobId, workerId, progress, stage],
  );
}

async function extractP12(p12Path, passwordBuffer, directory) {
  const keyPath = path.join(directory, 'signing-key.pem');
  const certPath = path.join(directory, 'signing-cert.pem');
  const password = passwordBuffer.toString('utf8');
  const base = ['pkcs12', '-in', p12Path];
  let extracted = false;
  for (const legacy of [false, true]) {
    const extra = legacy ? ['-legacy'] : [];
    try {
      await runCommand('openssl', [...base, ...extra, '-nocerts', '-nodes', '-passin', 'stdin', '-out', keyPath], {
        stdinText: `${password}\n`, timeoutMs: 60000,
      });
      await runCommand('openssl', [...base, ...extra, '-clcerts', '-nokeys', '-passin', 'stdin', '-out', certPath], {
        stdinText: `${password}\n`, timeoutMs: 60000,
      });
      const [keyInfo, certInfo] = await Promise.all([stat(keyPath), stat(certPath)]);
      if (keyInfo.size > 0 && certInfo.size > 0) {
        extracted = true;
        break;
      }
    } catch {
      await rm(keyPath, { force: true });
      await rm(certPath, { force: true });
    }
  }
  passwordBuffer.fill(0);
  if (!extracted) throw new PublicJobError('The P12 certificate could not be opened. Check that the password is correct and the certificate contains a private key.');
  await Promise.all([chmod(keyPath, 0o600), chmod(certPath, 0o600)]);
  return { keyPath, certPath };
}

async function walkDylibs(root, found = []) {
  const entries = await readdir(root, { withFileTypes: true });
  for (const entry of entries) {
    const current = path.join(root, entry.name);
    if (entry.isSymbolicLink()) continue;
    if (entry.isDirectory()) await walkDylibs(current, found);
    else if (entry.isFile() && entry.name.toLowerCase().endsWith('.dylib')) found.push(current);
  }
  return found;
}

async function prepareTweakLibraries(tweakFiles, workDir) {
  const outputDir = path.join(workDir, 'tweak-libraries');
  await mkdir(outputDir, { recursive: true, mode: 0o700 });
  const libraries = [];
  let count = 0;
  for (const tweakFile of tweakFiles) {
    const extension = path.extname(tweakFile).toLowerCase();
    if (extension === '.dylib') {
      const target = path.join(outputDir, `${count}-${path.basename(tweakFile).replace(/[^A-Za-z0-9._-]/g, '_')}`);
      await copyFile(tweakFile, target);
      await chmod(target, 0o600);
      libraries.push(target);
      count += 1;
      continue;
    }
    if (extension === '.deb') {
      const extractDir = path.join(workDir, `deb-${count}`);
      await mkdir(extractDir, { recursive: true, mode: 0o700 });
      try {
        await runCommand('dpkg-deb', ['--extract', tweakFile, extractDir], { timeoutMs: 90000, maxOutput: 64 * 1024 });
      } catch {
        throw new PublicJobError('One of the uploaded DEB tweak packages could not be extracted.');
      }
      const extracted = await walkDylibs(extractDir);
      if (!extracted.length) throw new PublicJobError('A DEB package did not contain an injectable .dylib file.');
      for (const source of extracted) {
        const target = path.join(outputDir, `${count}-${path.basename(source).replace(/[^A-Za-z0-9._-]/g, '_')}`);
        await copyFile(source, target);
        await chmod(target, 0o600);
        libraries.push(target);
        count += 1;
      }
    } else {
      throw new PublicJobError('Only .deb and .dylib tweak files are supported.');
    }
    if (count > 12) throw new PublicJobError('The selected tweak packages contain too many dynamic libraries to inject in one signing job.');
  }
  return libraries;
}

async function prepareIcon(iconPath, workDir) {
  const output = path.join(workDir, 'app-icon.png');
  try {
    await sharp(iconPath, { limitInputPixels: 40_000_000 })
      .rotate()
      .png()
      .toFile(output);
  } catch {
    throw new PublicJobError('The app icon could not be converted. Upload a valid PNG or JPG image.');
  }
  await chmod(output, 0o600);
  return output;
}

function xmlEscape(value) {
  return String(value ?? '').replace(/[<>&"']/g, (character) => ({
    '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;',
  })[character]);
}

function buildManifest({ ipaUrl, appName, bundleId, appVersion }) {
  const version = appVersion || '1.0';
  const title = appName || 'Signed App';
  const identifier = bundleId || 'com.xsign.signedapp';
  return `<?xml version="1.0" encoding="UTF-8"?>\n` +
    `<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n` +
    `<plist version="1.0"><dict>\n` +
    `<key>items</key><array><dict><key>assets</key><array><dict>` +
    `<key>kind</key><string>software-package</string><key>url</key><string>${xmlEscape(ipaUrl)}</string>` +
    `</dict></array><key>metadata</key><dict>` +
    `<key>bundle-identifier</key><string>${xmlEscape(identifier)}</string>` +
    `<key>bundle-version</key><string>${xmlEscape(version)}</string>` +
    `<key>kind</key><string>software</string><key>title</key><string>${xmlEscape(title)}</string>` +
    `</dict></dict></array></dict></plist>\n`;
}

function publicError(error) {
  if (error instanceof PublicJobError) return error.message;
  if (error?.timedOut) return 'The signing process exceeded its time limit. Try a smaller IPA or fewer tweaks.';
  if (error?.command === 'zsign') return 'Signing failed. Check that the P12 certificate, password, provisioning profile and selected app options are compatible.';
  if (error?.command === 'openssl') return 'The P12 certificate could not be opened. Check its password and certificate file.';
  if (String(error?.message || '').includes('restricted network')) return error.message;
  return 'The signing job could not be completed. Check the certificate, profile and uploaded files, then try again.';
}

async function safeDeleteInputObjects(inputs) {
  const keys = [
    inputs?.ipaObjectKey,
    inputs?.p12ObjectKey,
    inputs?.mobileprovisionObjectKey,
    inputs?.iconObjectKey,
    ...(Array.isArray(inputs?.tweakObjectKeys) ? inputs.tweakObjectKeys : []),
  ].filter(Boolean);
  const cleanupTasks = [];
  if (keys.length) cleanupTasks.push(deleteObjects(keys));
  if (inputs?.ipaDirectUploadId && /^[0-9a-f-]{36}$/i.test(inputs.ipaDirectUploadId)) {
    const localPath = path.join(config.directUploadDir, `${inputs.ipaDirectUploadId}.ipa`);
    cleanupTasks.push((async () => {
      await rm(localPath, { force: true });
      await pool.query('DELETE FROM direct_ipa_uploads WHERE id = $1', [inputs.ipaDirectUploadId]);
    })());
  }
  const results = await Promise.allSettled(cleanupTasks);
  if (results.some((result) => result.status === 'rejected')) {
    throw new Error('One or more input files could not be cleaned up.');
  }
}

export async function processSigningJob(job, workerId) {
  const workDir = await mkdtemp(path.join(config.tempDir, `${job.id}-`));
  await chmod(workDir, 0o700);
  const resultKeys = [];
  const inputs = job.input_objects || {};
  let heartbeat;
  let passwordBuffer;
  try {
    heartbeat = setInterval(() => {
      pool.query(
        `UPDATE signing_jobs SET locked_until = NOW() + INTERVAL '4 minutes', updated_at = NOW()
         WHERE id = $1 AND worker_id = $2 AND status = 'running'`,
        [job.id, workerId],
      ).catch(() => {});
    }, 30000);

    await updateStage(job.id, workerId, 22, 'Preparing the signing workspace');
    const ipaPath = path.join(workDir, 'source.ipa');
    if (inputs.ipaDirectUploadId && /^[0-9a-f-]{36}$/i.test(inputs.ipaDirectUploadId)) {
      const localIpaPath = path.join(config.directUploadDir, `${inputs.ipaDirectUploadId}.ipa`);
      const localStats = await stat(localIpaPath).catch(() => null);
      if (!localStats || localStats.size <= 0 || localStats.size > config.maxIpaBytes) {
        throw new PublicJobError('The direct Render upload is no longer available. Please upload the IPA again.');
      }
      await updateStage(job.id, workerId, 26, 'Loading IPA from the direct Render upload');
      await copyFile(localIpaPath, ipaPath);
    } else if (inputs.ipaObjectKey) {
      await updateStage(job.id, workerId, 26, 'Loading large IPA from Tigris storage');
      await downloadObject(inputs.ipaObjectKey, ipaPath, config.maxIpaBytes);
    } else if (inputs.ipaUrl) {
      await updateStage(job.id, workerId, 26, 'Downloading IPA from the supplied URL');
      await downloadRemoteIpa(inputs.ipaUrl, ipaPath, config.maxIpaBytes);
    } else {
      throw new PublicJobError('The IPA file or URL is missing.');
    }

    await updateStage(job.id, workerId, 32, 'Downloading certificate and provisioning profile');
    const p12Path = path.join(workDir, 'certificate.p12');
    const profilePath = path.join(workDir, 'profile.mobileprovision');
    await Promise.all([
      downloadObject(inputs.p12ObjectKey, p12Path, config.maxP12Bytes),
      downloadObject(inputs.mobileprovisionObjectKey, profilePath, config.maxProfileBytes),
    ]);
    const tweakFiles = [];
    for (let index = 0; index < (inputs.tweakObjectKeys || []).length; index += 1) {
      const key = inputs.tweakObjectKeys[index];
      const extension = path.extname(key).toLowerCase();
      const local = path.join(workDir, `tweak-${index}${extension}`);
      await downloadObject(key, local, config.maxTweakBytes);
      tweakFiles.push(local);
    }
    let iconInput = null;
    if (inputs.iconObjectKey) {
      iconInput = path.join(workDir, 'uploaded-icon');
      await downloadObject(inputs.iconObjectKey, iconInput, config.maxIconBytes);
    }

    await updateStage(job.id, workerId, 40, 'Validating and extracting IPA');
    const extractedDir = path.join(workDir, 'extracted');
    const extracted = await runPython(['extract', '--ipa', ipaPath, '--dest', extractedDir], { timeoutMs: 180000 });
    const appPath = extracted.appPath;
    const options = job.options || {};

    await updateStage(job.id, workerId, 48, 'Applying app name, version and display settings');
    const patched = await runPython([
      'patch', '--app', appPath, '--options', JSON.stringify(options),
    ], { timeoutMs: 60000 });

    await updateStage(job.id, workerId, 56, 'Preparing optional app icon and tweak files');
    const libraries = await prepareTweakLibraries(tweakFiles, workDir);
    const iconPng = iconInput ? await prepareIcon(iconInput, workDir) : null;
    await updateStage(job.id, workerId, 62, 'Unlocking and validating the P12 certificate');
    passwordBuffer = decryptSecret(job.password_ciphertext, job.password_nonce, job.password_tag);
    const { keyPath, certPath } = await extractP12(p12Path, passwordBuffer, workDir);
    passwordBuffer = null;

    await updateStage(job.id, workerId, 68, 'Signing application with zsign');
    const signedPath = path.join(workDir, 'signed.ipa');
    const args = [
      '-f', '-k', keyPath, '-c', certPath, '-m', profilePath,
      '-z', '1', '-o', signedPath,
    ];
    if (options.bundleId) args.push('-b', options.bundleId);
    if (options.appName) args.push('-n', options.appName);
    if (options.minimumIOS) args.push('-M', options.minimumIOS);
    if (options.removeExtensions) args.push('-E');
    if (options.removeWatchApp) args.push('-W');
    if (iconPng) args.push('-I', iconPng);
    for (const library of libraries) args.push('-l', library);
    args.push(appPath);

    try {
      await runCommand('zsign', args, { cwd: workDir, timeoutMs: config.jobTimeoutMs, maxOutput: 512 * 1024 });
    } catch (error) {
      if (error.command === 'zsign') throw error;
      throw new PublicJobError('The zsign engine could not be started. Please contact Xsign support.');
    }

    await updateStage(job.id, workerId, 82, 'Verifying the signed application');
    await runPython(['validate', '--ipa', signedPath], { timeoutMs: 180000 });
    const signedStats = await stat(signedPath);
    if (signedStats.size > config.maxIpaBytes * 2) throw new PublicJobError('The signed IPA is larger than the allowed output size.');

    await updateStage(job.id, workerId, 90, 'Uploading signed IPA to secure storage');
    const signedKey = `results/${job.id}/signed.ipa`;
    await uploadFile(signedKey, signedPath, 'application/octet-stream');
    resultKeys.push(signedKey);
    const downloadUrl = await createDownloadUrl(signedKey, 'application/octet-stream');

    await updateStage(job.id, workerId, 96, 'Generating OTA installation manifest');
    const manifestPath = path.join(workDir, 'manifest.plist');
    const metadata = patched || extracted.metadata || {};
    const appName = options.appName || metadata.appName || 'Signed App';
    const bundleId = options.bundleId || metadata.bundleId || 'com.xsign.signedapp';
    const appVersion = options.appVersion || metadata.appVersion || '1.0';
    const appBuildNumber = options.buildNumber || metadata.buildNumber || appVersion;
    const manifestText = buildManifest({ ipaUrl: downloadUrl, appName, bundleId, appVersion: appBuildNumber });
    await writeFile(manifestPath, manifestText, { mode: 0o600 });
    const manifestKey = `results/${job.id}/manifest.plist`;
    await uploadFile(manifestKey, manifestPath, 'application/xml');
    resultKeys.push(manifestKey);
    const manifestUrl = await createDownloadUrl(manifestKey, 'application/xml');
    const installUrl = `itms-services://?action=download-manifest&url=${encodeURIComponent(manifestUrl)}`;

    const expiresAt = new Date(Date.now() + config.retentionMinutes * 60 * 1000);
    const resultObject = {
      installUrl,
      downloadUrl,
      manifestUrl,
      appName,
      bundleId,
      appVersion,
      _storageKeys: resultKeys,
    };
    await pool.query(
      `UPDATE signing_jobs
       SET status = 'completed', progress = 100, stage = 'Signing completed', error = NULL,
           result = $3::jsonb, input_objects = '{}'::jsonb,
           password_ciphertext = NULL, password_nonce = NULL, password_tag = NULL,
           finished_at = NOW(), expires_at = $4, updated_at = NOW(), locked_until = NULL
       WHERE id = $1 AND worker_id = $2`,
      [job.id, workerId, JSON.stringify(resultObject), expiresAt],
    );
    try {
      await safeDeleteInputObjects(inputs);
      await pool.query('DELETE FROM uploads WHERE job_id = $1', [job.id]);
    } catch {
      // The completed-job cleanup pass retries deletion while the upload records remain.
    }
  } catch (error) {
    if (passwordBuffer) passwordBuffer.fill(0);
    await deleteObjects(resultKeys).catch(() => {});
    const message = publicError(error);
    if (error?.command === 'python3') {
      const stderr = String(error.stderr || '');
      if (stderr.includes('unsafe archive path') || stderr.includes('valid ZIP')) {
        await pool.query(
          `UPDATE signing_jobs SET status='failed', progress=0, stage='Signing failed', error=$3,
           input_objects='{}'::jsonb, password_ciphertext=NULL, password_nonce=NULL, password_tag=NULL,
           finished_at=NOW(), updated_at=NOW(), locked_until=NULL WHERE id=$1 AND worker_id=$2`,
          [job.id, workerId, 'The uploaded IPA archive is invalid or contains unsafe paths.'],
        );
        return;
      }
    }
    await pool.query(
      `UPDATE signing_jobs SET status='failed', progress=0, stage='Signing failed', error=$3,
       input_objects='{}'::jsonb, password_ciphertext=NULL, password_nonce=NULL, password_tag=NULL,
       finished_at=NOW(), updated_at=NOW(), locked_until=NULL WHERE id=$1 AND worker_id=$2`,
      [job.id, workerId, message],
    ).catch(() => {});
    try {
      await safeDeleteInputObjects(inputs);
      await pool.query('DELETE FROM uploads WHERE job_id = $1', [job.id]);
    } catch {
      // The failed-job cleanup pass retries deletion while the upload records remain.
    }
    console.warn(`Signing job ${job.id} failed: ${redactErrorMessage(error?.message || 'unknown error')}`);
  } finally {
    if (heartbeat) clearInterval(heartbeat);
    if (passwordBuffer) passwordBuffer.fill(0);
    await rm(workDir, { recursive: true, force: true }).catch(() => {});
  }
}
