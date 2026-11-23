# Xsign — Render API and signing service

This is the backend companion for the Xsign Next.js website. It implements the API contract already used by the Vercel frontend, processes IPA signing jobs in the background, stores uploads in a private Tigris S3 bucket, and produces OTA installation manifests.

## Included

- Express API with exact-origin CORS, security headers and per-IP rate limits
- Streamed, browser-to-Render IPA uploads for files within a configurable Render-safe threshold, with automatic Tigris fallback for larger IPAs or a Render 413 response
- Presigned, browser-to-Tigris uploads for P12, mobileprovision, app icon, tweak files and oversized IPA fallback
- Postgres-backed job queue with a separate background processing loop inside the Render service
- AES-256-GCM encryption for the P12 password while a job is queued; the encrypted fields are erased after processing
- P12/private-key extraction through OpenSSL using stdin for the password (not a command-line argument)
- zsign compilation and execution in a Linux Docker image
- IPA ZIP path validation and safe extraction before processing
- App name, bundle identifier, marketing version, build number and minimum iOS options
- ProMotion and Game Mode Info.plist properties
- App icon conversion, extension/watch removal options and dylib injection
- Basic .deb support by extracting its .dylib payloads and passing those libraries to zsign
- Private Tigris signed IPA and manifest objects, short-lived download URLs and `itms-services` install links
- Background cleanup of signed results after the configured retention period (10 minutes by default)

## Architecture

A single Render Docker Web Service runs both the HTTP API and an asynchronous worker loop. The worker claims queued jobs from Render Postgres using `FOR UPDATE SKIP LOCKED`, so the signing process does not run in the HTTP request. Job records survive service restarts; a lease lets a later worker cycle reclaim jobs interrupted by a restart.

The service does not need a separate Redis/Key Value instance. The recommended Render Blueprint creates the API service and a small Postgres database. Direct IPA uploads are streamed to a short-lived local file on the same Render service instance and consumed by its colocated worker; signing outputs and oversized source IPAs are stored in Tigris.

## Requirements

- Render account with a paid service plan recommended for actual signing workloads
- A Render Postgres database (created by `render.yaml`)
- A Tigris bucket named `ipa-signer`, configured as **private**
- A Tigris access key with read/write/delete access to that bucket
- Your deployed Xsign Vercel site origin (for example `https://xsign.vercel.app`)
- Apple signing certificate (`.p12`/`.pfx`), certificate password when required, and compatible `.mobileprovision`

**Rotate the Tigris access key and secret previously pasted into chat before deploying.** Treat those old credentials as exposed. Enter only the new credentials in Render's environment settings. No real credentials are included in this ZIP.

## Deploy to Render (recommended: Blueprint)

1. Download and extract this ZIP.
2. Create a new, private GitHub repository, such as `xsign-render-api`.
3. Upload the **contents** of the extracted folder to the repository root. `render.yaml` and `Dockerfile` must be at the root.
4. Open [Render Blueprints](https://dashboard.render.com/blueprints) and choose **New Blueprint Instance**.
5. Connect the repository containing this project. Render detects `render.yaml`.
6. During Blueprint setup, provide:
   - `FRONTEND_ORIGIN`: your exact production website origin, including `https://`, without a trailing slash. Example: `https://xsign.vercel.app`.
   - `AWS_ACCESS_KEY_ID`: the newly rotated Tigris access key.
   - `AWS_SECRET_ACCESS_KEY`: the newly rotated Tigris secret.
7. Confirm the resources and deploy. Render builds the Docker image, compiles zsign, creates the API service and creates the `xsign-postgres` database. Render generates `APP_MASTER_KEY` automatically; do not change it after jobs have been created because it encrypts queued P12 passwords.
8. Wait for the service health check to return `ok`. The API address will look like `https://xsign-api.onrender.com`.

The Blueprint uses the `2c-8g` web-service compute plan (2 CPU / 8 GB RAM) to give IPA extraction, tweak preparation and signing more headroom. It is a paid plan. The Postgres queue database uses the smallest paid `0.1c-256mb` plan because it stores job metadata rather than IPA files. You can change either plan in Render, but lower-memory API plans may need smaller upload limits or may fail on large IPAs.

### Manual Web Service deployment (without Blueprint)

If you create a Web Service manually, select **Docker** as the runtime and point Render at this repository's `Dockerfile`. Create a Render Postgres database separately, use its **Internal Database URL** as `DATABASE_URL`, and add `APP_MASTER_KEY`, `FRONTEND_ORIGIN`, and the Tigris AWS SDK credentials as environment variables. The application cannot create these managed Render resources when deployed as a plain Web Service.

Set `DIRECT_IPA_UPLOAD_MAX_MB` to a conservative limit for the selected Render service plan. The shipped default is 100 MB. The frontend reads the live capability endpoint and chooses the direct route only up to this size; larger IPAs go straight to Tigris. A Render gateway/proxy HTTP 413 response or a low temporary-disk capacity response also triggers an automatic Tigris retry. Lower this setting on smaller plans or when the service has limited free disk space.

### Render environment variables

The Blueprint sets these non-secret values automatically:

```env
AWS_ENDPOINT_URL_S3=https://t3.storage.dev
AWS_ENDPOINT_URL_IAM=https://iam.storage.dev
AWS_REGION=auto
TIGRIS_BUCKET=ipa-signer
FILE_RETENTION_MINUTES=10
UPLOAD_URL_TTL_SECONDS=900
MAX_IPA_MB=500
DIRECT_IPA_UPLOAD_ENABLED=true
DIRECT_IPA_UPLOAD_MAX_MB=100
DIRECT_IPA_MIN_FREE_DISK_MB=256
DIRECT_IPA_UPLOAD_TTL_MINUTES=30
MAX_P12_MB=10
MAX_PROFILE_MB=5
MAX_ICON_MB=20
MAX_TWEAK_MB=100
MAX_TWEAK_FILES=8
MAX_TOTAL_JOB_MB=900
JOB_TIMEOUT_SECONDS=1200
WORKER_POLL_MS=1500
```

Do not add Tigris credentials to Vercel. Keep them on Render only. The AWS SDK variable names above are the recommended integration; `AWS_ENDPOINT_URL_IAM` is retained for consistency with the Tigris account configuration, while the S3 client itself uses the S3 endpoint.

Optional variables:

- `MAX_IPA_MB`: maximum uploaded or remote IPA size (default 500 MB)
- `DIRECT_IPA_UPLOAD_ENABLED`: enable streamed direct-to-Render IPA uploads (default true)
- `DIRECT_IPA_UPLOAD_MAX_MB`: largest IPA routed through Render's HTTP upload endpoint (default 100 MB). IPAs above this limit automatically use Tigris. Set this conservatively for the service's available disk, memory and compute plan. If Render's edge rejects an upload with HTTP 413, the browser automatically retries through Tigris.
- `DIRECT_IPA_MIN_FREE_DISK_MB`: free temporary disk space to preserve after a direct IPA upload (default 256 MB). The capability endpoint subtracts this reserve from available filesystem space, and the upload route checks again before writing.
- `DIRECT_IPA_UPLOAD_TTL_MINUTES`: lifetime of an unused local direct IPA upload (default 30 minutes)
- `MAX_TOTAL_JOB_MB`: combined size of uploaded inputs in one job (default 900 MB)
- `FILE_RETENTION_MINUTES`: result retention (default 10; minimum 5)
- `DOWNLOAD_URL_TTL_SECONDS`: signed GET URL life (defaults to the result retention window)
- `UPLOAD_URL_TTL_SECONDS`: signed PUT URL life (default 900 seconds)
- `FRONTEND_ORIGIN`: comma-separated exact origins if you use more than one production website origin

## Configure Tigris bucket CORS

The bucket must be private. Direct browser uploads require Tigris bucket CORS to allow `PUT` requests from your Xsign website origin.

1. Open `tigris-cors.json` and replace `https://your-xsign-domain.example` with the exact Vercel website origin.
2. Configure the AWS CLI with the **newly rotated** Tigris credentials in your local shell. Do not paste them into this file or commit them.
3. Run:

```bash
aws s3api put-bucket-cors \
  --endpoint-url https://t3.storage.dev \
  --region auto \
  --bucket ipa-signer \
  --cors-configuration file://tigris-cors.json
```

Check the CORS configuration:

```bash
aws s3api get-bucket-cors \
  --endpoint-url https://t3.storage.dev \
  --region auto \
  --bucket ipa-signer
```

If you later connect a custom Xsign domain, add that exact origin to both `tigris-cors.json` and Render's `FRONTEND_ORIGIN`, then redeploy/sync. Do not use `*` for allowed origins.

The S3 client uses the AWS SDK for JavaScript with `region: auto` and endpoint `https://t3.storage.dev`, matching Tigris's S3-compatible configuration. The bucket name is `ipa-signer`.

## Connect the Vercel frontend

In **Vercel → Project → Settings → Environment Variables**, set:

```env
NEXT_PUBLIC_API_BASE_URL=https://xsign-api.onrender.com
NEXT_PUBLIC_SITE_URL=https://your-actual-xsign-domain.example
```

Replace both example domains with your real addresses. `NEXT_PUBLIC_API_BASE_URL` is the Render API service URL; `NEXT_PUBLIC_SITE_URL` is the public website URL. Redeploy the Vercel project after changing environment variables.

## API contract

All endpoints are under the Render service origin.

### `GET /v1/capabilities`

The frontend reads these values before choosing the IPA upload route. The response contains `maxIpaBytes`, `directIpaUploadEnabled`, `directIpaUploadMaxBytes` and the configured large-file fallback. The threshold is controlled by `DIRECT_IPA_UPLOAD_MAX_MB` because Render does not expose an application's current compute plan as a reliable runtime upload-size value. The API also checks live temporary-filesystem capacity and preserves the `DIRECT_IPA_MIN_FREE_DISK_MB` reserve; when free space is low, it reports Tigris as the route.

### `POST /v1/uploads/ipa-direct`

The browser streams the raw `.ipa` body to Render using `Content-Type: application/octet-stream` and the `X-File-Name` and `X-File-Size` headers. The endpoint writes the stream to a mode-0600 temporary file without buffering the entire IPA in memory, then returns `{ "uploadId": "uuid", "uploadMode": "render" }`. The signing job references the upload using `inputs.ipaDirectUploadId`.

If the file exceeds the configured direct-upload threshold or Render's HTTP ingress returns 413, the frontend retries the original file through the existing presigned Tigris route instead. Direct-upload files expire after `DIRECT_IPA_UPLOAD_TTL_MINUTES` if a signing job is never created. Because these are short-lived files on the service's local filesystem, a Render restart before the job begins may require the user to re-upload the IPA.

### `POST /v1/uploads/presign`

Request:

```json
{
  "fileName": "application.ipa",
  "contentType": "application/octet-stream",
  "size": 123456,
  "purpose": "ipa"
}
```

Supported `purpose` values: `ipa`, `p12`, `mobileprovision`, `app-icon`, `tweak`.

Response:

```json
{
  "uploadUrl": "https://...short-lived-presigned-put-url...",
  "objectKey": "incoming/ipa/uuid.ipa",
  "headers": { "Content-Type": "application/octet-stream" }
}
```

The browser sends the file directly to the returned Tigris URL using `PUT` and the returned headers. The API never receives the large file body. Upload URLs expire after 15 minutes by default; abandoned uploads are removed by the worker after their one-hour upload record expires.

### `POST /v1/signing/jobs`

The payload matches the current Vercel `components/signing-form.js`:

```json
{
  "inputs": {
    "ipaObjectKey": null,
    "ipaDirectUploadId": "uuid-from-direct-upload",
    "ipaUrl": null,
    "p12ObjectKey": "incoming/p12/uuid.p12",
    "mobileprovisionObjectKey": "incoming/mobileprovision/uuid.mobileprovision",
    "iconObjectKey": null,
    "tweakObjectKeys": []
  },
  "p12Password": "certificate-password-or-empty-string",
  "options": {
    "appName": null,
    "bundleId": null,
    "appVersion": null,
    "buildNumber": null,
    "minimumIOS": null,
    "proMotion": false,
    "gameMode": false,
    "removeExtensions": false,
    "removeWatchApp": false
  }
}
```

Provide exactly one of `ipaObjectKey` (Tigris), `ipaDirectUploadId` (streamed local Render upload), or `ipaUrl`, never more than one. The uploaded IPA, P12 and mobileprovision are required; icon and tweaks are optional. The API checks that each unguessable upload reference was issued for the correct file purpose, has not expired or already been claimed, and has the expected uploaded size. Upload references are single-use. Client IP hashes are retained for abuse auditing, but uploads are not IP-bound because mobile network IPs can change between upload and job submission.

Response:

```json
{ "jobId": "uuid", "stage": "Queued for signing" }
```

The P12 password is encrypted with AES-256-GCM using `APP_MASTER_KEY` before it is stored in Postgres. The worker decrypts it only while extracting the certificate key, sends it to OpenSSL over stdin (not in the process command line), clears the password buffer as soon as possible and erases the encrypted database fields after processing. Request bodies and passwords are not logged.

### `GET /v1/signing/jobs/:jobId`

While processing:

```json
{
  "jobId": "uuid",
  "status": "running",
  "progress": 48,
  "stage": "Signing application"
}
```

On success:

```json
{
  "jobId": "uuid",
  "status": "completed",
  "progress": 100,
  "stage": "Signing completed",
  "result": {
    "installUrl": "itms-services://?action=download-manifest&url=...",
    "downloadUrl": "https://...short-lived-signed-ipa-url...",
    "manifestUrl": "https://...short-lived-manifest-url..."
  }
}
```

On failure or expiration:

```json
{
  "jobId": "uuid",
  "status": "failed",
  "error": "A safe explanation of what needs to be checked"
}
```

Job IDs are random UUIDs and act as bearer references for polling. Anyone who obtains a job ID can view that job's status and, while it is valid, its short-lived result links. Keep job IDs private.

## Signing behavior and limitations

- **App name:** updates `CFBundleDisplayName` and `CFBundleName` and passes the requested display name through zsign.
- **Bundle ID:** updates the app's bundle identifier and passes the new value to zsign. The provisioning profile must authorize the requested identifier; changing the text alone cannot create Apple entitlements.
- **App version:** updates `CFBundleShortVersionString`.
- **Build number:** updates `CFBundleVersion`.
- **Minimum iOS:** updates `MinimumOSVersion` using zsign's `-M` option.
- **ProMotion:** sets `CADisableMinimumFrameDurationOnPhone` to `true`. This does not force an app or game to render at 120 FPS.
- **Game Mode:** sets `LSSupportsGameMode` to `true`. It declares support; iOS decides whether Game Mode applies.
- **App icon:** PNG/JPG is converted to PNG before it is passed to zsign.
- **Dylib:** passed to zsign for load-command injection.
- **DEB:** extracted without running package maintainer scripts. The backend finds `.dylib` files in the package and passes them to zsign. This first version does not install Debian dependencies, run maintainer scripts, or apply Substrate filter plist semantics; not every tweak package will work as a result.
- **Extensions:** the `Remove app extensions` and `Remove bundled Watch app` switches map to zsign's `-E` and `-W`. If extensions are retained, the supplied provisioning profile must be compatible with the extension bundle identifiers and signing requirements.
- **OTA:** the backend creates a manifest with temporary HTTPS download URLs and returns an `itms-services` installation link. OTA still requires a valid Apple signature, compatible provisioning profile/device eligibility and iOS installation support. It does not bypass Apple's signing rules.

Only upload applications and tweak files you own or are authorized to modify and distribute.

## File retention and cleanup

- Original IPA, P12, mobileprovision, icon and tweak uploads are deleted after a job completes or fails, where Tigris is reachable.
- Local work directories, extracted files, private-key PEM files and app data are removed when processing finishes.
- Successful signed IPAs and manifests are stored under `results/<job-id>/` and are deleted by the worker after `FILE_RETENTION_MINUTES` (10 minutes by default). Cleanup runs roughly once per minute, so deletion is performed at the first cleanup pass after the deadline rather than at a guaranteed exact second.
- Presigned download URLs expire at the configured URL TTL, which defaults to the same 10-minute window.
- Unclaimed uploads expire after one hour and are cleaned up by the worker.

If the Render service is stopped or Tigris is temporarily unavailable, cleanup cannot run until the worker is running and storage is reachable again. Do not describe this as a strict legal erasure guarantee without considering provider backups and retention.

## Local development

1. Install Node.js 22+, Python 3, OpenSSL, `dpkg-deb`, `zsign`, and an accessible Tigris S3-compatible bucket.
2. Copy `.env.example` to `.env`, then set the environment values in your shell or local secret manager. Never commit `.env`.
3. Install Node dependencies:

```bash
npm install
```

4. Start the API and worker:

```bash
npm start
```

5. Check `http://localhost:10000/healthz`.

For a local test, `FRONTEND_ORIGIN` must include your frontend origin, for example `http://localhost:3000`.

## Troubleshooting

- **Browser upload fails / CORS:** verify the exact Vercel origin is in `tigris-cors.json`, that bucket CORS was applied, and that the browser sends the returned `Content-Type` header unchanged.
- **403 from Tigris:** check the new access key, secret, bucket name, `AWS_ENDPOINT_URL_S3`, and `AWS_REGION=auto`; keep the bucket private.
- **P12 cannot be opened:** confirm the password, `.p12`/`.pfx` file and presence of a private key/certificate pair.
- **Signing fails:** check P12/profile compatibility, bundle identifier authorization, device eligibility and app-extension profiles.
- **Large IPA fails:** raise `MAX_IPA_MB` and `MAX_TOTAL_JOB_MB` only if the Render service has enough RAM/disk. The recommended service plan is `2c-8g` (2 CPU / 8 GB RAM).
- **Game Mode / ProMotion has no visible effect:** the options add Info.plist support declarations; they cannot force iOS to enable a system feature or force a frame-rate target.
- **OTA link expires:** signed output is retained for 10 minutes by default. Sign again to create a fresh result.

## Reference documentation

- [zsign source and command-line options](https://github.com/zhlynn/zsign)
- [Tigris S3-compatible object storage](https://www.tigrisdata.com/)
- [Render Blueprints](https://render.com/docs/infrastructure-as-code)
- [Render Blueprint specification](https://render.com/docs/blueprint-spec)
- [Render environment variables and secrets](https://render.com/docs/configure-environment-variables)
- [Render persistent disks](https://render.com/docs/disks)
