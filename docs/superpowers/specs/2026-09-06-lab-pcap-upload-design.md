# Lab PCAP Upload Design

## Objective

Correct the AI security lab's information architecture and add a real single-file PCAP experiment. The lab switches between `Prompt 攻防` and `PCAP 攻防`; `Token 侦探挑战` remains an independent global destination. A confirmed PCAP upload is validated outside the repository, inspected only through the existing Docker-isolated detector, and rendered with the same public Packet evidence used by SuperAgent.

## Information Architecture

- Replace the current `专业调查 / 侦探挑战` header switch on `/lab` with `Prompt 攻防 / PCAP 攻防`.
- Remove the same switch from `/challenge`; the challenge remains reachable from the global `互动演示` navigation group.
- Preserve the current Prompt lab as the default tab and do not change its form, API requests, evidence order, tools, or persistence.
- Keep directory-based PCAP triage, reconnaissance, and detection under `/super-agent` unchanged.
- The lab PCAP tab handles exactly one browser-selected file per experiment.

## User Flow

1. The user opens `攻防实验舱` and selects `PCAP 攻防`.
2. The browser shows an upload surface accepting `.pcap` and `.pcapng` files. Selecting a file reads no file content into application state and starts no request.
3. The page shows only local preflight metadata: original name, byte size, and detected extension. The original name is never transmitted.
4. The user clicks `准备检测`; a confirmation panel explains that the file will be copied into a server-side quarantine area and read in a no-network Docker container.
5. The user clicks `确认上传并检测`. Only this final action issues a one-time upload authorization, streams the file to the local PCAP backend, and starts the bounded single-file detection mission.
6. The page displays upload progress when the browser exposes it, then mission status, current stage, terminal conclusion, Packet/Request intervals, attack-family candidates, purpose candidates, confidence, supporting signals, failures, and limitations.
7. The user can cancel an active detection or choose another file after terminal cleanup.

The final confirmation is one explicit authorization for the combined upload-and-detect operation. No upload, Docker execution, or mission creation occurs from tab selection, file selection, refresh, tour progression, or the first preparation click.

## Frontend Architecture

Create a focused `LabPcapWorkspace` component owned by `LabPage`. `LabPage` owns only the `prompt | pcap` tab state and continues to own the existing Prompt lab state unchanged.

Extract the terminal evidence presentation from `PcapDetectionWorkspace` into a reusable `PcapDetectionResult` component. Both directory detection and the lab upload use this renderer, including:

- the explicit terminal conclusion (`发现异常证据`, `当前范围未命中`, or `检测未完整完成`);
- succeeded/failed/evidence counts;
- the scrolling processed-file indicator;
- localized evidence cards;
- Packet timeline;
- detector mascots and public trace events.

The lab labels the only processed item as `上传样本`; it does not expose the server-side capture identity. Existing SuperAgent labels and directory batch controls remain unchanged.

The upload uses `XMLHttpRequest` only for the binary upload request so real upload progress can be shown. All JSON authorization, polling, and cancellation requests continue through the existing typed API module. The request body is the browser `File` itself with `Content-Type: application/octet-stream`; no multipart filename or path is sent.

## Backend Architecture

Add a `PcapUploadService` under `backend/app/pcap` with one responsibility: accept a confirmed authorized byte stream and produce a private, one-use capture handle.

The service:

- stores uploads under `<quarantine_root>/uploads`, never under the repository;
- creates the directory only after validating every existing parent is a real directory and not a symlink or Windows reparse point;
- uses a random internal name and an exclusive temporary file;
- enforces a configurable byte limit while streaming, defaulting to 512 MiB;
- rejects empty, truncated, oversized, symlinked, or unsupported captures;
- identifies classic PCAP and PCAPNG from magic bytes rather than filename or MIME type;
- flushes and atomically renames a valid temporary file before returning a handle;
- never returns a filesystem path or original filename through the API;
- expires unused handles after five minutes and caps the in-memory store at 32 entries;
- deletes partial files on every rejected or interrupted upload.

Extend the PCAP authorization purpose with `upload_detection`. Add an authorization endpoint that always issues `max_files=1` only after receiving `{ "confirmed": true, "byte_count": <integer> }`, with `byte_count` bounded by the configured upload limit. The upload endpoint requires this authorization ID in `X-PCAP-Authorization`, checks that `Content-Length` matches the authorized size, consumes the authorization exactly once, accepts the raw body, and immediately hands the private capture handle to the detection coordinator.

The detection coordinator adds a private `start_uploaded` entry point. It accepts only a handle created by `PcapUploadService`, creates the normal public `detection_<hex>` mission, and schedules the existing detector against exactly that path. The executor gains a path-specific method but continues to build the same reviewed PowerShell command and Docker `HttpDetection` mode. It must not discover other files when executing an upload mission.

The coordinator deletes the uploaded file and retires its handle after completion, degradation, cancellation, scheduling failure, or shutdown. On application startup and subsequent uploads, the upload service removes expired orphaned temporary/upload files from its own uploads directory only.

## API Contract

### Capability

`GET /api/v1/superagent/pcap/detection/upload-capability`

Returns public fields only:

```json
{
  "enabled": true,
  "max_bytes": 536870912,
  "accepted_formats": ["pcap", "pcapng"]
}
```

### Authorization

`POST /api/v1/superagent/pcap/detection/upload-authorizations`

```json
{
  "confirmed": true,
  "byte_count": 1048576
}
```

Returns an existing-format `pcap_auth_<hex>` receipt with `max_files=1`. It does not upload or start detection.

### Upload And Start

`POST /api/v1/superagent/pcap/detection/uploads`

Headers:

- `Content-Type: application/octet-stream`
- `Content-Length: <authorized byte count>`
- `X-PCAP-Authorization: pcap_auth_<hex>`

Body: raw PCAP bytes.

Returns `201` with the existing `PcapDetectionMissionResult`. The response contains no upload ID, filename, path, hash, payload, address, or port.

Polling and cancellation reuse the existing PCAP-local routes:

- `GET /api/v1/superagent/missions/{detection_id}`
- `POST /api/v1/superagent/missions/{detection_id}/cancel`

## Validation And Errors

The backend returns fixed public errors without echoing request data:

- `400 pcap_upload_invalid`: empty body, size mismatch, invalid or truncated magic/header;
- `403 pcap_authorization_required`: missing or unknown authorization;
- `409 pcap_authorization_used`: replayed authorization;
- `410 pcap_authorization_expired`: expired authorization;
- `413 pcap_upload_too_large`: configured byte limit exceeded;
- `415 pcap_format_unsupported`: magic bytes are not classic PCAP or PCAPNG;
- `503 pcap_upload_unavailable`: local PCAP service or Docker detector unavailable;
- `500 pcap_upload_failed`: fixed fallback for storage or scheduling failure.

The frontend maps these codes to short Chinese recovery messages. It preserves the selected local file after a recoverable authorization/network failure so the user can retry, but clears the file after a successful upload or an invalid-format response. A terminal detector failure is not labeled as “safe”.

## Privacy And Security

- Browser-selected bytes go only to the local `/pcap-api` backend, never to AutoDL or the Prompt API target.
- The original filename is local-only UI state and is never included in request URLs, headers, JSON, logs, mission storage, or public evidence.
- Uploaded content is never parsed by the browser or host Python process; host validation reads only bounded header bytes, while full inspection happens through the existing no-network, read-only Docker path.
- Public contracts retain the current forbidden-key enforcement and cannot contain payload, IP, port, path, filename, hash, Prompt, Token text, raw stdout, or stderr.
- The uploaded file is mounted read-only into Docker, and the container has no network, dropped capabilities, a read-only root filesystem, and bounded CPU, memory, process, and timeout settings inherited from `inspect_pcap.ps1`.
- The feature never scans the user's filesystem or existing quarantine corpus; it processes only the explicitly selected uploaded file.

## Guided Tour

Update the `/lab` tour without increasing its four-step length:

1. Highlight `Prompt 攻防 / PCAP 攻防` and explain the two experiment inputs.
2. Highlight the active tab's scenario/input or upload surface.
3. Highlight the active tab's mode/boundary explanation.
4. Highlight the manual start/authorization command.

Switching tabs is a local action and may advance the tour. No tour action selects a file, uploads bytes, issues authorization, or starts detection.

## Testing And Verification

- Unit-test upload authorization binding, size limits, magic validation for all classic PCAP byte orders and PCAPNG, exclusive random storage, reparse/symlink rejection, cleanup, expiry, replay rejection, and public error redaction.
- Verify the uploaded mission calls the existing detector with exactly one private path and never runs directory discovery.
- Verify cleanup on success, invalid upload, detector degradation, cancellation, scheduling failure, and application shutdown.
- API tests stream synthetic minimal PCAP/PCAPNG fixtures only; tests never read the user's real corpus.
- Frontend tests cover tab separation, no request before final confirmation, raw-body upload without filename, progress, polling, cancellation, retry, explicit conclusions, shared evidence rendering, and Prompt-state preservation across tab switches.
- Existing Prompt lab, SuperAgent PCAP directory workflows, challenge, mascots, navigation, and guided-tour tests must remain green.
- Production build and backend full suite must pass.
- Browser verification at 1440x900 and 390x844 must confirm keyboard operation, no horizontal overflow, visible progress, unambiguous failure/safety wording, and no duplicate challenge switch.

