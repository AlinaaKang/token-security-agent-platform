# Lab PCAP Upload Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the lab/challenge header switch with Prompt/PCAP experiment modes and add an explicitly authorized, Docker-isolated, single-PCAP upload detection workflow.

**Architecture:** A new `PcapUploadService` streams a raw browser file into a private quarantine directory after consuming an upload-specific authorization, validates only bounded header bytes on the host, and returns a one-use private handle. The existing detection coordinator and executor gain path-specific entry points so the same Docker detector produces the existing public mission contract. The frontend adds `LabPcapWorkspace` and extracts the existing terminal detector presentation into a shared renderer used by both Lab and SuperAgent.

**Tech Stack:** Python 3.11, FastAPI, Pydantic 2, pytest, React 19, TypeScript 5.8, XMLHttpRequest, Vitest, Testing Library, Vite, PowerShell/Docker detector.

## Global Constraints

- `/lab` defaults to `Prompt 攻防`; switching tabs must preserve the current Prompt form and result state.
- `/challenge` remains independent and has no local `专业调查 / 侦探挑战` switch.
- File selection, tab selection, refresh, guided-tour progression, and the first preparation click never upload or start detection.
- Only the final `确认上传并检测` action may authorize, stream, and start a mission.
- Upload bytes use the local `/pcap-api` target only and never reach AutoDL.
- Do not transmit or persist the original filename, client path, IP, port, payload, hash, Prompt, Token text, stdout, or stderr.
- Accept only classic PCAP or PCAPNG identified by magic bytes, with a default maximum size of 536870912 bytes.
- Full capture inspection remains inside the existing no-network Docker path.
- Uploaded files are deleted after completion, degradation, cancellation, scheduling failure, or shutdown.
- Existing Prompt Lab and directory-based SuperAgent PCAP behavior must not change.

---

### Task 1: Upload-specific authorization contract

**Files:**
- Modify: `backend/app/pcap/authorization.py`
- Modify: `tests/unit/test_pcap_authorization.py`
- Modify: `backend/app/pcap/config.py`
- Modify: `tests/unit/test_pcap_config.py`

**Interfaces:**
- Produces: authorization purpose literal `upload_detection`, `expected_byte_count: int | None` on private authorization records, and `PcapConfig.upload_max_bytes` defaulting to `536870912`.
- Consumes later: API and upload service call `issue(1, purpose="upload_detection", expected_byte_count=N)` and `consume(..., purpose="upload_detection", expected_byte_count=N)`.

- [ ] **Step 1: Write failing authorization and configuration tests**

Assert upload authorizations require `max_files == 1`, require a positive strict integer byte count no greater than `upload_max_bytes`, reject purpose mismatch and byte-count mismatch, and remain one-use. Assert the environment override `TOKEN_SECURITY_PCAP_UPLOAD_MAX_BYTES` accepts `1..2147483648` and rejects missing-number, zero, boolean-like, or larger values while the default is exactly `536870912`.

- [ ] **Step 2: Verify RED**

Run: `pytest -q tests/unit/test_pcap_authorization.py tests/unit/test_pcap_config.py`

Expected: FAIL because `upload_detection`, expected byte binding, and config limit do not exist.

- [ ] **Step 3: Implement the minimal contracts**

Extend all authorization purpose annotations and validation with `upload_detection`; keep `triage`, `reconnaissance`, and `detection` behavior byte-for-byte compatible. Add optional expected-byte matching only for upload authorizations. Parse the upload limit in `PcapConfig.from_environ` with fixed validation and no new dependency.

- [ ] **Step 4: Verify GREEN and commit**

Run: `pytest -q tests/unit/test_pcap_authorization.py tests/unit/test_pcap_config.py`

```bash
git add backend/app/pcap/authorization.py backend/app/pcap/config.py tests/unit/test_pcap_authorization.py tests/unit/test_pcap_config.py
git commit -m "feat: bind PCAP upload authorizations"
```

### Task 2: Safe streaming upload store

**Files:**
- Create: `backend/app/pcap/upload.py`
- Create: `tests/unit/test_pcap_upload.py`

**Interfaces:**
- Produces: `PcapUploadHandle(handle_id: str, capture_path: Path, byte_count: int, capture_format: Literal["pcap", "pcapng"])` and `PcapUploadService.accept(chunks: AsyncIterable[bytes], *, authorization_id: str, content_length: int) -> PcapUploadHandle`.
- Produces: `claim(handle_id) -> PcapUploadHandle`, `discard(handle_id) -> None`, `close() -> None`, and fixed exceptions `PcapUploadInvalid`, `PcapUploadTooLarge`, `PcapUploadUnsupported`, `PcapUploadUnavailable`.

- [ ] **Step 1: Write failing upload service tests**

Use synthetic byte chunks for all four classic PCAP magic values (`a1b2c3d4`, `d4c3b2a1`, `a1b23c4d`, `4d3cb2a1`) and PCAPNG (`0a0d0d0a`). Assert streamed exclusive storage under `<quarantine>/uploads`, random internal names, no source filename parameter, content-length equality, byte limit enforcement during streaming, rejection of empty/truncated/unsupported data, one-use claim, capacity 32, five-minute expiry, reparse/symlink rejection, partial-file cleanup, and close cleanup.

- [ ] **Step 2: Verify RED**

Run: `pytest -q tests/unit/test_pcap_upload.py`

Expected: FAIL because `app.pcap.upload` does not exist.

- [ ] **Step 3: Implement the bounded upload service**

Validate root metadata before creating `uploads`; create `.part` files with exclusive mode, stream while counting bytes and retain at most the first 32 header bytes for format validation, flush and atomically rename to `upload_<random>.pcap|pcapng`, and store handles only in memory. Cleanup catches cancellation and all validation/storage exceptions without traversing outside the owned upload directory.

- [ ] **Step 4: Verify GREEN and commit**

Run: `pytest -q tests/unit/test_pcap_upload.py`

```bash
git add backend/app/pcap/upload.py tests/unit/test_pcap_upload.py
git commit -m "feat: quarantine authorized PCAP uploads"
```

### Task 3: Run exactly one uploaded capture through the existing detector

**Files:**
- Modify: `backend/app/pcap/detection_executor.py`
- Modify: `tests/unit/test_pcap_detection_executor.py`
- Modify: `backend/app/superagent/pcap_detection_coordinator.py`
- Modify: `tests/unit/test_superagent_pcap_detection_coordinator.py`

**Interfaces:**
- Produces: `PcapDetectionExecutor.execute_capture(detection_id, capture_path, on_progress=None) -> PcapDetectionSummary`.
- Produces: `PcapDetectionMissionCoordinator.start_uploaded(handle: PcapUploadHandle) -> PcapDetectionMissionResult`.
- Consumes: `PcapUploadService.claim()` happens before scheduling; `discard()` happens in every terminal/failure path.

- [ ] **Step 1: Write failing executor and coordinator tests**

Assert `execute_capture` accepts only a regular non-reparse file inside the upload service's owned root, invokes the existing `_command()` exactly once, produces sample index 1, and never calls `_capture_paths`. Assert `start_uploaded` returns the normal public detection mission, reports progress, rejects concurrent missions, and deletes the handle/file on success, degradation, cancellation, pool submission failure, and close.

- [ ] **Step 2: Verify RED**

Run: `pytest -q tests/unit/test_pcap_detection_executor.py tests/unit/test_superagent_pcap_detection_coordinator.py`

Expected: FAIL because path-specific execution and uploaded mission coordination do not exist.

- [ ] **Step 3: Implement path-specific execution and lifecycle cleanup**

Refactor only the shared one-file inspection/result aggregation needed by both `execute()` and `execute_capture()`. Pass an opaque handle into the coordinator, never serialize it into a mission snapshot, and place cleanup in `finally` plus explicit pre-scheduling failure handling.

- [ ] **Step 4: Verify GREEN and commit**

Run: `pytest -q tests/unit/test_pcap_detection_executor.py tests/unit/test_superagent_pcap_detection_coordinator.py`

```bash
git add backend/app/pcap/detection_executor.py backend/app/superagent/pcap_detection_coordinator.py tests/unit/test_pcap_detection_executor.py tests/unit/test_superagent_pcap_detection_coordinator.py
git commit -m "feat: detect one uploaded PCAP in isolation"
```

### Task 4: Upload capability, authorization, and streaming API

**Files:**
- Modify: `backend/app/api/superagent.py`
- Modify: `backend/app/main.py`
- Modify: `tests/integration/test_superagent_pcap_detection_api.py`
- Modify: `tests/unit/test_verify_pcap_agent_privacy.py`

**Interfaces:**
- Produces: `GET /api/v1/superagent/pcap/detection/upload-capability`.
- Produces: `POST /api/v1/superagent/pcap/detection/upload-authorizations` with `{confirmed: true, byte_count: int}`.
- Produces: raw streaming `POST /api/v1/superagent/pcap/detection/uploads` requiring `X-PCAP-Authorization` and exact `Content-Length`, returning the existing `PcapDetectionMissionResult` with status 201.

- [ ] **Step 1: Write failing integration and privacy tests**

Test disabled capability, valid synthetic PCAP and PCAPNG, absent/replayed/expired/mismatched authorization, absent/invalid content length, 400/403/409/410/413/415/500/503 fixed errors, and a successful mission response with no forbidden public key or private sentinel. Assert the application constructs and closes the upload service only when PCAP detection is ready.

- [ ] **Step 2: Verify RED**

Run: `pytest -q tests/integration/test_superagent_pcap_detection_api.py tests/unit/test_verify_pcap_agent_privacy.py`

Expected: FAIL because upload routes and application state are absent.

- [ ] **Step 3: Implement async route wiring**

Add strict Pydantic request/response models, consume `request.stream()` directly, never call `request.body()`, and map typed upload/authorization exceptions to the fixed public errors. Wire one upload service into application lifespan, detection coordinator, and cleanup state without affecting Prompt startup when PCAP configuration is absent.

- [ ] **Step 4: Verify GREEN and commit**

Run: `pytest -q tests/integration/test_superagent_pcap_detection_api.py tests/unit/test_verify_pcap_agent_privacy.py`

```bash
git add backend/app/api/superagent.py backend/app/main.py tests/integration/test_superagent_pcap_detection_api.py tests/unit/test_verify_pcap_agent_privacy.py
git commit -m "feat: expose authorized PCAP upload detection"
```

### Task 5: Shared public detector result renderer

**Files:**
- Create: `frontend/src/components/PcapDetectionResult.tsx`
- Create: `frontend/src/components/PcapDetectionResult.test.tsx`
- Modify: `frontend/src/pages/PcapDetectionWorkspace.tsx`
- Modify: `frontend/src/pages/PcapDetectionWorkspace.test.tsx`

**Interfaces:**
- Produces: `PcapDetectionResult({ mission, sampleLabel, onCancel, busy })` using existing `PcapDetectionMissionResult`.
- Preserves: directory detection controls, polling, storage key, scrolling behavior, conclusion wording, timeline, and mascots.

- [ ] **Step 1: Write failing shared renderer tests**

Assert explicit abnormal, no-hit, and incomplete conclusions; success/failure/evidence colors and labels; custom single-sample label; localized evidence/purpose/timeline; cancellation; and absence of protected raw fields.

- [ ] **Step 2: Verify RED**

Run: `npm.cmd test -- src/components/PcapDetectionResult.test.tsx src/pages/PcapDetectionWorkspace.test.tsx`

Expected: FAIL because the shared renderer does not exist.

- [ ] **Step 3: Extract presentation without changing directory workflow**

Move only terminal/status rendering and its label maps from `PcapDetectionWorkspace`; keep overview, authorization, mission creation, polling, storage, and batch controls in the page component. Use `sampleLabel(index)` so SuperAgent retains numbered samples and Lab can show `上传样本`.

- [ ] **Step 4: Verify GREEN and commit**

Run: `npm.cmd test -- src/components/PcapDetectionResult.test.tsx src/pages/PcapDetectionWorkspace.test.tsx`

```bash
git add frontend/src/components/PcapDetectionResult.tsx frontend/src/components/PcapDetectionResult.test.tsx frontend/src/pages/PcapDetectionWorkspace.tsx frontend/src/pages/PcapDetectionWorkspace.test.tsx
git commit -m "refactor: share PCAP detection results"
```

### Task 6: Prompt/PCAP lab tabs and upload workflow

**Files:**
- Create: `frontend/src/pages/LabPcapWorkspace.tsx`
- Create: `frontend/src/pages/LabPcapWorkspace.test.tsx`
- Modify: `frontend/src/types.ts`
- Modify: `frontend/src/api.ts`
- Modify: `frontend/src/api.test.ts`
- Modify: `frontend/src/pages/LabPage.tsx`
- Modify: `frontend/src/LabPage.test.tsx`
- Modify: `frontend/src/pages/ChallengePage.tsx`
- Modify: `frontend/src/ChallengePage.test.tsx`
- Delete: `frontend/src/components/LabModeSwitch.tsx`
- Modify: `frontend/src/tourConfig.ts`
- Modify: `frontend/src/tourConfig.test.ts`
- Modify: `frontend/src/styles.css`

**Interfaces:**
- Produces: `api.pcapUploadCapability()`, `api.authorizePcapUpload(byteCount)`, and `api.uploadPcapForDetection(file, authorizationId, onProgress)`.
- Produces: `LabPcapWorkspace` with local phases `empty | selected | confirming | uploading | running | terminal | error`.

- [ ] **Step 1: Write failing API, workflow, and navigation tests**

Assert the Lab defaults to Prompt with no PCAP call, the two tabs are `Prompt 攻防 / PCAP 攻防`, Prompt form/result state survives tab round trips, Challenge has no local Lab switch, and file selection sends nothing. Assert preparation sends nothing; final confirmation calls capability/authorization then an XHR whose raw body is the exact `File`, whose URL is `/pcap-api`, whose headers omit filename, and whose success starts polling. Cover upload progress, cancellation, recoverable retry, invalid-format clearing, explicit result conclusions, and selecting a new file after terminal state.

- [ ] **Step 2: Verify RED**

Run: `npm.cmd test -- src/api.test.ts src/pages/LabPcapWorkspace.test.tsx src/LabPage.test.tsx src/ChallengePage.test.tsx src/tourConfig.test.ts`

Expected: FAIL because the new tab, API methods, upload workspace, and revised tour are absent.

- [ ] **Step 3: Implement typed API and lab workflow**

Add public capability and authorization types. Implement XHR upload in a Promise with JSON response parsing and the same fixed `Error & {status?: number; code?: string}` shape used by JSON requests. Build an accessible file input/drop surface, local filename/size preview, two-step confirmation, progress bar, polling/cancel behavior, and shared result rendering. Never put the filename into the request.

- [ ] **Step 4: Replace the incorrect local navigation and update the tour**

Remove `LabModeSwitch` from Lab and Challenge. Add an icon-based segmented control inside Lab only, preserve both tab subtrees' state by keeping Prompt state in `LabPage`, and revise the four Lab tour targets so active Prompt or PCAP controls are discoverable without triggering work.

- [ ] **Step 5: Verify GREEN and commit**

Run: `npm.cmd test -- src/api.test.ts src/pages/LabPcapWorkspace.test.tsx src/LabPage.test.tsx src/ChallengePage.test.tsx src/tourConfig.test.ts`

```bash
git add frontend/src frontend/src/styles.css
git commit -m "feat: add PCAP upload experiments to the lab"
```

### Task 7: Complete verification and documentation

**Files:**
- Modify: `docs/security-lab.md`
- Modify: `docs/competition-delivery-guide.md`

**Interfaces:**
- Documents: exact user flow, local-backend prerequisite, size/format limits, result meanings, cleanup behavior, and Prompt/PCAP/challenge separation.

- [ ] **Step 1: Update operator and competition documentation**

Document that `发现异常证据` is a rule-backed candidate rather than proof of compromise; `当前范围未命中` is not “all safe”; `检测未完整完成` requires retry. Include the two confirmation clicks and explain that AutoDL is unrelated to PCAP upload availability.

- [ ] **Step 2: Run complete backend and frontend verification**

Run: `pytest -q`

Run: `npm.cmd test`

Run: `npm.cmd run build`

Expected: all suites PASS with no tracked PCAP, upload, report, state, or temporary artifacts.

- [ ] **Step 3: Verify live desktop and mobile workflows**

Use synthetic PCAP only. At 1440x900 and 390x844 verify Prompt default, state-preserving tab switch, two-click upload confirmation, progress, running/terminal output, keyboard focus, no horizontal overflow, no duplicate challenge switch, and no browser console error. Verify `/super-agent` directory PCAP modes and `/challenge` remain usable.

- [ ] **Step 4: Commit documentation**

```bash
git add docs/security-lab.md docs/competition-delivery-guide.md
git commit -m "docs: explain lab PCAP upload experiments"
```

