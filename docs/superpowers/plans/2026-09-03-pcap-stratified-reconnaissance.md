# PCAP Stratified Reconnaissance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an explicitly authorized, Docker-isolated 20-file size-stratified reconnaissance objective that characterizes the real PCAP corpus without exposing capture identity or changing Prompt behavior, then stop for a data-driven detector plan.

**Architecture:** Reuse the reviewed single-file `inspect_pcap.ps1` path so every selected capture is fully traversed inside an isolated no-network container. Add a separate stratified batch script, strict aggregate contracts, a dedicated coordinator/API branch, and a PCAP-only reconnaissance view; do not add Suricata, attack classification, Packet anomaly localization, or CPD in this phase.

**Tech Stack:** Python 3.11, FastAPI 0.116, Pydantic 2.11, Windows PowerShell 5.1, Docker Desktop, Tshark, React 19, TypeScript 5.8, Vitest 3, pytest 8.

## Global Constraints

- Existing Prompt analysis, semantic guard, Entropy-CPD, Token heatmap, Prompt SuperAgent, events, evaluation, Lab, challenge state, challenge mascots, API defaults, storage keys, and frozen metrics must retain their current behavior.
- Do not modify `frontend/src/pages/ChallengePage.tsx`, `frontend/src/components/MascotTeam.tsx`, challenge state, scoring, flags, Token tooltip behavior, or challenge tests except to run them unchanged.
- Real PCAP content may be read only after a fresh user confirmation creates and consumes a one-time reconnaissance authorization through the UI.
- Reconnaissance selects at most 20 captures: partition the size-ordered corpus into four index quartiles and choose at most five deterministic midpoint samples from each quartile.
- Process one file and one container at a time. Preserve `--network none`, `--read-only`, `--cap-drop ALL`, `no-new-privileges`, non-root execution, resource limits, and a single read-only capture mount.
- The Agent/API/UI/export boundary must never receive filenames, paths, IPs, ports, MACs, payloads, HTTP content, Prompts, suffixes, Token text, stable capture hashes, raw stderr, or hidden chain of thought.
- Filenames are private selection metadata only. They must not become features, labels, Agent evidence, public output, logs, screenshots, tests, or reports.
- This phase does not detect attacks. It reports corpus structure and method suitability only; it must not claim jailbreak, network attack, anomalous Packet, Entropy-CPD, or abnormal Token.
- The real reconnaissance run is a terminal human gate. Do not invoke a batch script directly against the 2318 real captures as a substitute for UI authorization.
- PCAP files, child reports, private sample mappings, checkpoint state, cancellation markers, and raw tool output remain outside Git.
- Every implementation task follows TDD: add a focused failing test, observe the expected failure, implement the minimum behavior, run focused and relevant regression tests, and commit.

## Phase Boundary

This plan ends after the user-authorized aggregate reconnaissance report is produced and interpreted. A second design/plan will use the observed packet-count, duration, protocol, plaintext, and sequence-suitability distributions to select Suricata rules, Request localization, behavior features, and optional CPD. No detector threshold is chosen in this plan.

## File Structure

### New backend units

- `backend/app/pcap/recon_models.py`: closed public reconnaissance enums, histograms, summary, mission, and privacy validation.
- `backend/app/pcap/recon_executor.py`: fixed-argument adapter for the stratified PowerShell script and handle-relative public-summary loading.
- `backend/app/superagent/pcap_recon_coordinator.py`: one-active reconnaissance mission lifecycle, cancellation, and deterministic evidence report.

### New script unit

- `scripts/inspect_pcap_recon_batch.ps1`: private quartile sampling, serial calls to the existing single-file inspector, atomic private state, and aggregate-only public output.

### New frontend unit

- `frontend/src/pages/PcapReconWorkspace.tsx`: separate reconnaissance confirmation, polling, cancellation, and aggregate profile view inside PCAP mode.

### Existing integration boundaries

- `backend/app/pcap/config.py`: expose the repository-owned reconnaissance script path.
- `backend/app/pcap/authorization.py`: bind one-time receipts to `triage` or `reconnaissance` purpose.
- `backend/app/superagent/models.py`, `service.py`, `store.py`: add the new discriminated request/result without changing existing branches.
- `backend/app/api/superagent.py`, `backend/app/main.py`: add reconnaissance authorization, mission delegation, polling, cancellation, and lifespan cleanup.
- `frontend/src/types.ts`, `frontend/src/api.ts`, `frontend/src/pages/PcapSuperAgentWorkspace.tsx`: add a PCAP-only `批量分诊 / 数据勘察` switch and isolated storage key.
- `scripts/verify_pcap_agent_privacy.py`, `README.md`, `docs/pcap-superagent.md`: verify and document the new public surface and phase boundary.

---

### Task 1: Define Closed Reconnaissance Contracts and Buckets

**Files:**
- Create: `backend/app/pcap/recon_models.py`
- Create: `tests/unit/test_pcap_recon_models.py`
- Modify: `backend/app/pcap/config.py`
- Modify: `tests/unit/test_pcap_config.py`

**Interfaces:**
- Produces: `bucket_size(size_bytes: int) -> PcapSizeBucket`.
- Produces: `bucket_packets(packet_count: int) -> PcapPacketBucket`.
- Produces: `bucket_duration(duration_seconds: float) -> PcapDurationBucket`.
- Produces: `PcapReconSummary`, `PcapReconMissionResult`, `PcapReconOverview`, and closed histogram models.
- Produces: `PcapConfig.recon_batch_script`, fixed to `<repository>/scripts/inspect_pcap_recon_batch.ps1`.

- [ ] **Step 1: Add failing bucket-boundary and privacy tests**

Create exact boundary tests:

```python
def test_recon_buckets_have_closed_boundaries() -> None:
    assert bucket_size(2047) is PcapSizeBucket.UNDER_2_KIB
    assert bucket_size(2048) is PcapSizeBucket.FROM_2_KIB_TO_64_KIB
    assert bucket_size(65536) is PcapSizeBucket.FROM_64_KIB_TO_1_MIB
    assert bucket_size(1048576) is PcapSizeBucket.AT_LEAST_1_MIB
    assert bucket_packets(0) is PcapPacketBucket.EMPTY
    assert bucket_packets(15) is PcapPacketBucket.FROM_1_TO_15
    assert bucket_packets(16) is PcapPacketBucket.FROM_16_TO_63
    assert bucket_packets(64) is PcapPacketBucket.AT_LEAST_64
    assert bucket_duration(0.0) is PcapDurationBucket.ZERO
    assert bucket_duration(0.999999) is PcapDurationBucket.UNDER_1_SECOND
    assert bucket_duration(1.0) is PcapDurationBucket.FROM_1_TO_10_SECONDS
    assert bucket_duration(10.0) is PcapDurationBucket.FROM_1_TO_10_SECONDS
    assert bucket_duration(10.000001) is PcapDurationBucket.OVER_10_SECONDS
```

Add parameterized model tests rejecting `filename`, `path`, `ip`, `port`, `mac`, `payload`, `uri`, `prompt`, `token_text`, `sha256`, and `stderr` at every nested public level.

- [ ] **Step 2: Run the focused tests and observe missing contracts**

Run:

```powershell
$env:PYTHONPATH = "$(Resolve-Path 'backend');$(Resolve-Path '.')"
python -m pytest tests/unit/test_pcap_recon_models.py tests/unit/test_pcap_config.py -q
```

Expected: collection or import failures for `app.pcap.recon_models` and `recon_batch_script`.

- [ ] **Step 3: Implement frozen enums and aggregate models**

Use these exact public enums:

```python
class PcapSizeBucket(StrEnum):
    UNDER_2_KIB = "under_2_kib"
    FROM_2_KIB_TO_64_KIB = "2_kib_to_64_kib"
    FROM_64_KIB_TO_1_MIB = "64_kib_to_1_mib"
    AT_LEAST_1_MIB = "at_least_1_mib"

class PcapPacketBucket(StrEnum):
    EMPTY = "empty"
    FROM_1_TO_15 = "1_to_15"
    FROM_16_TO_63 = "16_to_63"
    AT_LEAST_64 = "at_least_64"

class PcapDurationBucket(StrEnum):
    ZERO = "zero"
    UNDER_1_SECOND = "under_1_second"
    FROM_1_TO_10_SECONDS = "1_to_10_seconds"
    OVER_10_SECONDS = "over_10_seconds"
```

`PcapReconSummary` has exactly these fields:

```python
schema_version: Literal[1]
sampled_count: int  # 0..20
succeeded_count: int  # 0..20
failed_count: int  # 0..20
quartile_counts: PcapQuartileHistogram
size_bucket_counts: PcapSizeHistogram
packet_bucket_counts: PcapPacketHistogram
duration_bucket_counts: PcapDurationHistogram
protocol_presence_counts: dict[str, int]
plaintext_sample_count: int
encrypted_sample_count: int
sequence_candidate_count: int
```

Each histogram is a frozen model with one nonnegative integer field per enum member. Require all aggregate counts to be bounded by `sampled_count`, require `succeeded_count + failed_count == sampled_count`, require every protocol name to come from `ALLOWED_PROTOCOLS`, and require each protocol presence count to be at most `succeeded_count`.

`PcapReconMissionResult` uses objective literal `reconnoiter_pcap_dataset`, statuses from the existing `PcapMissionStatus`, no batch/capture IDs, a nullable `summary`, at most 10 deterministic trace events, fixed narratives, and a creation timestamp. Its public ID is `recon_<32 hex>`.

- [ ] **Step 4: Add the repository-owned script path without external override**

Add `recon_batch_script: Path` to `PcapConfig` and set it to `scripts/inspect_pcap_recon_batch.ps1`. Extend `_SCRIPT_OVERRIDE_VARIABLES` with `TOKEN_SECURITY_PCAP_RECON_BATCH_SCRIPT`, but preserve the rule that overrides must remain inside the repository.

- [ ] **Step 5: Run focused and existing PCAP model/config regressions**

Run:

```powershell
python -m pytest tests/unit/test_pcap_recon_models.py tests/unit/test_pcap_models.py tests/unit/test_pcap_config.py -q
```

Expected: all pass; existing `PcapBatchSummary` serialization remains byte-compatible.

- [ ] **Step 6: Commit**

```powershell
git add backend/app/pcap/recon_models.py backend/app/pcap/config.py tests/unit/test_pcap_recon_models.py tests/unit/test_pcap_config.py
git commit -m "feat: define pcap reconnaissance contracts"
```

---

### Task 2: Implement Deterministic Size-Quartile Sampling and Aggregate Output

**Files:**
- Create: `scripts/inspect_pcap_recon_batch.ps1`
- Create: `tests/unit/test_inspect_pcap_recon_batch_script.py`

**Interfaces:**
- Consumes: existing `scripts/inspect_pcap.ps1` unchanged for one-file Docker inspection.
- Produces: fixed stdout `pcap_recon_result=<recon_id>` or `pcap_recon_error=<fixed_code>`.
- Produces privately: `<quarantine>/state/pcap-recon-private.json` and temporary child reports.
- Produces publicly: `<quarantine>/output/pcap-recon-<recon_id>.json` matching `PcapReconSummary`.

- [ ] **Step 1: Add failing deterministic-sampling tests**

Create 40 synthetic capture placeholders with distinct sizes and a fake inspector that writes valid child reports. Assert selected private ordinals correspond to five midpoint positions from each ten-item quartile:

```python
assert selected_sizes == [2, 4, 6, 8, 10, 12, 14, 16, 18, 20,
                          22, 24, 26, 28, 30, 32, 34, 36, 38, 40]
```

Also test 1, 4, 7, 19, and 21 total files; every input appears at most once, every nonempty quartile contributes up to five samples, and total selection never exceeds 20.

- [ ] **Step 2: Add failing safety, cancellation, and privacy tests**

Tests must prove:

```python
assert inspector.max_concurrent_calls == 1
assert all(call.readonly_single_capture for call in inspector.calls)
assert set(public_summary) == EXPECTED_RECON_SUMMARY_KEYS
assert "PRIVATE_SENTINEL" not in json.dumps(public_summary)
```

Add reparse-point refusal, cancellation between files, atomic private-state replacement, child-report cleanup, invalid child schema, fixed error output, bounded stdout/stderr, and no raw exception reflection.

- [ ] **Step 3: Run tests and observe the missing-script failure**

Run:

```powershell
python -m pytest tests/unit/test_inspect_pcap_recon_batch_script.py -q
```

Expected: every case fails because `inspect_pcap_recon_batch.ps1` is absent.

- [ ] **Step 4: Implement exact quartile selection**

Enumerate regular `.pcap` and `.pcapng` files without following reparse points. Sort by `(Length, OrdinalPath)` using ordinal string comparison. For `N` files, assign sorted index `i` to quartile:

```text
quartile = min(3, floor(i * 4 / N))
```

For a quartile with `M` members, choose `min(5, M)` zero-based local indices using:

```text
index(k) = floor((k + 0.5) * M / min(5, M)), k = 0..min(5, M)-1
```

Reject duplicate indices as `invalid_sampling_state`. This produces the tested odd positions for ten-member quartiles and avoids filename-derived sampling.

- [ ] **Step 5: Call the existing one-file inspector serially**

Accept only fixed parameters:

```powershell
param(
  [string]$QuarantineRoot,
  [string]$InspectorScript,
  [string]$ReconId,
  [ValidatePattern('^state_[0-9a-f]{32}$')][string]$StateId,
  [ValidateRange(1,20)][int]$MaxFiles = 20,
  [string]$DockerExecutable
)
```

Invoke `inspect_pcap.ps1` once per selected sample, with the same fixed PowerShell executable, literal paths, async stdout/stderr draining, and single-file Docker mount already used by `inspect_pcap_batch.ps1`. Do not add a payload or filename field to the child schema.

- [ ] **Step 6: Bucket child reports and write aggregate-only JSON**

Read `size_bytes`, `packet_count`, `duration_seconds`, `link_types`, `protocol_counts`, and `visibility` from the existing validated child report. Store raw identity and child metrics only in the private state. Increment public histograms and protocol presence once per successful sample. Set `sequence_candidate_count` only when `packet_count >= 64`.

The public report contains no per-sample array, capture ID, file identity, exact size, exact duration, link path, SHA, or tool error text.

- [ ] **Step 7: Run focused script tests and the unchanged batch suite**

Run:

```powershell
python -m pytest tests/unit/test_inspect_pcap_recon_batch_script.py tests/unit/test_inspect_pcap_batch_script.py tests/unit/test_inspect_pcap_script.py -q
```

Expected: all pass; existing smallest-first triage and resume tests remain unchanged.

- [ ] **Step 8: Commit**

```powershell
git add scripts/inspect_pcap_recon_batch.ps1 tests/unit/test_inspect_pcap_recon_batch_script.py
git commit -m "feat: sample pcap corpus by size quartile"
```

---

### Task 3: Add the Fixed-Argument Reconnaissance Executor

**Files:**
- Create: `backend/app/pcap/recon_executor.py`
- Create: `backend/app/pcap/windows_handles.py`
- Modify: `backend/app/pcap/executor.py`
- Create: `tests/unit/test_pcap_recon_executor.py`
- Modify: `tests/unit/test_pcap_executor.py`

**Interfaces:**
- Produces: `PcapReconExecutor.overview() -> PcapReconOverview`.
- Produces: `PcapReconExecutor.execute(recon_id: str, max_files: int = 20) -> PcapReconSummary`.
- Produces: `PcapReconExecutor.request_cancel(recon_id: str) -> None`.
- Reuses: move the handle-relative state/output access helpers from `backend/app/pcap/executor.py` into `backend/app/pcap/windows_handles.py`; both executors import the same implementation.

- [ ] **Step 1: Add failing fixed-command and report-validation tests**

Assert the runner receives an argument list with `shell=False`, a fixed repository script path, the configured external root, `-ReconId`, private `-StateId`, and `-MaxFiles 20`. Assert no caller-controlled path or filename appears in the request model.

```python
summary = executor.execute("recon_" + "a" * 32)
assert summary.sampled_count == 20
assert runner.call_args.kwargs["shell"] is False
```

Add rejection tests for unknown keys, wrong recon ID, mismatched histogram totals, oversized output, reparse output handles, timeout, nonzero exit, reflected stderr, and invalid UTF-8.

- [ ] **Step 2: Run focused tests and observe missing executor**

Run:

```powershell
python -m pytest tests/unit/test_pcap_recon_executor.py -q
```

Expected: import failure for `PcapReconExecutor`.

- [ ] **Step 3: Implement the executor with existing security primitives**

First move `_open_quarantine_root`, `_open_or_create_directory_relative`, `_open_directory_relative`, `_create_marker_relative_to`, `_read_file_relative`, `_nt_create_relative`, `_verified_handle`, `_reject_handle_reparse_point`, `_close_handle`, their ctypes structures, and their constants into `windows_handles.py` without changing behavior. Keep the existing executor tests unchanged except import paths needed for direct helper tests.

Use exact ID validation `^recon_[0-9a-f]{32}$`, fixed maximum 20, timeout `20 * 160 + 30` seconds, and the existing private checkpoint-scope derivation extended with the reconnaissance script identity. Read only `pcap-recon-<recon_id>.json` through a verified handle relative to the configured quarantine root.

`overview()` returns only:

```json
{
  "enabled": true,
  "eligible_file_count": 2318,
  "sample_limit": 20,
  "sampling_method": "size_quartile_v1"
}
```

The numeric count is dynamic; `2318` is an example, not a constant.

- [ ] **Step 4: Run focused executor and existing executor regressions**

Run:

```powershell
python -m pytest tests/unit/test_pcap_recon_executor.py tests/unit/test_pcap_executor.py -q
```

Expected: all pass on Windows; existing cancellation and handle-relative tests remain green.

- [ ] **Step 5: Commit**

```powershell
git add backend/app/pcap/recon_executor.py backend/app/pcap/windows_handles.py backend/app/pcap/executor.py tests/unit/test_pcap_recon_executor.py tests/unit/test_pcap_executor.py
git commit -m "feat: execute authorized pcap reconnaissance"
```

---

### Task 4: Add a Separate Reconnaissance Objective, Authorization, and API

**Files:**
- Create: `backend/app/superagent/pcap_recon_coordinator.py`
- Create: `tests/unit/test_superagent_pcap_recon_coordinator.py`
- Modify: `backend/app/pcap/authorization.py`
- Modify: `backend/app/superagent/models.py`
- Modify: `backend/app/superagent/service.py`
- Modify: `backend/app/superagent/store.py`
- Modify: `backend/app/api/superagent.py`
- Modify: `backend/app/main.py`
- Modify: `tests/integration/test_superagent_api.py`
- Modify: `tests/integration/test_health_api.py`

**Interfaces:**
- Produces request: `PcapReconMissionRequest(objective="reconnoiter_pcap_dataset", authorization_id=...)`.
- Produces endpoint: `GET /api/v1/superagent/pcap/reconnaissance/overview`.
- Produces endpoint: `POST /api/v1/superagent/pcap/reconnaissance/authorizations`.
- Extends existing mission create/get/cancel endpoints with the new discriminated result.
- Preserves: `triage_pcap_evidence` and `investigate_and_respond` request/response behavior.

- [ ] **Step 1: Add failing purpose-bound authorization tests**

Add `purpose: Literal["triage", "reconnaissance"]` to private authorization records. Test that a triage receipt cannot start reconnaissance and a reconnaissance receipt cannot start triage; both return fixed `pcap_authorization_purpose_mismatch` without consuming the receipt.

- [ ] **Step 2: Add failing lifecycle and API tests**

Test one active reconnaissance mission, one-time receipt use, expiry, confirmation false, max-files fixed at 20, polling, refresh restore, cancellation acknowledgement remaining nonterminal until cleanup, deterministic terminal report, and no Prompt capability/API changes.

```python
receipt = client.post(
    "/api/v1/superagent/pcap/reconnaissance/authorizations",
    json={"confirmed": True, "sample_limit": 20},
)
mission = client.post(
    "/api/v1/superagent/missions",
    json={
        "objective": "reconnoiter_pcap_dataset",
        "authorization_id": receipt.json()["authorization_id"],
    },
)
assert mission.status_code == 201
```

- [ ] **Step 3: Run focused tests and observe missing objective/routes**

Run:

```powershell
python -m pytest tests/unit/test_superagent_pcap_recon_coordinator.py tests/integration/test_superagent_api.py tests/integration/test_health_api.py -q
```

Expected: request validation and route failures for the new objective.

- [ ] **Step 4: Implement purpose-bound authorization and coordinator**

Use a separate single-worker coordinator. It emits only these deterministic stages:

```text
authorization_accepted
quartile_sample_selected
isolated_full_capture_scan_running
aggregate_profile_validated
method_selection_checkpoint_ready
```

The coordinator does not infer attack type. The final report states observed aggregate counts and that detector selection remains pending. Cancellation and close semantics must match the cleanup-gated behavior in `PcapMissionCoordinator`.

- [ ] **Step 5: Wire opt-in services and fixed errors**

Construct the executor/coordinator only when existing PCAP configuration is ready. Add fixed codes:

```text
pcap_reconnaissance_unavailable       503
pcap_authorization_purpose_mismatch   403
pcap_reconnaissance_active            409
pcap_reconnaissance_failed            500
```

Do not return exception strings. Existing Prompt and triage errors remain byte-compatible.

- [ ] **Step 6: Run focused, full SuperAgent, and privacy regressions**

Run:

```powershell
python -m pytest tests/unit/test_superagent_pcap_recon_coordinator.py tests/unit/test_superagent_pcap_coordinator.py tests/unit/test_superagent_service.py tests/integration/test_superagent_api.py tests/integration/test_health_api.py tests/unit/test_verify_lab_privacy.py -q
```

Expected: all pass; existing Prompt and PCAP triage snapshots do not change.

- [ ] **Step 7: Commit**

```powershell
git add backend/app/pcap/authorization.py backend/app/superagent/pcap_recon_coordinator.py backend/app/superagent/models.py backend/app/superagent/service.py backend/app/superagent/store.py backend/app/api/superagent.py backend/app/main.py tests/unit/test_superagent_pcap_recon_coordinator.py tests/integration/test_superagent_api.py tests/integration/test_health_api.py
git commit -m "feat: coordinate pcap corpus reconnaissance"
```

---

### Task 5: Add the PCAP-Only Reconnaissance Workspace

**Files:**
- Create: `frontend/src/pages/PcapReconWorkspace.tsx`
- Create: `frontend/src/PcapReconWorkspace.test.tsx`
- Modify: `frontend/src/types.ts`
- Modify: `frontend/src/api.ts`
- Modify: `frontend/src/pages/PcapSuperAgentWorkspace.tsx`
- Modify: `frontend/src/PcapSuperAgentWorkspace.test.tsx`
- Modify: `frontend/src/styles.css`

**Interfaces:**
- Produces: `pcapReconOverview`, `authorizePcapRecon`, and `createPcapReconMission` API methods.
- Produces: storage key `token-security-superagent-pcap-recon-mission-id`.
- Produces: PCAP-only segmented control `批量分诊 | 数据勘察`.
- Preserves: Prompt mode default, triage storage, original PCAP mascot playback, and challenge components.

- [ ] **Step 1: Add failing mode-isolation and confirmation tests**

Test that opening Prompt mode calls no PCAP endpoint, opening PCAP keeps `批量分诊` as default, and choosing `数据勘察` fetches only the reconnaissance overview. Two confirmation clicks are required; neither mode selection nor refresh issues authorization.

```tsx
fireEvent.click(screen.getByRole("button", { name: "数据勘察" }));
expect(await screen.findByText("按文件大小四分位抽取 20 个代表样本")).toBeVisible();
expect(requestsTo("/reconnaissance/authorizations")).toHaveLength(0);
```

- [ ] **Step 2: Add failing aggregate-profile and privacy tests**

Render fixed synthetic results and assert the page shows quartile coverage, packet-count histogram, duration histogram, protocol presence, plaintext/encrypted sample counts, and sequence-candidate count. Assert it never renders filename, path, IP, port, Payload, Prompt, attack type, anomalous Packet, CPD result, or Token result.

- [ ] **Step 3: Run focused tests and observe missing UI**

Run:

```powershell
Set-Location frontend
npm.cmd test -- --run PcapReconWorkspace.test.tsx PcapSuperAgentWorkspace.test.tsx
```

Expected: missing component, types, and controls.

- [ ] **Step 4: Implement typed APIs and isolated state**

Add `PcapReconMissionResult` to `SuperAgentStoredMission`. Narrow every existing triage and Prompt consumer on `objective`; do not add reconnaissance to `LabToolId` or Prompt tool labels.

The confirmation copy must say:

```text
本次将在无网络只读容器中完整扫描 20 个分层样本，仅返回聚合画像，不检测攻击，不展示文件身份或载荷。
```

- [ ] **Step 5: Implement the aggregate profile view**

Use compact bar rows for the three histograms and protocol presence. Show an explicit phase banner:

```text
当前阶段：认识数据
下一阶段：根据真实画像选择规则、Request 定位、行为异常或可选 CPD
```

Do not mount `PcapMascotTeam` in reconnaissance mode because no attack evidence exists yet. Preserve it unchanged in batch-triage mode.

- [ ] **Step 6: Run focused, full frontend, challenge, and build checks**

Run:

```powershell
npm.cmd test -- --run PcapReconWorkspace.test.tsx PcapSuperAgentWorkspace.test.tsx SuperAgentPage.test.tsx ChallengePage.test.tsx components/MascotTeam.test.tsx
npm.cmd test
npm.cmd run build
```

Expected: all pass; Prompt and challenge screenshots/behavior remain unchanged.

- [ ] **Step 7: Commit**

```powershell
git add frontend/src/pages/PcapReconWorkspace.tsx frontend/src/PcapReconWorkspace.test.tsx frontend/src/types.ts frontend/src/api.ts frontend/src/pages/PcapSuperAgentWorkspace.tsx frontend/src/PcapSuperAgentWorkspace.test.tsx frontend/src/styles.css
git commit -m "feat: show stratified pcap reconnaissance"
```

---

### Task 6: Extend Privacy Verification and Document the Phase Gate

**Files:**
- Modify: `scripts/verify_pcap_agent_privacy.py`
- Modify: `tests/unit/test_verify_pcap_agent_privacy.py`
- Modify: `docs/pcap-superagent.md`
- Modify: `README.md`
- Create: `docs/pcap-reconnaissance-report-template.md`

**Interfaces:**
- Extends: `verify_pcap_agent_privacy.py` with reconnaissance overview, invalid authorization, invalid mixed-objective mission, unknown restore, and unknown cancel surfaces.
- Produces: a report template containing only aggregate public fields and method-selection decisions.

- [ ] **Step 1: Add failing verifier tests**

Add exact-schema checks and recursive forbidden-key/value scans for every reconnaissance response. Use a valid-format unknown authorization ID so mixed-objective validation proves discriminator separation instead of ID syntax.

Assert fixed output remains aggregate only:

```text
pcap_agent_privacy_verification=passed
checked_endpoint_count=11
privacy_violation_count=0
tracked_private_artifact_count=0
```

- [ ] **Step 2: Run focused tests and observe the endpoint-count/schema failures**

Run:

```powershell
python -m pytest tests/unit/test_verify_pcap_agent_privacy.py -q
```

Expected: failures because only the six existing triage surfaces are checked.

- [ ] **Step 3: Extend the verifier without reflecting values**

Never print bodies, IDs, paths, Git matches, exception strings, or raw HTTP content. Extend tracked-artifact rejection with `*pcap-recon*.json`, `*pcap-recon-private*`, and reconnaissance cancellation markers.

- [ ] **Step 4: Write operator and experiment documentation**

Document:

- why smallest-first triage cannot characterize the corpus;
- the exact four-quartile sampling formula;
- the fresh UI authorization boundary;
- full-file parsing inside the existing Docker sandbox;
- the aggregate-only public schema;
- that this phase does not detect attacks;
- how the observed report selects the second detector plan;
- why filenames cannot be detector inputs or public labels.

The report template has sections for corpus structure, protocol visibility, sequence suitability, evidence limitations, and the next-plan decision. It contains no file-level rows.

- [ ] **Step 5: Run full synthetic verification**

First start the current backend on port `18002` with PCAP enabled against a newly created empty system-temporary quarantine root. This proves the live verifier without exposing the real 2318-file directory:

```powershell
$reconTemp = Join-Path ([System.IO.Path]::GetTempPath()) ("pcap-recon-verification-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path (Join-Path $reconTemp "input") -Force | Out-Null
$env:TOKEN_SECURITY_PCAP_ENABLED = "true"
$env:TOKEN_SECURITY_PCAP_QUARANTINE_ROOT = $reconTemp
$env:TOKEN_SECURITY_PCAP_POWERSHELL_EXECUTABLE = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$env:PYTHONPATH = "$(Resolve-Path 'backend');$(Resolve-Path '.')"
$backend = Start-Process -PassThru -WindowStyle Hidden -FilePath "python" -ArgumentList @("-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "18002") -WorkingDirectory (Resolve-Path "backend")
```

Run from repository root:

```powershell
python -m pytest -q
python scripts/verify_pcap_agent_privacy.py --base-url http://127.0.0.1:18002 --repo-root .
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File scripts/verify_pcap_sandbox.ps1
Set-Location frontend
npm.cmd test
npm.cmd run build
```

After verification, stop only `$backend.Id`. Resolve `$reconTemp`, require its final path to start with the system temporary directory plus `pcap-recon-verification-`, then remove that exact temporary directory recursively. Never point this synthetic gate at `E:\Codex\pcap-quarantine`.

Expected: zero failures; privacy violations `0`, tracked private artifacts `0`, payload leaks `0`, residual containers `0`, and production build exit `0`.

- [ ] **Step 6: Run synthetic desktop/mobile workflow checks**

Use synthetic API fixtures only. Verify `/analyze`, Prompt SuperAgent, PCAP triage, PCAP reconnaissance, and `/challenge` at `1440x900` and `390x844`. Require no horizontal overflow, no console errors, no automatic authorization, and unchanged Prompt/challenge controls.

- [ ] **Step 7: Commit**

```powershell
git add scripts/verify_pcap_agent_privacy.py tests/unit/test_verify_pcap_agent_privacy.py docs/pcap-superagent.md docs/pcap-reconnaissance-report-template.md README.md
git commit -m "docs: verify pcap reconnaissance boundary"
```

---

### Task 7: User-Authorized Real Reconnaissance and Detector-Plan Gate

**Files:**
- Create after authorized run: `docs/advanced-task/pcap-reconnaissance-findings.md`
- Modify after authorized run: `docs/advanced-task/test-report.md`

**Interfaces:**
- Consumes: only the public `PcapReconMissionResult` returned through the API.
- Produces: an aggregate findings document with no file identity, payload, addresses, ports, hashes, raw errors, or per-sample rows.
- Produces next: a separate detector design/implementation plan grounded in observed distributions.

- [ ] **Step 1: Stop at the explicit human authorization gate**

Open PCAP `数据勘察`, show eligible count and fixed sample limit 20, then wait. Do not call a real batch script or authorization API on the user's behalf. The user must click `准备勘察` and then `确认并开始`.

- [ ] **Step 2: Observe only public mission fields**

After UI confirmation, poll the public mission. Verify:

```text
sampled_count <= 20
succeeded_count + failed_count = sampled_count
sum(quartile_counts) = sampled_count
every histogram count <= succeeded_count
every protocol key is allowlisted
no per-file identity or content field exists
```

Cancel once between files only if the user explicitly requests the cancellation acceptance scenario; otherwise do not interrupt the first research run.

- [ ] **Step 3: Write the aggregate findings**

Use only returned aggregate fields. The decision rules are:

```text
If succeeded_count < 16: repeat reconnaissance after tool/data-quality repair; do not choose a detector.
If plaintext_sample_count >= 8: prioritize application-layer Request inspection in the next plan.
If sequence_candidate_count >= 12: include Packet/Flow behavior detection and evaluate optional CPD.
If encrypted_sample_count >= 12: prioritize metadata behavior detection and document content limits.
If both plaintext_sample_count >= 8 and sequence_candidate_count >= 12: plan a hybrid Request + sequence detector.
Otherwise: plan the smallest method supported by the dominant observed evidence and retain evidence-insufficient handling.
```

These are method-selection gates, not attack decisions.

- [ ] **Step 4: Run final privacy and Git checks**

Run:

```powershell
python scripts/verify_pcap_agent_privacy.py --base-url http://127.0.0.1:8000 --repo-root .
git ls-files "*.pcap" "*.pcapng" "*pcap-recon*.json" "*pcap-recon-private*" "*.cancel"
git diff --check
```

Expected: zero privacy violations, zero tracked private artifacts, empty `git ls-files` output, and clean diff.

- [ ] **Step 5: Commit only the aggregate findings**

```powershell
git add docs/advanced-task/pcap-reconnaissance-findings.md docs/advanced-task/test-report.md
git commit -m "docs: record aggregate pcap reconnaissance"
```

- [ ] **Step 6: End this plan and start a new design gate**

Compare the aggregate findings with `docs/superpowers/specs/2026-09-03-pcap-multigranular-localization-design.md`. Write a new detector design and implementation plan selecting only methods supported by the real evidence. Do not continue directly into Suricata, anomaly modeling, Packet localization, or CPD implementation without that approved second design.

---

## Final Review Gate

Before declaring this reconnaissance phase complete, verify every global constraint and reject completion if any real capture was read without fresh UI authorization, if sampling used filenames, if a public surface exposes per-file identity/content, if a report claims an attack or Token result, if Docker isolation changed, or if any Prompt/challenge behavior regressed.
