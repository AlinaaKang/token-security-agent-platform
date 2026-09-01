# PCAP Batch SuperAgent Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an explicitly authorized, privacy-preserving PCAP batch triage objective to the existing SuperAgent without changing the behavior of Prompt analysis, Entropy-CPD, or the Token detective challenge.

**Architecture:** Keep `investigate_and_respond` on its current synchronous Lab path and delegate the new `triage_pcap_evidence` objective to a separate PCAP coordinator. The coordinator consumes a one-time authorization, runs a PowerShell batch wrapper around the reviewed single-file `inspect_pcap.ps1`, stores only public mission snapshots in the existing bounded mission store, and exposes polling/cancellation through the existing SuperAgent API namespace. The frontend adds a separate workspace mode and new PCAP-specific mascot components that reuse the original image assets without modifying `/challenge` or `MascotTeam.tsx`.

**Tech Stack:** Python 3.11, FastAPI 0.116, Pydantic 2.11, PowerShell 5.1, Docker Desktop, React 19, TypeScript 5.8, Vitest 3, pytest 8.

## Global Constraints

- Existing Prompt detection, `investigate_and_respond`, Entropy-CPD, frozen samples, metrics, response actions, and API defaults must retain their current behavior.
- Do not modify `frontend/src/pages/ChallengePage.tsx`, `frontend/src/components/MascotTeam.tsx`, challenge state, scoring, flags, Token tooltip behavior, or challenge tests except to run them unchanged.
- Do not add `pcap_batch_triage` to `LabToolId`; PCAP uses independent types and execution code.
- PCAP content may be read only after a user creates and consumes a one-time authorization.
- Process at most 20 files per mission, in ascending file-size order, one file and one container at a time.
- Each single-file inspection must retain `--network none`, `--read-only`, `--cap-drop ALL`, `no-new-privileges`, resource limits, and a single read-only capture mount.
- The Agent/API/UI/export boundary must never receive original filenames, paths, IPs, ports, MACs, stable capture SHA values, payloads, Prompts, suffixes, Token text, raw stderr, or hidden chain of thought.
- `token_eligible` means only that a plaintext application protocol was observed; it must not be labeled as LLM traffic, jailbreak, or Token anomaly.
- Only an actual recovered Prompt that is re-tokenized and processed by the existing model may produce CPD or Token-level output. The first release does not implement payload recovery and therefore must show those fields as unavailable.
- PCAP files, PCAP reports, batch state, cancellation markers, and private mappings must remain outside Git and under existing ignore rules.
- Every task follows TDD: failing focused test, observed failure, minimal implementation, focused pass, relevant regression pass, commit.

## File Structure

### New backend and script units

- `backend/app/pcap/__init__.py`: package boundary for PCAP-only services.
- `backend/app/pcap/config.py`: opt-in environment configuration and absolute quarantine/tool paths.
- `backend/app/pcap/models.py`: strict public PCAP capability, authorization, batch, evidence, and mission contracts.
- `backend/app/pcap/authorization.py`: one-time, expiring, in-memory authorization store.
- `backend/app/pcap/executor.py`: fixed-argument PowerShell process adapter, cancellation marker, and public-summary loader.
- `backend/app/superagent/pcap_coordinator.py`: bounded background mission lifecycle and deterministic Agent events/report.
- `scripts/inspect_pcap_batch.ps1`: Windows PowerShell 5.1 batch selection, resume state, per-file launcher invocation, and redacted public report.

### New frontend units

- `frontend/src/pages/PcapSuperAgentWorkspace.tsx`: PCAP overview, confirmation, mission polling, cancellation, and terminal report.
- `frontend/src/components/PcapMascotTeam.tsx`: original three image assets with PCAP-only interaction state and CSS namespace.
- `frontend/src/components/PcapEvidenceDesk.tsx`: deterministic per-role public evidence playback.
- `frontend/src/pcap/investigation.ts`: pure Guard -> CPD -> Captain interaction state transitions and evidence-line builders.

### Existing files changed only at integration boundaries

- `backend/app/main.py`: optional PCAP service construction and lifespan cleanup using `PcapConfig`.
- `backend/app/superagent/models.py`, `service.py`, `store.py`: request/result union and delegation while preserving the existing Prompt branch.
- `backend/app/api/superagent.py`: overview, authorization, cancel, and discriminated mission creation endpoints.
- `frontend/src/types.ts`, `frontend/src/api.ts`, `frontend/src/pages/SuperAgentPage.tsx`, `frontend/src/styles.css`: additive PCAP contracts, API methods, mode switch, and PCAP-only styles.
- `.env.example`, `README.md`, `docs/pcap-superagent.md`: operator configuration, execution boundaries, and demonstration steps.

---

### Task 1: Freeze Baseline and Define PCAP Contracts

**Files:**
- Create: `backend/app/pcap/__init__.py`
- Create: `backend/app/pcap/config.py`
- Create: `backend/app/pcap/models.py`
- Create: `tests/unit/test_pcap_config.py`
- Create: `tests/unit/test_pcap_models.py`
- Modify: `.env.example`

**Interfaces:**
- Produces: `PcapConfig.from_environ(environ) -> PcapConfig | None`.
- Produces: `PcapOverview`, `PcapAuthorizationRequest`, `PcapAuthorizationReceipt`, `PcapCaptureEvidence`, `PcapBatchSummary`, `PcapMissionResult`, and `PcapMissionStatus`.
- Consumes later: Tasks 2-7 import these exact types; do not duplicate public PCAP schemas elsewhere.

- [ ] **Step 1: Record the unchanged baseline**

Run:

```powershell
pytest -q
Set-Location frontend
npm.cmd test
npm.cmd run build
```

Expected baseline: pytest completes with `617 passed, 2 skipped`; Vitest completes with `199 passed`; the production build exits `0`. If totals have legitimately increased before execution, record the observed totals in the task notes and require no failures.

- [ ] **Step 2: Write failing configuration and privacy-contract tests**

Add tests that prove configuration is opt-in and absolute, and that public models reject prohibited fields:

```python
def test_pcap_config_is_disabled_without_explicit_flag(tmp_path: Path) -> None:
    assert PcapConfig.from_environ({}) is None


def test_enabled_pcap_config_requires_absolute_existing_paths(tmp_path: Path) -> None:
    env = {
        "TOKEN_SECURITY_PCAP_ENABLED": "true",
        "TOKEN_SECURITY_PCAP_QUARANTINE_ROOT": str(tmp_path / "missing"),
        "TOKEN_SECURITY_PCAP_POWERSHELL_EXECUTABLE": str(tmp_path / "missing.exe"),
    }
    with pytest.raises(ValueError, match="PCAP quarantine root"):
        PcapConfig.from_environ(env)


@pytest.mark.parametrize("private_key", ["filename", "path", "sha256", "prompt", "payload", "token_text"])
def test_public_capture_evidence_rejects_private_keys(private_key: str) -> None:
    payload = public_capture_payload() | {private_key: "PRIVATE_SENTINEL"}
    with pytest.raises(ValidationError):
        PcapCaptureEvidence.model_validate(payload)
```

- [ ] **Step 3: Run the focused tests and observe the missing-module failure**

Run:

```powershell
pytest tests/unit/test_pcap_config.py tests/unit/test_pcap_models.py -q
```

Expected: collection fails because `app.pcap` does not exist.

- [ ] **Step 4: Implement strict configuration and frozen public models**

Use these contracts:

```python
class PcapCapability(StrEnum):
    TOKEN_ELIGIBLE = "token_eligible"
    TRAFFIC_ONLY = "traffic_only"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class PcapMissionStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    DEGRADED = "degraded"


class PcapVisibility(_FrozenPcapPublicModel):
    plaintext_application_protocol_observed: bool
    encrypted_transport_observed: bool
    tls_observed: bool
    quic_observed: bool


class PcapCaptureEvidence(_FrozenPcapPublicModel):
    capture_id: str = Field(pattern=r"^capture_[0-9a-f]{32}$")
    status: Literal["succeeded", "failed", "skipped"]
    packet_count: int = Field(ge=0)
    protocol_counts: dict[str, int]
    visibility: PcapVisibility
    capability: PcapCapability | None = None
    error_code: str | None = Field(default=None, pattern=r"^[a-z0-9_]+$")


class PcapBatchSummary(_FrozenPcapPublicModel):
    schema_version: Literal[1] = 1
    batch_id: str = Field(pattern=r"^batch_[0-9a-f]{32}$")
    selected_count: int = Field(ge=0, le=20)
    succeeded_count: int = Field(ge=0, le=20)
    failed_count: int = Field(ge=0, le=20)
    skipped_count: int = Field(ge=0, le=20)
    captures: tuple[PcapCaptureEvidence, ...] = Field(max_length=20)
```

Validate `protocol_counts` against the same closed protocol-name allowlist already used by `pcap_preflight.py`; require nonnegative integer values and reject unknown names.

Define PCAP-only `PcapToolId.PCAP_BATCH_TRIAGE`, actors `coordinator | network_evidence_analyst | knowledge_analyst | response_operator`, and `PcapTraceEvent` with at most 12 ordered public events. `PcapMissionResult` must have `mission_id`, objective literal `triage_pcap_evidence`, `status`, `batch_id`, `events`, optional `summary`, deterministic `report` sections `confirmed | candidates | unknowns | recommended_action`, `limitations`, and `created_at`. It must not reuse `run_id`, `base_action`, Prompt execution receipts, or `LabToolId`.

`PcapConfig.from_environ` must require an explicit truthy `TOKEN_SECURITY_PCAP_ENABLED`, an existing absolute quarantine root containing `input`, and an existing absolute PowerShell executable. Resolve the repository-owned batch and single-file scripts internally; reject environment overrides that point outside the repository.

- [ ] **Step 5: Run model/config tests and the existing schema suite**

Run:

```powershell
pytest tests/unit/test_pcap_config.py tests/unit/test_pcap_models.py tests/unit/test_superagent_models.py tests/unit/test_schemas.py -q
```

Expected: all tests pass and existing SuperAgent model serialization is unchanged.

- [ ] **Step 6: Document disabled-by-default environment variables and commit**

Add to `.env.example` with empty values:

```dotenv
TOKEN_SECURITY_PCAP_ENABLED=false
TOKEN_SECURITY_PCAP_QUARANTINE_ROOT=
TOKEN_SECURITY_PCAP_POWERSHELL_EXECUTABLE=
```

Commit:

```powershell
git add backend/app/pcap tests/unit/test_pcap_config.py tests/unit/test_pcap_models.py .env.example
git commit -m "feat: define private pcap triage contracts"
```

---

### Task 2: Build the Resumable Single-File Batch Orchestrator

**Files:**
- Create: `scripts/inspect_pcap_batch.ps1`
- Create: `tests/unit/test_inspect_pcap_batch_script.py`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: existing `scripts/inspect_pcap.ps1 -Path -QuarantineRoot -DockerExecutable`.
- Produces: `inspect_pcap_batch.ps1 -QuarantineRoot -BatchId -MaxFiles -InspectorScript -DockerExecutable`.
- Produces: repository-external `output/pcap-batch-<batch_id>.json` matching `PcapBatchSummary` and private `state/pcap-batch-private.json`.
- Produces stdout only as `pcap_batch_result=<batch_id>` or `pcap_batch_error=<fixed_code>`.

- [ ] **Step 1: Write failing launcher-harness tests**

The test harness creates captures of different sizes and a fake inspector that records concurrency and writes valid single-file reports. Add exact assertions:

```python
def test_batch_selects_smallest_twenty_and_runs_serially(tmp_path: Path) -> None:
    root, captures = make_capture_batch(tmp_path, count=23)
    result = run_batch(root, fake_inspector(tmp_path), max_files=20)
    summary = load_public_summary(root, result)
    assert result.returncode == 0
    assert summary["selected_count"] == 20
    assert recorded_sizes(tmp_path) == sorted(path.stat().st_size for path in captures)[:20]
    assert max_recorded_concurrency(tmp_path) == 1


def test_batch_resume_skips_unchanged_success_retries_failure_and_adds_new_file(tmp_path: Path) -> None:
    root, captures = make_capture_batch(tmp_path, count=3)
    first = run_batch(root, fake_inspector(tmp_path, fail_names={captures[1].name}), max_files=3)
    add_capture(root, size=999)
    second = run_batch(root, fake_inspector(tmp_path), max_files=4)
    assert public_counts(first) == {"succeeded": 2, "failed": 1, "skipped": 0}
    assert public_counts(second) == {"succeeded": 2, "failed": 0, "skipped": 2}
    assert invocation_count(tmp_path, captures[0]) == 1
    assert invocation_count(tmp_path, captures[1]) == 2
```

Also test uppercase extensions, nested regular directories, reparse-point rejection, cancellation between files, atomic state replacement, malformed child reports, fixed error output, public report key allowlist, and absence of original filenames/SHA/private stderr.

- [ ] **Step 2: Run the focused tests and verify script absence**

Run:

```powershell
pytest tests/unit/test_inspect_pcap_batch_script.py -q
```

Expected: failures identify missing `scripts/inspect_pcap_batch.ps1`.

- [ ] **Step 3: Implement safe discovery and deterministic ordering**

Use a manual directory queue that never traverses reparse points. Accept only regular `.pcap` and `.pcapng` files under `<root>/input`, then sort by `Length` and an internal ordinal path tie-breaker. The path tie-breaker must never enter public output.

```powershell
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$QuarantineRoot,
    [Parameter(Mandatory = $true)][ValidatePattern('^batch_[0-9a-f]{32}$')][string]$BatchId,
    [ValidateRange(1, 20)][int]$MaxFiles = 20,
    [Parameter(Mandatory = $true)][string]$InspectorScript,
    [string]$DockerExecutable
)

function Get-SafeCaptureFiles {
    param([Parameter(Mandatory = $true)][System.IO.DirectoryInfo]$InputRoot)
    $queue = [System.Collections.Generic.Queue[System.IO.DirectoryInfo]]::new()
    $queue.Enqueue($InputRoot)
    while ($queue.Count -gt 0) {
        $directory = $queue.Dequeue()
        foreach ($entry in $directory.GetFileSystemInfos()) {
            if (($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
            if ($entry -is [System.IO.DirectoryInfo]) { $queue.Enqueue($entry); continue }
            if ($entry.Extension.ToLowerInvariant() -in @('.pcap', '.pcapng')) { $entry }
        }
    }
}
```

- [ ] **Step 4: Implement private resume state, anonymous IDs, and cancellation**

Create `state` and `output` only after validating neither path contains a reparse point. Persist private entries atomically through a same-directory temporary file and `Move-Item`. Each entry stores internal path, SHA, size, last result, and a random `capture_<32 hex>` ID. Before skipping a prior success, hash the current file and require the stored SHA to match. A file-backed `<root>/state/<batch_id>.cancel` marker is checked before selecting the next file and is never copied to public output.

The public report must contain only the model allowlist from Task 1. Read the child report internally, replace its SHA/path identity with `capture_id`, retain only packet/protocol/capability fields, and reject any unknown child key before conversion.

- [ ] **Step 5: Run batch, single-file sandbox, and PowerShell 5.1 tests**

Run:

```powershell
pytest tests/unit/test_inspect_pcap_batch_script.py tests/unit/test_inspect_pcap_script.py tests/unit/test_verify_pcap_sandbox_script.py -q
```

Expected: all pass; existing single-file sandbox assertions remain unchanged.

- [ ] **Step 6: Strengthen ignore rules and commit**

Ensure these patterns remain present exactly once:

```gitignore
*.pcap
*.pcapng
pcap-quarantine/
**/pcap-quarantine/
**/pcap-batch-*.json
**/pcap-batch-private.json
**/*.cancel
```

Commit:

```powershell
git add scripts/inspect_pcap_batch.ps1 tests/unit/test_inspect_pcap_batch_script.py .gitignore
git commit -m "feat: batch isolated pcap preflight runs"
```

---

### Task 3: Add One-Time Authorization and the Fixed-Argument Executor

**Files:**
- Create: `backend/app/pcap/authorization.py`
- Create: `backend/app/pcap/executor.py`
- Create: `tests/unit/test_pcap_authorization.py`
- Create: `tests/unit/test_pcap_executor.py`

**Interfaces:**
- Produces: `PcapAuthorizationStore.issue(max_files) -> PcapAuthorizationReceipt`.
- Produces: `PcapAuthorizationStore.consume(authorization_id) -> ConsumedPcapAuthorization` exactly once.
- Produces: `PcapBatchExecutor.overview() -> PcapOverview`, `execute(batch_id, max_files) -> PcapBatchSummary`, and `request_cancel(batch_id) -> None`.
- Consumes: `PcapConfig`, Task 1 models, and Task 2 batch script.

- [ ] **Step 1: Write failing authorization tests**

```python
def test_authorization_is_single_use_bound_and_expiring() -> None:
    clock = MutableClock()
    store = PcapAuthorizationStore(ttl_seconds=30, clock=clock)
    receipt = store.issue(max_files=20)
    consumed = store.consume(receipt.authorization_id)
    assert consumed.max_files == 20
    with pytest.raises(PcapAuthorizationAlreadyUsed):
        store.consume(receipt.authorization_id)
    expired = store.issue(max_files=3)
    clock.advance(31)
    with pytest.raises(PcapAuthorizationExpired):
        store.consume(expired.authorization_id)
```

Test `max_files` bounds `1..20`, unknown IDs, and receipt serialization without root/path fields.

- [ ] **Step 2: Write failing executor tests with an injected process runner**

```python
def test_executor_uses_only_configured_paths_and_fixed_arguments(tmp_path: Path) -> None:
    runner = RecordingRunner(stdout="pcap_batch_result=batch_" + "a" * 32)
    executor = PcapBatchExecutor(config=config_fixture(tmp_path), runner=runner)
    summary = executor.execute("batch_" + "a" * 32, 20)
    assert runner.command[0] == str(config_fixture(tmp_path).powershell_executable)
    assert runner.command[1:5] == ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass"]
    assert "-MaxFiles" in runner.command and runner.command[-1] == "20"
    assert summary.selected_count <= 20


def test_executor_never_reflects_raw_stderr(tmp_path: Path) -> None:
    runner = RecordingRunner(returncode=2, stdout="", stderr="PRIVATE_SENTINEL")
    with pytest.raises(PcapToolFailed, match="pcap_batch_failed") as failure:
        PcapBatchExecutor(config=config_fixture(tmp_path), runner=runner).execute(batch_id(), 1)
    assert "PRIVATE_SENTINEL" not in str(failure.value)
```

Also test overview counts without opening file contents, malformed stdout, missing/malformed public summary, batch ID mismatch, cancel-marker creation inside configured state only, and report rejection when a prohibited key appears.

- [ ] **Step 3: Run focused tests and observe missing implementations**

Run:

```powershell
pytest tests/unit/test_pcap_authorization.py tests/unit/test_pcap_executor.py -q
```

Expected: import/attribute failures for the new store and executor.

- [ ] **Step 4: Implement authorization and executor with dependency injection**

`PcapAuthorizationStore` uses `RLock`, monotonic time, opaque `pcap_auth_<32 hex>` IDs, and an ordered bounded store. `consume` atomically marks an entry used before returning it.

`PcapBatchExecutor` uses `subprocess.run` with a list of fixed arguments, `shell=False`, `capture_output=True`, UTF-8, and a batch timeout of `max_files * 160 + 30` seconds. Never pass Agent-supplied paths or script names. Load the known report path from `<root>/output/pcap-batch-<batch_id>.json`, validate with `PcapBatchSummary`, then return only the validated model.

- [ ] **Step 5: Run focused and public-model tests**

Run:

```powershell
pytest tests/unit/test_pcap_authorization.py tests/unit/test_pcap_executor.py tests/unit/test_pcap_models.py -q
```

Expected: all pass.

- [ ] **Step 6: Commit**

```powershell
git add backend/app/pcap/authorization.py backend/app/pcap/executor.py tests/unit/test_pcap_authorization.py tests/unit/test_pcap_executor.py
git commit -m "feat: authorize bounded pcap tool execution"
```

---

### Task 4: Implement the PCAP SuperAgent Coordinator

**Files:**
- Create: `backend/app/superagent/pcap_coordinator.py`
- Create: `tests/unit/test_superagent_pcap_coordinator.py`
- Modify: `backend/app/superagent/models.py`
- Modify: `backend/app/superagent/store.py`
- Modify: `backend/app/superagent/service.py`
- Modify: `tests/unit/test_superagent_models.py`
- Modify: `tests/unit/test_superagent_store.py`
- Modify: `tests/unit/test_superagent_service.py`

**Interfaces:**
- Produces: `PcapTriageMissionRequest(objective, authorization_id)` and discriminated `SuperAgentCreateMissionRequest`.
- Produces: `PcapMissionCoordinator.start(request) -> PcapMissionResult`, `cancel(mission_id) -> PcapMissionResult`, and `close() -> None`.
- Modifies: `SuperAgentService.create_mission` delegates only the new objective; the existing private Prompt mission body remains byte-for-byte behaviorally equivalent.
- Modifies: `SuperAgentMissionStore` stores `SuperAgentMissionResult | PcapMissionResult`.

- [ ] **Step 1: Write failing delegation and non-regression tests**

```python
def test_pcap_objective_consumes_authorization_and_calls_only_pcap_executor() -> None:
    lab = FakeLabService(decision=Decision.BLOCK)
    pcap = FakePcapCoordinator()
    service = SuperAgentService(lab_service=lab, pcap_coordinator=pcap)
    result = service.create_mission(PcapTriageMissionRequest(
        objective="triage_pcap_evidence",
        authorization_id="pcap_auth_" + "a" * 32,
    ))
    assert result.objective == "triage_pcap_evidence"
    assert pcap.started == 1
    assert lab.executed == []


def test_existing_prompt_objective_never_calls_pcap_coordinator() -> None:
    pcap = FakePcapCoordinator()
    service = SuperAgentService(lab_service=FakeLabService(Decision.ALLOW), pcap_coordinator=pcap)
    result = service.create_mission(existing_prompt_request())
    assert result.final_status is SuperAgentFinalStatus.CLOSED_SAFE
    assert pcap.started == 0
```

Add coordinator tests for queued -> running -> completed, tool failure -> degraded, cancel marker -> cancelled, deterministic event ordering, maximum 12 events, fixed report fallback, and no private fields in snapshots.

- [ ] **Step 2: Run focused tests and observe unsupported-objective failures**

Run:

```powershell
pytest tests/unit/test_superagent_models.py tests/unit/test_superagent_store.py tests/unit/test_superagent_service.py tests/unit/test_superagent_pcap_coordinator.py -q
```

Expected: PCAP request/model imports or objective validation fail while existing tests still pass.

- [ ] **Step 3: Add discriminated request/result types without altering Prompt fields**

Keep `SuperAgentMissionRequest` unchanged. Add:

```python
class PcapTriageMissionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    objective: Literal[SuperAgentObjective.TRIAGE_PCAP_EVIDENCE]
    authorization_id: str = Field(pattern=r"^pcap_auth_[0-9a-f]{32}$")


SuperAgentCreateMissionRequest = Annotated[
    SuperAgentMissionRequest | PcapTriageMissionRequest,
    Field(discriminator="objective"),
]
SuperAgentStoredMission = SuperAgentMissionResult | PcapMissionResult
```

Do not add PCAP actors or tools to existing Prompt `SuperAgentActor`, `SuperAgentTraceEvent`, `SuperAgentCapabilities`, or `LabToolId`; PCAP models own `network_evidence_analyst` and `pcap_batch_triage`.

- [ ] **Step 4: Implement bounded background coordination**

Use one `ThreadPoolExecutor(max_workers=1)` owned by `PcapMissionCoordinator`. `start` consumes authorization before scheduling, writes a queued snapshot, then schedules one worker. The worker writes running and terminal snapshots to the common store. `cancel` sets the executor's repository-external cancellation marker and updates only the target PCAP mission. `close` shuts down the pool with `cancel_futures=True`.

Generate deterministic public events in this order:

```text
coordinator plan
coordinator tool authorization accepted
network_evidence_analyst batch observation
knowledge_analyst evidence-level validation
response_operator deterministic response
coordinator complete
```

For each capture, report only network capability. `token_eligible` maps to “明文应用协议候选，尚未证明 LLM 流量”; CPD and Token evidence remain explicitly unavailable in this release.

- [ ] **Step 5: Run coordinator and complete existing SuperAgent unit suite**

Run:

```powershell
pytest tests/unit/test_superagent_models.py tests/unit/test_superagent_store.py tests/unit/test_superagent_policy.py tests/unit/test_superagent_service.py tests/unit/test_superagent_pcap_coordinator.py -q
```

Expected: all pass; existing Prompt mission expected plans, events, tools, and statuses are unchanged.

- [ ] **Step 6: Commit**

```powershell
git add backend/app/superagent backend/app/pcap/models.py tests/unit/test_superagent_models.py tests/unit/test_superagent_store.py tests/unit/test_superagent_service.py tests/unit/test_superagent_pcap_coordinator.py
git commit -m "feat: coordinate pcap evidence missions"
```

---

### Task 5: Wire PCAP Capabilities, Authorization, Mission Polling, and Cancellation APIs

**Files:**
- Modify: `backend/app/main.py`
- Modify: `backend/app/api/superagent.py`
- Modify: `tests/integration/test_superagent_api.py`
- Modify: `tests/integration/test_health_api.py`
- Modify: `tests/unit/test_verify_lab_privacy.py`

**Interfaces:**
- Produces: `GET /api/v1/superagent/pcap/capabilities`.
- Produces: `GET /api/v1/superagent/pcap/overview`.
- Produces: `POST /api/v1/superagent/pcap/authorizations`.
- Extends: `POST /api/v1/superagent/missions` with discriminated PCAP requests while preserving Prompt requests.
- Produces: `POST /api/v1/superagent/missions/{mission_id}/cancel` for PCAP missions only.
- Preserves: existing capabilities and mission response bodies for Prompt mode.

- [ ] **Step 1: Write failing API tests for disabled state and explicit authorization**

```python
def test_pcap_api_is_unavailable_without_configuration_and_does_not_change_prompt_capabilities() -> None:
    prompt = client.get("/api/v1/superagent/capabilities")
    pcap = client.get("/api/v1/superagent/pcap/capabilities")
    assert prompt.json() == existing_prompt_capabilities_payload()
    assert pcap.status_code == 503
    assert pcap.json()["error"]["code"] == "pcap_triage_unavailable"


def test_pcap_mission_requires_one_time_authorization() -> None:
    overview = client.get("/api/v1/superagent/pcap/overview")
    unauthorized = client.post("/api/v1/superagent/missions", json={
        "objective": "triage_pcap_evidence",
        "authorization_id": "pcap_auth_" + "f" * 32,
    })
    receipt = client.post("/api/v1/superagent/pcap/authorizations", json={
        "confirmed": True,
        "max_files": 20,
    })
    started = client.post("/api/v1/superagent/missions", json={
        "objective": "triage_pcap_evidence",
        "authorization_id": receipt.json()["authorization_id"],
    })
    reused = client.post("/api/v1/superagent/missions", json={
        "objective": "triage_pcap_evidence",
        "authorization_id": receipt.json()["authorization_id"],
    })
    assert overview.status_code == 200
    assert unauthorized.status_code == 403
    assert started.status_code == 201
    assert reused.status_code == 409
```

Add polling, cancellation, expired authorization, `confirmed=False`, max-files bounds, unknown Prompt mission behavior, and forbidden-field scans for every new response.

- [ ] **Step 2: Run integration tests and observe missing routes**

Run:

```powershell
pytest tests/integration/test_superagent_api.py tests/integration/test_health_api.py -q
```

Expected: new endpoints return 404 or validation errors before implementation.

- [ ] **Step 3: Add opt-in lifespan wiring and deterministic health**

Import and call `PcapConfig.from_environ(os.environ)` from `main.py`. Create the authorization store, executor, and coordinator only when configuration validates. Add each disposable state name to `_LIFESPAN_STATE_NAMES`; close the coordinator in lifespan cleanup. PCAP initialization failure sets only the PCAP capability reason to unavailable and must not prevent Prompt SuperAgent startup.

- [ ] **Step 4: Add routes and fixed error mapping**

Map internal failures to fixed public codes only:

```text
pcap_triage_unavailable       503
pcap_authorization_required  403
pcap_authorization_expired   410
pcap_authorization_used      409
pcap_mission_not_cancellable 409
pcap_batch_failed            500
```

Do not include exception strings. Keep the existing `/capabilities`, Prompt `POST /missions`, and Prompt `GET /missions/{id}` success/error payloads byte-for-byte compatible.

- [ ] **Step 5: Run API, health, and privacy regression tests**

Run:

```powershell
pytest tests/integration/test_superagent_api.py tests/integration/test_health_api.py tests/unit/test_verify_lab_privacy.py -q
```

Expected: all pass and private sentinel hit count is zero.

- [ ] **Step 6: Commit**

```powershell
git add backend/app/main.py backend/app/api/superagent.py tests/integration/test_superagent_api.py tests/integration/test_health_api.py tests/unit/test_verify_lab_privacy.py
git commit -m "feat: expose authorized pcap agent missions"
```

---

### Task 6: Add the PCAP SuperAgent Workspace Without Changing Prompt Mode

**Files:**
- Create: `frontend/src/pages/PcapSuperAgentWorkspace.tsx`
- Create: `frontend/src/PcapSuperAgentWorkspace.test.tsx`
- Modify: `frontend/src/types.ts`
- Modify: `frontend/src/api.ts`
- Modify: `frontend/src/pages/SuperAgentPage.tsx`
- Modify: `frontend/src/SuperAgentPage.test.tsx`
- Modify: `frontend/src/styles.css`

**Interfaces:**
- Produces: typed API methods `pcapCapabilities`, `pcapOverview`, `authorizePcapBatch`, `createPcapMission`, `getSuperAgentMission`, and `cancelPcapMission`.
- Produces: `<PcapSuperAgentWorkspace />` with no Prompt/Lab scenario dependency.
- Preserves: Prompt mode is the default and keeps storage key `token-security-superagent-mission-id`.
- Produces: PCAP-only storage key `token-security-superagent-pcap-mission-id`.

- [ ] **Step 1: Write failing frontend mode and authorization tests**

```tsx
it("keeps Prompt investigation as the default unchanged mode", async () => {
  render(<App />);
  expect(await screen.findByLabelText("任务场景")).toBeVisible();
  expect(screen.getByRole("button", { name: "启动自主任务" })).toBeEnabled();
  expect(fetch).not.toHaveBeenCalledWith("/api/v1/superagent/pcap/overview", expect.anything());
});

it("does not authorize or start PCAP until the second confirmation click", async () => {
  render(<App />);
  fireEvent.click(await screen.findByRole("button", { name: "PCAP 证据分诊" }));
  expect(await screen.findByText("待处理文件 2318")).toBeVisible();
  expect(requestsTo("/pcap/authorizations")).toHaveLength(0);
  fireEvent.click(screen.getByRole("button", { name: "准备开始" }));
  expect(requestsTo("/pcap/authorizations")).toHaveLength(0);
  fireEvent.click(screen.getByRole("button", { name: "确认并开始" }));
  expect(requestsTo("/pcap/authorizations")).toHaveLength(1);
  expect(requestsTo("/superagent/missions")).toContainEqual(expect.objectContaining({ objective: "triage_pcap_evidence" }));
});
```

Also test disabled PCAP capability, max-files range, polling until terminal, refresh restoration from the PCAP-only key, cancellation, fixed error copy, and Prompt storage isolation.

- [ ] **Step 2: Run tests and observe missing PCAP workspace**

Run:

```powershell
Set-Location frontend
npm.cmd test -- PcapSuperAgentWorkspace.test.tsx SuperAgentPage.test.tsx
```

Expected: PCAP mode/button/component assertions fail.

- [ ] **Step 3: Add discriminated TypeScript contracts and API methods**

Keep current `SuperAgentMissionRequest` and `SuperAgentMissionResult` interfaces unchanged. Add separate PCAP interfaces and this union:

```ts
export type SuperAgentStoredMission = SuperAgentMissionResult | PcapMissionResult;

export interface PcapAuthorizationRequest { confirmed: true; max_files: number; }
export interface PcapMissionRequest {
  objective: "triage_pcap_evidence";
  authorization_id: string;
}
```

`getSuperAgentMission` returns the union; Prompt call sites narrow on `objective`. Do not add `pcap_batch_triage` to `LabToolId` or `superAgentToolLabels`.

- [ ] **Step 4: Implement the additive task switch and PCAP workspace shell**

Add an icon+text segmented control above the existing Prompt form:

```tsx
<div className="superagent-task-switch" role="group" aria-label="SuperAgent 任务类型">
  <button aria-pressed={taskKind === "prompt"} onClick={() => setTaskKind("prompt")}>Prompt 安全调查</button>
  <button aria-pressed={taskKind === "pcap"} onClick={() => setTaskKind("pcap")}>PCAP 证据分诊</button>
</div>
```

Render all existing Prompt markup unmodified when `taskKind === "prompt"`. Mount `PcapSuperAgentWorkspace` only in PCAP mode, so its overview API is not called during normal Prompt use. Use an explicit inline confirmation surface; do not auto-start from mode selection, refresh, polling, or restoration.

- [ ] **Step 5: Run focused tests, all frontend tests, and build**

Run:

```powershell
Set-Location frontend
npm.cmd test -- PcapSuperAgentWorkspace.test.tsx SuperAgentPage.test.tsx
npm.cmd test
npm.cmd run build
```

Expected: all pass and build exits `0`; existing `/analyze` and `/challenge` tests remain unchanged.

- [ ] **Step 6: Commit**

```powershell
git add frontend/src/pages/PcapSuperAgentWorkspace.tsx frontend/src/PcapSuperAgentWorkspace.test.tsx frontend/src/types.ts frontend/src/api.ts frontend/src/pages/SuperAgentPage.tsx frontend/src/SuperAgentPage.test.tsx frontend/src/styles.css
git commit -m "feat: add pcap superagent workspace mode"
```

---

### Task 7: Reuse the Original Mascot Assets for PCAP Evidence Playback

**Files:**
- Create: `frontend/src/pcap/investigation.ts`
- Create: `frontend/src/pcap/investigation.test.ts`
- Create: `frontend/src/components/PcapMascotTeam.tsx`
- Create: `frontend/src/components/PcapMascotTeam.test.tsx`
- Create: `frontend/src/components/PcapEvidenceDesk.tsx`
- Create: `frontend/src/components/PcapEvidenceDesk.test.tsx`
- Modify: `frontend/src/pages/PcapSuperAgentWorkspace.tsx`
- Modify: `frontend/src/PcapSuperAgentWorkspace.test.tsx`
- Modify: `frontend/src/styles.css`

**Interfaces:**
- Produces: `PcapInvestigationState`, `selectPcapRole`, `roleStateForPcap`, and `buildPcapRoleLines`.
- Produces: `PcapMascotTeam` using `/mascots/guard-detective.webp`, `/mascots/cpd-detective.webp`, and `/mascots/agent-captain.webp`.
- Produces: Guard -> CPD -> Captain click/review flow over a terminal `PcapMissionResult`.
- Preserves: existing `MascotTeam.tsx`, challenge investigation functions, challenge CSS selectors, and challenge behavior.

- [ ] **Step 1: Write failing pure-state and component tests**

```ts
it("unlocks Guard then CPD then Captain and allows completed-role review", () => {
  let state = initialPcapInvestigationState();
  expect(roleStateForPcap(state, "guard")).toBe("ready");
  expect(roleStateForPcap(state, "cpd")).toBe("locked");
  state = finishPcapRole(selectPcapRole(state, "guard"));
  expect(roleStateForPcap(state, "cpd")).toBe("ready");
  state = finishPcapRole(selectPcapRole(state, "cpd"));
  state = finishPcapRole(selectPcapRole(state, "captain"));
  expect(selectPcapRole(state, "guard").selectedRole).toBe("guard");
});
```

```tsx
it("uses the three original mascot assets and never invents Token evidence", () => {
  render(<PcapMascotTeam mission={networkOnlyMission} />);
  expect(screen.getByRole("img", { name: "Guard 语义侦探" })).toHaveAttribute("src", "/mascots/guard-detective.webp");
  expect(screen.getByRole("img", { name: "CPD 曲线侦探" })).toHaveAttribute("src", "/mascots/cpd-detective.webp");
  expect(screen.getByRole("img", { name: "Agent 小队队长" })).toHaveAttribute("src", "/mascots/agent-captain.webp");
  fireEvent.click(screen.getByRole("button", { name: "Guard 语义侦探" }));
  expect(screen.getByText("尚未恢复 Prompt，语义证据暂不可用")).toBeVisible();
  expect(screen.queryByText(/异常 Token 起点/)).not.toBeInTheDocument();
});
```

Test original-position hop state, next-role cue, locked controls, reduced motion, completed-role replay, encrypted evidence, `token_eligible` wording, and captain separation of confirmed/candidate/unknown findings.

- [ ] **Step 2: Run focused tests and observe missing components**

Run:

```powershell
Set-Location frontend
npm.cmd test -- pcap/investigation.test.ts components/PcapMascotTeam.test.tsx components/PcapEvidenceDesk.test.tsx
```

Expected: module/component-not-found failures.

- [ ] **Step 3: Implement deterministic role evidence builders**

Guard lines may contain only content visibility and the explicit absence of recovered semantic evidence. CPD lines may contain protocol eligibility and the explicit absence of model/Token evidence. Captain lines contain counts plus `已证实`, `候选`, and `未知` sections. Build every line from validated mission fields; never display API error bodies or hidden fields.

Use a 420 ms line-reveal interval for the first playback, immediate complete replay for visited roles, and no timers when `prefers-reduced-motion: reduce` matches.

- [ ] **Step 4: Implement PCAP-only mascot markup and styles**

Use a new `pcap-mascot-*` CSS namespace and stable grid dimensions. Apply the hop animation only to the current ready/presenting mascot image wrapper with `translateY`; never move a mascot into the center or resize the lineup. Add the next-click cue above the ready role. Import image URLs from the same public paths; do not duplicate or regenerate the assets.

- [ ] **Step 5: Run focused, full frontend, and challenge-specific tests**

Run:

```powershell
Set-Location frontend
npm.cmd test -- pcap/investigation.test.ts components/PcapMascotTeam.test.tsx components/PcapEvidenceDesk.test.tsx ChallengePage.test.tsx components/MascotTeam.test.tsx
npm.cmd test
npm.cmd run build
```

Expected: all pass; the unchanged challenge tests prove no game regression.

- [ ] **Step 6: Commit**

```powershell
git add frontend/src/pcap frontend/src/components/PcapMascotTeam.tsx frontend/src/components/PcapMascotTeam.test.tsx frontend/src/components/PcapEvidenceDesk.tsx frontend/src/components/PcapEvidenceDesk.test.tsx frontend/src/pages/PcapSuperAgentWorkspace.tsx frontend/src/PcapSuperAgentWorkspace.test.tsx frontend/src/styles.css
git commit -m "feat: replay pcap evidence with original mascots"
```

---

### Task 8: Privacy Verification, Documentation, and End-to-End Acceptance

**Files:**
- Create: `scripts/verify_pcap_agent_privacy.py`
- Create: `tests/unit/test_verify_pcap_agent_privacy.py`
- Create: `docs/pcap-superagent.md`
- Modify: `README.md`
- Modify: `docs/advanced-task/test-report.md`

**Interfaces:**
- Produces: `python scripts/verify_pcap_agent_privacy.py --base-url http://127.0.0.1:8000 --repo-root .`.
- Verifies: endpoint key allowlists, forbidden sentinel absence, Git tracking exclusions, and objective separation.
- Documents: opt-in startup, safe UI workflow, result meanings, limitations, cancellation/resume, and competition demonstration language.

- [ ] **Step 1: Write failing privacy-verifier tests**

```python
def test_verifier_rejects_private_keys_and_tracked_capture_files(tmp_path: Path) -> None:
    server = PublicApiFixture(pcap_summary={"path": "PRIVATE_SENTINEL"})
    result = run_verifier(tmp_path, server.base_url)
    assert result.returncode == 1
    assert "privacy_violation_count=1" in result.stdout
    assert "PRIVATE_SENTINEL" not in result.stdout + result.stderr


def test_verifier_accepts_redacted_pcap_agent_responses(tmp_path: Path) -> None:
    server = PublicApiFixture(pcap_summary=valid_public_batch_summary())
    result = run_verifier(tmp_path, server.base_url)
    assert result.returncode == 0
    assert "privacy_violation_count=0" in result.stdout
```

The verifier must check the new PCAP capabilities, overview, authorization validation, mission create/restore, and cancel validation endpoints without reading a real capture. It must run `git ls-files` and fail if tracked names end in `.pcap`, `.pcapng`, or match private report/state patterns.

- [ ] **Step 2: Run the verifier tests and observe missing-script failure**

Run:

```powershell
pytest tests/unit/test_verify_pcap_agent_privacy.py -q
```

Expected: missing verifier script failure.

- [ ] **Step 3: Implement the verifier and fixed summary output**

Use explicit endpoint schemas and recursive forbidden-key detection. Print only aggregate lines:

```text
pcap_agent_privacy_verification=passed
checked_endpoint_count=6
privacy_violation_count=0
tracked_private_artifact_count=0
```

Never print response bodies, filenames, paths, capture IDs, authorization IDs, or mission IDs.

- [ ] **Step 4: Document operator and competition workflow**

`docs/pcap-superagent.md` must explain:

1. PCAP is optional and disabled by default.
2. Configure absolute repository-external quarantine and PowerShell paths.
3. Build the existing inspector image and run the existing sandbox verifier.
4. Start backend/frontend normally; Prompt mode remains default.
5. Select PCAP mode, inspect count-only overview, confirm one batch, poll, cancel/resume, and review the three mascots.
6. Say “网络证据分诊” for traffic-only results and “明文应用协议候选” for `token_eligible`; do not say “检测到 jailbreak” or “异常 Token”.
7. Explain that actual Prompt recovery and Token analysis require a separate, evidence-producing content recovery module and are unavailable in this first release.

Update README with a short link and update the test report only with observed command totals and explicit limitations.

- [ ] **Step 5: Run all automated verification before real data**

Run from repository root:

```powershell
pytest -q
python scripts/verify_pcap_agent_privacy.py --base-url http://127.0.0.1:8000 --repo-root .
Set-Location frontend
npm.cmd test
npm.cmd run build
```

Expected: no failures, privacy violation count `0`, tracked private artifact count `0`, and production build success.

- [ ] **Step 6: Run the existing Docker sandbox verifier**

Run:

```powershell
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File scripts/verify_pcap_sandbox.ps1
```

Expected: every existing sandbox assertion passes before the Agent is permitted to inspect real files.

- [ ] **Step 7: Perform the user-confirmed 20-file acceptance run**

This step requires a fresh explicit user confirmation in the UI. Do not invoke the batch script directly against real PCAP files as a substitute for authorization.

After the user clicks `确认并开始`, verify through public fields only:

```text
selected_count <= 20
succeeded_count + failed_count + skipped_count = selected_count
each capture_id matches ^capture_[0-9a-f]{32}$
no CPD/onset/Token fields appear
mission reaches completed, cancelled, or degraded
```

Cancel once between files, start a newly authorized mission, and verify unchanged successes skip while failures retry. Do not print or record original file identity.

- [ ] **Step 8: Inspect Git and run the unchanged challenge smoke flow**

Run:

```powershell
git status --short
git ls-files "*.pcap" "*.pcapng" "*pcap-batch*.json" "*pcap-batch-private*" "*.cancel"
```

Expected: the second command prints nothing. Open `/analyze`, `/super-agent`, and `/challenge`; verify Prompt analysis, existing SuperAgent Prompt mode, and the original three-round challenge behave as before. On mobile `390x844`, verify the PCAP mode has no horizontal overflow and all confirmation/cancel/mascot controls remain usable.

- [ ] **Step 9: Commit documentation and verification evidence**

```powershell
git add scripts/verify_pcap_agent_privacy.py tests/unit/test_verify_pcap_agent_privacy.py docs/pcap-superagent.md README.md docs/advanced-task/test-report.md
git commit -m "docs: verify pcap superagent delivery"
```

---

## Final Review Gate

Before declaring the feature complete, compare every item in `docs/superpowers/specs/2026-09-01-pcap-batch-superagent-design.md` against the implemented tests and observed outputs. Reject completion if any existing test regresses, if real processing occurred without a fresh UI authorization, if a prohibited field crosses the Agent boundary, if Git tracks a private artifact, or if any network-only result is described as Entropy-CPD, jailbreak, or Token anomaly.
