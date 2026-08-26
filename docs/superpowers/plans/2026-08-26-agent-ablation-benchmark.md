# Agent Ablation Benchmark Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a frozen, privacy-safe benchmark that compares semantic-only, Entropy-CPD-only, and the production fusion agent across semantic hazards, optimized suffix attacks, benign prompts, and benign distribution shifts.

**Architecture:** A protected collector calls the existing analysis API once per Prompt and stores normalized observations outside Git. A pure evaluation module selects FPR-constrained profiles on dev, freezes them, and computes aggregate-only test metrics. Strict loaders expose only validated aggregate reports to the existing evaluation API and Web page.

**Tech Stack:** Python 3.11/3.12, Pydantic v2, FastAPI, httpx/urllib, pytest, React 19, TypeScript, Vitest.

## Global Constraints

- Preserve `qwen25-7b-cpd-paper-v2`, the production `EvidenceFusionPolicy`, and the existing schema v2 report bytes.
- Raw Prompt, suffix text, Token text, Guard raw output, per-sample API response, and protected observation cache never enter Git, SQLite, aggregate reports, logs, screenshots, or Web responses.
- Use group-aware SHA-256 `20/20/60` splits; profile selection reads dev only and test evaluation reads a frozen profile only.
- Report fixed production behavior plus dev-selected `FPR <= 0.10` and `FPR <= 0.05` operating points.
- If no candidate satisfies an FPR constraint, set `constraint_satisfied=false` and never label it a low-FPR success.
- Only source-verified attack families enter headline metrics. Unverified BEAST remains a coverage gap.
- `review` and `block` count as binary risk-positive, while action counts remain separate.
- Knowledge mode stays `off` during detector benchmarking.
- All committed JSON is ASCII, deterministic, schema-strict, and aggregate-only.

---

### Task 1: Evaluation Contracts and FPR-Constrained Profile Selection

**Files:**
- Create: `backend/app/evaluation/ablation.py`
- Create: `tests/unit/test_ablation_evaluation.py`

**Interfaces:**
- Produces: `EvaluationDomain`, `AblationMethod`, `OperatingPoint`, `AblationObservation`, `AblationProfile`, `AblationMethodReport`, `AgentAblationReport`
- Produces: `select_ablation_profiles(observations: Sequence[AblationObservation], *, dataset_hash: str) -> tuple[AblationProfile, ...]`
- Produces: `evaluate_ablation(observations: Sequence[AblationObservation], profiles: Sequence[AblationProfile], *, benchmark_version: str, dataset_hash: str, source_coverage: Mapping[str, str]) -> AgentAblationReport`

- [x] **Step 1: Write strict contract and privacy failing tests**

```python
def test_observation_rejects_prompt_and_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        AblationObservation.model_validate({**safe_observation(), "prompt": "PRIVATE"})


def test_report_is_aggregate_only() -> None:
    report = evaluate_ablation(safe_observations(), fixed_profiles(),
        benchmark_version="agent-ablation-v1", dataset_hash="sha256:" + "a" * 64,
        source_coverage={"gcg": "verified"})
    payload = report.model_dump_json()
    assert "sample_id" not in payload
    assert "prompt" not in payload.casefold()
```

- [x] **Step 2: Run red tests**

Run: `python -m pytest tests/unit/test_ablation_evaluation.py -q`

Expected: collection fails because `app.evaluation.ablation` does not exist.

- [x] **Step 3: Implement strict enums and models**

Use `ConfigDict(extra="forbid", frozen=True)`. Domains are `benign_plain`, `benign_shift`, `semantic_unsafe`, and `optimized_suffix`. Methods are `semantic_only`, `cpd_only`, and `fusion`. Operating points are `production`, `fpr_10`, and `fpr_05`. Observation fields are normalized only:

```python
sample_id: str
group_id: str
split: Literal["calibration", "dev", "test"]
domain: EvaluationDomain
label_risky: bool
attack_family: str | None
semantic_severity: SemanticSeverity
semantic_verification: Literal["performed", "unavailable"]
detector_score: float
production_cpd_alarm: bool
predicted_onset: int | None
suffix_start: int | None
suffix_end: int | None
semantic_latency_ms: float
total_latency_ms: float
```

- [x] **Step 4: Write profile-selection red tests**

Cover semantic policy choice, CPD threshold choice, fusion through the real `EvidenceFusionPolicy`, deterministic tie breaks, and an unsatisfied constraint:

```python
def test_unsatisfied_fpr_constraint_is_explicit() -> None:
    profiles = select_ablation_profiles(impossible_fpr_rows(), dataset_hash=HASH)
    profile = find_profile(profiles, "fusion", "fpr_05")
    assert profile.constraint_satisfied is False
    assert profile.dev_false_positive_rate == min_candidate_fpr(impossible_fpr_rows())
```

- [x] **Step 5: Implement deterministic profile selection**

For semantic-only enumerate `unsafe_only` and `controversial_or_unsafe`. For CPD enumerate unique finite dev detector scores plus a threshold above the maximum. For fusion apply each CPD candidate through `EvidenceFusionPolicy(mode="analysis")` with the unchanged semantic severity. Rank candidates by constraint satisfaction, recall, precision, negative FPR, and conservative threshold/policy.

- [x] **Step 6: Write aggregate metric red tests**

Assert TP/FP/TN/FN, precision/recall/F1/FPR, domain error rates, family recall, action counts, P50/P95 latency, localization count/MAE/in-suffix rate, requested/completed/failed counts, and source coverage gaps.

- [x] **Step 7: Implement aggregate evaluation**

Reject duplicate IDs, mixed splits, unknown profile dataset hashes, missing method/operating-point pairs, non-finite values, and suffix coordinates on non-suffix rows. Output sorted method, family, domain, and source keys for deterministic serialization.

- [x] **Step 8: Run Task 1 tests and backend regression**

```powershell
$env:PYTHONPATH=".localdeps;backend"
python -m pytest tests/unit/test_ablation_evaluation.py -q
python -m pytest -q
```

- [x] **Step 9: Commit Task 1**

```powershell
git add backend/app/evaluation/ablation.py tests/unit/test_ablation_evaluation.py
git commit -m "feat: evaluate frozen agent ablations"
```

---

### Task 2: Strict Manifest, Profile, and Report I/O

**Files:**
- Create: `backend/app/evaluation/ablation_io.py`
- Create: `tests/unit/test_ablation_io.py`

**Interfaces:**
- Produces: `SourceRevision`, `AblationSplitManifest`, `AblationBenchmarkManifest`
- Produces: `load_ablation_manifest(path: Path) -> AblationBenchmarkManifest`
- Produces: `load_ablation_profiles(path: Path, *, expected_dataset_hash: str) -> tuple[AblationProfile, ...]`
- Produces: `load_ablation_report(path: Path, *, expected_benchmark_version: str) -> AgentAblationReport`
- Produces: `write_ascii_json(path: Path, payload: BaseModel) -> None`

- [x] **Step 1: Write manifest validation red tests**

Reject Prompt fields, duplicate IDs, overlap among calibration/dev/test group IDs, count mismatches, invalid SHA-256, mutable source URLs without revision, and unknown fields. Accept a minimal manifest with four domains and source coverage.

- [x] **Step 2: Run red tests**

Run: `python -m pytest tests/unit/test_ablation_io.py -q`

- [x] **Step 3: Implement strict loaders and forbidden-key scan**

Recursively reject keys matching `prompt`, `suffix`, `token_text`, `raw_output`, `guard_raw_output`, and `query_text`, except normalized coordinate keys `suffix_start` and `suffix_end` in protected observations, which are never accepted by committed manifest/report loaders.

- [x] **Step 4: Write deterministic serialization tests**

Write the same profile/report twice and assert byte equality, ASCII-only bytes, final newline, sorted keys, and reload equality.

- [x] **Step 5: Implement deterministic ASCII writer**

Use `json.dumps(model.model_dump(mode="json"), ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"`. Refuse overwrite when benchmark version or dataset hash differs from the existing file.

- [x] **Step 6: Run Task 2 tests**

Run: `python -m pytest tests/unit/test_ablation_io.py tests/unit/test_ablation_evaluation.py -q`

- [x] **Step 7: Commit Task 2**

```powershell
git add backend/app/evaluation/ablation_io.py tests/unit/test_ablation_io.py
git commit -m "feat: validate ablation benchmark artifacts"
```

---

### Task 3: Protected API Observation Collector

**Files:**
- Create: `scripts/collect_agent_ablation.py`
- Create: `tests/unit/test_ablation_collector_cli.py`

**Interfaces:**
- Input JSONL: protected records containing `sample_id`, `group_id`, `split`, `domain`, `label_risky`, optional family/coordinates, and `prompt`
- Output JSONL: protected `AblationObservation` records without Prompt, Token text, evidence, knowledge, or raw model output
- CLI: `collect_agent_ablation.py --input-jsonl <protected> --api-base <url> --output-jsonl <protected> --model-id <id> --resume`

- [x] **Step 1: Write collector privacy red test**

Use a local fake HTTP server that returns extra `prompt`, `signals`, `evidence`, and raw fields. Assert output contains only `AblationObservation` fields, request uses `knowledge_mode=off`, stdout contains counts only, and exceptions never include Prompt text.

- [x] **Step 2: Run red test**

Run: `python -m pytest tests/unit/test_ablation_collector_cli.py -q`

- [x] **Step 3: Implement one-call collector**

Validate protected input with a script-local strict model, call `/api/analyze` once per sample, derive only normalized observation fields, write through a temporary file followed by atomic rename, and keep errors as `{sample_id, error_type}` in a separate protected file.

- [x] **Step 4: Add resume and identity tests**

Assert resume skips completed IDs, rejects duplicate or unknown IDs, refuses a different API deployment identity, and never appends across benchmark hashes.

- [x] **Step 5: Implement resume metadata**

Persist a protected sidecar containing benchmark hash, API model ID, calibration version, semantic model version, and completed ID count. Do not persist Prompt or API response bodies.

- [x] **Step 6: Run Task 3 tests**

Run: `python -m pytest tests/unit/test_ablation_collector_cli.py -q`

- [x] **Step 7: Commit Task 3**

```powershell
git add scripts/collect_agent_ablation.py tests/unit/test_ablation_collector_cli.py
git commit -m "feat: collect protected ablation observations"
```

---

### Task 4: Source Registry and Frozen Manifest Builder

**Files:**
- Create: `configs/ablation_sources.json`
- Create: `scripts/build_ablation_manifest.py`
- Create: `tests/unit/test_ablation_manifest_cli.py`
- Modify: `THIRD_PARTY_NOTICES.md`

**Interfaces:**
- CLI: `build_ablation_manifest.py --input-jsonl <protected> --sources <json> --output <manifest> --benchmark-version agent-ablation-v1 --seed token-security-agent-ablation-v1`
- Verified initial revisions:
  - CPDonline `1a6c055865c44cc1d10dfbe5d014576c7331322e`
  - AutoDAN-HGA `34062e964185693e81a6775b4f0d00bfd7507612`
  - AdvPrompter `802a500c91f1dcd7c8b76869d3e39bf8e40ed7d7`
  - GCG/llm-attacks `098262edf85f807224e70ecd87b9d83716bf6b73`
  - HarmBench `8e1604d1171fe8a48d8febecd22f600e462bdcdd`
  - XSTest/exaggerated-safety `d7bb5bd738c1fcbc36edd83d5e7d1b71a3e2d84d`
  - BEAST status `source_unavailable`

- [x] **Step 1: Write source registry and manifest red tests**

Assert registry requires HTTPS URL, 40-character lowercase revision, SPDX license, attribution, and expected file SHA-256 for verified sources. Assert unavailable sources require a reason and cannot contribute sample IDs.

- [x] **Step 2: Run red tests**

Run: `python -m pytest tests/unit/test_ablation_manifest_cli.py -q`

- [x] **Step 3: Implement protected manifest builder**

Validate domains/labels (`benign_*` false, unsafe/suffix true), group near-duplicates through input group IDs, call existing `split_by_group`, verify domain/family coverage, and write only IDs, groups, counts, hashes, and source revisions.

- [x] **Step 4: Add leakage and reproducibility tests**

Assert no Prompt fragment appears in manifest/stdout/errors, same seed produces byte-identical output, changed group changes dataset hash, and all split group intersections are empty.

- [x] **Step 5: Create audited source registry and notices**

Store verified repository URL/revision/license metadata. Keep file SHA-256 entries in unavailable state until the exact protected source file is mounted and audited; such sources cannot enter verified coverage. Update notices with repository attribution and explain that no attack text is redistributed.

- [x] **Step 6: Run Task 4 tests and privacy scan**

```powershell
python -m pytest tests/unit/test_ablation_manifest_cli.py tests/unit/test_ablation_io.py -q
Select-String -Path configs/ablation_sources.json -Pattern 'prompt|suffix_text|raw_output'
```

Expected: tests pass and privacy scan returns no matches.

- [x] **Step 7: Commit Task 4**

```powershell
git add configs/ablation_sources.json scripts/build_ablation_manifest.py tests/unit/test_ablation_manifest_cli.py THIRD_PARTY_NOTICES.md
git commit -m "feat: freeze ablation source manifest"
```

---

### Task 5: Profile Selection and Test Evaluation CLIs

**Files:**
- Create: `scripts/select_ablation_profiles.py`
- Create: `scripts/evaluate_agent_ablation.py`
- Create: `tests/unit/test_ablation_cli.py`

**Interfaces:**
- Selection CLI reads manifest + protected dev observations and writes protected/frozen profile JSON.
- Evaluation CLI reads manifest + frozen profile + protected test observations and writes aggregate report JSON.

- [x] **Step 1: Write split-isolation red tests**

Assert selector rejects test rows, evaluator rejects dev/calibration rows, profile hash mismatch fails, missing observation IDs fail, extra IDs fail, and neither stdout nor report includes sample IDs.

- [x] **Step 2: Run red tests**

Run: `python -m pytest tests/unit/test_ablation_cli.py -q`

- [x] **Step 3: Implement selector CLI**

Load dev IDs from manifest, require exact observation identity, call `select_ablation_profiles`, and write deterministic profile JSON containing only thresholds/policies, dev aggregate selection metrics, dataset hash, and method/operating-point IDs.

- [x] **Step 4: Implement evaluator CLI**

Load test IDs and frozen profiles, require exact identity, call `evaluate_ablation`, add requested/completed/failed counts from a normalized protected error summary, and write the aggregate report atomically.

- [x] **Step 5: Add forbidden-key and failure-count tests**

Feed fake observations with private marker values and API failure records. Assert private values and sample IDs are absent while failure type counts and requested/completed totals remain correct.

- [x] **Step 6: Run Task 5 tests and backend regression**

```powershell
python -m pytest tests/unit/test_ablation_cli.py tests/unit/test_ablation_evaluation.py tests/unit/test_ablation_io.py -q
python -m pytest -q
```

- [x] **Step 7: Commit Task 5**

```powershell
git add scripts/select_ablation_profiles.py scripts/evaluate_agent_ablation.py tests/unit/test_ablation_cli.py
git commit -m "feat: run split-isolated ablation benchmark"
```

---

### Task 6: Evaluation API and Web Presentation

**Files:**
- Modify: `backend/app/evaluation/service.py`
- Modify: `backend/app/api/evaluation.py`
- Modify: `tests/unit/test_evaluation_service.py`
- Modify: `tests/integration/test_evaluation_api.py`
- Modify: `frontend/src/types.ts`
- Modify: `frontend/src/pages/EvaluationPage.tsx`
- Modify: `frontend/src/App.test.tsx`
- Modify: `frontend/src/styles.css`

**Interfaces:**
- Extends evaluation response with optional `agent_ablation` node.
- Displays fixed production, FPR 10%, and FPR 5% columns for three methods without exposing observations.

- [ ] **Step 1: Write backend report-loading red tests**

Assert a valid report loads, absent/invalid report leaves existing evaluation ready, version/hash mismatch is unavailable, and response contains no sample-level fields.

- [ ] **Step 2: Run backend red tests**

Run: `python -m pytest tests/unit/test_evaluation_service.py tests/integration/test_evaluation_api.py -q`

- [ ] **Step 3: Implement optional backend report node**

Read `TOKEN_SECURITY_AGENT_ABLATION_REPORT_PATH` at bootstrap, validate with `load_ablation_report`, and preserve the existing schema v2 and knowledge nodes byte-for-byte when no ablation report is configured.

- [ ] **Step 4: Write frontend red tests**

Assert the page shows method names, production/FPR columns, semantic/suffix recall, benign-shift FPR, source coverage gap, constraint-unsatisfied label, and no sample ID or Prompt marker.

- [ ] **Step 5: Run frontend red tests**

Run: `npm.cmd test -- --run`

- [ ] **Step 6: Implement unframed ablation section**

Add a dense comparison table with local horizontal scroll on mobile, compact metric labels, and explicit copy: `冻结 test 聚合结果；知识增强不参与判定`. Do not add cards inside the existing evaluation cards.

- [ ] **Step 7: Run backend/frontend tests and build**

```powershell
python -m pytest -q
Set-Location frontend
npm.cmd test -- --run
npm.cmd run build
Set-Location ..
```

- [ ] **Step 8: Commit Task 6**

```powershell
git add backend/app/evaluation/service.py backend/app/api/evaluation.py tests frontend/src
git commit -m "feat: present frozen agent ablations"
```

---

### Task 7: AutoDL Execution, Privacy Acceptance, and Competition Report

**Files:**
- Create: `data/agent-ablation-v1-manifest.json`
- Create: `data/agent-ablation-v1-report.json`
- Create: `docs/basic-task/ablation-report.md`
- Modify: `docs/basic-task/experiment-report.md`
- Modify: `docs/basic-task/test-report.md`
- Modify: `docs/basic-task/demo-script-3min.md`
- Modify: `README.md`

- [ ] **Step 1: Audit mounted protected sources**

For each source file compute SHA-256, validate license/revision against `configs/ablation_sources.json`, and record verified/unavailable status. Do not copy raw files from AutoDL to the workstation.

- [ ] **Step 2: Build and freeze `agent-ablation-v1` manifest**

Run the manifest builder on AutoDL, copy only the aggregate manifest to `data/`, verify no Prompt hits, and record its SHA-256 before profile selection.

- [ ] **Step 3: Collect observations once**

Use the running AutoDL API with `knowledge_mode=off`, resume on interruption, verify deployment identity matches Qwen2.5-7B + `qwen25-7b-cpd-paper-v2` + Qwen3Guard, and keep cache/error files under `/root/autodl-tmp/token-security-results/agent-ablation-v1/`.

- [ ] **Step 4: Select dev profiles and freeze them**

Run selector against dev only, record profile SHA-256, then make the profile read-only before any test evaluation.

- [ ] **Step 5: Run test evaluation once**

Generate aggregate report, copy only report JSON to `data/`, and record requested/completed/failed counts, OOM count, GPU memory, and wall-clock duration.

- [ ] **Step 6: Perform privacy and integrity scans**

Verify protected Prompt hits are zero in Git, aggregate JSON, API logs, SQLite, and screenshots. Verify original schema v2 report hash remains `8dffdd87a734740cbf71ddf8a85701a3a85f324373ad9f7855f7cd613ebd3c87`.

- [ ] **Step 7: Write evidence-bounded competition report**

Document source coverage, split/hash, fixed and constrained operating points, three-method metrics, family/domain results, localization, latency, failures, limitations, and whether fusion actually improves over each single route. Do not claim unavailable BEAST coverage.

- [ ] **Step 8: Run full final verification**

```powershell
$env:PYTHONPATH=".localdeps;backend"
python -m pytest -q
Set-Location frontend
npm.cmd test -- --run
npm.cmd run build
Set-Location ..
git diff --check
git diff --cached --check
```

- [ ] **Step 9: Commit Task 7**

```powershell
git add data/agent-ablation-v1-manifest.json data/agent-ablation-v1-report.json docs README.md
git commit -m "docs: report frozen agent ablation results"
```
