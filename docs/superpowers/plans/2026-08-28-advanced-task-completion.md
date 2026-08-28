# Advanced Task Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the competition advanced task with an 18-card offline official knowledge snapshot, separated retrieval/report experiments, and three user-confirmed in-platform tools that create persistent, redacted, verifiable receipts.

**Architecture:** Preserve the basic detection result as an immutable upstream snapshot. Extend the existing SQLite FTS5 knowledge layer and strict grounded-report boundary, then add a separate SQLite execution store and executor service behind the existing lab API. Keep `/analyze` unchanged; expose previews and confirmed execution only in `/lab`.

**Tech Stack:** Python 3.11, FastAPI, Pydantic 2, SQLite/FTS5, pytest, React 19, TypeScript 5.8, Vite 7, Vitest, AutoDL RTX 4090 D, Qwen2.5-7B report runtime.

## Global Constraints

- The project title remains “面向 AI 安全的 Token 流量异常检测智能体平台”.
- Knowledge retrieval, report generation, and tools must never weaken or rewrite the basic `Decision`.
- Raw Prompt, attack suffix, Token text/IDs, retrieval query, model raw output, and hidden reasoning must not enter Git, public API payloads, SQLite, logs, reports, screenshots, or downloadable artifacts.
- Knowledge is offline and deterministic; do not add a vector database or online retrieval.
- Real tools act only inside this platform and require explicit user confirmation; do not claim external firewall, EDR, SIEM, or ticket-system integration.
- Keep the current dry-run behavior for comparison.
- Use only development data for tuning. Run each frozen test once and do not tune on its output.
- Retrieval targets: Hit@3 >= 0.95, citation validity = 1.0, decision invariance = 1.0.
- Report targets: generated rate >= 0.90, citation validity = 1.0, decision invariance = 1.0, P95 <= 5000 ms.
- Report failures must return a deterministic fallback and a fixed failure code without exposing raw model output.
- `/analyze` remains stable. UI changes are isolated to `/lab`.
- BEAST and AutoDAN-HGA remain unverified and must not be described as covered.

## File Structure

### Knowledge and experiments

- Modify `backend/app/knowledge/models.py`: add three risk domains and the CAC publisher/official host rules.
- Modify `backend/app/knowledge/reporting.py`: compact report input and expose fixed internal failure codes.
- Modify `backend/app/bootstrap.py`: load the versioned selected report configuration.
- Modify `backend/app/evaluation/knowledge.py`: identify development/test split in generated reports.
- Create `backend/app/evaluation/grounded_report.py`: report experiment schemas, deterministic selection, and aggregate metrics.
- Modify `scripts/evaluate_knowledge.py`: emit split-aware v2 retrieval reports.
- Create `scripts/evaluate_grounded_reports.py`: run the 9 development configurations and one frozen test with aggregate-only output.
- Create `knowledge/sources/official-v2.cards.json`: 18 reviewed official-source cards.
- Create `knowledge/snapshots/official-v2/cards.json` and `manifest.json`: reproducible generated snapshot.
- Create `data/knowledge-evaluation-v2-development.json` and `data/knowledge-evaluation-v2-test.json`: 36 redacted metadata cases each.
- Create `data/knowledge-evaluation-v2-development-report.json` and `data/knowledge-evaluation-v2-test-report.json`: generated retrieval results.
- Create `data/report-generation-config-v2.json`: mechanically selected development configuration; contains no samples or outputs.
- Create `data/report-generation-development-report-v2.json` and `data/report-generation-test-report-v2.json`: aggregate report metrics and fixed failure counts only.

### Real tool execution

- Modify `backend/app/lab/models.py`: replace preview-only tool IDs and reference execution response models.
- Create `backend/app/lab/execution_models.py`: request, execution, receipt, case, and artifact schemas.
- Create `backend/app/lab/execution_store.py`: SQLite schema, transactions, idempotency, list, and artifact reads.
- Create `backend/app/lab/executors.py`: gateway receipt, security case, and canonical evidence bundle builders.
- Modify `backend/app/lab/tools.py`: keep side-effect-free previews using the same real tool IDs.
- Modify `backend/app/lab/service.py`: coordinate run lookup, immutable action derivation, executor, and store.
- Modify `backend/app/api/lab.py`: confirmed execution, execution list, and evidence download endpoints.
- Modify `backend/app/main.py`: create/close the lab execution store and expose truthful readiness.
- Modify `frontend/src/types.ts`: execution, receipt, and artifact types.
- Modify `frontend/src/api.ts`: confirmed execution/list/download methods.
- Create `frontend/src/components/LabToolCenter.tsx`: previews, confirmation, receipts, retry-safe busy state, and download.
- Modify `frontend/src/pages/LabPage.tsx`: replace the preview-only sandbox panel with the tool center.
- Modify `frontend/src/styles.css`: compact responsive tool center styles.

### Verification and documentation

- Extend existing knowledge, report, lab, API, privacy, and frontend tests.
- Modify `scripts/verify_lab_privacy.ps1`: inspect all new API/SQLite/artifact surfaces.
- Modify `docs/advanced-task/design.md`, `experiment-report.md`, and `test-report.md`: record v2 architecture and measured results only.

---

### Task 1: Extend the official knowledge schema and build `official-v2`

**Files:**
- Modify: `backend/app/knowledge/models.py`
- Modify: `tests/unit/test_knowledge_loader.py`
- Modify: `tests/unit/test_knowledge_snapshot_cli.py`
- Create: `knowledge/sources/official-v2.cards.json`
- Create: `knowledge/snapshots/official-v2/cards.json`
- Create: `knowledge/snapshots/official-v2/manifest.json`

**Interfaces:**
- Produces: `KnowledgePublisher.CAC`; `RiskDomain.SUPPLY_CHAIN`, `DATA_MODEL_POISONING`, `UNBOUNDED_RESOURCE_CONSUMPTION`; a valid 18-card `KnowledgeSnapshot` named `official-v2`.
- Consumes: existing `build_snapshot(source: Path, output_dir: Path, snapshot_version: str) -> bytes`.

- [ ] **Step 1: Write failing publisher, domain, and snapshot tests**

Add tests that validate the new enum values, accept `https://www.cac.gov.cn/2023-07/13/c_1690898327029107.htm` only for `publisher="cac"`, accept `https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf` for NIST, reject CAC content hosted elsewhere, and assert:

```python
snapshot = load_knowledge_snapshot(Path("knowledge/snapshots/official-v2"))
assert snapshot.manifest.snapshot_version == "official-v2"
assert snapshot.manifest.card_count == 18
assert {card.risk_domain.value for card in snapshot.cards} >= {
    "supply_chain",
    "data_model_poisoning",
    "unbounded_resource_consumption",
}
assert {card.source.publisher.value for card in snapshot.cards} == {
    "owasp", "mitre", "nist", "cac"
}
```

- [ ] **Step 2: Run the focused tests and verify failure**

Run:

```powershell
python -m pytest tests/unit/test_knowledge_loader.py tests/unit/test_knowledge_snapshot_cli.py -v
```

Expected: FAIL because the CAC publisher, three risk domains, and `official-v2` snapshot do not exist.

- [ ] **Step 3: Add the schema values and official host allowlists**

Implement these exact enum values and hosts:

```python
class KnowledgePublisher(StrEnum):
    OWASP = "owasp"
    MITRE = "mitre"
    NIST = "nist"
    CAC = "cac"

class RiskDomain(StrEnum):
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    SENSITIVE_INFORMATION = "sensitive_information"
    EXCESSIVE_AGENCY = "excessive_agency"
    SUPPLY_CHAIN = "supply_chain"
    DATA_MODEL_POISONING = "data_model_poisoning"
    UNBOUNDED_RESOURCE_CONSUMPTION = "unbounded_resource_consumption"
    GOVERNANCE = "governance"
    INCIDENT_RESPONSE = "incident_response"
```

Extend the host map with `nvlpubs.nist.gov` for NIST and `www.cac.gov.cn` for CAC.

- [ ] **Step 4: Create the 18-card source and reproducible snapshot**

Copy all 12 `official-v1` source cards unchanged, then append these IDs and sources with Chinese summaries, indicators, recommendations, and retrieval tags derived only from the linked official documents:

```text
owasp-llm03-supply-chain
  https://genai.owasp.org/llmrisk/llm03-supply-chain/
owasp-llm04-data-model-poisoning
  https://genai.owasp.org/llmrisk/llm04-data-and-model-poisoning/
owasp-llm10-unbounded-consumption
  https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/
nist-ai-600-1-genai-profile
  https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf
cac-generative-ai-interim-measures
  https://www.cac.gov.cn/2023-07/13/c_1690898327029107.htm
cac-ai-generated-content-labeling
  https://www.cac.gov.cn/2025-03/14/c_1743654684782215.htm
```

Verify each URL returns an official page before recording `verified_at=2026-08-28T00:00:00Z`. Build the snapshot:

```powershell
python scripts/build_knowledge_snapshot.py `
  --source knowledge/sources/official-v2.cards.json `
  --output-dir knowledge/snapshots/official-v2 `
  --snapshot-version official-v2
```

- [ ] **Step 5: Run the focused tests and snapshot reproducibility check**

Run:

```powershell
python -m pytest tests/unit/test_knowledge_loader.py tests/unit/test_knowledge_snapshot_cli.py -v
python scripts/build_knowledge_snapshot.py --source knowledge/sources/official-v2.cards.json --output-dir tmp/official-v2-rebuild --snapshot-version official-v2
git diff --no-index knowledge/snapshots/official-v2 tmp/official-v2-rebuild
```

Expected: tests PASS and `git diff --no-index` returns no content differences.

- [ ] **Step 6: Commit the schema and snapshot**

```powershell
git add backend/app/knowledge/models.py tests/unit/test_knowledge_loader.py tests/unit/test_knowledge_snapshot_cli.py knowledge/sources/official-v2.cards.json knowledge/snapshots/official-v2
git commit -m "feat: add official v2 knowledge snapshot"
```

### Task 2: Create separated 72-case retrieval evaluation

**Files:**
- Modify: `backend/app/evaluation/knowledge.py`
- Modify: `scripts/evaluate_knowledge.py`
- Modify: `tests/unit/test_knowledge_evaluation.py`
- Modify: `tests/unit/test_knowledge_evaluation_cli.py`
- Create: `data/knowledge-evaluation-v2-development.json`
- Create: `data/knowledge-evaluation-v2-test.json`
- Create: `data/knowledge-evaluation-v2-development-report.json`
- Create: `data/knowledge-evaluation-v2-test-report.json`

**Interfaces:**
- Produces: `EvaluationSplit = Literal["development", "test"]`; `evaluate_knowledge(snapshot: KnowledgeSnapshot, cases: list[KnowledgeEvaluationCase], *, split: EvaluationSplit) -> KnowledgeEvaluationReport`; report fields `split` and `target_status`.
- Consumes: `official-v2` and existing deterministic FTS5 search.

- [ ] **Step 1: Write failing split and target-status tests**

Test that the report records its split and mechanically evaluates targets:

```python
report = evaluate_knowledge(snapshot, cases, split="development")
assert report.split == "development"
assert report.target_status == {
    "hit_at_3": report.hit_at_3 >= 0.95,
    "citation_validity": report.citation_validity == 1.0,
    "decision_invariance": report.decision_invariance == 1.0,
}
```

Also test that a value other than `development` or `test` is rejected and that serialized reports contain none of `safe_terms`, `query_text`, or `case_id`.

- [ ] **Step 2: Run focused tests and verify failure**

```powershell
python -m pytest tests/unit/test_knowledge_evaluation.py tests/unit/test_knowledge_evaluation_cli.py -v
```

Expected: FAIL because reports are not split-aware.

- [ ] **Step 3: Implement split-aware reports without changing retrieval weights**

Add:

```python
EvaluationSplit = Literal["development", "test"]

class KnowledgeEvaluationReport(BaseModel):
    # existing fields remain
    split: EvaluationSplit
    decision_invariance_basis: Literal["retrieval_has_no_decision_output"]
    target_status: dict[Literal[
        "hit_at_3", "citation_validity", "decision_invariance"
    ], bool]
```

Pass `split` through `evaluate_knowledge` and add required CLI argument `--split` with the two choices. Compute retrieval-layer invariance by recursively asserting that every retrieval result contains no `decision` field, rather than assigning `1.0` unconditionally; label this basis in the report. The protected report experiment in Task 4 separately compares real pre/post decisions. Keep tag weight 2.0, lexical weight 1.0, Top-3, and ID tie-breaking unchanged.

- [ ] **Step 4: Author development and frozen fixtures**

Create exactly 4 redacted metadata cases per risk domain per split: `9 domains x 4 = 36`. Use only `safe_terms`, normalized metadata, and expected knowledge IDs. Enforce disjoint IDs using prefixes `dev-v2-` and `test-v2-`; do not include Prompt or attack instructions.

Run a schema-only load before evaluation:

```powershell
python -c "import json; from pydantic import TypeAdapter; from app.evaluation.knowledge import KnowledgeEvaluationCase; [print(p, len(TypeAdapter(list[KnowledgeEvaluationCase]).validate_python(json.load(open(p, encoding='utf-8'))))) for p in ['data/knowledge-evaluation-v2-development.json','data/knowledge-evaluation-v2-test.json']]"
```

Expected: each file prints `36`.

- [ ] **Step 5: Tune only the development card tags, then freeze**

Run development evaluation after each change to source-card retrieval tags. Do not change scoring weights:

```powershell
python scripts/evaluate_knowledge.py --snapshot knowledge/snapshots/official-v2 --fixture data/knowledge-evaluation-v2-development.json --split development --output data/knowledge-evaluation-v2-development-report.json
```

Stop changing cards when development Hit@3 reaches at least 0.95 or when all official wording variants have been represented. Rebuild `official-v2` after a card edit.

- [ ] **Step 6: Run the frozen test exactly once and evaluate targets**

```powershell
python scripts/evaluate_knowledge.py --snapshot knowledge/snapshots/official-v2 --fixture data/knowledge-evaluation-v2-test.json --split test --output data/knowledge-evaluation-v2-test-report.json
python -c "import json; r=json.load(open('data/knowledge-evaluation-v2-test-report.json')); print(r['target_status']); assert r['citation_validity']==1.0; assert r['decision_invariance']==1.0"
```

Record the result without further tuning, whether or not Hit@3 reaches 0.95.

- [ ] **Step 7: Run tests and commit**

```powershell
python -m pytest tests/unit/test_knowledge_evaluation.py tests/unit/test_knowledge_evaluation_cli.py -v
git add backend/app/evaluation/knowledge.py scripts/evaluate_knowledge.py tests/unit/test_knowledge_evaluation.py tests/unit/test_knowledge_evaluation_cli.py data/knowledge-evaluation-v2-*.json knowledge/sources/official-v2.cards.json knowledge/snapshots/official-v2
git commit -m "test: add frozen v2 knowledge evaluation"
```

### Task 3: Make grounded report generation compact and diagnosable

**Files:**
- Modify: `backend/app/knowledge/reporting.py`
- Modify: `tests/unit/test_grounded_reporting.py`
- Modify: `tests/unit/test_knowledge_service.py`

**Interfaces:**
- Produces: `ReportFailureCode`; `ReportGeneration.failure_code`; `build_report_messages(facts, evidence) -> list[dict[str, str]]`.
- Consumes: `NormalizedSecurityFacts`, Top-3 `KnowledgeEvidence`, and `StructuredRuntime.generate_structured`.

- [ ] **Step 1: Write failing compact-prompt and fixed-error tests**

Test that the model input contains only these evidence fields:

```python
allowed_evidence_keys = {
    "knowledge_id", "title_zh", "risk_domain", "summary", "recommendations"
}
```

Test mappings:

```text
TimeoutError                         -> runtime_timeout
other runtime exception             -> runtime_error
malformed JSON                       -> invalid_report_json
schema violation                    -> invalid_report_schema
unknown knowledge_id                -> invalid_report_citation
```

Every failure must return `status="fallback"`, a deterministic report, and no raw output field.

- [ ] **Step 2: Run focused tests and verify failure**

```powershell
python -m pytest tests/unit/test_grounded_reporting.py tests/unit/test_knowledge_service.py -v
```

Expected: FAIL because `ReportGeneration` has no fixed failure code and the prompt serializes full source metadata.

- [ ] **Step 3: Implement the compact message builder and typed failure mapping**

Add:

```python
ReportFailureCode = Literal[
    "runtime_timeout",
    "runtime_error",
    "invalid_report_json",
    "invalid_report_schema",
    "invalid_report_citation",
]

class ReportGeneration(BaseModel):
    report: GroundedReport
    status: ReportStatus
    failure_code: ReportFailureCode | None = None
```

Make `GroundedReportError` store one of the three validation codes. Catch `TimeoutError`, `GroundedReportError`, and other exceptions separately. Build evidence payloads explicitly from the five allowed fields rather than `model_dump()` of the complete card.

- [ ] **Step 4: Verify deterministic fallback and action invariance**

```powershell
python -m pytest tests/unit/test_grounded_reporting.py tests/unit/test_knowledge_service.py -v
```

Expected: PASS; the report schema still has no `decision` output field and fallback citations are a subset of Top-3.

- [ ] **Step 5: Commit**

```powershell
git add backend/app/knowledge/reporting.py tests/unit/test_grounded_reporting.py tests/unit/test_knowledge_service.py
git commit -m "feat: harden grounded report generation"
```

### Task 4: Build and run the development/frozen report experiment

**Files:**
- Create: `backend/app/evaluation/grounded_report.py`
- Create: `scripts/evaluate_grounded_reports.py`
- Create: `tests/unit/test_grounded_report_evaluation.py`
- Create: `tests/unit/test_grounded_report_evaluation_cli.py`
- Modify: `backend/app/bootstrap.py`
- Modify: `tests/unit/test_bootstrap.py`
- Create: `data/report-generation-config-v2.json`
- Create: `data/report-generation-development-report-v2.json`
- Create: `data/report-generation-test-report-v2.json`

**Interfaces:**
- Produces: `ReportExperimentConfig(max_new_tokens, timeout_seconds)`; `select_report_config(results) -> ReportExperimentConfig`; aggregate `ReportExperimentReport`; `TOKEN_SECURITY_KNOWLEDGE_REPORT_CONFIG_PATH` loader.
- Consumes: a protected local sample service, Qwen2.5-7B runtime, `QwenGroundedReportGenerator`, and `official-v2`.

- [ ] **Step 1: Write failing metric, privacy, disjointness, and selector tests**

Use synthetic fake runtimes to assert:

```python
assert set(candidate_pairs) == {
    (64, 3.0), (64, 5.0), (64, 6.0),
    (96, 3.0), (96, 5.0), (96, 6.0),
    (128, 3.0), (128, 5.0), (128, 6.0),
}
assert report.generated_rate == generated / total
assert report.citation_validity == 1.0
assert report.action_invariance == 1.0
```

The selector order is exact: prefer candidates with P95 <= 5000 ms, then higher generated rate, then citation validity, then lower P95, then fewer tokens, then shorter timeout. Reject overlapping hashed sample IDs between development and frozen test. Serialized output must not include sample IDs, Prompt, suffix, Token text, or raw output.

- [ ] **Step 2: Run tests and verify failure**

```powershell
python -m pytest tests/unit/test_grounded_report_evaluation.py tests/unit/test_grounded_report_evaluation_cli.py tests/unit/test_bootstrap.py -v
```

Expected: FAIL because the evaluator and versioned config loader do not exist.

- [ ] **Step 3: Implement aggregate schemas and deterministic experiment selection**

Define aggregate output fields:

```python
class ReportExperimentMetrics(BaseModel):
    total_count: int
    generated_count: int
    fallback_count: int
    generated_rate: float
    citation_validity: float
    action_invariance: float
    latency_p50_ms: float
    latency_p95_ms: float
    failure_counts: dict[ReportFailureCode, int]
    family_counts: dict[str, int]
```

Hash sample IDs in memory only to verify split disjointness; do not serialize hashes or IDs. Measure wall-clock generation latency for every sample. Validate every cited ID against that sample's Top-3 and compare the immutable pre/post decision.

- [ ] **Step 4: Implement the CLI and selected-config loader**

The CLI accepts `--phase development|test`, private sample source paths, snapshot path, output path, and selected-config path. Within each attack family, order candidates by `sha256("advanced-v2:" + family + ":" + sample_id)`; use the first 5 for development and the next 10 for frozen test. Keep those hashes in memory only. Development runs all nine candidates and writes the chosen pair. Test requires the chosen config and refuses to run if development aggregate is absent.

Make `KnowledgeConfig.from_environ` load and validate:

```json
{
  "schema_version": 1,
  "snapshot_version": "official-v2",
  "max_new_tokens": 96,
  "timeout_seconds": 5.0,
  "selection_rule": "p95_budget_generated_rate_citation_latency_size"
}
```

The numeric values shown are test fixtures; production values come from the mechanically selected development output. The environment key is `TOKEN_SECURITY_KNOWLEDGE_REPORT_CONFIG_PATH`.

- [ ] **Step 5: Verify locally with fake runtimes**

```powershell
python -m pytest tests/unit/test_grounded_report_evaluation.py tests/unit/test_grounded_report_evaluation_cli.py tests/unit/test_bootstrap.py -v
```

Expected: PASS with no GPU.

- [ ] **Step 6: Run the 15-sample development experiment on AutoDL**

Run with the protected local source already present on AutoDL. The evaluator must select 5 GCG, 5 AutoDAN, and 5 AdvPrompter cases and monitor each configuration until completion or its per-sample timeout. Write only aggregate output and the selected config to the repository work directory on AutoDL, then copy those two JSON files back.

The raw development aggregate is historical-only and its recorded action
invariance is superseded. Once the frozen report and correction artifact are
present, consume the experiment only through the effective summary command:

```powershell
python scripts/summarize_grounded_reports.py
```

Expected: `raw_artifact_status` is `historical_only_superseded`,
`action_invariance_evidence` is `legacy_unverified`, and effective
`target_status.action_invariance` is `false`.

- [ ] **Step 7: Run the disjoint 30-sample frozen test exactly once**

Use 10 different protected cases per family. Do not change prompt format, selected token limit, timeout, knowledge cards, or retrieval settings afterward. Copy back only `data/report-generation-test-report-v2.json`.

```powershell
python scripts/summarize_grounded_reports.py
```

Do not read the raw report as an effective status or assert its invalidated
action-invariance value. The effective command validates the correction and all
three bound historical artifacts before emitting status.

- [ ] **Step 8: Commit code and aggregate results**

```powershell
git add backend/app/evaluation/grounded_report.py scripts/evaluate_grounded_reports.py tests/unit/test_grounded_report_evaluation.py tests/unit/test_grounded_report_evaluation_cli.py backend/app/bootstrap.py tests/unit/test_bootstrap.py data/report-generation-config-v2.json data/report-generation-development-report-v2.json data/report-generation-test-report-v2.json
git commit -m "test: add frozen grounded report experiment"
```

### Task 5: Add typed execution models and transactional SQLite storage

**Files:**
- Modify: `backend/app/lab/models.py`
- Create: `backend/app/lab/execution_models.py`
- Create: `backend/app/lab/execution_store.py`
- Create: `tests/unit/test_lab_execution_models.py`
- Create: `tests/unit/test_lab_execution_store.py`

**Interfaces:**
- Produces: `LabToolId` values `gateway_enforcement`, `security_case`, `evidence_bundle`; `LabExecuteRequest`; `LabToolExecution`; `LabSecurityCase`; `LabArtifact`; `SQLiteLabExecutionStore`.
- Consumes: `Decision`, `KnowledgeId`, and `assert_public_payload`.

- [ ] **Step 1: Write failing model and privacy tests**

Define expected request validation:

```python
request = LabExecuteRequest(
    confirmed=True,
    idempotency_key=UUID("6f9619ff-8b86-d011-b42d-00cf4fc964ff"),
)
assert request.confirmed is True
```

Reject `confirmed=False`, malformed UUIDs, extra `action`, `url`, `command`, or `credential` fields, and any execution/case/artifact containing forbidden public keys.

- [ ] **Step 2: Write failing store tests**

Test schema creation, a successful atomic commit, ordering by `created_at`, retrieval by artifact ID, and uniqueness of `(run_id, tool_id, idempotency_key)`. Inject a failure while writing the artifact and assert neither execution nor artifact remains.

- [ ] **Step 3: Run tests and verify failure**

```powershell
python -m pytest tests/unit/test_lab_execution_models.py tests/unit/test_lab_execution_store.py -v
```

Expected: FAIL because the execution modules do not exist.

- [ ] **Step 4: Implement focused immutable models**

Use frozen Pydantic models and fixed status/error enums. `LabToolExecution` includes:

```text
execution_id, run_id, tool_id, idempotency_key, status,
effective_action, receipt_id, artifact_id, error_code,
evidence_sha256, latency_ms, created_at
```

`LabSecurityCase` contains exactly: `case_id`, `run_id`, `created_at`, `risk_score`, `semantic_severity`, `semantic_categories`, `detector_status`, `anomaly_char_start`, `fusion_reason`, `effective_action`, `handling_status`, `knowledge_ids`, `model_id`, `calibration_version`, `knowledge_snapshot_version`, `execution_id`, and `receipt_id`. `LabArtifact` contains `artifact_id`, `run_id`, `execution_id`, `media_type`, `payload: bytes`, `sha256`, and `created_at`; exclude raw `payload` from JSON serialization returned by API.

- [ ] **Step 5: Implement the SQLite store with one transaction per tool result**

Create tables `lab_tool_executions`, `lab_security_cases`, and `lab_artifacts`. Use a single connection with `check_same_thread=False`, a lock, foreign keys on, and explicit transaction context. Implement these exact public interfaces:

- `get_by_idempotency(self, run_id: str, tool_id: LabToolId, idempotency_key: UUID) -> LabToolExecution | None`
- `commit_result(self, execution: LabToolExecution, *, security_case: LabSecurityCase | None = None, artifact: LabArtifact | None = None) -> LabToolExecution`
- `list_executions(self, run_id: str) -> tuple[LabToolExecution, ...]`
- `get_artifact(self, artifact_id: str) -> LabArtifact`
- `close(self) -> None`

- [ ] **Step 6: Run tests and commit**

```powershell
python -m pytest tests/unit/test_lab_execution_models.py tests/unit/test_lab_execution_store.py -v
git add backend/app/lab/models.py backend/app/lab/execution_models.py backend/app/lab/execution_store.py tests/unit/test_lab_execution_models.py tests/unit/test_lab_execution_store.py
git commit -m "feat: add persistent lab tool records"
```

### Task 6: Implement the three real in-platform executors

**Files:**
- Create: `backend/app/lab/executors.py`
- Modify: `backend/app/lab/tools.py`
- Modify: `tests/unit/test_lab_tools.py`
- Create: `tests/unit/test_lab_executors.py`

**Interfaces:**
- Produces: `LabToolExecutor.execute(run: LabRunResult, tool_id: LabToolId, idempotency_key: UUID) -> ExecutionBundle`; `canonical_evidence_bytes(run: LabRunResult, executions: tuple[LabToolExecution, ...]) -> bytes`.
- Consumes: immutable `LabRunResult`, `SQLiteLabExecutionStore`, and v2 execution models.

- [ ] **Step 1: Write failing executor tests for all decisions and tools**

Parameterize gateway receipts:

```text
allow             -> allow_authorized
review            -> review_queued
sanitize_recheck  -> sanitize_recheck_queued
block             -> block_enforced
```

Assert the executor ignores no server value because it accepts no client action. Verify the security-case tool creates one redacted case. Verify the evidence-bundle tool creates canonical UTF-8 JSON, stable bytes for stable inputs, and `sha256:<64 lowercase hex>`.

- [ ] **Step 2: Write failure and no-external-side-effect tests**

Monkeypatch network and subprocess entry points to raise if called. Inject store failure and assert a fixed `persistence_failed` execution result whose effective action equals the immutable basic decision. Assert no filesystem artifact is created.

- [ ] **Step 3: Run tests and verify failure**

```powershell
python -m pytest tests/unit/test_lab_tools.py tests/unit/test_lab_executors.py -v
```

Expected: FAIL because only preview execution exists.

- [ ] **Step 4: Implement canonical builders and dispatcher**

Build IDs with prefixes `exec_`, `receipt_`, `case_`, and `artifact_` plus UUID hex. Evidence JSON uses `ensure_ascii=True`, `sort_keys=True`, and `separators=(",", ":")`, then appends one newline before hashing. Include only detector/model/calibration/snapshot versions, redacted result fields, knowledge IDs, and prior platform receipts.

Update `build_response_plan` and `execute_dry_run` to use the three real `LabToolId` values while remaining side-effect-free. Preview summaries must say “预览” and real summaries must say “平台内部执行”.

- [ ] **Step 5: Run tests and commit**

```powershell
python -m pytest tests/unit/test_lab_tools.py tests/unit/test_lab_executors.py -v
git add backend/app/lab/executors.py backend/app/lab/tools.py tests/unit/test_lab_tools.py tests/unit/test_lab_executors.py
git commit -m "feat: execute internal response tools"
```

### Task 7: Expose confirmed, idempotent execution APIs

**Files:**
- Modify: `backend/app/lab/service.py`
- Modify: `backend/app/api/lab.py`
- Modify: `backend/app/main.py`
- Modify: `tests/unit/test_lab_service.py`
- Modify: `tests/integration/test_lab_api.py`
- Create: `tests/integration/test_lab_artifact_api.py`

**Interfaces:**
- Produces: `LabService.execute_tool`, `LabService.list_executions`, `LabService.get_artifact`; three approved HTTP endpoints.
- Consumes: `LabToolExecutor`, `SQLiteLabExecutionStore`, existing in-memory `LabRunStore`.

- [ ] **Step 1: Write failing service tests**

Test that `execute_tool`:

1. loads the immutable server-side run;
2. returns an existing execution for the same idempotency key;
3. creates a new execution for a different key;
4. never allows a result action below `run.detection.decision`;
5. keeps persisted execution history after later dry-run calls.

- [ ] **Step 2: Write failing API tests**

Test exact routes and statuses. Execution requires a live run, while listing already persisted executions and downloading artifacts do not depend on the in-memory run TTL:

```text
POST /api/v1/lab/runs/{run_id}/tools/{tool_id}/execute confirmed=true -> 201
POST same key                         -> 200 and same execution_id
POST confirmed=false                  -> 422
POST unknown/expired run              -> 404/410
GET  /api/v1/lab/runs/{run_id}/executions -> 200 ordered list
GET  valid artifact/download           -> 200 application/json
GET  unknown artifact                  -> 404 fixed code
```

Recompute SHA-256 from downloaded bytes and compare it with the execution response.

- [ ] **Step 3: Run tests and verify failure**

```powershell
python -m pytest tests/unit/test_lab_service.py tests/integration/test_lab_api.py tests/integration/test_lab_artifact_api.py -v
```

Expected: FAIL because confirmed execution routes are absent.

- [ ] **Step 4: Implement service orchestration and fixed API errors**

Use these exact service interfaces:

- `execute_tool(self, run_id: str, tool_id: LabToolId, request: LabExecuteRequest) -> tuple[LabToolExecution, bool]`, where the Boolean is `newly_created`.
- `list_executions(self, run_id: str) -> tuple[LabToolExecution, ...]`
- `get_artifact(self, artifact_id: str) -> LabArtifact`

Return 201 for a new execution and 200 for idempotent replay. Serve `artifact.payload` via FastAPI `Response` with `Content-Disposition: attachment`, the stored media type, `ETag` equal to the SHA-256, and `X-Content-Type-Options: nosniff`.

- [ ] **Step 5: Wire store lifecycle and health**

Create `SQLiteLabExecutionStore(event_db_path_from_environ(os.environ))` in `main.lifespan`, inject it into `LabService`, close it in `finally`, and report `lab.tool_storage="sqlite"` only when construction succeeds. If storage fails, keep basic analysis available but mark real tools unavailable.

- [ ] **Step 6: Run tests and commit**

```powershell
python -m pytest tests/unit/test_lab_service.py tests/integration/test_lab_api.py tests/integration/test_lab_artifact_api.py -v
git add backend/app/lab/service.py backend/app/api/lab.py backend/app/main.py tests/unit/test_lab_service.py tests/integration/test_lab_api.py tests/integration/test_lab_artifact_api.py
git commit -m "feat: expose confirmed lab tool execution"
```

### Task 8: Build the `/lab` tool execution center

**Files:**
- Modify: `frontend/src/types.ts`
- Modify: `frontend/src/api.ts`
- Create: `frontend/src/components/LabToolCenter.tsx`
- Modify: `frontend/src/pages/LabPage.tsx`
- Modify: `frontend/src/styles.css`
- Modify: `frontend/src/LabPage.test.tsx`

**Interfaces:**
- Produces: `LabToolCenter` with preview, confirmation, restored execution history, receipt display, and evidence download.
- Consumes: `api.dryRunLabTool`, `api.executeLabTool`, `api.listLabExecutions`, and artifact download URL.

- [ ] **Step 1: Write failing frontend tests**

Cover these user-visible behaviors:

- The tab label becomes “工具执行中心”.
- Every tool has an icon preview button and a separate “确认执行” command.
- Clicking execute opens a confirmation dialog that says “仅在本平台内部执行”.
- Cancel sends no request.
- Confirm sends `{confirmed:true,idempotency_key:<uuid>}`.
- A busy tool disables both actions without resizing the row.
- Idempotent response renders one receipt, not duplicates.
- Refresh/list response restores receipt state.
- Evidence bundle renders SHA-256 and a download button.
- No Prompt, suffix, Token text, or hidden reasoning appears.

- [ ] **Step 2: Run the focused test and verify failure**

```powershell
Set-Location frontend
npm.cmd test -- --run src/LabPage.test.tsx
```

Expected: FAIL because only preview execution exists.

- [ ] **Step 3: Add exact TypeScript types and API methods**

Add:

```ts
export type LabToolId = "gateway_enforcement" | "security_case" | "evidence_bundle";
export type LabExecutionStatus = "succeeded" | "failed";
export interface LabToolExecution {
  execution_id: string;
  run_id: string;
  tool_id: LabToolId;
  status: LabExecutionStatus;
  effective_action: Decision;
  receipt_id: string | null;
  artifact_id: string | null;
  error_code: string | null;
  latency_ms: number;
  created_at: string;
  evidence_sha256: string | null;
}
```

Generate one UUID per confirmation attempt with `crypto.randomUUID()` and retain it until the request resolves so a retry uses the same key.

- [ ] **Step 4: Implement the focused tool-center component**

Use Lucide `Eye`, `Play`, `ShieldCheck`, `ClipboardCheck`, `FileDown`, `LoaderCircle`, and `CircleAlert` icons. Keep cards at 8 px radius or less. Use a native accessible `<dialog>` or the project’s existing modal pattern; focus the cancel button first. Do not place the tool center inside another decorative card.

Display “预览” and “平台内部执行” as distinct statuses. Do not retain the old “无外部副作用的沙箱” page copy after real tools are enabled.

- [ ] **Step 5: Add stable responsive styles**

Use a fixed tool row grid with `minmax(0, 1fr)` content and fixed-width action columns. At the existing mobile breakpoint, stack metadata above actions. Add `prefers-reduced-motion` handling for the loading icon and avoid layout movement during state transitions.

- [ ] **Step 6: Run frontend tests and build**

```powershell
Set-Location frontend
npm.cmd test -- --run src/LabPage.test.tsx
npm.cmd run build
```

Expected: focused tests PASS and production build succeeds.

- [ ] **Step 7: Commit**

```powershell
git add frontend/src/types.ts frontend/src/api.ts frontend/src/components/LabToolCenter.tsx frontend/src/pages/LabPage.tsx frontend/src/styles.css frontend/src/LabPage.test.tsx
git commit -m "feat: add lab tool execution center"
```

### Task 9: Extend privacy verification and full regression coverage

**Files:**
- Modify: `scripts/verify_lab_privacy.ps1`
- Modify: `tests/unit/test_verify_lab_privacy.py`
- Modify: `tests/unit/test_lab_models.py`
- Modify: `tests/integration/test_lab_api.py`
- Modify: `frontend/src/LabPage.test.tsx`

**Interfaces:**
- Produces: one privacy command that scans API responses, SQLite columns/values, downloaded artifacts, and frontend-rendered text.
- Consumes: all new execution surfaces.

- [ ] **Step 1: Write failing privacy-verifier tests**

Create a temporary SQLite DB and artifact fixture containing each forbidden key in turn. Assert the verifier fails for:

```text
prompt, suffix, token_text, token_id, query_text,
raw_output, guard_raw_output
```

Create a valid redacted execution database and assert the verifier passes. Include a sentinel private string in the analyzed request and assert it appears nowhere except the in-memory request input.

- [ ] **Step 2: Run privacy tests and verify failure**

```powershell
python -m pytest tests/unit/test_verify_lab_privacy.py tests/unit/test_lab_models.py tests/integration/test_lab_api.py -v
```

Expected: FAIL because the verifier does not inspect the new tables/artifacts.

- [ ] **Step 3: Extend the verifier without printing matched private values**

Report only surface name, forbidden key category, and count. Exit nonzero on any hit. Do not print SQL cell contents, artifact bodies, or HTTP response bodies.

- [ ] **Step 4: Run all backend and frontend tests**

```powershell
python -m pytest -q
Set-Location frontend
npm.cmd test -- --run
npm.cmd run build
```

Expected: all tests PASS and build succeeds. Record exact counts from the command output; do not reuse earlier counts.

- [ ] **Step 5: Run the live privacy smoke check through the AutoDL tunnel**

With the backend reachable at `http://127.0.0.1:18000`, run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/verify_lab_privacy.ps1 -BaseUrl http://127.0.0.1:18000
```

Expected: exit code 0 and zero violations. The script output must contain counts only.

- [ ] **Step 6: Commit**

```powershell
git add scripts/verify_lab_privacy.ps1 tests/unit/test_verify_lab_privacy.py tests/unit/test_lab_models.py tests/integration/test_lab_api.py frontend/src/LabPage.test.tsx
git commit -m "test: verify advanced task privacy boundary"
```

### Task 10: Browser QA and measured documentation

**Files:**
- Modify: `docs/advanced-task/design.md`
- Modify: `docs/advanced-task/experiment-report.md`
- Modify: `docs/advanced-task/test-report.md`

**Interfaces:**
- Produces: competition-ready evidence that distinguishes current measurements, missed targets, and unimplemented external integrations.
- Consumes: the effective grounded-report summary emitted by `python scripts/summarize_grounded_reports.py` for target status; committed v2 config and aggregate JSON artifacts only as historical-only superseded evidence; full test output, build output, and browser observations.

- [ ] **Step 1: Start the verified local frontend and backend/tunnel**

Confirm health reports `official-v2`, 18 cards, lab ready, and SQLite tool storage. Use a free frontend port if 5175 is occupied; do not terminate unrelated processes.

- [ ] **Step 2: Exercise all three tools in a desktop browser**

At 1440 x 900:

1. create one harmless run and one protected run;
2. preview each tool;
3. cancel one confirmation and verify no receipt appears;
4. execute gateway, case, and evidence tools;
5. repeat one request with the same idempotency key and verify no duplicate;
6. download the evidence JSON and recompute SHA-256;
7. refresh and verify execution history returns.

Check browser console for errors and confirm the UI says “平台内部执行”, not external linkage.

- [ ] **Step 3: Exercise responsive and reduced-motion behavior**

At 390 x 844, verify no horizontal overflow, no clipped command labels, and no overlap. Enable reduced motion and confirm the busy state remains understandable without continuous animation. Revisit `/analyze` and `/challenge` to verify their primary workflows are unchanged.

- [ ] **Step 4: Update documentation from measured artifacts only**

Before editing any of the three documentation files, first run:

```powershell
python scripts/summarize_grounded_reports.py
```

Only the effective summary output may supply target status to these documents.
The raw config, development aggregate, and frozen aggregate are
historical-only superseded original evidence; they must not be used as a source for action invariance or any target PASS.

In `experiment-report.md`, include:

- v1 baseline metrics labeled as baseline;
- v2 development and frozen retrieval metrics;
- all nine report development configurations;
- selected configuration and frozen 30-sample result;
- target met/missed status and fixed failure counts;
- no raw samples or outputs.

In `test-report.md`, include fresh backend/frontend/build counts, desktop/mobile QA, artifact hash verification, and privacy scan count. In `design.md`, update snapshot/tool architecture and retain the external-integration disclaimer.

- [ ] **Step 5: Run documentation and secret checks**

```powershell
git diff --check
git grep -n -I -E "PRIVATE_CONTINUATION|BEGIN .*PRIVATE KEY|Bearer [A-Za-z0-9]|raw_output|guard_raw_output" -- . ':!docs/superpowers/specs/*' ':!docs/superpowers/plans/*'
git status --short
```

Expected: no private sample/output or credential matches. References to forbidden field names are permitted only inside validator/test allowlists and must be manually reviewed.

- [ ] **Step 6: Commit final advanced-task evidence**

```powershell
git add docs/advanced-task/design.md docs/advanced-task/experiment-report.md docs/advanced-task/test-report.md
git commit -m "docs: complete advanced task evidence"
```

### Task 11: Final verification and branch review

**Files:**
- Review only; modify files only when a verified defect requires a focused fix and its regression test.

**Interfaces:**
- Produces: a clean, tested branch ready for user review and later integration.
- Consumes: Tasks 1-10.

- [ ] **Step 1: Run the complete verification suite from a clean prompt**

```powershell
python -m pytest -q
Set-Location frontend
npm.cmd test -- --run
npm.cmd run build
```

Return to the repository root and run:

```powershell
git diff --check
git status --short
```

- [ ] **Step 2: Review the cumulative diff against the approved design**

```powershell
git diff feature/basic-platform-foundation HEAD --stat
git log --oneline feature/basic-platform-foundation..HEAD
```

Verify every approved requirement maps to an implementation/test and that no final-task autonomy, external integration, or unverified attack-family claim entered the branch.

- [ ] **Step 3: Commit only verified review fixes**

For each defect, return to the task that owns the affected files, add one failing regression test, implement the smallest fix, rerun that task's exact focused command, and stage only the concrete files changed for that defect. Use commit message `fix: address advanced task review finding`.

If no defect is found, create no empty commit.

- [ ] **Step 4: Present the branch using the finishing workflow**

Before reporting grounded-report target status, rerun:

```powershell
python scripts/summarize_grounded_reports.py
```

Report only the effective summary's target statuses. Raw config, development,
and frozen aggregate values may be described only as historical-only
superseded evidence and cannot support action invariance or a target PASS.
Also report fresh test counts, measured v2 metrics, target misses, the live
`/lab` URL, privacy result, commit list, and the existing pull request. Do not
merge or push additional external changes without the user’s instruction.
