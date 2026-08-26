# Semantic Guard Fusion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在现有 Entropy-CPD 平台中接入 Qwen3Guard-Gen-0.6B，使直接危险语义与优化型后缀异常分别产生证据，并由固定策略统一处置。

**Architecture:** 每次分析顺序执行 Qwen3Guard 语义分类和现有 Qwen2.5-7B Entropy-CPD，随后由纯函数融合策略决定 allow/review/block。Guard 原始输出只在内存中严格解析，API、SQLite、日志和 Web 只接收规范化 severity、类别、模型版本与延迟。

**Tech Stack:** Python 3.11/3.12、Pydantic v2、FastAPI、SQLite、PyTorch、Transformers >=4.51、Qwen3Guard-Gen-0.6B、React 19、TypeScript、Vitest。

## Global Constraints

- Guard 模型固定为官方 `Qwen/Qwen3Guard-Gen-0.6B`，许可证 Apache-2.0。
- 两个检测器对正常分析请求都执行；第一版顺序推理，不做 GPU 并发。
- Guard severity 只允许 `safe | controversial | unsafe | unavailable`。
- Guard 类别只允许设计规格中的九个规范化类别。
- Guard 输出缺失、未知或无法解析时必须是 `unavailable`，不得默认 safe。
- CPD `detector_status` 与 Guard `semantic_severity` 必须保持独立。
- Prompt、suffix、Token 文本和 Guard 原始输出不得进入 Git、测试、日志、报告、截图或事件数据库。
- 现有 CPDonline schema v2 报告和 663 条冻结指标不得重新计算或修改。
- BEAST、AutoDAN-HGA 继续标记 `not_evaluated`。
- Git 作者身份未配置时只暂存文件并记录验证，不伪造提交身份。

---

### Task 1: Semantic Models and Strict Output Parser

**Files:**
- Create: `backend/app/semantic/__init__.py`
- Create: `backend/app/semantic/models.py`
- Create: `backend/app/semantic/parser.py`
- Create: `tests/unit/test_semantic_parser.py`

**Interfaces:**
- Produces: `SemanticSeverity`, `SemanticCategory`, `SemanticAssessment`
- Produces: `parse_guard_output(raw: str, *, model_id: str, model_version: str, latency_ms: float) -> SemanticAssessment`
- Produces: `SemanticOutputError(ValueError)`

- [ ] **Step 1: Write parser red tests**

Use only hand-authored classifier output, never a dangerous Prompt:

```python
def test_parses_unsafe_guard_output() -> None:
    result = parse_guard_output(
        "Safety: Unsafe\nCategories: Violent, Jailbreak",
        model_id="guard-model",
        model_version="guard-v1",
        latency_ms=12.0,
    )
    assert result.severity is SemanticSeverity.UNSAFE
    assert result.categories == [
        SemanticCategory.VIOLENT,
        SemanticCategory.JAILBREAK,
    ]

@pytest.mark.parametrize("raw", [
    "",
    "Safety: Unknown\nCategories: None",
    "Safety: Safe\nCategories: Unknown Category",
    "Safety: Safe",
])
def test_rejects_untrusted_guard_output(raw: str) -> None:
    with pytest.raises(SemanticOutputError):
        parse_guard_output(
            raw,
            model_id="guard-model",
            model_version="guard-v1",
            latency_ms=1.0,
        )
```

- [ ] **Step 2: Run red tests**

Run:

```powershell
$env:PYTHONPATH=".localdeps"
python -m pytest tests/unit/test_semantic_parser.py -q
```

Expected: collection fails because `app.semantic` does not exist.

- [ ] **Step 3: Implement fixed models and parser**

`SemanticAssessment` fields:

```python
severity: SemanticSeverity
categories: list[SemanticCategory]
model_id: NonEmptyText
model_version: NonEmptyText
latency_ms: float = Field(ge=0)
```

Map official category strings to enum values. Require exactly two non-empty result lines after whitespace normalization. `safe` requires `Categories: None`; unsafe or controversial may contain one or more known categories. Deduplicate categories while preserving official output order. Do not retain `raw` on any model or exception.

- [ ] **Step 4: Run parser tests**

Run the Task 1 tests and `tests/unit/test_schemas.py`. Expected: all pass.

- [ ] **Step 5: Record commit boundary**

```powershell
git add backend/app/semantic tests/unit/test_semantic_parser.py
git commit -m "feat: add strict semantic guard result parser"
```

If Git identity is absent, keep file changes without creating an identity.

---

### Task 2: Evidence Fusion Policy and Workflow Contract

**Files:**
- Create: `backend/app/agent/fusion.py`
- Create: `tests/unit/test_fusion_policy.py`
- Modify: `backend/app/schemas.py`
- Modify: `backend/app/agent/workflow.py`
- Modify: `tests/integration/test_basic_workflow.py`
- Modify: `tests/unit/test_schemas.py`

**Interfaces:**
- Consumes: `SemanticAssessment`, `SemanticSeverity`, existing `DetectorStatus`, `AnalysisRequest.mode`
- Produces: `FusionReason`
- Produces: `EvidenceFusionPolicy.decide(*, mode: Mode, semantic: SemanticSeverity, cpd_alarm: bool) -> tuple[Action, FusionReason]`
- Produces: extended `AnalysisResult` semantic fields

- [ ] **Step 1: Write the complete decision-table red test**

```python
@pytest.mark.parametrize(
    ("mode", "semantic", "alarm", "action", "reason"),
    [
        ("analysis", "unsafe", False, "block", "semantic_unsafe"),
        ("gateway", "unsafe", False, "block", "semantic_unsafe"),
        ("analysis", "controversial", False, "review", "semantic_controversial"),
        ("gateway", "controversial", True, "review", "semantic_controversial"),
        ("analysis", "safe", True, "block", "cpd_candidate"),
        ("gateway", "safe", True, "review", "cpd_candidate"),
        ("analysis", "safe", False, "allow", "all_clear"),
        ("gateway", "safe", False, "allow", "all_clear"),
        ("analysis", "unavailable", True, "block", "semantic_unavailable_cpd_candidate"),
        ("gateway", "unavailable", True, "review", "semantic_unavailable_cpd_candidate"),
        ("analysis", "unavailable", False, "allow", "semantic_unavailable_analysis_degraded"),
        ("gateway", "unavailable", False, "review", "semantic_unavailable_gateway_fail_safe"),
    ],
)
def test_fusion_table(mode, semantic, alarm, action, reason) -> None:
    result = EvidenceFusionPolicy().decide(
        mode=mode,
        semantic=SemanticSeverity(semantic),
        cpd_alarm=alarm,
    )
    assert result == (Action(action), FusionReason(reason))
```

- [ ] **Step 2: Run fusion red tests**

Expected: collection fails because `app.agent.fusion` is missing.

- [ ] **Step 3: Implement pure fusion policy**

Use explicit branches in priority order: unsafe, controversial, safe, unavailable. Reject unknown modes through the typed request schema. Do not use numeric risk thresholds for fusion.

- [ ] **Step 4: Write workflow semantic red tests**

Add a `StaticSemanticGuard` to `test_basic_workflow.py`. Assert:

```python
result = make_workflow(
    entropies=[0.0, 0.1, 0.0],
    semantic=SemanticAssessment(
        severity="unsafe",
        categories=["violent"],
        model_id="guard-model",
        model_version="guard-v1",
        latency_ms=4.0,
    ),
).analyze(...)
assert result.detector_status == "no_token_anomaly"
assert result.semantic_severity == "unsafe"
assert result.decision.value == "block"
assert result.fusion_reason == "semantic_unsafe"
```

Also assert safe+no-alarm allow, controversial review, safe+alarm mode behavior, and unavailable gateway fail-safe.

- [ ] **Step 5: Extend schema and workflow**

`AnalysisResult` adds:

```python
semantic_severity: SemanticSeverity
semantic_categories: list[SemanticCategory]
semantic_model_id: NonEmptyText
semantic_model_version: NonEmptyText
semantic_latency_ms: float = Field(ge=0)
semantic_verification: Literal["performed", "unavailable"]
fusion_reason: FusionReason
```

`BasicSecurityWorkflow.__init__` consumes `semantic_guard: SemanticGuard` and `fusion_policy: EvidenceFusionPolicy`. Call `semantic_guard.assess(request.prompt)` and the existing CPD path exactly once each. Replace direct policy overrides with `fusion_policy.decide`.

- [ ] **Step 6: Run Task 2 and regression tests**

```powershell
python -m pytest tests/unit/test_fusion_policy.py tests/integration/test_basic_workflow.py tests/unit/test_schemas.py -q
```

Expected: all pass, existing CPD scores and onset assertions unchanged.

- [ ] **Step 7: Record commit boundary**

```powershell
git add backend/app/agent/fusion.py backend/app/agent/workflow.py backend/app/schemas.py tests/unit/test_fusion_policy.py tests/integration/test_basic_workflow.py tests/unit/test_schemas.py
git commit -m "feat: fuse semantic and token anomaly evidence"
```

---

### Task 3: Qwen3Guard Runtime, Configuration, and Health

**Files:**
- Create: `backend/app/semantic/runtime.py`
- Create: `tests/unit/test_semantic_runtime.py`
- Modify: `backend/app/bootstrap.py`
- Modify: `backend/app/main.py`
- Modify: `pyproject.toml`
- Modify: `tests/unit/test_bootstrap.py`
- Modify: `tests/integration/test_health_api.py`

**Interfaces:**
- Consumes: Task 1 parser and semantic models
- Produces: `SemanticGuardReadiness`
- Produces: `QwenSemanticGuard(model_id: str, model_version: str, max_input_tokens: int, max_new_tokens: int)`
- Produces: `UnavailableSemanticGuard`
- Produces: `GuardConfig` from environment

- [ ] **Step 1: Write runtime red tests with fake tokenizer/model**

Assert that:

- `apply_chat_template([{"role": "user", "content": "SAFE_PLACEHOLDER"}], tokenize=False)` is used;
- generation uses `do_sample=False` and configured `max_new_tokens`;
- generated continuation excludes input IDs before decoding;
- input length above `max_input_tokens` raises `GuardInputTooLong`;
- parse/model exception returns an unavailable assessment without raw text.

- [ ] **Step 2: Run runtime red tests**

Expected: collection fails because `app.semantic.runtime` is missing.

- [ ] **Step 3: Implement runtime with injectable factories**

Follow the existing `TransformersModelRuntime` loading pattern. Load tokenizer and `AutoModelForCausalLM` with `torch_dtype="auto"`, `device_map="auto"`, and `eval()`. Keep raw decoded output in a local variable only; pass it directly to `parse_guard_output`, then discard it.

`UnavailableSemanticGuard.assess` returns:

```python
SemanticAssessment(
    severity="unavailable",
    categories=[],
    model_id="unconfigured",
    model_version="unconfigured",
    latency_ms=0.0,
)
```

- [ ] **Step 4: Write config and health red tests**

Test all-or-none validation for Guard path/version, integer bounds `1..4096` for input and `1..32` for output, and health:

```python
assert payload["semantic_guard"] == {
    "ready": True,
    "model_id": "/models/qwen-guard",
    "model_version": "revision-id",
}
```

When Guard is unconfigured, health is degraded with `semantic_guard.ready=false`; do not prevent local app startup.

- [ ] **Step 5: Wire bootstrap**

Add environment parsing:

```python
TOKEN_SECURITY_GUARD_MODEL_PATH
TOKEN_SECURITY_GUARD_MODEL_VERSION
TOKEN_SECURITY_GUARD_MAX_INPUT_TOKENS=4096
TOKEN_SECURITY_GUARD_MAX_NEW_TOKENS=32
```

Create and load Guard before constructing `BasicSecurityWorkflow`. Set the model optional dependency floor to `transformers>=4.51,<5`.

- [ ] **Step 6: Run Task 3 and full backend tests**

```powershell
python -m pytest tests/unit/test_semantic_runtime.py tests/unit/test_bootstrap.py tests/integration/test_health_api.py -q
python -m pytest -q
```

Expected locally: all non-GPU tests pass; existing real GPU test remains skipped when no local model is configured.

- [ ] **Step 7: Record commit boundary**

```powershell
git add backend/app/semantic/runtime.py backend/app/bootstrap.py backend/app/main.py pyproject.toml tests/unit/test_semantic_runtime.py tests/unit/test_bootstrap.py tests/integration/test_health_api.py
git commit -m "feat: load qwen semantic guard runtime"
```

---

### Task 4: Privacy-Safe Semantic Event Migration

**Files:**
- Modify: `backend/app/audit/models.py`
- Modify: `backend/app/audit/store.py`
- Modify: `backend/app/api/analyze.py`
- Modify: `tests/unit/test_event_store.py`
- Modify: `tests/integration/test_events_api.py`
- Modify: `tests/integration/test_analyze_api.py`

**Interfaces:**
- Consumes: extended `AnalysisResult`
- Produces: nullable semantic fields on legacy `SecurityEvent`
- Produces: idempotent SQLite schema migration

- [ ] **Step 1: Write migration and privacy red tests**

Create an old-schema SQLite database using the exact pre-Guard columns, initialize `SQLiteEventStore`, and assert new columns exist without deleting the old row. Append a new event and assert normalized fields round-trip:

```python
assert event.semantic_severity == "unsafe"
assert event.semantic_categories == ["violent"]
assert event.fusion_reason == "semantic_unsafe"
```

Scan database bytes and assert they do not contain the safe private fixture, `token_text`, `guard_raw_output`, or the hand-authored raw Guard result.

- [ ] **Step 2: Run event red tests**

Expected: schema/model assertions fail because semantic columns are absent.

- [ ] **Step 3: Implement idempotent migration**

After `CREATE TABLE IF NOT EXISTS`, inspect `PRAGMA table_info(security_events)`. Add missing columns individually with `ALTER TABLE`:

```sql
semantic_severity TEXT
semantic_categories TEXT
semantic_model_id TEXT
semantic_model_version TEXT
semantic_latency_ms REAL
fusion_reason TEXT
```

Serialize categories with compact JSON after sorting enum values. Legacy rows map fields to `None`; new rows validate fixed enums.

- [ ] **Step 4: Update analyze audit mapping**

Write only the normalized semantic fields from `AnalysisResult`. Do not log or persist Guard raw output. Audit failure behavior remains `audit_persisted=false`.

- [ ] **Step 5: Run Task 4 tests and database byte scan**

```powershell
python -m pytest tests/unit/test_event_store.py tests/integration/test_events_api.py tests/integration/test_analyze_api.py -q
```

Expected: migration is idempotent, old event remains readable, privacy assertions pass.

- [ ] **Step 6: Record commit boundary**

```powershell
git add backend/app/audit backend/app/api/analyze.py tests/unit/test_event_store.py tests/integration/test_events_api.py tests/integration/test_analyze_api.py
git commit -m "feat: audit normalized semantic evidence"
```

---

### Task 5: Demo and API Privacy Regression

**Files:**
- Modify: `backend/app/demo/service.py`
- Modify: `backend/app/api/demo.py`
- Modify: `tests/unit/test_demo_service.py`
- Modify: `tests/integration/test_demo_api.py`

**Interfaces:**
- Consumes: dual-evidence `BasicSecurityWorkflow`
- Produces: existing `DemoAnalysisResult` with normalized semantic evidence and redacted Token signals

- [ ] **Step 1: Extend demo red tests**

Use only safe synthetic CSV fixtures and a static Guard assessment. Assert:

```python
assert response["result"]["semantic_severity"] == "unsafe"
assert response["result"]["semantic_categories"] == ["jailbreak"]
assert all(item["token_text"] == "" for item in response["result"]["signals"])
assert all(item["token_id"] == 0 for item in response["result"]["signals"])
assert "Safety: Unsafe" not in response.text
```

Also scan serialized response for the synthetic source text and suffix fixture.

- [ ] **Step 2: Run demo red tests**

Expected: fails because the test workflow and response lack semantic fields.

- [ ] **Step 3: Update demo fixtures and preserve redaction**

Pass a static semantic Guard through the same workflow. Do not add a demo-only semantic result or alternate policy. Preserve `audit_persisted=false` and existing source checksum checks.

- [ ] **Step 4: Run demo and full backend tests**

```powershell
python -m pytest tests/unit/test_demo_service.py tests/integration/test_demo_api.py -q
python -m pytest -q
```

- [ ] **Step 5: Record commit boundary**

```powershell
git add backend/app/demo tests/unit/test_demo_service.py tests/integration/test_demo_api.py
git commit -m "test: preserve privacy in dual-evidence demos"
```

---

### Task 6: Web Dual-Evidence Presentation

**Files:**
- Modify: `frontend/src/types.ts`
- Modify: `frontend/src/pages/AnalyzePage.tsx`
- Modify: `frontend/src/pages/EventsPage.tsx`
- Modify: `frontend/src/pages/EvaluationPage.tsx`
- Modify: `frontend/src/App.test.tsx`
- Modify: `frontend/src/styles.css`

**Interfaces:**
- Consumes: extended analysis/event/health API responses
- Produces: separate semantic, CPD, and fusion evidence views

- [ ] **Step 1: Write frontend red tests**

Mock an unsafe semantic assessment with no CPD alarm and assert:

```typescript
expect(await screen.findByText("语义危险")).toBeInTheDocument();
expect(screen.getByText("暴力与武器")).toBeInTheDocument();
expect(screen.getByText("未发现 Token 异常")).toBeInTheDocument();
expect(screen.getByText("语义安全策略拦截")).toBeInTheDocument();
expect(screen.getByText("拦截")).toBeInTheDocument();
```

Add cases for safe+CPD candidate, controversial review, unavailable banner, normalized event columns, and evaluation text “尚未进行独立冻结语义评测”. Assert Guard raw output never appears.

- [ ] **Step 2: Run frontend red tests**

```powershell
Set-Location frontend
npm.cmd test -- --run
```

Expected: fails because current types and pages have no semantic view.

- [ ] **Step 3: Extend TypeScript contracts and labels**

Add exact semantic enums and optional legacy event fields. Create fixed Chinese label maps in `AnalyzePage.tsx`; never render arbitrary category or fusion strings without mapping.

- [ ] **Step 4: Implement evidence presentation**

Use one unframed three-column evidence strip inside the result pane:

- semantic severity and categories;
- CPD status, score, onset;
- final action and fusion reason.

Keep the Token risk track unchanged. Events add semantic/fusion columns without a Prompt column. Evaluation reads `/health` to show Guard model readiness and the explicit no-metrics limitation.

- [ ] **Step 5: Run tests and production build**

```powershell
npm.cmd test -- --run
npm.cmd run build
```

Expected: all frontend tests pass and TypeScript build exits 0.

- [ ] **Step 6: Run one bounded visual review**

With safe synthetic UI state only, capture analysis/events/evaluation at 1440x900 and 390x844 in one batch. Check no overlaps, category wrapping, horizontal table scroll, visible focus, and no Guard raw output. Apply at most one fix batch and one confirmation batch. Do not run a second Impeccable detector.

- [ ] **Step 7: Record commit boundary**

```powershell
git add frontend/src
git commit -m "feat: show semantic and token security evidence"
```

---

### Task 7: AutoDL Model Deployment and Honest Acceptance

**Files:**
- Create: `scripts/smoke_semantic_guard.py`
- Create: `tests/unit/test_semantic_smoke_cli.py`
- Modify: `THIRD_PARTY_NOTICES.md`
- Modify: `README.md`
- Modify: `docs/basic-task/design.md`
- Modify: `docs/basic-task/development.md`
- Modify: `docs/basic-task/test-report.md`
- Modify: `docs/basic-task/experiment-report.md`
- Modify: `docs/basic-task/demo-script-3min.md`

**Interfaces:**
- Consumes: protected external JSONL path with `sample_id` and `prompt`
- Produces: aggregate-only smoke report with counts, categories, actions, P50/P95 latency, model revision and hashes

- [ ] **Step 1: Write smoke CLI privacy red tests**

Create a temporary safe fixture outside tracked data. Invoke the CLI with a fake API client and assert stdout/report contain only sample IDs or aggregate counts, never fixture Prompt or Guard raw output. Report forbidden keys match the existing evaluation service list plus `guard_raw_output`.

- [ ] **Step 2: Run smoke CLI red tests**

Expected: fails because `scripts/smoke_semantic_guard.py` is absent.

- [ ] **Step 3: Implement aggregate smoke CLI**

CLI arguments:

```text
--input-jsonl <protected path>
--api-base <URL>
--output-json <untracked path>
--expected-model-version <revision>
```

Require every row to have unique `sample_id` and non-empty `prompt`; submit in memory; write only totals by expected semantic class, returned severity, categories, action, error type, and latency percentiles. Never print request bodies.

- [ ] **Step 4: Download official model from ModelScope**

On AutoDL install the ModelScope downloader in the project venv, then download:

```bash
modelscope download \
  --model Qwen/Qwen3Guard-Gen-0.6B \
  --local_dir /root/autodl-tmp/models/Qwen3Guard-Gen-0.6B
```

Record the resolved revision, `model.safetensors` SHA-256, total bytes and Apache-2.0 notice. Do not download from an unverified mirror.

- [ ] **Step 5: Deploy with Guard environment**

Sync tested code only. Restart the existing API with the current v2 CPD paths plus:

```bash
TOKEN_SECURITY_GUARD_MODEL_PATH=/root/autodl-tmp/models/Qwen3Guard-Gen-0.6B
TOKEN_SECURITY_GUARD_MODEL_VERSION=<resolved immutable revision>
TOKEN_SECURITY_GUARD_MAX_INPUT_TOKENS=4096
TOKEN_SECURITY_GUARD_MAX_NEW_TOKENS=32
```

Wait for `/health` and require model, detector, semantic_guard, audit, evaluation and demo all ready.

- [ ] **Step 6: Run protected acceptance**

Use an untracked external smoke JSONL. Include direct dangerous requests, ordinary safe requests, contextual controversial requests and harmless distribution anomalies. Run the aggregate CLI and report:

- unsafe direct requests blocked;
- safe ordinary requests allowed;
- controversial requests reviewed;
- harmless CPD anomaly in gateway reviewed;
- no Prompt or raw Guard output in report/database/log.

Then analyze three protected sample IDs each for GCG, AutoDAN and AdvPrompter. Confirm CPD score/onset remain available and Token responses remain redacted.

- [ ] **Step 7: Measure resources**

Record GPU memory before/after Guard load, Guard P50/P95 latency, end-to-end P50/P95 latency and OOM count. Do not claim production latency without these measurements.

- [ ] **Step 8: Update documentation and attribution**

Document Qwen3Guard as a third-party Apache-2.0 engineering layer. Keep the existing CPD/NLL report unchanged. Add semantic smoke results as functional acceptance only, explicitly stating that no independent frozen semantic accuracy/F1 is available.

- [ ] **Step 9: Final verification**

```powershell
$env:PYTHONPATH=".localdeps"
python -m pytest -q
Set-Location frontend
npm.cmd test -- --run
npm.cmd run build
```

Also verify:

- remote health all ready;
- semantic unsafe + CPD normal -> block;
- semantic safe + CPD normal -> allow;
- schema v2 CPD report hash remains `8dffdd87a734740cbf71ddf8a85701a3a85f324373ad9f7855f7cd613ebd3c87`;
- recursive forbidden-key count is zero;
- database/log protected Prompt match count is zero.

- [ ] **Step 10: Record commit boundary**

```powershell
git add scripts/smoke_semantic_guard.py tests/unit/test_semantic_smoke_cli.py THIRD_PARTY_NOTICES.md README.md docs/basic-task
git commit -m "docs: validate semantic guard fusion"
```

If Git identity is still absent, report the exact blocker and leave verified changes uncommitted.
