# AI Security Lab Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an isolated `/lab` investigation workspace that turns the existing semantic Guard, Entropy-CPD, fixed fusion, and local knowledge results into an evidence timeline, counterfactual sensitivity check, deterministic response rehearsal, and redacted incident report without changing the stable product pages or frozen metrics.

**Architecture:** A new `app.lab` package owns strict public models, redaction, counterfactual orchestration, a bounded in-memory run store, and three deterministic dry-run tools. `LabService` composes the existing workflow, demo catalog, and knowledge output without adding branches to `BasicSecurityWorkflow.analyze`; a feature-gated FastAPI router exposes only redacted contracts. The React client adds a self-contained `/lab` route and renders recorded evidence rather than model reasoning or simulated parallelism.

**Tech Stack:** Python 3.12+, FastAPI, Pydantic v2, pytest, React 19, TypeScript 5.8, Vite 7, Vitest, Testing Library, CSS, lucide-react.

## Global Constraints

- Do not change the request, response, persistence, or UI behavior of `/analyze`, `/events`, or `/evaluation`.
- Do not add experimental arguments or branches to `BasicSecurityWorkflow.analyze`.
- Do not alter `qwen25-7b-cpd-paper-v2`, frozen profiles, benchmark reports, protected source data, or existing report hashes.
- Never persist or return protected Prompt text, suffix text, Token text/IDs, query text, model raw output, or Guard raw output.
- Recursively reject keys named `prompt`, `suffix`, `token_text`, `token_id`, `query_text`, `raw_output`, or `guard_raw_output` at the lab response boundary.
- Keep at most 32 completed runs for 15 minutes; cache only redacted structured results and evict the oldest completed run first.
- A counterfactual uses only `prompt[:suspicious_span.char_start]`, the same workflow configuration, and `knowledge_mode="off"`; it is labelled counterfactual sensitivity evidence, never strict causality.
- A failed or inconclusive lab stage must preserve or strengthen the original action and must never change `block` to `review` or `allow`.
- Dry-run tools are limited to `gateway_preview`, `soc_case_preview`, and `evidence_export_preview`; they accept no URL, credential, path, command, or free-form failure text and perform no network, filesystem, or subprocess action.
- Protected optimized attacks are selected by sample ID only; direct unsafe and optimized source text never enters Git, local logs, reports, screenshots, or browser responses.
- Do not add a third model, another permanent GPU service, a graph database, or claim real firewall/EDR/ticket integration.
- The lab is controlled by `TOKEN_SECURITY_LAB_ENABLED`; a disabled or unavailable lab degrades only `/lab` and never the base health status.
- Experimental metrics remain separate from `agent-ablation-v1` and make no universal classification, causality, BEAST, or AutoDAN-HGA claim.

## File Structure

- `backend/app/lab/models.py`: strict request/response models, public signal conversion, forbidden-key validation, action ordering.
- `backend/app/lab/counterfactual.py`: provenance-compatible truncation and one-shot counterfactual workflow execution.
- `backend/app/lab/store.py`: lock-protected TTL/capacity run cache and fixed expired/not-found errors.
- `backend/app/lab/tools.py`: deterministic response plans and dry-run result generation.
- `backend/app/lab/reporting.py`: citation-validated deterministic redacted case report.
- `backend/app/lab/service.py`: custom/frozen scenario orchestration, timing stages, run storage, tool invocation, aggregate counters.
- `backend/app/api/lab.py`: feature-gated routes and stable error envelopes.
- `backend/app/bootstrap.py`, `backend/app/main.py`: lab configuration, dependency wiring, health information, router registration.
- `frontend/src/types.ts`, `frontend/src/api.ts`: exact lab API contracts.
- `frontend/src/pages/LabPage.tsx`: isolated workbench behavior and accessibility.
- `frontend/src/components/LabSignalChart.tsx`: synchronized, nonblank SVG evidence plots.
- `frontend/src/App.tsx`, `frontend/src/styles.css`: navigation, route, responsive lab styling only.
- `tests/unit/test_lab_*.py`, `tests/integration/test_lab_api.py`: backend behavior, security, and API regression coverage.
- `frontend/src/LabPage.test.tsx`, `frontend/src/App.test.tsx`: route, workflow, degradation, and privacy UI coverage.
- `docs/security-lab.md`: operation, limitations, evidence meaning, and demonstration procedure.

---

### Task 1: Strict Lab Public Contracts and Redaction Boundary

**Files:**
- Create: `backend/app/lab/__init__.py`
- Create: `backend/app/lab/models.py`
- Create: `tests/unit/test_lab_models.py`

**Interfaces:**
- Consumes: `app.schemas.AnalysisResult`, `app.schemas.Decision`, `app.knowledge.models.KnowledgeEvidence`.
- Produces: `LabRunRequest`, `LabPublicSignal.from_token_signal(signal)`, `LabDetectionSnapshot.from_analysis(result)`, `LabRunResult`, `CounterfactualResult`, `ToolDryRunRequest`, `ToolDryRunResult`, `assert_public_payload(payload)`, and `safer_action(original, proposed)`.

- [ ] **Step 1: Write failing contract tests**

  Add tests proving custom input and `sample_id` are mutually exclusive, `ToolDryRunRequest` accepts only `inject_failure: bool`, public signals omit Token IDs/text, recursive forbidden keys are rejected at every depth, and `safer_action("block", "allow") == "block"`. Use a literal `TokenSignal` fixture and assert the exact public dictionary `{index, entropy, nll, cpd_entropy, cpd_nll, risk}`. The tool ID belongs only to the fixed API path and typed `LabToolId` union.

- [ ] **Step 2: Run the tests and observe the expected missing-module failure**

  Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/test_lab_models.py -q`

  Expected: collection fails with `ModuleNotFoundError: No module named 'app.lab'`.

- [ ] **Step 3: Implement the strict models and recursive validator**

  Use `ConfigDict(extra="forbid", frozen=True)` for response models. Define `FORBIDDEN_PUBLIC_KEYS` as the seven exact names in Global Constraints. `assert_public_payload` must recursively walk Pydantic dumps, dictionaries, lists, and tuples and raise `ValueError("lab payload contains forbidden field: <key>")`. Model `scenario_kind` as `custom | frozen`, tool status as `planned | succeeded | failed`, and counterfactual interpretation as `risk_reduced | unchanged | inconclusive`.

- [ ] **Step 4: Run focused and schema regression tests**

  Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/test_lab_models.py tests/unit/test_schemas.py -q`

  Expected: all pass.

- [ ] **Step 5: Commit the contract boundary**

  Run: `git add backend/app/lab tests/unit/test_lab_models.py && git commit -m "feat: add redacted lab contracts"`

### Task 2: Counterfactual Sensitivity Runner

**Files:**
- Create: `backend/app/lab/counterfactual.py`
- Create: `tests/unit/test_lab_counterfactual.py`

**Interfaces:**
- Consumes: `BasicSecurityWorkflow.analyze(AnalysisRequest, request_id=...)`, original transient Prompt, `AnalysisResult`, `LabDetectionSnapshot`.
- Produces: `CounterfactualRunner.run(*, prompt: str, original: AnalysisResult, mode: Literal["analysis", "gateway"]) -> CounterfactualResult`.

- [ ] **Step 1: Write failing behavior tests**

  Use a recording fake workflow and literal original results to prove: no onset yields `inconclusive` without a second call; onset `0`, onset equal to prompt length, or whitespace-only prefixes are inconclusive; a valid onset calls the workflow exactly once with the prefix, same model ID/mode, and `knowledge_mode="off"`; provenance mismatch is inconclusive; score deltas and action change are computed from literal values; an exception returns inconclusive and preserves the original action.

- [ ] **Step 2: Verify the tests fail because the runner is absent**

  Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/test_lab_counterfactual.py -q`

  Expected: import failure for `app.lab.counterfactual`.

- [ ] **Step 3: Implement a single safe recheck**

  Keep the prefix only in a local variable and never place it in `CounterfactualResult`. Compare `model_id`, `tokenizer_id`, `system_prompt_hash`, and `calibration_version`; mismatches set interpretation to `inconclusive`. Classify `risk_reduced` only when either detector or risk score falls by at least `1e-6`; otherwise return `unchanged`. Always pass the proposed action through `safer_action` before returning it.

- [ ] **Step 4: Run focused tests**

  Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/test_lab_counterfactual.py tests/integration/test_basic_workflow.py -q`

  Expected: all pass and the existing workflow integration behavior remains unchanged.

- [ ] **Step 5: Commit the recheck runner**

  Run: `git add backend/app/lab/counterfactual.py tests/unit/test_lab_counterfactual.py && git commit -m "feat: add counterfactual sensitivity runner"`

### Task 3: Bounded Run Store

**Files:**
- Create: `backend/app/lab/store.py`
- Create: `tests/unit/test_lab_store.py`

**Interfaces:**
- Consumes: completed `LabRunResult` objects and an injectable monotonic clock.
- Produces: `LabRunStore(capacity: int = 32, ttl_seconds: float = 900, clock=time.monotonic)`, `put(run)`, `get(run_id)`, `snapshot()`, `LabRunExpired`, and `LabRunNotFound`.

- [ ] **Step 1: Write failing capacity, TTL, and concurrency tests**

  Prove a retrieved run equals the redacted stored value; the 33rd insertion evicts the oldest completion; TTL boundary returns `LabRunExpired`; unknown IDs return `LabRunNotFound`; and concurrent puts/gets do not exceed 32 or raise mutation errors. Also recursively scan every stored snapshot with `assert_public_payload`.

- [ ] **Step 2: Verify the store tests fail for the missing implementation**

  Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/test_lab_store.py -q`

  Expected: import failure for `app.lab.store`.

- [ ] **Step 3: Implement lock-protected ordered storage**

  Use `threading.RLock` plus `OrderedDict[str, tuple[float, LabRunResult]]`. Purge expired values before every public operation, retain a separate bounded set of expired IDs so callers receive `lab_run_expired`, and validate the serialized run with `assert_public_payload` before insertion.

- [ ] **Step 4: Run the store and model tests**

  Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/test_lab_store.py tests/unit/test_lab_models.py -q`

  Expected: all pass.

- [ ] **Step 5: Commit the safe cache**

  Run: `git add backend/app/lab/store.py tests/unit/test_lab_store.py && git commit -m "feat: add bounded lab run store"`

### Task 4: Deterministic Knowledge-Driven Dry-Run Tools and Case Report

**Files:**
- Create: `backend/app/lab/tools.py`
- Create: `backend/app/lab/reporting.py`
- Create: `tests/unit/test_lab_tools.py`
- Create: `tests/unit/test_lab_reporting.py`

**Interfaces:**
- Consumes: base decision, fusion reason, work mode, legal `KnowledgeEvidence`, counterfactual result, fixed optional `failure_tool_id`.
- Produces: `build_response_plan(...) -> tuple[LabToolPlan, ...]`, `execute_dry_run(plan, *, inject_failure: bool) -> ToolDryRunResult`, and `build_case_report(...) -> LabCaseReport`.

- [ ] **Step 1: Write failing deterministic tool tests**

  Assert exact tool IDs and fixed summaries for allow/review/block inputs. Prove the input models reject URL/path/command/credential fields, execution performs no network/file/subprocess calls, injected failure emits fixed code `simulated_tool_failure`, and a failed block preview still reports effective action `block` or `review`, never `allow`.

- [ ] **Step 2: Write failing report citation tests**

  Assert every `evidence_id` is drawn from returned `knowledge_id` values, an unknown citation forces `report_status="fallback"`, and the report dump passes `assert_public_payload`. Assert limitations explicitly say sensitivity is not strict causal proof and all tool actions are simulations.

- [ ] **Step 3: Run tests and observe missing modules**

  Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/test_lab_tools.py tests/unit/test_lab_reporting.py -q`

  Expected: collection fails for `app.lab.tools` and `app.lab.reporting`.

- [ ] **Step 4: Implement pure deterministic planners and reporter**

  Do not import HTTP clients, `subprocess`, `pathlib`, or filesystem APIs in `tools.py`. Use `time.perf_counter` only for measured latency. Hash evidence exports from already-redacted JSON bytes with SHA-256. The report builder accepts structured fields only and validates requested citations against the supplied evidence set before constructing the report.

- [ ] **Step 5: Run focused tests**

  Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/test_lab_tools.py tests/unit/test_lab_reporting.py -q`

  Expected: all pass.

- [ ] **Step 6: Commit dry-run behavior**

  Run: `git add backend/app/lab/tools.py backend/app/lab/reporting.py tests/unit/test_lab_tools.py tests/unit/test_lab_reporting.py && git commit -m "feat: add deterministic lab response tools"`

### Task 5: Lab Orchestration for Custom and Protected Scenarios

**Files:**
- Create: `backend/app/lab/service.py`
- Create: `tests/unit/test_lab_service.py`
- Modify: `backend/app/demo/service.py`
- Modify: `tests/unit/test_demo_service.py`

**Interfaces:**
- Consumes: workflow, `DemoSampleService`, `CounterfactualRunner`, `LabRunStore`, existing knowledge-enriched `AnalysisResult`.
- Produces: `DemoSampleService.analyze_for_lab(sample_id, workflow, *, mode) -> tuple[str, AnalysisResult]` where the Prompt stays inside the call boundary, and `LabService.list_scenarios()`, `LabService.create_run(request)`, `LabService.run_tool(run_id, tool_id, request)`, `LabService.metrics()`.

- [ ] **Step 1: Write a failing protected-scenario adapter test**

  Prove callers provide only sample ID, receive only family plus `AnalysisResult`, and serialized output contains no source Prompt or forbidden fields. The adapter may internally pass the protected record to the workflow but must not expose it or add it to an exception.

- [ ] **Step 2: Run the adapter test and observe the missing method**

  Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/test_demo_service.py -q`

  Expected: failure because `analyze_for_lab` does not exist.

- [ ] **Step 3: Implement the narrow adapter and rerun its tests**

  Reuse the existing private record lookup and redaction pattern; do not add a Prompt getter. Run the same test command and expect all demo service tests to pass.

- [ ] **Step 4: Write failing LabService tests**

  Cover six scenario descriptors: safe synthetic, benign format shift, direct unsafe protected ID, GCG ID, AutoDAN ID, AdvPrompter ID. Prove custom runs use `knowledge_mode="report"`, frozen runs call only `analyze_for_lab`, timeline stages preserve real sequential ordering, results contain public signals only, counterfactual is skipped/used correctly, knowledge absence degrades cleanly, creation failure stores no run, and tool execution retrieves only a redacted run.

- [ ] **Step 5: Verify the service tests fail for the missing implementation**

  Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/test_lab_service.py -q`

  Expected: import failure for `app.lab.service`.

- [ ] **Step 6: Implement orchestration without normal audit writes**

  Call `workflow.analyze` directly, never the `/analyze` route. Keep custom Prompt in method-local scope, log only run ID/input SHA-256/character count/fixed status, convert all signals immediately, build response plans from legal knowledge IDs, validate the final dump before storing, and update aggregate counters without retaining per-input text.

- [ ] **Step 7: Run all lab unit tests**

  Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/test_lab_models.py tests/unit/test_lab_counterfactual.py tests/unit/test_lab_store.py tests/unit/test_lab_tools.py tests/unit/test_lab_reporting.py tests/unit/test_lab_service.py tests/unit/test_demo_service.py -q`

  Expected: all pass.

- [ ] **Step 8: Commit orchestration**

  Run: `git add backend/app/lab/service.py backend/app/demo/service.py tests/unit/test_lab_service.py tests/unit/test_demo_service.py && git commit -m "feat: orchestrate security lab investigations"`

### Task 6: Feature-Gated Lab API, Bootstrap, and Health Isolation

**Files:**
- Create: `backend/app/api/lab.py`
- Create: `tests/integration/test_lab_api.py`
- Modify: `backend/app/bootstrap.py`
- Modify: `backend/app/main.py`
- Modify: `tests/unit/test_bootstrap.py`
- Modify: `tests/integration/test_health_api.py`
- Modify: `tests/integration/test_analyze_api.py`

**Interfaces:**
- Consumes: `TOKEN_SECURITY_LAB_ENABLED`, existing workflow/demo dependencies, `LabService`.
- Produces: `GET /api/v1/lab/scenarios`, `POST /api/v1/lab/runs`, `GET /api/v1/lab/runs/{run_id}`, `POST /api/v1/lab/runs/{run_id}/tools/{tool_id}/dry-run`, `GET /api/v1/lab/metrics`, and `health.lab={enabled,ready,reason}`.

- [ ] **Step 1: Write failing configuration and route tests**

  Test exact truthy values `1`, `true`, `yes`, `on`; disabled routes return HTTP 503 with code `lab_disabled`; missing workflow returns `lab_unavailable`; unknown/expired runs return `lab_run_not_found`/`lab_run_expired`; invalid request fields return 422; tool path IDs outside the fixed set return 404; and every successful JSON response passes a recursive forbidden-key scan.

- [ ] **Step 2: Add regression assertions for base behavior**

  Extend health tests so lab failure leaves the existing top-level status unchanged. Extend analyze tests to prove a lab run does not add an audit event and the `/api/v1/analyze` response schema is byte-for-byte equivalent for the existing fixture.

- [ ] **Step 3: Run the API tests and observe missing route/config failures**

  Run: `.\.venv\Scripts\python.exe -m pytest tests/integration/test_lab_api.py tests/unit/test_bootstrap.py tests/integration/test_health_api.py tests/integration/test_analyze_api.py -q`

  Expected: new lab tests fail because the feature flag and routes are absent; existing assertions pass.

- [ ] **Step 4: Wire the router and optional service**

  Parse the flag in `bootstrap.py`; create `LabService` only when enabled and the workflow exists; attach it to `application.state.lab_service`; always add a `lab` health object; register the router unconditionally so disabled deployments return the stable degraded response. Catch lab initialization errors separately and never alter `base_health["status"]`.

- [ ] **Step 5: Run focused API regression tests**

  Run the Step 3 command again.

  Expected: all pass.

- [ ] **Step 6: Commit the feature-gated API**

  Run: `git add backend/app/api/lab.py backend/app/bootstrap.py backend/app/main.py tests/integration/test_lab_api.py tests/unit/test_bootstrap.py tests/integration/test_health_api.py tests/integration/test_analyze_api.py && git commit -m "feat: expose feature-gated security lab API"`

### Task 7: Frontend Contracts, Route, and Stable Lab Skeleton

**Files:**
- Modify: `frontend/src/types.ts`
- Modify: `frontend/src/api.ts`
- Modify: `frontend/src/App.tsx`
- Create: `frontend/src/pages/LabPage.tsx`
- Create: `frontend/src/LabPage.test.tsx`
- Modify: `frontend/src/App.test.tsx`
- Modify: `frontend/src/styles.css`

**Interfaces:**
- Consumes: backend lab routes and `health.lab`.
- Produces: typed `api.labScenarios`, `api.createLabRun`, `api.getLabRun`, `api.runLabTool`, `api.labMetrics`, and the `/lab` route.

- [ ] **Step 1: Write failing navigation and stable-page regression tests**

  Assert the main navigation contains “攻防实验舱”, `/lab` renders a `main` landmark named “AI 安全攻防实验舱”, and `/analyze`, `/events`, `/evaluation` continue rendering their current page-specific landmark/text. Assert loading, disabled, unavailable, and retry states use clear text and do not crash when legacy `/health` lacks `lab`.

- [ ] **Step 2: Run Vitest and observe route failures**

  Run: `npm.cmd test -- src/App.test.tsx src/LabPage.test.tsx`

  Expected: tests fail because the route and page do not exist.

- [ ] **Step 3: Add exact TypeScript contracts and API methods**

  Mirror Pydantic field names and literal unions exactly. Requests send either `{scenario_kind:"custom", custom_input, mode}` or `{scenario_kind:"frozen", sample_id, mode}`, never both. Tool requests send only `{inject_failure:boolean}`.

- [ ] **Step 4: Implement the isolated page shell**

  Add `FlaskConical` from lucide-react to navigation. Build an unframed workbench with the scenario controls, mode segmented control, one “开始调查” command, four stage indicators, three tabs, and explicit degraded empty states. Do not import or restructure `AnalyzePage`.

- [ ] **Step 5: Add responsive base styles and rerun tests**

  Prefix lab selectors with `.lab-`; preserve existing declarations. Use fixed control heights, 8px or smaller radii, visible keyboard focus, 44px touch targets, no viewport-scaled fonts, and `@media (max-width: 720px)` to stack controls without global horizontal overflow.

  Run: `npm.cmd test -- src/App.test.tsx src/LabPage.test.tsx`

  Expected: all pass.

- [ ] **Step 6: Commit the stable UI shell**

  Run: `git add frontend/src/types.ts frontend/src/api.ts frontend/src/App.tsx frontend/src/pages/LabPage.tsx frontend/src/LabPage.test.tsx frontend/src/App.test.tsx frontend/src/styles.css && git commit -m "feat: add isolated security lab workspace"`

### Task 8: Evidence Timeline and Synchronized Signal Curves

**Files:**
- Create: `frontend/src/components/LabSignalChart.tsx`
- Modify: `frontend/src/pages/LabPage.tsx`
- Modify: `frontend/src/LabPage.test.tsx`
- Modify: `frontend/src/styles.css`

**Interfaces:**
- Consumes: redacted `LabPublicSignal[]`, stage statuses/latencies, original decision and fusion reason.
- Produces: accessible evidence timeline plus synchronized entropy, NLL, and CPD cumulative SVG plots sharing one index cursor.

- [ ] **Step 1: Write failing visualization behavior tests**

  Render a literal result with four signals. Assert five stages appear in recorded order, latency labels come from the response, the SVG contains nonempty paths for entropy/NLL/CPD, hovering or focusing index 2 updates all three displayed values, and no token ID/text or private input appears in the evidence region.

- [ ] **Step 2: Run the test and observe missing chart failures**

  Run: `npm.cmd test -- src/LabPage.test.tsx`

  Expected: fails because the timeline and chart are not rendered.

- [ ] **Step 3: Implement deterministic SVG geometry**

  Use `viewBox`, fixed responsive aspect ratio, hand-scaled points, `<path>`/`<line>`, semantic `<title>`, and keyboard-focusable index hit areas. Empty or one-point input renders an explicit “信号不足” state rather than a blank SVG. Animation only moves opacity/cursor and is disabled under `prefers-reduced-motion`.

- [ ] **Step 4: Implement evidence status and action comparison**

  Label agreement/conflict/unavailable from returned structured fields, show analysis/gateway actions side by side, and state that CPD is independent localization evidence rather than semantic intent detection.

- [ ] **Step 5: Run frontend tests and build**

  Run: `npm.cmd test -- src/LabPage.test.tsx`

  Run: `npm.cmd run build`

  Expected: both pass without TypeScript errors.

- [ ] **Step 6: Commit the evidence visualization**

  Run: `git add frontend/src/components/LabSignalChart.tsx frontend/src/pages/LabPage.tsx frontend/src/LabPage.test.tsx frontend/src/styles.css && git commit -m "feat: visualize lab evidence pipeline"`

### Task 9: Counterfactual, Response Sandbox, Knowledge Relation Band, and Report UI

**Files:**
- Modify: `frontend/src/pages/LabPage.tsx`
- Modify: `frontend/src/LabPage.test.tsx`
- Modify: `frontend/src/styles.css`

**Interfaces:**
- Consumes: `counterfactual`, legal knowledge evidence, tool plans/results, case report.
- Produces: three complete investigation tabs, simulated failure control, and redacted full-width report.

- [ ] **Step 1: Write failing interaction and safety tests**

  Assert the counterfactual tab compares original/recheck scores and labels `risk_reduced`, `unchanged`, or `inconclusive`; tool buttons include “模拟执行”; a failed block tool never displays allow as the effective action; knowledge relations render `publisher -> risk domain -> recommendation -> tool`; report citations correspond to visible knowledge IDs; and the rendered DOM contains none of the seven forbidden field names or protected fixture strings.

- [ ] **Step 2: Run the test and observe missing sections**

  Run: `npm.cmd test -- src/LabPage.test.tsx`

  Expected: fails on absent counterfactual, sandbox, and report controls.

- [ ] **Step 3: Implement the three investigation tabs**

  Use real buttons with `aria-selected`, status icons from lucide-react, and deterministic result copy. Disable counterfactual controls when the server returns inconclusive. Tool failure injection is a checkbox tied only to the selected fixed tool ID; never provide free-form parameters.

- [ ] **Step 4: Implement knowledge and report bands**

  Render official source links already supplied by the backend, visible `knowledge_id`, report status, handling steps, limitations, and a “模拟处置，不代表真实外部系统已执行” banner. Avoid nested cards; use full-width sections and restrained dividers.

- [ ] **Step 5: Run frontend tests and build**

  Run: `npm.cmd test`

  Run: `npm.cmd run build`

  Expected: all tests and build pass.

- [ ] **Step 6: Commit the complete investigation UI**

  Run: `git add frontend/src/pages/LabPage.tsx frontend/src/LabPage.test.tsx frontend/src/styles.css && git commit -m "feat: complete security lab investigation flow"`

### Task 10: Separate Experimental Metrics and Documentation

**Files:**
- Modify: `backend/app/lab/service.py`
- Modify: `tests/unit/test_lab_service.py`
- Modify: `frontend/src/pages/LabPage.tsx`
- Modify: `frontend/src/LabPage.test.tsx`
- Create: `docs/security-lab.md`
- Modify: `.env.example`

**Interfaces:**
- Consumes: aggregate redacted run/tool/report outcomes only.
- Produces: `LabMetrics` with run count, counterfactual eligible/executed counts, evidence agreement/conflict counts, tool success/failure counts, report generated/fallback counts, action invariance count, latency samples summarized as P50/P95, and privacy violation count fixed at zero unless validation blocks a payload.

- [ ] **Step 1: Write failing aggregate metric tests**

  Feed literal completed outcomes and assert exact coverage/rate/percentile values. Prove metrics contain no sample IDs, input hashes, family-by-run rows, Prompt-derived values, or `agent-ablation-v1` fields. Add UI tests that label these as “实验舱运行指标” and not frozen classification performance.

- [ ] **Step 2: Run tests and observe absent metric behavior**

  Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/test_lab_service.py -q`

  Run: `npm.cmd test -- src/LabPage.test.tsx`

  Expected: new metric assertions fail.

- [ ] **Step 3: Implement aggregate-only counters and UI**

  Update counters under the service lock, store only numeric latency samples bounded to the same 32-run window, and compute literal P50/P95 via the existing project percentile convention. Present the metrics below the report with explicit non-causality/non-classification limitations.

- [ ] **Step 4: Document operation and limitations**

  Document `TOKEN_SECURITY_LAB_ENABLED=false` as the default, API routes, six scenario types, why protected scenarios use IDs, what counterfactual sensitivity means, why dry-run tools cannot affect external systems, failure behavior, and the three demonstration paths. Add only the flag to `.env.example`; do not add protected paths or secrets.

- [ ] **Step 5: Run focused tests**

  Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/test_lab_service.py tests/integration/test_lab_api.py -q`

  Run: `npm.cmd test -- src/LabPage.test.tsx`

  Expected: all pass.

- [ ] **Step 6: Commit metrics and documentation**

  Run: `git add backend/app/lab/service.py tests/unit/test_lab_service.py frontend/src/pages/LabPage.tsx frontend/src/LabPage.test.tsx docs/security-lab.md .env.example && git commit -m "docs: define security lab operation and metrics"`

### Task 11: Full Regression, Privacy Audit, AutoDL Smoke Test, and Visual QA

**Files:**
- Create: `scripts/verify_lab_privacy.ps1`
- Create: `tests/unit/test_verify_lab_privacy.py`
- Modify: `docs/security-lab.md`

**Interfaces:**
- Consumes: repository files, local fake-runtime responses, protected AutoDL sample IDs.
- Produces: a non-destructive verifier that exits nonzero on forbidden response keys/protected artifacts and a recorded verification section containing only counts, hashes, statuses, and timings.

- [ ] **Step 1: Write a failing verifier behavior test**

  Run the script against temporary safe and unsafe JSON fixtures. Assert safe exits 0, nested `token_text` exits nonzero, and output reports only the offending key/path without printing its value. Assert protected extensions/paths such as `.secrets`, observation caches, SQLite databases, and source Prompt JSONL are excluded from allowed artifacts.

- [ ] **Step 2: Run the test and observe the missing script failure**

  Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/test_verify_lab_privacy.py -q`

  Expected: failure because `scripts/verify_lab_privacy.ps1` does not exist.

- [ ] **Step 3: Implement the read-only privacy verifier**

  Parse JSON structurally, recurse through keys, scan Git tracked paths with `git ls-files`, and print counts plus sanitized field paths only. Do not inspect or print `.secrets` contents or protected source file contents.

- [ ] **Step 4: Run the complete local verification suite**

  Run: `.\.venv\Scripts\python.exe -m pytest -q`

  Run: `npm.cmd test`

  Run: `npm.cmd run build`

  Expected baseline: at least the prior `229 passed, 1 skipped` backend and `13 passed` frontend tests plus all new lab tests; build completes successfully. Record actual counts, not the baseline, in documentation.

- [ ] **Step 5: Run privacy and stability checks**

  Execute the verifier on captured fake-runtime lab JSON, then compare `git diff` to confirm no changes to calibration/frozen report/data files. Call `/health`, `/api/v1/analyze`, `/api/v1/events`, `/api/v1/evaluation/summary`, and disabled/enabled lab endpoints; record status codes and response hashes only.

- [ ] **Step 6: Deploy the source-only changes and perform protected-ID smoke tests**

  Copy only tracked source/config files to AutoDL using the established SSH key and existing deployment procedure. Never copy `.secrets`, local SQLite files, protected Prompt data, screenshots, or caches. Test one GCG, one AutoDAN, and one AdvPrompter sample by ID; verify successful structured results, forbidden-key count zero, and base health unchanged. Do not claim direct-unsafe coverage unless a source-verified protected ID exists.

- [ ] **Step 7: Perform browser visual and interaction QA**

  With the local web/API running, use Playwright at 1440x900 and 390x844. Verify `/analyze` is visually unchanged; `/lab` has no overlap or global horizontal overflow; chart paths contain nonzero geometry; timeline/tabs/buttons work by keyboard; mobile tables/charts scroll only inside their own containers; reduced motion disables replay animation; and screenshots use synthetic benign content only.

- [ ] **Step 8: Update the verification record and rerun targeted checks**

  Add actual test counts, build module count, browser viewport outcomes, AutoDL family statuses, forbidden-key count, and limitations to `docs/security-lab.md`. Rerun the privacy verifier and documentation-adjacent tests; expected result is zero privacy violations.

- [ ] **Step 9: Commit final verification assets**

  Run: `git add scripts/verify_lab_privacy.ps1 tests/unit/test_verify_lab_privacy.py docs/security-lab.md && git commit -m "test: verify security lab privacy and stability"`

## Final Review Checklist

- [ ] Every production behavior was preceded by a focused failing test and the failure reason was recorded in command output.
- [ ] All backend and frontend tests pass from a clean process, and the frontend production build succeeds.
- [ ] Existing `/analyze`, `/events`, and `/evaluation` contracts and page behavior remain unchanged.
- [ ] Frozen profiles, benchmark reports, source datasets, and protected artifacts have no Git diff.
- [ ] Every lab response and stored run has zero forbidden-key hits.
- [ ] Counterfactual output is labelled sensitivity evidence and never strict causality.
- [ ] Tool UI and reports clearly state simulation; no external system side effect is possible.
- [ ] Failed/inconclusive stages never downgrade the original security action.
- [ ] AutoDL smoke tests use protected IDs only and expose no source text.
- [ ] Desktop/mobile screenshots contain synthetic benign content only and show no overlap or global overflow.
