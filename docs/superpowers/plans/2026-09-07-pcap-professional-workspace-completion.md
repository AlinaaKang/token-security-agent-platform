# PCAP Professional Workspace Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the PCAP professional workspace with a standalone aggregate traffic profile and a privacy-safe, versioned evaluation center without duplicating PCAP conversation uploads.

**Architecture:** Reuse the existing PCAP reconnaissance component and API behind a dedicated `/pcap-profile` page. Add a strict backend loader for a sanitized regression manifest, compute metrics through the existing `evaluate_pcap_detection` function, expose one read-only endpoint, and render it at `/pcap-evaluation` with explicit synthetic-data limits.

**Tech Stack:** FastAPI, Pydantic v2, pytest, React 19, TypeScript, React Router, Vitest, Testing Library, Vite, existing CSS tokens and Lucide icons.

## Global Constraints

- `PCAP 数据调查` remains the only user-file investigation/upload entry.
- The PCAP professional workspace contains exactly `PCAP 流量画像`, `PCAP 攻防实验`, `PCAP 评测中心`, and `PCAP 侦探挑战`.
- Profile output is aggregate only and must not expose filenames, paths, addresses, ports, raw payloads, prompts, or attack conclusions.
- Evaluation output is derived only from a versioned sanitized regression manifest and must state that it does not represent production-network accuracy.
- Missing or invalid evaluation data returns an unavailable state instead of invented metrics.
- Both new pages use the existing light-blue workbench design and have non-empty contextual tours.

---

### Task 1: Versioned PCAP Evaluation Contract

**Files:**
- Create: `data/pcap-detection-regression-v1.json`
- Modify: `backend/app/evaluation/pcap_detection.py`
- Test: `tests/unit/test_pcap_detection_evaluation.py`

**Interfaces:**
- Consumes: `PcapEvaluationCase` and `evaluate_pcap_detection(cases)`.
- Produces: `PcapEvaluationManifest`, `PcapEvaluationSummary`, and `load_pcap_evaluation(path: Path) -> PcapEvaluationSummary`.

- [ ] **Step 1: Write failing loader and privacy tests**

Add tests that load a valid versioned manifest, assert the five fused metrics and three ablations, reject forbidden identity/payload fields at any depth, and reject empty or inconsistent manifests.

- [ ] **Step 2: Run the focused backend test and verify RED**

Run: `E:\Codex\token-security-agent-platform\.venv\Scripts\python.exe -m pytest tests/unit/test_pcap_detection_evaluation.py -q`

Expected: FAIL because `load_pcap_evaluation` and the report models do not exist.

- [ ] **Step 3: Implement the strict manifest loader**

Use Pydantic models with `extra="forbid"`, validate `dataset_kind="synthetic_sanitized_regression"`, require a non-empty version and UTC generation time, recursively reject `filename`, `path`, `ip`, `port`, `payload`, `prompt`, and related raw-data keys, then calculate the summary through `evaluate_pcap_detection`.

- [ ] **Step 4: Add the sanitized regression manifest**

Store only boolean labels, expected packet intervals, detector enum values, packet spans, confidence, and allow-listed supporting-signal identifiers. Include enough benign and risky cases to make every displayed metric meaningful without claiming production representativeness.

- [ ] **Step 5: Run the focused backend test and verify GREEN**

Run: `E:\Codex\token-security-agent-platform\.venv\Scripts\python.exe -m pytest tests/unit/test_pcap_detection_evaluation.py -q`

Expected: PASS.

### Task 2: Read-only PCAP Evaluation API

**Files:**
- Modify: `backend/app/api/evaluation.py`
- Modify: `backend/app/main.py`
- Create: `tests/integration/test_pcap_evaluation_api.py`

**Interfaces:**
- Consumes: `load_pcap_evaluation(path)` and app state `pcap_evaluation_summary`.
- Produces: `GET /api/v1/evaluation/pcap-summary` returning `PcapEvaluationSummary` or HTTP 503.

- [ ] **Step 1: Write failing API success and unavailable tests**

Create one app with a validated summary and one without it; assert a strict 200 response for the former and `503 evaluation report is unavailable` for the latter.

- [ ] **Step 2: Run the integration test and verify RED**

Run: `E:\Codex\token-security-agent-platform\.venv\Scripts\python.exe -m pytest tests/integration/test_pcap_evaluation_api.py -q`

Expected: FAIL with route not found.

- [ ] **Step 3: Implement endpoint and startup loading**

Load `data/pcap-detection-regression-v1.json` during app creation, retain only the validated summary in app state, log the exception type on invalid data, and expose the read-only response model from the evaluation router.

- [ ] **Step 4: Run API and evaluation tests and verify GREEN**

Run: `E:\Codex\token-security-agent-platform\.venv\Scripts\python.exe -m pytest tests/unit/test_pcap_detection_evaluation.py tests/integration/test_pcap_evaluation_api.py -q`

Expected: PASS.

### Task 3: Standalone PCAP Traffic Profile

**Files:**
- Create: `frontend/src/pages/PcapProfilePage.tsx`
- Create: `frontend/src/pages/PcapProfilePage.test.tsx`
- Modify: `frontend/src/pages/PcapReconWorkspace.tsx`
- Modify: `frontend/src/App.tsx`

**Interfaces:**
- Consumes: existing `PcapReconWorkspace`, `api.pcapReconOverview()`, authorization, mission creation, and restoration APIs.
- Produces: route `/pcap-profile` with a page header, scope summary, profile workflow, and result explanation.

- [ ] **Step 1: Write a failing route/page test**

Assert `/pcap-profile` renders `PCAP 流量画像`, the 20-sample quartile explanation, the authorization action, and no upload input or attack conclusion.

- [ ] **Step 2: Run the page test and verify RED**

Run: `npm.cmd test -- src/pages/PcapProfilePage.test.tsx`

Expected: FAIL because the route and page do not exist.

- [ ] **Step 3: Implement the standalone page**

Wrap the existing reconnaissance workflow in the standard page shell, update its public label from old data-recon wording to traffic-profile wording, and preserve all existing authorization, restore, retry, and aggregate-only filtering behavior.

- [ ] **Step 4: Run profile and existing reconnaissance tests and verify GREEN**

Run: `npm.cmd test -- src/pages/PcapProfilePage.test.tsx src/PcapReconWorkspace.test.tsx`

Expected: PASS.

### Task 4: PCAP Evaluation Center UI

**Files:**
- Modify: `frontend/src/types.ts`
- Modify: `frontend/src/api.ts`
- Create: `frontend/src/pages/PcapEvaluationPage.tsx`
- Create: `frontend/src/pages/PcapEvaluationPage.test.tsx`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/styles.css`

**Interfaces:**
- Consumes: `GET /api/v1/evaluation/pcap-summary`.
- Produces: typed `api.pcapEvaluation()` and route `/pcap-evaluation`.

- [ ] **Step 1: Write failing success and unavailable-state page tests**

Assert the page shows sample count, Precision, Recall, F1, false-positive rate, localization hit rate, three ablations, version metadata, and the synthetic-regression disclaimer. Assert an API error shows a recovery message and no numeric placeholders pretending to be results.

- [ ] **Step 2: Run the page test and verify RED**

Run: `npm.cmd test -- src/pages/PcapEvaluationPage.test.tsx`

Expected: FAIL because the page, types, and API method do not exist.

- [ ] **Step 3: Implement types, API method, route, and page**

Render five compact metric cells followed by a three-row ablation table. Format rates as percentages, show manifest version and generation time, and keep the disclaimer visible above the comparison table.

- [ ] **Step 4: Add responsive light-blue styles**

Reuse `.page`, `.page-header`, `.stat-strip`, `.data-section`, `.table-scroll`, and existing semantic color variables; add only PCAP-specific selectors needed for stable metric and disclaimer layout at 1440 and 390 pixel widths.

- [ ] **Step 5: Run the page test and verify GREEN**

Run: `npm.cmd test -- src/pages/PcapEvaluationPage.test.tsx`

Expected: PASS.

### Task 5: Navigation, Tours, and Regression Verification

**Files:**
- Modify: `frontend/src/components/AgentSidebar.tsx`
- Modify: `frontend/src/components/AgentSidebar.test.tsx`
- Modify: `frontend/src/tourConfig.ts`
- Modify: `frontend/src/App.test.tsx`

**Interfaces:**
- Consumes: `/pcap-profile` and `/pcap-evaluation` routes.
- Produces: four ordered PCAP professional links with correct active states and route-specific guided tours.

- [ ] **Step 1: Extend failing navigation and tour tests**

Assert the PCAP professional group contains exactly four ordered links, contains no upload entry, and both new paths resolve non-empty tour steps whose targets exist on their pages.

- [ ] **Step 2: Run focused frontend tests and verify RED**

Run: `npm.cmd test -- src/components/AgentSidebar.test.tsx src/App.test.tsx`

Expected: FAIL because the two navigation links and tours are absent.

- [ ] **Step 3: Add navigation entries and contextual tours**

Order links as profile, lab, evaluation, challenge. Give the profile tour scope/authorization/results steps and the evaluation tour scope/metrics/limits steps.

- [ ] **Step 4: Run focused and full verification**

Run: `npm.cmd test -- src/components/AgentSidebar.test.tsx src/pages/PcapProfilePage.test.tsx src/pages/PcapEvaluationPage.test.tsx src/App.test.tsx`

Run: `npm.cmd run build`

Run: `E:\Codex\token-security-agent-platform\.venv\Scripts\python.exe -m pytest tests/unit/test_pcap_detection_evaluation.py tests/integration/test_pcap_evaluation_api.py -q`

Expected: all commands exit 0.

- [ ] **Step 5: Perform final privacy and layout checks**

Run `git diff --check`, inspect `/pcap-profile` and `/pcap-evaluation` at 1440x900 and 390x844, and run the configured Impeccable detector once against the changed UI targets after all edits are complete.
