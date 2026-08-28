# Bounded SuperAgent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a privacy-preserving, deterministic SuperAgent mission that plans, observes, replans, executes existing internal response tools, and closes a sanitized security scenario without changing the base detector decision.

**Architecture:** A new `app.superagent` package wraps the existing `LabService` instead of duplicating model, CPD, knowledge, counterfactual, or tool logic. A bounded state machine creates one lab run, converts its sanitized result into structured trace events, selects zero to three internal tools from a fixed monotonic policy, executes them through the existing idempotent SQLite executor, and stores the sanitized mission in a TTL memory store. A separate `/super-agent` React page visualizes returned events and leaves all existing pages untouched.

**Tech Stack:** Python 3.12, FastAPI, Pydantic v2, SQLite-backed existing lab tools, React 19, TypeScript, Vite, Vitest, Testing Library.

## Global Constraints

- Never return or persist raw Prompt, attack suffix, Token text/ID, query text, model raw output, hidden reasoning, secrets, or private paths.
- The SuperAgent may only use existing platform-internal tools; it must not perform network calls, spawn subprocesses, or claim external firewall/EDR/SIEM integration.
- The effective action must never be weaker than the immutable base `LabRunResult.detection.decision`.
- Each mission may create one lab run, perform one deterministic replan, execute each selected tool at most once, execute at most three tools total, and emit at most twelve trace events.
- Public trace events are deterministic audit summaries, not hidden chain-of-thought.
- Existing `/analyze`, `/lab`, and `/challenge` behavior and privacy boundaries must remain unchanged.
- Do not rerun or modify the frozen report-generation experiment artifacts.

---

### Task 1: SuperAgent models, policy, and TTL store

**Files:**
- Create: `backend/app/superagent/__init__.py`
- Create: `backend/app/superagent/models.py`
- Create: `backend/app/superagent/policy.py`
- Create: `backend/app/superagent/store.py`
- Test: `tests/unit/test_superagent_models.py`
- Test: `tests/unit/test_superagent_policy.py`
- Test: `tests/unit/test_superagent_store.py`

**Interfaces:**
- Consumes: `Decision`, `LabRunRequest`, `LabToolExecution`, `LabToolId`, `assert_public_payload`.
- Produces: `SuperAgentMissionRequest`, `SuperAgentTraceEvent`, `SuperAgentMissionResult`, `SuperAgentFinalStatus`, `response_tools_for(decision)`, `final_status_for(decision, executions)`, and `SuperAgentMissionStore`.

- [ ] **Step 1: Write failing model tests**

Add tests proving that the request accepts only `objective="investigate_and_respond"`, rejects unknown fields and custom free text, the result is frozen, and `assert_public_payload(result)` accepts a valid mission while rejecting forbidden keys.

```python
def test_mission_request_rejects_free_text_fields() -> None:
    with pytest.raises(ValidationError):
        SuperAgentMissionRequest.model_validate({
            "objective": "investigate_and_respond",
            "scenario_kind": "frozen",
            "sample_id": "sample_safe",
            "mode": "analysis",
            "command": "inspect everything",
        })
```

- [ ] **Step 2: Run model tests and verify RED**

Run: `.venv\Scripts\python.exe -m pytest tests/unit/test_superagent_models.py -q`

Expected: FAIL because `app.superagent.models` does not exist.

- [ ] **Step 3: Implement immutable public models**

Define strict Pydantic models and enums for mission status, trace phase, actor, plan steps, execution references, capabilities, and mission results. Every result model validator must call `assert_public_payload(self.model_dump(mode="json"))`.

- [ ] **Step 4: Run model tests and verify GREEN**

Run: `.venv\Scripts\python.exe -m pytest tests/unit/test_superagent_models.py -q`

Expected: PASS.

- [ ] **Step 5: Write failing policy tests**

Cover the exact mapping:

```python
@pytest.mark.parametrize(("decision", "expected"), [
    (Decision.ALLOW, ()),
    (Decision.REVIEW, (LabToolId.SECURITY_CASE, LabToolId.EVIDENCE_BUNDLE)),
    (Decision.SANITIZE_RECHECK, (LabToolId.SECURITY_CASE, LabToolId.EVIDENCE_BUNDLE)),
    (Decision.BLOCK, (
        LabToolId.GATEWAY_ENFORCEMENT,
        LabToolId.SECURITY_CASE,
        LabToolId.EVIDENCE_BUNDLE,
    )),
])
def test_response_tools_are_bounded(decision, expected) -> None:
    assert response_tools_for(decision) == expected
```

Also verify that any failed selected execution produces `degraded`, all successful block tools produce `contained`, review-like actions produce `review_required`, and allow produces `closed_safe`.

- [ ] **Step 6: Run policy tests and verify RED**

Run: `.venv\Scripts\python.exe -m pytest tests/unit/test_superagent_policy.py -q`

Expected: FAIL because the policy functions do not exist.

- [ ] **Step 7: Implement the fixed policy**

Implement only the mappings in the design. Reject duplicate tools, more than three tools, source/effective action mismatches, or weaker effective actions.

- [ ] **Step 8: Run policy tests and verify GREEN**

Run: `.venv\Scripts\python.exe -m pytest tests/unit/test_superagent_policy.py -q`

Expected: PASS.

- [ ] **Step 9: Write failing TTL store tests**

Test put/get, unknown ID, deterministic expiration using an injected clock, maximum size eviction, and no serialization to disk.

- [ ] **Step 10: Implement and verify the TTL store**

Run: `.venv\Scripts\python.exe -m pytest tests/unit/test_superagent_store.py -q`

Expected before implementation: FAIL. Expected after implementation: PASS.

- [ ] **Step 11: Commit Task 1**

```powershell
git add backend/app/superagent tests/unit/test_superagent_*.py
git commit -m "feat: define bounded superagent mission policy"
```

### Task 2: Bounded mission service and API

**Files:**
- Create: `backend/app/superagent/service.py`
- Create: `backend/app/api/superagent.py`
- Modify: `backend/app/main.py`
- Test: `tests/unit/test_superagent_service.py`
- Test: `tests/integration/test_superagent_api.py`
- Modify: `tests/integration/test_health_api.py`

**Interfaces:**
- Consumes: `LabService.create_run`, `LabService.execute_tool`, `LabService.list_executions`, Task 1 policy and store.
- Produces: `SuperAgentService.create_mission(request)`, `SuperAgentService.get_mission(mission_id)`, `/api/v1/superagent/*`, and a `superagent` health object.

- [ ] **Step 1: Write a failing safe-mission service test**

Use a real fake `LabService` contract, not mock call-count-only assertions. Return a sanitized allow run and assert the completed mission contains plan/act/observe/replan/complete phases, executes no tools, finishes `closed_safe`, stays under twelve events, and passes `assert_public_payload`.

- [ ] **Step 2: Run the service test and verify RED**

Run: `.venv\Scripts\python.exe -m pytest tests/unit/test_superagent_service.py::test_allow_mission_closes_without_tools -q`

Expected: FAIL because `SuperAgentService` does not exist.

- [ ] **Step 3: Implement the minimal allow path**

Create the lab run, emit deterministic role events, calculate the empty tool plan, emit the final event, validate privacy, and store the result.

- [ ] **Step 4: Verify the allow path GREEN**

Run the same focused test; expected PASS.

- [ ] **Step 5: Write failing block and review service tests**

For block, assert exact tool order, deterministic UUIDv5 idempotency keys, same source/effective action, three execution references, and `contained`. For review, assert only case and evidence tools and `review_required`.

- [ ] **Step 6: Run focused tests and verify RED**

Run: `.venv\Scripts\python.exe -m pytest tests/unit/test_superagent_service.py -q`

Expected: new block/review assertions FAIL.

- [ ] **Step 7: Implement tool execution and post-action observation**

Use `LabExecuteRequest(confirmed=True, idempotency_key=uuid5(...))`. Catch only known lab storage/invariant failures, emit a fixed failed observation, retain the base action, and complete `degraded`. Never include exception text.

- [ ] **Step 8: Verify service tests GREEN**

Run the full service test file; expected PASS.

- [ ] **Step 9: Write failing API and health tests**

Cover capabilities, create 201, restore 200, unknown 404, expired 410, unavailable 503, validation 422, `internal_only=true`, and the new health status. Scan every JSON response recursively for forbidden keys.

- [ ] **Step 10: Implement API and lifespan wiring**

Instantiate `SuperAgentService` only when `lab_health.ready` is true, add `superagent_service` to `_LIFESPAN_STATE_NAMES`, include the router, and expose fixed health:

```python
{
    "ready": True,
    "internal_only": True,
    "max_tool_calls": 3,
    "max_trace_events": 12,
}
```

- [ ] **Step 11: Verify backend task tests**

Run: `.venv\Scripts\python.exe -m pytest tests/unit/test_superagent_*.py tests/integration/test_superagent_api.py tests/integration/test_health_api.py -q`

Expected: PASS with zero failures.

- [ ] **Step 12: Commit Task 2**

```powershell
git add backend/app/api/superagent.py backend/app/main.py backend/app/superagent tests/unit/test_superagent_service.py tests/integration/test_superagent_api.py tests/integration/test_health_api.py
git commit -m "feat: execute bounded superagent missions"
```

### Task 3: SuperAgent Web workspace

**Files:**
- Create: `frontend/src/pages/SuperAgentPage.tsx`
- Create: `frontend/src/SuperAgentPage.test.tsx`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/api.ts`
- Modify: `frontend/src/types.ts`
- Modify: `frontend/src/styles.css`
- Modify: `frontend/src/App.test.tsx`

**Interfaces:**
- Consumes: Task 2 capabilities, scenario, create mission, and restore mission endpoints.
- Produces: `/super-agent` route, typed API calls, mission setup, role status, trace timeline, execution receipts, and final closure panel.

- [ ] **Step 1: Write failing page interaction tests**

Test that the page labels itself “平台内部仿真闭环”, loads scenarios and capabilities independently, starts a mission, renders all trace phases and actors, shows `closed_safe` without tool receipts, shows exact block receipts, and never renders forbidden field labels.

- [ ] **Step 2: Run page tests and verify RED**

Run: `npm.cmd test -- --run src/SuperAgentPage.test.tsx`

Expected: FAIL because the page and route do not exist.

- [ ] **Step 3: Add TypeScript contracts and API methods**

Add exhaustive literal unions matching backend models and methods `superAgentCapabilities`, `createSuperAgentMission`, and `getSuperAgentMission`.

- [ ] **Step 4: Implement the minimal page**

Use existing visual tokens and Lucide icons. Keep setup controls compact, use a stable seven-stage timeline, show five role rows, and render tool receipts only after completion. Do not nest cards or expose model raw output.

- [ ] **Step 5: Add responsive and reduced-motion CSS**

At 390px, switch setup and trace to one column, guarantee no horizontal overflow, and allow IDs to wrap. Disable event entry animation under `prefers-reduced-motion: reduce`.

- [ ] **Step 6: Verify focused page tests GREEN**

Run: `npm.cmd test -- --run src/SuperAgentPage.test.tsx src/App.test.tsx`

Expected: PASS.

- [ ] **Step 7: Commit Task 3**

```powershell
git add frontend/src
git commit -m "feat: add superagent response workspace"
```

### Task 4: Privacy, documentation, and full regression

**Files:**
- Create: `docs/challenge-task.md`
- Modify: `README.md`
- Modify: `docs/advanced-task/test-report.md`
- Modify: `scripts/verify_lab_privacy.ps1`
- Modify: `tests/unit/test_verify_lab_privacy.py`

**Interfaces:**
- Consumes: completed backend and frontend mission surfaces.
- Produces: competition-facing capability boundary, reproducible usage steps, and privacy scanning of all new endpoints.

- [ ] **Step 1: Write a failing privacy scanner regression**

Extend the fixture HTTP surface with capabilities, mission create, mission restore, and a fixed 422. Assert the scanner counts the new requests and still reports zero forbidden key hits, tracked path hits, JSON errors, SQLite violations, and API violations.

- [ ] **Step 2: Run privacy test and verify RED**

Run: `.venv\Scripts\python.exe -m pytest tests/unit/test_verify_lab_privacy.py -q`

Expected: FAIL because SuperAgent endpoints are not scanned.

- [ ] **Step 3: Extend the scanner with response-surface-only checks**

Do not print response bodies, matches, private paths, prompts, tokens, or model output. Print only endpoint labels and aggregate counts.

- [ ] **Step 4: Verify privacy test GREEN**

Run the focused privacy test; expected PASS.

- [ ] **Step 5: Document exact claims and limits**

Document setup, mission phases, status meanings, deterministic policy, internal-only tools, structured trace versus hidden CoT, and the absence of external device integration. Keep `legacy_unverified` unchanged.

- [ ] **Step 6: Run full backend verification**

Run: `.venv\Scripts\python.exe -m pytest -q`

Expected: all tests PASS; only the existing unconfigured local GPU integration test may SKIP.

- [ ] **Step 7: Run full frontend verification**

Run: `npm.cmd test -- --run`

Run: `npm.cmd run build`

Expected: all tests PASS and Vite production build exits 0.

- [ ] **Step 8: Commit Task 4**

```powershell
git add README.md docs/challenge-task.md docs/advanced-task/test-report.md scripts/verify_lab_privacy.ps1 tests/unit/test_verify_lab_privacy.py
git commit -m "docs: verify superagent challenge task"
```

### Task 5: AutoDL deployment and browser acceptance

**Files:**
- Modify remotely: tracked backend application files only under `/root/autodl-tmp/token-security-agent-platform/backend/app`
- No model, protected dataset, SQLite, secret, frozen report, or GitHub mutation.

**Interfaces:**
- Consumes: verified local build and existing SSH tunnel.
- Produces: live `/super-agent` workspace backed by AutoDL GPU inference.

- [ ] **Step 1: Verify local and remote source checksums before deployment**

Compare changed backend `.py` hashes and confirm the remote GPU API process is the only process bound to port 8000.

- [ ] **Step 2: Sync tracked backend files and restart the remote API with the existing environment**

Preserve the current models, immutable Guard identity, `qwen25-7b-cpd-paper-v2`, official-v2 knowledge snapshot, demo hashes, event database, and lab-enabled settings.

- [ ] **Step 3: Poll health by condition**

Require model, detector, semantic guard, knowledge, evaluation, demo, lab, and superagent all ready; require `official-v2`, 18 cards, and `deployment_match=true`.

- [ ] **Step 4: Run live mission acceptance**

Through `http://127.0.0.1:5175`, execute one synthetic safe mission and one protected block mission. Verify safe executes zero tools; block executes gateway, case, and evidence once; all response bodies pass forbidden-key scanning.

- [ ] **Step 5: Run Playwright desktop and mobile QA**

Verify 1440x900 and 390x844 layouts, no overlap or horizontal overflow, route refresh, reduced motion, zero console errors, and no regressions on `/analyze`, `/lab`, or `/challenge`.

- [ ] **Step 6: Record verification evidence without protected content**

Update test counts, health fields, event/tool counts, layout results, and limitations. Do not include Prompt, suffix, Token data, raw response bodies, private paths, or screenshots containing protected content.

- [ ] **Step 7: Commit deployment evidence**

```powershell
git add docs/challenge-task.md docs/advanced-task/test-report.md
git commit -m "test: validate superagent on autodl"
```
