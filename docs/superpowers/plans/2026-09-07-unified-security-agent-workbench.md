# Unified Security Agent Workbench Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a conversational, recoverable, policy-constrained security agent that orchestrates the platform's real Prompt, Token, PCAP, RAG, reporting, and internal-response capabilities while keeping simulated endpoint, identity, and log evidence visibly separate.

**Architecture:** Add a `security_agent` backend domain with strict public models, a SQLite task/event store, deterministic intent fallback, schema-constrained planning, a policy-checked tool registry, and an observation-driven coordinator. Replace the global frontend shell with the approved light-blue three-pane workbench while preserving existing professional routes and Token Challenge behavior; stream public task events with SSE and fall back to bounded polling.

**Tech Stack:** Python 3.11+, FastAPI, Pydantic v2, SQLite, pytest, React 19, TypeScript 5.8, React Router 7, Lucide React, Vitest, Testing Library, Playwright.

## Global Constraints

- Execute from `feature/superagent-pcap-interactive-review` at commit `a5a913a` or a descendant containing those four PCAP commits; bring design commit `34c3b1b` into the execution branch before implementation.
- Do not modify frozen detector algorithms, thresholds, calibration artifacts, fusion policy, protected datasets, or Token Challenge scoring and investigation rules.
- PCAP content remains readable only by the existing no-network, read-only, non-root, capability-dropped, resource-limited Docker path.
- Persist no raw Prompt, suffix, payload, Token text/ID, private path, file identity, network identity, model raw output, hidden reasoning, credential, or authorization secret.
- Every evidence item carries `authenticity: real | simulated | derived`; simulated evidence is accepted only for versioned built-in demo cases and never enters real metrics.
- Tool IDs, schemas, limits, authorization requirements, and timeouts are code-owned; model output may propose but never create or weaken them.
- Default limits are 12 plan steps, 3 concurrent tools, 2 replans, 5 active hypotheses, 20 PCAP files per detection batch, and explicit cancellation only.
- Show complete structured CoT through questions, hypotheses, support, counter-evidence, observations, confidence changes, plan revisions, and conclusions; protect only system prompts, temporary model scratchpads, raw reasoning tokens, and private data.
- The UI uses the approved translucent light-blue sidebar, blue identity icons, unified blue reasoning-chain accents, red for detected risk, green for success, and amber for failure or review.
- Keep existing `/analyze`, `/events`, `/evaluation`, `/lab`, `/super-agent`, and `/challenge` entry URLs usable; `/super-agent` becomes the default conversational workspace.
- Use Chinese user-facing copy, ASCII identifiers, 44px minimum mobile command controls, no horizontal overflow, and reduced-motion support.

---

### Task 1: Public Agent Domain Models

**Files:**
- Create: `backend/app/security_agent/__init__.py`
- Create: `backend/app/security_agent/models.py`
- Test: `tests/unit/test_security_agent_models.py`

**Interfaces:**
- Consumes: `app.lab.models.assert_public_payload`, `app.schemas.NonEmptyText`.
- Produces: `AgentTaskType`, `AgentTaskStatus`, `EvidenceAuthenticity`, `AgentIntent`, `AgentPlanStep`, `AgentObservation`, `AgentEvidence`, `AgentHypothesis`, `AgentConfidenceChange`, `AgentTimelineEvent`, `AgentEvidenceConflict`, `AgentMessage`, `AgentTaskSnapshot`, `AgentCapabilities`, and `AgentCommandRequest`.

- [ ] **Step 1: Write failing model and privacy tests**

```python
def test_agent_snapshot_separates_real_simulated_and_derived_evidence():
    snapshot = AgentTaskSnapshot.model_validate(snapshot_payload())
    assert [item.authenticity for item in snapshot.evidence] == [
        EvidenceAuthenticity.REAL,
        EvidenceAuthenticity.SIMULATED,
        EvidenceAuthenticity.DERIVED,
    ]

@pytest.mark.parametrize("private_key", ["prompt", "payload", "file_path", "token_ids"])
def test_agent_public_models_reject_private_keys(private_key: str):
    payload = snapshot_payload()
    payload[private_key] = "PRIVATE"
    with pytest.raises(ValidationError):
        AgentTaskSnapshot.model_validate(payload)

def test_structured_cot_requires_evidence_for_confidence_changes():
    payload = hypothesis_payload(confidence_changes=[{"before": .25, "after": .80, "evidence_refs": []}])
    with pytest.raises(ValidationError):
        AgentHypothesis.model_validate(payload)
```

- [ ] **Step 2: Run the focused tests and confirm failure**

Run: `python -m pytest tests/unit/test_security_agent_models.py -q`

Expected: FAIL because `app.security_agent.models` does not exist.

- [ ] **Step 3: Implement strict immutable models**

```python
class EvidenceAuthenticity(StrEnum):
    REAL = "real"
    SIMULATED = "simulated"
    DERIVED = "derived"

class AgentTaskType(StrEnum):
    KNOWLEDGE_EXPLANATION = "knowledge_explanation"
    PROMPT_INVESTIGATION = "prompt_investigation"
    PCAP_DATASET_INVESTIGATION = "pcap_dataset_investigation"
    PCAP_CAPTURE_INVESTIGATION = "pcap_capture_investigation"
    CROSS_DOMAIN_CASE = "cross_domain_case"
    REPORT_GENERATION = "report_generation"

class AgentPlanStep(_PublicModel):
    step_id: str = Field(pattern=r"^step_[0-9]{2}$")
    tool_id: NonEmptyText | None = None
    status: Literal["waiting", "running", "succeeded", "failed", "skipped"]
    requires_authorization: bool = False
    summary: NonEmptyText
```

Set `extra="forbid"`, `frozen=True`, and call `assert_public_payload` after validation. Limit messages to 100, plan steps to 12, evidence to 200, observations to 200, active hypotheses to 5, and reports to public artifact metadata only. A confidence change requires at least one supporting or opposing evidence reference and a public reason.

- [ ] **Step 4: Run model tests**

Run: `python -m pytest tests/unit/test_security_agent_models.py -q`

Expected: PASS.

- [ ] **Step 5: Commit the domain contract**

```bash
git add backend/app/security_agent tests/unit/test_security_agent_models.py
git commit -m "feat: define public security agent contracts"
```

### Task 2: Durable Task And Event Store

**Files:**
- Create: `backend/app/security_agent/store.py`
- Test: `tests/unit/test_security_agent_store.py`

**Interfaces:**
- Consumes: Task and event models from Task 1.
- Produces: `SecurityAgentStore(database_path: Path, *, clock: Callable[[], datetime])`, `create(snapshot)`, `replace(snapshot, expected_version)`, `get(task_id)`, `list(limit, offset)`, and `events_after(task_id, sequence)`.

- [ ] **Step 1: Write failing persistence and concurrency tests**

```python
def test_store_restores_messages_plan_evidence_and_events(tmp_path):
    store = SecurityAgentStore(tmp_path / "agent.sqlite3")
    created = store.create(snapshot_payload())
    restored = SecurityAgentStore(tmp_path / "agent.sqlite3").get(created.task_id)
    assert restored == created

def test_store_rejects_stale_task_version(tmp_path):
    store = SecurityAgentStore(tmp_path / "agent.sqlite3")
    created = store.create(snapshot_payload())
    store.replace(created.model_copy(update={"version": 2}), expected_version=1)
    with pytest.raises(AgentTaskConflict):
        store.replace(created.model_copy(update={"version": 3}), expected_version=1)
```

Also test WAL mode, pagination, monotonic event sequence, malformed stored JSON, close behavior, and that serialized database bytes do not contain private sentinel values.

- [ ] **Step 2: Verify the store tests fail**

Run: `python -m pytest tests/unit/test_security_agent_store.py -q`

Expected: FAIL because the store is missing.

- [ ] **Step 3: Implement the SQLite store**

Use two tables: `agent_tasks(task_id PRIMARY KEY, version, status, created_at, updated_at, snapshot_json)` and `agent_events(task_id, sequence, event_json, PRIMARY KEY(task_id, sequence))`. Validate every object before write and after read, use `BEGIN IMMEDIATE` for compare-and-swap updates, and enable foreign keys and WAL.

- [ ] **Step 4: Run store and existing persistence tests**

Run: `python -m pytest tests/unit/test_security_agent_store.py tests/unit/test_lab_execution_store.py tests/unit/test_event_store.py -q`

Expected: PASS.

- [ ] **Step 5: Commit durable task storage**

```bash
git add backend/app/security_agent/store.py tests/unit/test_security_agent_store.py
git commit -m "feat: persist security agent tasks"
```

### Task 3: Conversational Intent And Safe Knowledge Answers

**Files:**
- Create: `backend/app/security_agent/intent.py`
- Create: `backend/app/security_agent/education.py`
- Test: `tests/unit/test_security_agent_intent.py`
- Test: `tests/unit/test_security_agent_education.py`

**Interfaces:**
- Consumes: `AgentCommandRequest`, current `AgentTaskSnapshot`, `KnowledgeService`, and public PCAP purpose/protocol labels.
- Produces: `parse_intent(message: str, context: AgentTaskSnapshot | None) -> AgentIntent` and `SecurityEducationService.answer(intent, evidence) -> AgentMessage`.

- [ ] **Step 1: Write failing intent examples**

```python
@pytest.mark.parametrize((message, expected), [
    ("你叫什么名字", "identity"),
    ("你能做什么", "capabilities"),
    ("什么是提示词注入", "explain_attack"),
    ("packet 4-4 是什么", "explain_pcap"),
    ("检测下一批 PCAP", "continue_task"),
    ("为什么 1482 是高风险", "explain_current_evidence"),
    ("生成调查报告", "generate_report"),
])
def test_deterministic_intent_fallback(message, expected):
    assert parse_intent(message, None).kind == expected
```

Test leading/trailing blank lines, Chinese punctuation, prompt-injection instructions, overly long messages, unrelated complex requests, and explicit versus ambiguous cancellation.

- [ ] **Step 2: Confirm intent and education tests fail**

Run: `python -m pytest tests/unit/test_security_agent_intent.py tests/unit/test_security_agent_education.py -q`

Expected: FAIL because the modules are missing.

- [ ] **Step 3: Implement deterministic fallback and grounded education**

Normalize whitespace with the existing input normalization semantics. Use ordered, explicit intent patterns; return `clarify` when multiple side-effect intents match. Identity and capability answers are fixed templates. Attack and protocol explanations consume only approved knowledge IDs and public evidence fields, and always include `evidence_scope: general | current_case`.

- [ ] **Step 4: Run tests**

Run: `python -m pytest tests/unit/test_security_agent_intent.py tests/unit/test_security_agent_education.py tests/unit/test_safe_query_builder.py tests/unit/test_knowledge_service.py -q`

Expected: PASS.

- [ ] **Step 5: Commit conversational understanding**

```bash
git add backend/app/security_agent/intent.py backend/app/security_agent/education.py tests/unit/test_security_agent_intent.py tests/unit/test_security_agent_education.py
git commit -m "feat: add grounded security conversations"
```

### Task 4: Policy-Constrained Planner And Replanner

**Files:**
- Create: `backend/app/security_agent/planner.py`
- Create: `backend/app/security_agent/policy.py`
- Test: `tests/unit/test_security_agent_planner.py`
- Test: `tests/unit/test_security_agent_policy.py`

**Interfaces:**
- Consumes: `AgentIntent`, `AgentObservation`, `AgentCapabilities`, `AgentHypothesis`, and `AgentEvidenceConflict`.
- Produces: `SecurityAgentPlanner.create_plan(intent, capabilities)`, `SecurityAgentPlanner.replan(snapshot, observation)`, `HypothesisEvaluator.evaluate(snapshot, observation)`, and `validate_plan(plan, capabilities, authorization_scope)`.

- [ ] **Step 1: Write failing plan and adversarial policy tests**

```python
def test_pcap_plan_changes_after_encrypted_only_observation():
    plan = planner.create_plan(pcap_dataset_intent(), capabilities())
    revised = planner.replan(task_with(plan), observation("encrypted_only"))
    assert "inspect_encrypted_flow_behavior" in tool_ids(revised)
    assert "inspect_http_payload" not in tool_ids(revised)

def test_policy_rejects_model_proposed_unknown_tool():
    with pytest.raises(AgentPlanRejected):
        validate_plan(plan_with_tool("shell_exec"), capabilities(), scope())

def test_counter_evidence_lowers_hypothesis_confidence():
    updated = evaluator.evaluate(task_with_injection_hypothesis(.82), observation("normal_response_ratio"))
    assert updated.hypotheses[0].confidence < .82
    assert updated.hypotheses[0].opposing_evidence_refs
```

Cover 12-step, two-replan, dependency-cycle, unknown-parameter, unapproved-path, automatic-external-action, simulation-on-real-task, cancellation, and weaker-action rejection.

- [ ] **Step 2: Verify planner tests fail**

Run: `python -m pytest tests/unit/test_security_agent_planner.py tests/unit/test_security_agent_policy.py -q`

Expected: FAIL because planner and policy do not exist.

- [ ] **Step 3: Implement deterministic plan templates and typed revisions**

Implement one code-owned template per task type. Optional model proposals must parse into `AgentPlanProposal`, then pass `validate_plan`; invalid proposals fall back to the deterministic template and add a public `planner_degraded` observation. Replans accept only the trigger matrix from the design: parse failure, encrypted-only, HTTP candidate, Prompt evidence conflict, knowledge shortage, temporary tool failure, or newly authorized user scope. The hypothesis evaluator uses code-owned evidence weights, records support and counter-evidence, and cannot mark a hypothesis `supported` without a direct `real` evidence reference.

- [ ] **Step 4: Run planner and existing SuperAgent policy tests**

Run: `python -m pytest tests/unit/test_security_agent_planner.py tests/unit/test_security_agent_policy.py tests/unit/test_superagent_policy.py -q`

Expected: PASS.

- [ ] **Step 5: Commit planning policy**

```bash
git add backend/app/security_agent/planner.py backend/app/security_agent/policy.py tests/unit/test_security_agent_planner.py tests/unit/test_security_agent_policy.py
git commit -m "feat: plan bounded security investigations"
```

### Task 5: Typed Tool Registry And Existing Capability Adapters

**Files:**
- Create: `backend/app/security_agent/tools.py`
- Create: `backend/app/security_agent/adapters.py`
- Test: `tests/unit/test_security_agent_tools.py`
- Test: `tests/unit/test_security_agent_adapters.py`

**Interfaces:**
- Consumes: existing `LabService`, `SuperAgentService`, `PcapMissionCoordinator`, `PcapReconMissionCoordinator`, `PcapDetectionMissionCoordinator`, and `KnowledgeService`.
- Produces: `SecurityToolSpec`, `SecurityToolRegistry`, and adapters for all 17 tool IDs in the design.

- [ ] **Step 1: Write failing registry and adapter contract tests**

```python
def test_registry_exposes_only_declared_tools():
    registry = build_registry(fake_dependencies())
    assert set(registry.ids()) == EXPECTED_SECURITY_TOOL_IDS

def test_pcap_adapter_returns_reference_not_private_file_identity():
    observation = registry.execute("detect_pcap_batch", authorized_pcap_input())
    assert observation.evidence_refs
    assert "path" not in observation.model_dump_json()
```

Assert each spec has schemas, permission level, timeout, retry count, concurrency cost, privacy level, and `auto_executable`. Assert adapters preserve existing objective IDs and never call cancellation during task switches.

- [ ] **Step 2: Verify tests fail**

Run: `python -m pytest tests/unit/test_security_agent_tools.py tests/unit/test_security_agent_adapters.py -q`

Expected: FAIL because registry and adapters are missing.

- [ ] **Step 3: Implement adapters without duplicating detector logic**

Adapters call existing public service methods and translate results into `AgentObservation` and `AgentEvidence`. They do not import Docker subprocess details or reimplement detection rules. Mark `analyze_prompt`, PCAP reads, feedback writes, and internal actions as authorization-bound; mark identity and general education as read-only. Framework mapping, similar-case search, response simulation, and response verification must return derived or explicitly simulated provenance and uncertainty.

- [ ] **Step 4: Run adapter and underlying service tests**

Run: `python -m pytest tests/unit/test_security_agent_tools.py tests/unit/test_security_agent_adapters.py tests/unit/test_superagent_service.py tests/unit/test_superagent_pcap_detection_coordinator.py -q`

Expected: PASS.

- [ ] **Step 5: Commit the tool layer**

```bash
git add backend/app/security_agent/tools.py backend/app/security_agent/adapters.py tests/unit/test_security_agent_tools.py tests/unit/test_security_agent_adapters.py
git commit -m "feat: expose typed security agent tools"
```

### Task 6: Simulated Cross-Domain Connectors

**Files:**
- Create: `backend/app/security_agent/simulated.py`
- Create: `data/demo/security-agent-cases.json`
- Test: `tests/unit/test_security_agent_simulated.py`

**Interfaces:**
- Consumes: versioned built-in demo case IDs only.
- Produces: `SimulatedTelemetryConnector.query(case_id: str) -> tuple[AgentEvidence, ...]`.

- [ ] **Step 1: Write failing provenance and isolation tests**

```python
def test_demo_connector_marks_every_item_simulated():
    evidence = connector.query("demo_llm_injection_01")
    assert evidence
    assert all(item.authenticity == "simulated" for item in evidence)

def test_demo_connector_rejects_arbitrary_identifiers():
    with pytest.raises(SimulatedCaseNotFound):
        connector.query("capture_1482.pcap")
```

Also assert fixed SHA-256 snapshot identity, no private keys, no IP/username/process command line, and no simulated item accepted by real evaluation collectors.

- [ ] **Step 2: Confirm tests fail**

Run: `python -m pytest tests/unit/test_security_agent_simulated.py -q`

Expected: FAIL because the connector and fixture are missing.

- [ ] **Step 3: Implement three compact built-in cases**

Create versioned, synthetic cases for Prompt injection reconnaissance, internal-address probing, and scripted extraction. Store only abstract endpoint, identity, and log facts such as `endpoint_process_anomaly`, `identity_session_burst`, and `gateway_request_correlation`; never store realistic private identifiers.

- [ ] **Step 4: Run simulation and evaluation isolation tests**

Run: `python -m pytest tests/unit/test_security_agent_simulated.py tests/unit/test_evaluation_service.py tests/unit/test_pcap_detection_evaluation.py -q`

Expected: PASS.

- [ ] **Step 5: Commit simulated connectors**

```bash
git add backend/app/security_agent/simulated.py data/demo/security-agent-cases.json tests/unit/test_security_agent_simulated.py
git commit -m "feat: add labeled cross-domain demo evidence"
```

### Task 7: Recoverable Coordinator, Report Generator, And SSE API

**Files:**
- Create: `backend/app/security_agent/coordinator.py`
- Create: `backend/app/security_agent/reporting.py`
- Create: `backend/app/api/agent.py`
- Modify: `backend/app/main.py`
- Test: `tests/unit/test_security_agent_coordinator.py`
- Test: `tests/unit/test_security_agent_reporting.py`
- Test: `tests/integration/test_security_agent_api.py`

**Interfaces:**
- Consumes: Tasks 1-6 plus application dependency state.
- Produces: `/api/v1/agent/capabilities`, `/tasks`, `/tasks/{id}`, `/tasks/{id}/messages`, `/tasks/{id}/authorizations`, `/tasks/{id}/events`, and explicit `/cancel`.

- [ ] **Step 1: Write failing end-to-end coordinator tests**

```python
def test_observation_drives_real_replan_and_report(fake_registry, store):
    task = coordinator.create(command("调查这批 PCAP 并生成报告"))
    coordinator.authorize(task.task_id, pcap_scope())
    finished = coordinator.run_until_blocked(task.task_id)
    assert finished.replan_count == 1
    assert any(event.kind == "plan_revised" for event in finished.events)
    assert finished.report.evidence_refs

def test_task_switch_does_not_cancel_background_execution(client):
    created = client.post("/api/v1/agent/tasks", json=pcap_command()).json()
    client.get("/api/v1/agent/tasks")
    restored = client.get(f"/api/v1/agent/tasks/{created['task_id']}").json()
    assert restored["status"] != "cancelled"

def test_successful_action_requires_independent_verification(client):
    task = run_block_case(client, verification="unavailable")
    assert task["final_status"] != "contained"
    assert any(item["kind"] == "response_unverified" for item in task["observations"])
```

Cover identity Q&A without task side effects, transient retry, degraded close, event replay using `Last-Event-ID`, explicit cancellation, authorization mismatch, prompt placeholder persistence, task listing, malformed adapter output, and public error codes.

- [ ] **Step 2: Verify coordinator and API tests fail**

Run: `python -m pytest tests/unit/test_security_agent_coordinator.py tests/unit/test_security_agent_reporting.py tests/integration/test_security_agent_api.py -q`

Expected: FAIL because coordinator and endpoints are missing.

- [ ] **Step 3: Implement the coordinator and cited Markdown report**

Use a bounded background executor and store every state transition before scheduling the next tool. After every response action, schedule `verify_response_effect`; only a successful independent observation permits `contained`. The report renderer accepts only `AgentEvidence` references, groups real/simulated/derived evidence separately, and renders hypotheses, support, counter-evidence, confidence changes, timeline, findings, purpose candidate, limitations, failures, uncovered scope, recommendations, actions, and verification status.

- [ ] **Step 4: Wire the router and lifecycle**

Construct and close `SecurityAgentStore` and the coordinator in application lifespan. Read `TOKEN_SECURITY_AGENT_DATABASE_PATH` with the same local data-root discipline as Lab storage. Do not make application startup fail when optional planner generation is unavailable; capabilities must show deterministic fallback.

- [ ] **Step 5: Run backend suites**

Run: `python -m pytest tests/unit/test_security_agent_coordinator.py tests/unit/test_security_agent_reporting.py tests/integration/test_security_agent_api.py tests/integration/test_superagent_api.py tests/integration/test_superagent_pcap_detection_api.py -q`

Expected: PASS.

- [ ] **Step 6: Commit the agent runtime**

```bash
git add backend/app/security_agent backend/app/api/agent.py backend/app/main.py tests/unit/test_security_agent_coordinator.py tests/unit/test_security_agent_reporting.py tests/integration/test_security_agent_api.py
git commit -m "feat: run recoverable security agent tasks"
```

### Task 8: Frontend Agent Contracts And Task Controller

**Files:**
- Create: `frontend/src/agent/types.ts`
- Create: `frontend/src/agent/taskState.ts`
- Create: `frontend/src/agent/useAgentTask.ts`
- Modify: `frontend/src/api.ts`
- Test: `frontend/src/agent/taskState.test.ts`
- Test: `frontend/src/agent/useAgentTask.test.tsx`
- Modify: `frontend/src/api.test.ts`

**Interfaces:**
- Consumes: Task 7 HTTP/SSE contracts.
- Produces: `AgentTaskSnapshot`, `AgentEvent`, `AgentCapabilities`, `reduceAgentEvent`, and `useAgentTask(taskId)`.

- [ ] **Step 1: Write failing event reduction and reconnect tests**

```tsx
it("applies only monotonic events for the active task", () => {
  const state = reduceAgentEvent(snapshot, event({ task_id: snapshot.task_id, sequence: 8 }));
  expect(reduceAgentEvent(state, event({ task_id: "task_other", sequence: 9 }))).toBe(state);
  expect(reduceAgentEvent(state, event({ task_id: snapshot.task_id, sequence: 7 }))).toBe(state);
});

it("falls back to bounded polling after repeated SSE failures", async () => {
  renderHook(() => useAgentTask("task_01"));
  await waitFor(() => expect(api.getAgentTask).toHaveBeenCalled());
});
```

Cover cleanup on unmount, no cancellation on route switch, 404/410 removal, transient restoration failure, message idempotency, and unknown objective rejection.

- [ ] **Step 2: Verify frontend controller tests fail**

Run: `npm.cmd test -- --run src/agent/taskState.test.ts src/agent/useAgentTask.test.tsx src/api.test.ts`

Expected: FAIL because agent contracts are missing.

- [ ] **Step 3: Implement strict client state and API methods**

Add create/list/get/message/authorize/cancel methods and an `EventSource` URL helper. Keep task state keyed by task ID, persist only the last selected public task ID in session storage, and call cancel only from an explicit cancel command.

- [ ] **Step 4: Run focused tests**

Run: `npm.cmd test -- --run src/agent/taskState.test.ts src/agent/useAgentTask.test.tsx src/api.test.ts`

Expected: PASS.

- [ ] **Step 5: Commit frontend task state**

```bash
git add frontend/src/agent frontend/src/api.ts frontend/src/api.test.ts
git commit -m "feat: manage live security agent tasks"
```

### Task 9: Approved Three-Pane Application Shell

**Files:**
- Create: `frontend/src/components/AgentSidebar.tsx`
- Create: `frontend/src/components/AgentInspectorShell.tsx`
- Create: `frontend/src/components/AgentMobileNav.tsx`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/styles.css`
- Modify: `frontend/src/App.test.tsx`
- Test: `frontend/src/components/AgentSidebar.test.tsx`

**Interfaces:**
- Consumes: Task summaries and existing route definitions.
- Produces: responsive global shell used by every route.

- [ ] **Step 1: Write failing navigation and visual-semantic tests**

```tsx
it("groups cases, professional workspaces, and agent resources", () => {
  render(<App />);
  expect(screen.getByText("安全案件")).toBeVisible();
  expect(screen.getByText("专业工作区")).toBeVisible();
  expect(screen.getByText("智能体资源")).toBeVisible();
  expect(screen.getByRole("link", { name: "Token 侦探挑战" })).toHaveAttribute("href", "/challenge");
});
```

Assert `/super-agent` is the default, all legacy routes work, headings are larger than items, the selected row has text plus blue styling, mobile drawers have 44px controls, and Challenge receives no altered props.

- [ ] **Step 2: Confirm tests fail**

Run: `npm.cmd test -- --run src/App.test.tsx src/components/AgentSidebar.test.tsx src/ChallengePage.test.tsx`

Expected: FAIL on the new shell expectations while Challenge remains green.

- [ ] **Step 3: Implement the shell with approved colors**

Use Lucide icons, CSS variables, `grid-template-columns: 240px minmax(0, 1fr) 360px`, translucent `rgba(229, 241, 250, .94)` sidebar, `#347fbe` identity icons, and route-aware center/inspector slots. At widths below 1100px collapse the inspector; below 760px use one column with drawers.

- [ ] **Step 4: Run shell tests**

Run: `npm.cmd test -- --run src/App.test.tsx src/components/AgentSidebar.test.tsx src/ChallengePage.test.tsx`

Expected: PASS.

- [ ] **Step 5: Commit the unified shell**

```bash
git add frontend/src/App.tsx frontend/src/styles.css frontend/src/components/AgentSidebar.tsx frontend/src/components/AgentInspectorShell.tsx frontend/src/components/AgentMobileNav.tsx frontend/src/App.test.tsx frontend/src/components/AgentSidebar.test.tsx
git commit -m "feat: add unified security agent shell"
```

### Task 10: Conversation, Plan, Progress, And Authorization UI

**Files:**
- Create: `frontend/src/pages/AgentWorkspacePage.tsx`
- Create: `frontend/src/components/AgentConversation.tsx`
- Create: `frontend/src/components/AgentComposer.tsx`
- Create: `frontend/src/components/AgentPlan.tsx`
- Create: `frontend/src/components/AgentAuthorizationDialog.tsx`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/styles.css`
- Test: `frontend/src/AgentWorkspacePage.test.tsx`

**Interfaces:**
- Consumes: Task 8 controller and Task 9 shell.
- Produces: working `/super-agent` conversational workspace.

- [ ] **Step 1: Write failing conversational workflow tests**

```tsx
it("answers identity without creating a detection task", async () => {
  render(<AgentWorkspacePage />);
  await userEvent.type(screen.getByRole("textbox", { name: "安全任务" }), "你叫什么名字");
  await userEvent.click(screen.getByRole("button", { name: "发送" }));
  expect(await screen.findByText(/我是 Token Security 安全智能体/)).toBeVisible();
  expect(api.authorizeAgentTask).not.toHaveBeenCalled();
});

it("shows a plan before requesting PCAP authorization", async () => {
  await submit("检测这批 PCAP 并生成报告");
  expect(await screen.findByRole("region", { name: "执行计划" })).toBeVisible();
  expect(screen.getByRole("dialog", { name: "授权 PCAP 调查" })).toBeVisible();
});
```

Cover attack education, `packet 4-4`, follow-up context, ambiguous cancel clarification, explicit cancel, retry, background task switching, plan revision, keyboard focus, and no auto-execution from example prompts.

- [ ] **Step 2: Verify workspace tests fail**

Run: `npm.cmd test -- --run src/AgentWorkspacePage.test.tsx src/SuperAgentPage.test.tsx src/PcapSuperAgentWorkspace.test.tsx`

Expected: FAIL because the new workspace is absent; legacy component tests remain green.

- [ ] **Step 3: Implement the central workspace**

Render user/agent messages, a unified-blue `AgentPlan`, actual tool progress, observed replans, result cards, report links, and an icon-based composer supporting text, Prompt, PCAP upload, and data-source selection. Do not render fake typing or hidden thought text. Authorization dialogs default focus to cancel and describe exact purpose and scope.

- [ ] **Step 4: Run workspace tests**

Run: `npm.cmd test -- --run src/AgentWorkspacePage.test.tsx src/SuperAgentPage.test.tsx src/PcapSuperAgentWorkspace.test.tsx`

Expected: PASS.

- [ ] **Step 5: Commit conversation UI**

```bash
git add frontend/src/pages/AgentWorkspacePage.tsx frontend/src/components/AgentConversation.tsx frontend/src/components/AgentComposer.tsx frontend/src/components/AgentPlan.tsx frontend/src/components/AgentAuthorizationDialog.tsx frontend/src/App.tsx frontend/src/styles.css frontend/src/AgentWorkspacePage.test.tsx
git commit -m "feat: converse with the security agent"
```

### Task 11: Evidence Inspector, PCAP Education, And Reports

**Files:**
- Create: `frontend/src/components/AgentEvidenceInspector.tsx`
- Create: `frontend/src/components/AgentToolInspector.tsx`
- Create: `frontend/src/components/AgentReportInspector.tsx`
- Create: `frontend/src/components/AuthenticityBadge.tsx`
- Create: `frontend/src/components/AgentHypothesisPanel.tsx`
- Create: `frontend/src/components/AgentAttackTimeline.tsx`
- Modify: `frontend/src/pages/AgentWorkspacePage.tsx`
- Modify: `frontend/src/styles.css`
- Test: `frontend/src/components/AgentEvidenceInspector.test.tsx`
- Test: `frontend/src/components/AgentReportInspector.test.tsx`

**Interfaces:**
- Consumes: Agent evidence, observations, executions, and report metadata.
- Produces: task-aware right inspector and mobile inspector drawer.

- [ ] **Step 1: Write failing explainability tests**

```tsx
it("never presents simulated evidence as real", () => {
  render(<AgentEvidenceInspector evidence={[simulatedEvidence()]} />);
  expect(screen.getByText("仿真")).toBeVisible();
  expect(screen.queryByText("真实检测")).not.toBeInTheDocument();
});

it("separates anomaly failure and no-hit states", () => {
  render(<AgentEvidenceInspector evidence={mixedPcapEvidence()} />);
  expect(screen.getByText("发现异常候选")).toBeVisible();
  expect(screen.getByText("检测失败")).toBeVisible();
  expect(screen.getByText("当前范围未命中")).toBeVisible();
});

it("shows support counter-evidence and confidence changes", () => {
  render(<AgentHypothesisPanel hypotheses={[injectionHypothesis()]} />);
  expect(screen.getByText("支持证据")).toBeVisible();
  expect(screen.getByText("反对证据")).toBeVisible();
  expect(screen.getByText("置信度变化")).toBeVisible();
});
```

Cover attack-purpose caveats, encrypted payload wording, packet ranges, Wireshark filters, cited reports, unavailable downloads, long filenames, and red/green/amber labels with non-color text.

- [ ] **Step 2: Confirm inspector tests fail**

Run: `npm.cmd test -- --run src/components/AgentEvidenceInspector.test.tsx src/components/AgentReportInspector.test.tsx`

Expected: FAIL because the inspector components are missing.

- [ ] **Step 3: Implement evidence, tool, and report tabs**

Use blue source badges for real evidence, amber badges for simulation, and neutral derived badges. Preserve existing sanitized `PcapDetectionResult` semantics. Add hypotheses and timeline tabs showing structured CoT without system prompts or scratchpads. Display generated Wireshark filters as copyable code only when the backend returns a public filter; never synthesize from hidden identities in the browser.

- [ ] **Step 4: Run inspector and PCAP presentation tests**

Run: `npm.cmd test -- --run src/components/AgentEvidenceInspector.test.tsx src/components/AgentReportInspector.test.tsx src/components/PcapDetectionResult.test.tsx src/components/PcapEvidenceDesk.test.tsx`

Expected: PASS.

- [ ] **Step 5: Commit explainability UI**

```bash
git add frontend/src/components/AgentEvidenceInspector.tsx frontend/src/components/AgentToolInspector.tsx frontend/src/components/AgentReportInspector.tsx frontend/src/components/AuthenticityBadge.tsx frontend/src/components/AgentHypothesisPanel.tsx frontend/src/components/AgentAttackTimeline.tsx frontend/src/pages/AgentWorkspacePage.tsx frontend/src/styles.css frontend/src/components/AgentEvidenceInspector.test.tsx frontend/src/components/AgentReportInspector.test.tsx
git commit -m "feat: explain agent evidence and reports"
```

### Task 12: Versioned Playbooks, Connector Center, And Analyst Feedback

**Files:**
- Create: `backend/app/security_agent/playbooks.py`
- Create: `backend/app/security_agent/feedback.py`
- Create: `data/demo/security-agent-playbooks.json`
- Modify: `backend/app/api/agent.py`
- Create: `frontend/src/components/AgentResourceCenter.tsx`
- Test: `tests/unit/test_security_agent_playbooks.py`
- Test: `tests/unit/test_security_agent_feedback.py`
- Test: `frontend/src/components/AgentResourceCenter.test.tsx`

**Interfaces:**
- Consumes: registered tool specs, capabilities, task snapshots, and versioned demo connectors.
- Produces: read-only playbook catalog, connector health catalog, and append-only analyst feedback records.

- [ ] **Step 1: Write failing playbook and feedback safety tests**

```python
def test_playbook_can_only_reference_registered_tools(registry):
    with pytest.raises(PlaybookInvalid):
        load_playbook({"id": "bad", "steps": [{"tool_id": "python_exec"}]}, registry)

def test_feedback_never_changes_frozen_detector_thresholds(service):
    before = service.detector_identity()
    service.record_feedback(task_id="task_01", verdict="false_positive", reason_code="known_test")
    assert service.detector_identity() == before
```

Frontend tests must show real, simulated, unavailable, and degraded connector states with text labels, and must not offer arbitrary connector URLs or arbitrary code nodes.

- [ ] **Step 2: Verify tests fail**

Run: `python -m pytest tests/unit/test_security_agent_playbooks.py tests/unit/test_security_agent_feedback.py -q`

Run: `npm.cmd test -- --run src/components/AgentResourceCenter.test.tsx`

Expected: FAIL because playbooks, feedback, and resource center are missing.

- [ ] **Step 3: Implement bounded resources**

Provide versioned playbooks for Prompt investigation, PCAP dataset investigation, cross-domain demo investigation, and report generation. A playbook contains only registered tool IDs, allowed observation conditions, authorization gates, and fallback targets. Store feedback as append-only task ID, public verdict, reason code, timestamp, and evidence refs; expose it as an offline improvement suggestion only.

- [ ] **Step 4: Run resource tests**

Run: `python -m pytest tests/unit/test_security_agent_playbooks.py tests/unit/test_security_agent_feedback.py tests/unit/test_security_agent_policy.py -q`

Run: `npm.cmd test -- --run src/components/AgentResourceCenter.test.tsx src/App.test.tsx`

Expected: PASS.

- [ ] **Step 5: Commit resource management**

```bash
git add backend/app/security_agent/playbooks.py backend/app/security_agent/feedback.py backend/app/api/agent.py data/demo/security-agent-playbooks.json tests/unit/test_security_agent_playbooks.py tests/unit/test_security_agent_feedback.py frontend/src/components/AgentResourceCenter.tsx frontend/src/components/AgentResourceCenter.test.tsx
git commit -m "feat: add bounded agent resources"
```

### Task 13: Competition Traceability, Full Regression, And Browser QA

**Files:**
- Create: `docs/security-agent-user-guide.md`
- Create: `docs/competition-requirement-traceability.md`
- Modify: `README.md`
- Test: `tests/integration/test_security_agent_api.py`
- Test: `frontend/src/App.test.tsx`

**Interfaces:**
- Consumes: all previous tasks.
- Produces: submission-ready requirement mapping, user guide, verified build, and screenshots with synthetic/sanitized inputs only.

- [ ] **Step 1: Add executable competition assertions**

```python
def test_challenge_demo_contains_plan_observation_replan_and_close(client):
    task = run_builtin_cross_domain_demo(client)
    phases = [event["phase"] for event in task["events"]]
    assert "plan" in phases
    assert "observe" in phases
    assert "replan" in phases
    assert phases[-1] == "complete"
    assert any(item["authenticity"] == "simulated" for item in task["evidence"])
    assert len(task["hypotheses"]) >= 2
    assert any(item["opposing_evidence_refs"] for item in task["hypotheses"])
    assert task["response_verification"]["status"] in {"verified", "not_effective", "unavailable"}
```

Add frontend assertions for the visible plan, tool invocation, observation, plan revision, final limitations, and simulation labels.

- [ ] **Step 2: Write documentation with an evidence table**

The traceability document must use `已实现`, `部分实现`, or `未实现`; map every claim to an endpoint, test, screenshot, or report. Explicitly state the official-platform waiver, auditable decision-chain interpretation of CoT, internal-only response tools, simulated connector boundary, and that one authorization precedes the autonomous bounded run.

- [ ] **Step 3: Run complete backend and frontend suites**

Run: `python -m pytest -q`

Expected: all backend tests PASS.

Run: `npm.cmd test`

Expected: all frontend tests PASS.

Run: `npm.cmd run build`

Expected: TypeScript and Vite production build PASS.

Run: `git diff --check`

Expected: no whitespace errors.

- [ ] **Step 4: Verify desktop and mobile with Playwright**

At `1440x900` and `390x844`, run identity Q&A, attack education, a sanitized Prompt task, a synthetic PCAP task, and the built-in cross-domain demo. Verify no horizontal overflow, no console/page/resource errors, no overlapping controls, correct blue chain accents, explicit authenticity labels, task restoration after reload, and that route switches never cancel a running task.

- [ ] **Step 5: Commit documentation and final verification changes**

```bash
git add README.md docs/security-agent-user-guide.md docs/competition-requirement-traceability.md tests/integration/test_security_agent_api.py frontend/src/App.test.tsx
git commit -m "docs: map security agent to competition requirements"
```
