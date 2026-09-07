# Proactive Security Dialogue Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn Prompt and PCAP results into persistent conversations that proactively offer evidence-grounded questions and executable next actions.

**Architecture:** Extend the existing SQLite-backed `AgentTaskSnapshot` with typed suggested questions and next actions computed by a pure policy module. Keep Prompt and PCAP detectors as the only factual sources; import a completed PCAP detection mission into an agent task through an idempotent backend boundary. Execute approved actions through the coordinator and append every request, progress update, result, and failure to the same task conversation.

**Tech Stack:** FastAPI, Pydantic, SQLite, React, TypeScript, Vitest, Testing Library, pytest.

## Global Constraints

- User messages render on the right; Token Security messages render on the left in true chronological order.
- Every completed investigation exposes two to four context-relevant follow-up entries.
- Suggested questions explain evidence and never mutate task state.
- Next actions are returned by the backend and only reference registered, currently available capabilities.
- Read-only actions execute after one click; isolation, blocking, account changes, and scope expansion require explicit authorization.
- Raw Prompt text stays browser-local except while a user-confirmed request is in flight; it is not persisted in server task state, reports, logs, or public evidence.
- PCAP payloads, paths, filenames, addresses, ports, and credentials never enter public agent task state.
- External EDR, firewall, identity, and SIEM actions remain unavailable unless a real connector is installed.
- Preserve unrelated dirty-worktree changes.

---

### Task 1: Typed Recommendation Contract

**Files:**
- Create: `backend/app/security_agent/recommendations.py`
- Modify: `backend/app/security_agent/models.py`
- Modify: `frontend/src/agent/types.ts`
- Test: `tests/unit/test_security_agent_recommendations.py`
- Test: `tests/unit/test_security_agent_models.py`

**Interfaces:**
- Produces: `AgentSuggestedQuestion(question_id, label, message)`.
- Produces: `AgentNextAction(action_id, label, action_kind, requires_authorization, enabled, disabled_reason)`.
- Produces: `recommendations_for(snapshot: AgentTaskSnapshot, capabilities: AgentCapabilities) -> tuple[tuple[AgentSuggestedQuestion, ...], tuple[AgentNextAction, ...]]`.
- Produces matching TypeScript `AgentSuggestedQuestion` and `AgentNextAction` types.

- [ ] **Step 1: Write failing policy tests**

```python
def test_prompt_risk_recommends_explanation_repair_recheck_and_report():
    questions, actions = recommendations_for(prompt_snapshot(final_status="risk_found"), capabilities())
    assert [item.question_id for item in questions] == ["why_risky", "locate_tokens"]
    assert [item.action_id for item in actions] == ["suggest_prompt_repair", "recheck_prompt", "generate_report"]


def test_unavailable_tools_are_not_exposed_as_enabled_actions():
    questions, actions = recommendations_for(pcap_snapshot(), capabilities(tool_ids=()))
    assert questions
    assert all(not item.enabled for item in actions)
    assert all(item.disabled_reason for item in actions)
```

- [ ] **Step 2: Run the focused tests and verify failure**

Run: `python -m pytest tests/unit/test_security_agent_recommendations.py tests/unit/test_security_agent_models.py -q`

Expected: FAIL because the recommendation models and policy module do not exist.

- [ ] **Step 3: Add strict public models and snapshot fields**

```python
class AgentSuggestedQuestion(_PublicModel):
    question_id: str = Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")
    label: NonEmptyText
    message: NonEmptyText


class AgentNextAction(_PublicModel):
    action_id: Literal[
        "explain_evidence", "suggest_prompt_repair", "recheck_prompt",
        "inspect_suspicious_packets", "analyze_attack_chain",
        "generate_response_plan", "generate_report", "expand_pcap_scope",
    ]
    label: NonEmptyText
    action_kind: Literal["read_only", "state_change"]
    requires_authorization: bool = False
    enabled: bool = True
    disabled_reason: NonEmptyText | None = None
```

Add `suggested_questions: tuple[AgentSuggestedQuestion, ...] = Field(default=(), max_length=4)` and `next_actions: tuple[AgentNextAction, ...] = Field(default=(), max_length=4)` to `AgentTaskSnapshot`. Mirror the exact fields and string unions in TypeScript.

- [ ] **Step 4: Implement deterministic recommendation mapping**

Map task type, status, final status, evidence presence, report presence, and registered tool IDs. Do not inspect raw Prompt or PCAP content. Deduplicate by stable ID and cap each group at four entries.

- [ ] **Step 5: Run tests green and commit**

Run: `python -m pytest tests/unit/test_security_agent_recommendations.py tests/unit/test_security_agent_models.py -q`

```bash
git add backend/app/security_agent/recommendations.py backend/app/security_agent/models.py frontend/src/agent/types.ts tests/unit/test_security_agent_recommendations.py tests/unit/test_security_agent_models.py
git commit -m "feat: define agent next-step recommendations"
```

### Task 2: Natural Conversation Scope and Grounded Questions

**Files:**
- Modify: `backend/app/security_agent/intent.py`
- Modify: `backend/app/security_agent/education.py`
- Modify: `backend/app/security_agent/coordinator.py`
- Test: `tests/unit/test_security_agent_intent.py`
- Test: `tests/unit/test_security_agent_coordinator.py`

**Interfaces:**
- Consumes: recommendation models from Task 1.
- Produces: `parse_intent()` support for greetings, presence questions, thanks, navigation questions, security education, and current-case questions.
- Produces: completed conversational tasks with recommendations but no tool execution.

- [ ] **Step 1: Add failing intent and response tests**

```python
@pytest.mark.parametrize("message", ["你好", "hi", "你在干嘛", "谢谢你", "再见"])
def test_everyday_conversation_is_not_out_of_scope(message):
    assert parse_intent(message, None).kind == "smalltalk"


def test_presence_question_answers_naturally_without_tools(tmp_path):
    service = coordinator(tmp_path)
    task = service.create("你在干嘛")
    assert "等待你的安全问题" in task.messages[-1].content
    assert service.registry.calls == []
```

- [ ] **Step 2: Run tests and verify the current rejection**

Run: `python -m pytest tests/unit/test_security_agent_intent.py tests/unit/test_security_agent_coordinator.py -q`

Expected: FAIL because `你在干嘛` currently routes to `out_of_scope`.

- [ ] **Step 3: Expand bounded intent routing and copy**

Recognize greetings, presence, gratitude, farewell, product navigation, security concepts, and current-case evidence wording before the out-of-scope fallback. Keep unsafe tool requests and unrelated complex work rejected. Make responses contextual when a current task exists and neutral otherwise.

- [ ] **Step 4: Attach recommendations after create and follow-up**

Add one coordinator helper that stores a snapshot after calling `recommendations_for(updated, self.capabilities)`. Use it after conversational creation, tool completion, message replies, action completion, and action failure so recommendations cannot become stale.

- [ ] **Step 5: Run tests green and commit**

Run: `python -m pytest tests/unit/test_security_agent_intent.py tests/unit/test_security_agent_coordinator.py -q`

```bash
git add backend/app/security_agent/intent.py backend/app/security_agent/education.py backend/app/security_agent/coordinator.py tests/unit/test_security_agent_intent.py tests/unit/test_security_agent_coordinator.py
git commit -m "feat: broaden grounded security conversation"
```

### Task 3: Executable Next Actions

**Files:**
- Modify: `backend/app/security_agent/models.py`
- Modify: `backend/app/security_agent/coordinator.py`
- Modify: `backend/app/security_agent/reporting.py`
- Modify: `backend/app/api/agent.py`
- Test: `tests/unit/test_security_agent_coordinator.py`
- Test: `tests/integration/test_security_agent_api.py`

**Interfaces:**
- Produces: `AgentActionRequest(action_id, transient_input=None, authorization_scopes=())`.
- Produces: `AgentIntent.report_requested: bool`, set only when the initial request explicitly asks for a report.
- Produces: `SecurityAgentCoordinator.execute_action(task_id: str, request: AgentActionRequest) -> AgentTaskSnapshot`.
- Produces: `POST /api/v1/agent/tasks/{task_id}/actions`.

- [ ] **Step 1: Write failing coordinator and API tests**

```python
def test_generate_report_action_appends_user_then_agent_result(tmp_path):
    service, task = completed_prompt_task(tmp_path)
    updated = service.execute_action(task.task_id, AgentActionRequest(action_id="generate_report"))
    assert updated.messages[-2].role == "user"
    assert updated.messages[-2].content == "生成调查报告"
    assert updated.messages[-1].role == "agent"
    assert updated.report is not None
    assert all(item.action_id != "generate_report" for item in updated.next_actions)


def test_unknown_or_stale_action_is_rejected(client, completed_task):
    response = client.post(f"/api/v1/agent/tasks/{completed_task}/actions", json={"action_id": "expand_pcap_scope"})
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "agent_action_not_available"
```

- [ ] **Step 2: Run tests and verify failure**

Run: `python -m pytest tests/unit/test_security_agent_coordinator.py tests/integration/test_security_agent_api.py -q`

Expected: FAIL because the action request and endpoint do not exist.

- [ ] **Step 3: Implement action validation and message ordering**

Validate the requested ID against the current snapshot's `next_actions`, reject disabled and duplicate in-flight actions, append a user message before execution, and append an agent result or warning afterward. Implement these first-version behaviors:

```python
ACTION_HANDLERS = {
    "explain_evidence": "render current public evidence and limitations",
    "suggest_prompt_repair": "produce evidence-bound repair guidance",
    "recheck_prompt": "require transient_input and call the registered prompt runtime",
    "inspect_suspicious_packets": "render public Packet ranges and confidence",
    "analyze_attack_chain": "derive a bounded chain from timeline and evidence",
    "generate_response_plan": "produce read-only containment recommendations",
    "generate_report": "call the existing report renderer and attach metadata",
    "expand_pcap_scope": "return awaiting_authorization with pcap:read scope",
}
```

The `transient_input` field may be accepted only for `recheck_prompt`; pass it directly to the runtime and discard it before storing the snapshot. Never place it in events, evidence, report metadata, or errors.

- [ ] **Step 4: Stop automatic report generation for ordinary investigations**

Add `report_requested: bool = False` to `AgentIntent` and set it during intent parsing when the initial request contains both a report noun and a generation verb. Remove `generate_case_report` from ordinary Prompt and PCAP plans when this field is false. Preserve automatic report generation when it is true or when the task is the full closed-loop demonstration. Update existing tests so a normal completed investigation exposes `generate_report` while an explicit report objective still finishes with a report.

- [ ] **Step 5: Run tests green and commit**

Run: `python -m pytest tests/unit/test_security_agent_coordinator.py tests/unit/test_security_agent_intent.py tests/integration/test_security_agent_api.py -q`

```bash
git add backend/app/security_agent/models.py backend/app/security_agent/coordinator.py backend/app/security_agent/reporting.py backend/app/api/agent.py tests/unit/test_security_agent_coordinator.py tests/integration/test_security_agent_api.py
git commit -m "feat: execute agent-recommended security actions"
```

### Task 4: Import PCAP Detection into Agent Tasks

**Files:**
- Create: `backend/app/security_agent/pcap_import.py`
- Modify: `backend/app/security_agent/coordinator.py`
- Modify: `backend/app/api/agent.py`
- Modify: `frontend/src/api.ts`
- Test: `tests/unit/test_security_agent_pcap_import.py`
- Test: `tests/integration/test_security_agent_api.py`
- Test: `frontend/src/api.test.ts`

**Interfaces:**
- Produces: `import_pcap_detection(result: PcapDetectionMissionResult) -> AgentPcapImport` containing only public counts, evidence ranges, candidates, confidence, and limitations.
- Produces: `SecurityAgentCoordinator.create_from_pcap(result) -> AgentTaskSnapshot`.
- Produces: `POST /api/v1/agent/tasks/import-pcap` with `{ "detection_id": "detect_<id>" }`.
- Produces: `api.importPcapAgentTask(detectionId: string): Promise<AgentTaskSnapshot>`.

- [ ] **Step 1: Write failing privacy and idempotency tests**

```python
def test_imported_pcap_task_contains_public_evidence_only(client, finished_detection):
    first = client.post("/api/v1/agent/tasks/import-pcap", json={"detection_id": finished_detection}).json()
    second = client.post("/api/v1/agent/tasks/import-pcap", json={"detection_id": finished_detection}).json()
    assert second["task_id"] == first["task_id"]
    encoded = json.dumps(first).lower()
    for forbidden in ("filename", "file_path", "payload", "ip_address", "port"):
        assert forbidden not in encoded
```

- [ ] **Step 2: Run tests and verify failure**

Run: `python -m pytest tests/unit/test_security_agent_pcap_import.py tests/integration/test_security_agent_api.py -q`

Expected: FAIL because no import boundary exists.

- [ ] **Step 3: Implement the public adapter and idempotent import**

Resolve the detection ID through the existing PCAP coordinator in the API layer. Accept terminal `completed` or `degraded` results only. Convert evidence IDs, Packet start/end, attack candidates, purpose candidates, confidence, succeeded/failed counts, and uncertainty into agent evidence and observations. Use the detection ID as a unique source reference so retries return the same task.

Declare `/tasks/import-pcap` before `/tasks/{task_id}` in `backend/app/api/agent.py` so FastAPI never interprets `import-pcap` as a task ID.

- [ ] **Step 4: Add frontend API typing and tests**

```ts
importPcapAgentTask: (detectionId: string) =>
  requestJson<AgentTaskSnapshot>("/api/v1/agent/tasks/import-pcap", {
    method: "POST",
    body: JSON.stringify({ detection_id: detectionId }),
  }),
```

- [ ] **Step 5: Run tests green and commit**

Run: `python -m pytest tests/unit/test_security_agent_pcap_import.py tests/integration/test_security_agent_api.py -q`

Run: `npm.cmd test -- api.test.ts`

```bash
git add backend/app/security_agent/pcap_import.py backend/app/security_agent/coordinator.py backend/app/api/agent.py frontend/src/api.ts tests/unit/test_security_agent_pcap_import.py tests/integration/test_security_agent_api.py frontend/src/api.test.ts
git commit -m "feat: import pcap results into agent conversations"
```

### Task 5: Suggested Questions and Actions UI

**Files:**
- Create: `frontend/src/components/AgentNextSteps.tsx`
- Create: `frontend/src/components/AgentNextSteps.test.tsx`
- Modify: `frontend/src/components/AgentConversation.tsx`
- Modify: `frontend/src/pages/AgentWorkspacePage.tsx`
- Modify: `frontend/src/api.ts`
- Modify: `frontend/src/styles.css`
- Test: `frontend/src/AgentWorkspacePage.test.tsx`

**Interfaces:**
- Consumes: `AgentSuggestedQuestion[]` and `AgentNextAction[]` from Task 1.
- Consumes: `api.executeAgentAction(taskId, actionId, transientInput?)`.
- Produces: `AgentNextSteps({ questions, actions, busy, onQuestion, onAction })`.

- [ ] **Step 1: Write failing component tests**

```tsx
render(<AgentNextSteps questions={questions} actions={actions} busy={false} onQuestion={ask} onAction={act} />);
expect(screen.getByRole("group", { name: "推荐追问" })).toBeVisible();
expect(screen.getByRole("group", { name: "建议动作" })).toBeVisible();
fireEvent.click(screen.getByRole("button", { name: "为什么判断为高风险？" }));
expect(ask).toHaveBeenCalledWith("为什么判断为高风险？");
```

- [ ] **Step 2: Run tests and verify failure**

Run: `npm.cmd test -- components/AgentNextSteps.test.tsx AgentWorkspacePage.test.tsx`

Expected: FAIL because no next-step component is rendered.

- [ ] **Step 3: Implement the next-step component**

Render it only below the latest agent message. Use compact light-blue outlined question buttons and solid-blue action buttons with Lucide icons. Disabled actions remain visible only when the reason helps explain a missing capability; expose the reason through visible text and `aria-describedby`. On mobile, use one full-width button per row.

- [ ] **Step 4: Wire question and action execution**

Question clicks call the existing message endpoint so the right-side user message appears before the agent answer. Action clicks call the action endpoint. For `recheck_prompt`, retrieve the current browser-local Prompt; when it is missing, prefill the composer with a request to paste the repaired Prompt instead of sending an empty action. Keep the composer usable after terminal results.

- [ ] **Step 5: Import completed PCAP missions automatically**

When PCAP polling reaches a terminal state, call `importPcapAgentTask()` exactly once, replace the standalone result state with the returned agent task, update the URL to `?mode=pcap&task=<id>`, and refresh the recent-task list. Preserve upload progress and cancellation behavior before terminal state.

- [ ] **Step 6: Run frontend tests green and commit**

Run: `npm.cmd test -- components/AgentNextSteps.test.tsx components/AgentConversation.test.tsx AgentWorkspacePage.test.tsx api.test.ts`

```bash
git add frontend/src/components/AgentNextSteps.tsx frontend/src/components/AgentNextSteps.test.tsx frontend/src/components/AgentConversation.tsx frontend/src/pages/AgentWorkspacePage.tsx frontend/src/api.ts frontend/src/styles.css frontend/src/AgentWorkspacePage.test.tsx
git commit -m "feat: add proactive conversation next steps"
```

### Task 6: End-to-End Dialogue Verification

**Files:**
- Modify only files required by defects discovered in this bounded verification pass.

**Interfaces:**
- Verifies the complete Prompt and PCAP conversation contracts.

- [ ] **Step 1: Run backend focused tests**

Run: `python -m pytest tests/unit/test_security_agent_models.py tests/unit/test_security_agent_recommendations.py tests/unit/test_security_agent_intent.py tests/unit/test_security_agent_coordinator.py tests/unit/test_security_agent_pcap_import.py tests/integration/test_security_agent_api.py -q`

Expected: PASS.

- [ ] **Step 2: Run frontend focused tests**

Run: `npm.cmd test -- AgentWorkspacePage.test.tsx components/AgentConversation.test.tsx components/AgentNextSteps.test.tsx api.test.ts`

Expected: PASS.

- [ ] **Step 3: Run privacy checks**

Run: `python scripts/verify_pcap_agent_privacy.py`

Expected: exit code 0 and no forbidden Prompt, payload, path, address, port, or credential field in public snapshots.

- [ ] **Step 4: Run the full frontend suite and production build**

Run: `npm.cmd test`

Run: `npm.cmd run build`

Expected: both commands pass.

- [ ] **Step 5: Perform desktop and mobile browser verification**

At 1440x900 and 390x844, verify greeting, Prompt risk investigation, recommended question, report action, PCAP upload import, attack-chain action, history reopen, and task deletion. Confirm user messages remain right aligned, agent output remains left aligned, buttons do not cover the composer or inspector, and every real/simulated boundary remains visible.

- [ ] **Step 6: Check the final diff**

Run: `git diff --check`

If verification finds no defect, create no commit. If it finds a defect, return to the owning task, add the failing regression test there, apply that task's explicit file list, and rerun this verification task from Step 1.
