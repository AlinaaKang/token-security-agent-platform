# Unified Security Conversation and Guidance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn Prompt and PCAP investigations into persistent, distinguishable multi-turn conversations, separate the PCAP challenge from real upload detection, and provide working contextual guidance on every agent surface.

**Architecture:** Extend the existing SQLite-backed security-agent task contract instead of creating a second conversation store. Keep real PCAP upload results in the conversation workspace, make the challenge a deterministic client-side exercise over built-in sanitized cases, and resolve guided tours from pathname plus query context. UI components remain mode-specific at the evidence layer while sharing the same conversation shell.

**Tech Stack:** FastAPI, Pydantic, SQLite, React, TypeScript, React Router, Vitest, Testing Library, CSS.

## Global Constraints

- Prompt and PCAP conversations remain usable after refresh and history reopening.
- User messages render on the right; agent messages render on the left.
- Evidence-grounded replies must state uncertainty when evidence is unavailable.
- The PCAP detective challenge uses built-in sanitized cases and does not upload user files.
- Guided tours never send messages, upload files, or execute detection APIs.
- Preserve unrelated dirty-worktree changes.

---

### Task 1: Distinguishable Tasks, Final Replies, and Deletion Contract

**Files:**
- Modify: `backend/app/security_agent/coordinator.py`
- Modify: `backend/app/security_agent/store.py`
- Modify: `backend/app/api/agent.py`
- Modify: `frontend/src/api.ts`
- Test: `tests/unit/test_security_agent_coordinator.py`
- Test: `tests/unit/test_security_agent_store.py`
- Test: `tests/integration/test_security_agent_api.py`
- Test: `frontend/src/api.test.ts`

**Interfaces:**
- Produces: `SecurityAgentCoordinator.delete(task_id: str) -> None`
- Produces: `DELETE /api/v1/agent/tasks/{task_id}` with HTTP 204 or structured 404.
- Produces: `api.deleteAgentTask(taskId: string): Promise<void>`.
- Produces: task/report titles derived from normalized first user text, capped to a stable display length.

- [ ] **Step 1: Write failing backend and frontend API tests**

```python
def test_task_title_uses_first_request_and_delete_removes_task(client):
    task = client.post("/api/v1/agent/tasks", json={"message": "检测这段 Prompt 是否包含越狱风险"}).json()
    assert "越狱风险" in task["title"]
    assert client.delete(f"/api/v1/agent/tasks/{task['task_id']}").status_code == 204
    assert client.get(f"/api/v1/agent/tasks/{task['task_id']}").status_code == 404
```

- [ ] **Step 2: Run focused tests and confirm failure**

Run: `python -m pytest tests/unit/test_security_agent_coordinator.py tests/unit/test_security_agent_store.py tests/integration/test_security_agent_api.py -q`

- [ ] **Step 3: Implement title derivation, cascade deletion, and report naming**

```python
def _title_for(task_type: AgentTaskType | None, message: str) -> str:
    compact = " ".join(message.split())
    return compact[:28] + ("…" if len(compact) > 28 else "")
```

Use the existing foreign-key cascade for related events, discard transient Prompt content, and return 404 for unknown task IDs. Build report titles from the task title and generated local timestamp rather than the generic task type.

- [ ] **Step 4: Add `deleteAgentTask` to the frontend API and run tests green**

Run: `npm.cmd test -- api.test.ts`

- [ ] **Step 5: Commit the task contract**

```bash
git add backend/app/security_agent/coordinator.py backend/app/security_agent/store.py backend/app/api/agent.py frontend/src/api.ts tests/unit/test_security_agent_coordinator.py tests/unit/test_security_agent_store.py tests/integration/test_security_agent_api.py frontend/src/api.test.ts
git commit -m "feat: manage distinguishable agent tasks"
```

### Task 2: Unified Multi-turn Prompt and PCAP Conversation

**Files:**
- Modify: `backend/app/security_agent/coordinator.py`
- Modify: `backend/app/security_agent/intent.py`
- Modify: `backend/app/security_agent/prompt_runtime.py`
- Modify: `frontend/src/pages/AgentWorkspacePage.tsx`
- Modify: `frontend/src/components/AgentConversation.tsx`
- Modify: `frontend/src/components/PcapDetectionResult.tsx`
- Modify: `frontend/src/agent/localConversation.ts`
- Test: `tests/unit/test_security_agent_coordinator.py`
- Test: `tests/unit/test_security_agent_intent.py`
- Test: `frontend/src/AgentWorkspacePage.test.tsx`
- Test: `frontend/src/components/AgentConversation.test.tsx`

**Interfaces:**
- Consumes: persistent task snapshots and `api.deleteAgentTask` from Task 1.
- Produces: evidence-grounded follow-up replies for completed Prompt and PCAP tasks.
- Produces: a PCAP result message block inside the shared conversation flow.

- [ ] **Step 1: Write failing tests for greeting, final reply, PCAP result embedding, and follow-up**

```tsx
expect(screen.getByRole("article", { name: /你/ })).toHaveClass("is-user");
expect(screen.getByRole("region", { name: "PCAP 调查结果" })).toBeWithin(screen.getByRole("region", { name: "任务对话" }));
expect(screen.queryByRole("region", { name: "PCAP 检测小队" })).not.toBeInTheDocument();
```

- [ ] **Step 2: Run focused tests and confirm failure**

Run: `npm.cmd test -- AgentWorkspacePage.test.tsx components/AgentConversation.test.tsx`

- [ ] **Step 3: Implement conversation state and grounded follow-up behavior**

Keep the composer enabled after terminal results. Convert uploaded PCAP metadata and mission results into persisted/local conversation entries, and route subsequent questions through a bounded evidence-answer formatter. Append a readable final agent result after every completed tool plan.

- [ ] **Step 4: Remove `DetectionMascots` from `PcapDetectionResult`**

The result component retains status, sample counts, localized evidence, and Packet timeline only.

- [ ] **Step 5: Run backend and frontend focused tests green**

Run: `python -m pytest tests/unit/test_security_agent_coordinator.py tests/unit/test_security_agent_intent.py tests/unit/test_security_agent_prompt_runtime.py -q`

Run: `npm.cmd test -- AgentWorkspacePage.test.tsx components/AgentConversation.test.tsx components/PcapDetectionResult.test.tsx`

- [ ] **Step 6: Commit unified conversation behavior**

```bash
git add backend/app/security_agent/coordinator.py backend/app/security_agent/intent.py backend/app/security_agent/prompt_runtime.py frontend/src/pages/AgentWorkspacePage.tsx frontend/src/components/AgentConversation.tsx frontend/src/components/PcapDetectionResult.tsx frontend/src/agent/localConversation.ts tests frontend/src/AgentWorkspacePage.test.tsx frontend/src/components/AgentConversation.test.tsx
git commit -m "feat: make security investigations conversational"
```

### Task 3: Sidebar Cleanup and Recent-task Deletion

**Files:**
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/components/AgentSidebar.tsx`
- Modify: `frontend/src/agent/localConversation.ts`
- Modify: `frontend/src/styles.css`
- Test: `frontend/src/App.test.tsx`
- Test: `frontend/src/components/AgentSidebar.test.tsx`

**Interfaces:**
- Consumes: `api.deleteAgentTask(taskId)` from Task 1.
- Produces: `onDeleteTask(taskId: string): Promise<void>` sidebar callback.

- [ ] **Step 1: Write failing tests for duplicate PCAP entry removal and deletion flow**

```tsx
expect(screen.queryByRole("link", { name: "PCAP 上传检测" })).not.toBeInTheDocument();
await user.click(screen.getByRole("button", { name: /删除.*越狱风险/ }));
await user.click(screen.getByRole("button", { name: "确认删除" }));
expect(api.deleteAgentTask).toHaveBeenCalledWith("task_01");
```

- [ ] **Step 2: Run focused tests and confirm failure**

Run: `npm.cmd test -- App.test.tsx components/AgentSidebar.test.tsx`

- [ ] **Step 3: Implement removal, confirmation, and local cleanup**

Remove `PCAP 上传检测` from `routeGroups`. Add a compact trash-icon action revealed on hover/focus, confirmation dialog, and active-task fallback to a new conversation of the same mode.

- [ ] **Step 4: Apply larger left-aligned recent-task typography**

Use stable line heights and truncation for long task titles; preserve status as secondary text and keep count/collapse controls on the heading row.

- [ ] **Step 5: Run focused tests green and commit**

Run: `npm.cmd test -- App.test.tsx components/AgentSidebar.test.tsx`

```bash
git add frontend/src/App.tsx frontend/src/components/AgentSidebar.tsx frontend/src/agent/localConversation.ts frontend/src/styles.css frontend/src/App.test.tsx frontend/src/components/AgentSidebar.test.tsx
git commit -m "feat: streamline recent security tasks"
```

### Task 4: Built-in PCAP Detective Challenge

**Files:**
- Create: `frontend/src/pcap/challengeCases.ts`
- Modify: `frontend/src/pages/PcapChallengePage.tsx`
- Modify: `frontend/src/styles.css`
- Test: `frontend/src/PcapChallengePage.test.tsx`

**Interfaces:**
- Produces: `PCAP_CHALLENGE_CASES`, sanitized deterministic cases with packet clues, expected interval, attack type, purpose, and explanation.

- [ ] **Step 1: Replace upload-based challenge expectations with failing interaction tests**

```tsx
expect(screen.queryByRole("region", { name: "PCAP 异常检测工作区" })).not.toBeInTheDocument();
await user.click(screen.getByRole("button", { name: "开始挑战" }));
await user.click(screen.getByRole("button", { name: "Packet 4-4" }));
await user.click(screen.getByRole("button", { name: "提交研判" }));
expect(screen.getByRole("region", { name: "挑战评分" })).toBeVisible();
```

- [ ] **Step 2: Run the test and confirm failure**

Run: `npm.cmd test -- PcapChallengePage.test.tsx`

- [ ] **Step 3: Implement setup, evidence investigation, answer, and reveal states**

Use built-in cases only. Place the three-member detection team in the investigation phase, unlock public clues in order, and score packet interval, attack type, and purpose separately. Never expose raw sensitive payloads.

- [ ] **Step 4: Add responsive challenge styling and run green**

Run: `npm.cmd test -- PcapChallengePage.test.tsx`

- [ ] **Step 5: Commit the challenge**

```bash
git add frontend/src/pcap/challengeCases.ts frontend/src/pages/PcapChallengePage.tsx frontend/src/PcapChallengePage.test.tsx frontend/src/styles.css
git commit -m "feat: add interactive pcap detective challenge"
```

### Task 5: Query-aware Guided Tours and Inspector Readability

**Files:**
- Modify: `frontend/src/tourConfig.ts`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/pages/AgentWorkspacePage.tsx`
- Modify: `frontend/src/pages/AgentResourcePage.tsx`
- Modify: `frontend/src/components/AgentResourceCenter.tsx`
- Modify: `frontend/src/components/AgentInspectorShell.tsx`
- Modify: `frontend/src/styles.css`
- Test: `frontend/src/tourConfig.test.ts`
- Test: `frontend/src/App.test.tsx`
- Test: `frontend/src/components/GuidedTour.test.tsx`
- Test: `frontend/src/components/AgentInspectorShell.test.tsx`

**Interfaces:**
- Produces: `resolveTour(pathname: string, search: string): { route: string; steps: GuidedTourStep[] } | null`.

- [ ] **Step 1: Write failing resolver and DOM-target tests**

```ts
expect(resolveTour("/super-agent", "?mode=prompt")?.route).toBe("/super-agent:prompt");
expect(resolveTour("/super-agent", "?resource=knowledge")?.route).toBe("/super-agent:resource:knowledge");
```

- [ ] **Step 2: Run focused tests and confirm failure**

Run: `npm.cmd test -- tourConfig.test.ts App.test.tsx components/GuidedTour.test.tsx`

- [ ] **Step 3: Implement contextual resolver and stable targets**

Add separate Prompt, PCAP, knowledge, connector, and report tours. Mark only visible, stable regions with `data-tour`; key `GuidedTour` by the resolved route identity so completion state cannot leak between surfaces.

- [ ] **Step 4: Increase inspector typography and preserve layout constraints**

Increase header, tab, field-label, empty-state, and body sizes one step without changing evidence density or causing horizontal overflow.

- [ ] **Step 5: Run focused tests green and commit**

Run: `npm.cmd test -- tourConfig.test.ts App.test.tsx components/GuidedTour.test.tsx components/AgentInspectorShell.test.tsx`

```bash
git add frontend/src/tourConfig.ts frontend/src/App.tsx frontend/src/pages/AgentWorkspacePage.tsx frontend/src/pages/AgentResourcePage.tsx frontend/src/components/AgentResourceCenter.tsx frontend/src/components/AgentInspectorShell.tsx frontend/src/styles.css frontend/src/tourConfig.test.ts frontend/src/App.test.tsx frontend/src/components/GuidedTour.test.tsx frontend/src/components/AgentInspectorShell.test.tsx
git commit -m "feat: add contextual agent workspace guidance"
```

### Task 6: Integrated Verification and Visual QA

**Files:**
- Modify only files required by defects discovered in this bounded pass.

- [ ] **Step 1: Run full frontend tests**

Run: `npm.cmd test`

- [ ] **Step 2: Run focused backend tests**

Run: `python -m pytest tests/unit/test_security_agent_coordinator.py tests/unit/test_security_agent_intent.py tests/unit/test_security_agent_prompt_runtime.py tests/unit/test_security_agent_store.py tests/integration/test_security_agent_api.py -q`

- [ ] **Step 3: Run production build**

Run: `npm.cmd run build`

- [ ] **Step 4: Run one bounded desktop/mobile visual pass**

Inspect Prompt conversation, PCAP conversation, all three resource pages, recent-task deletion, and the PCAP challenge at 1440x900 and 390x844. Confirm message direction, readable inspector type, non-overlapping composer, visible guide content, and responsive challenge controls.

- [ ] **Step 5: Run Impeccable detector exactly once after UI edits**

Run the project-configured Impeccable detector and fix any in-scope findings in one batch.

- [ ] **Step 6: Check whitespace and summarize evidence**

Run: `git diff --check`

