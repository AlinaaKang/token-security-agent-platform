# Agent History, Message Time, and Draggable Guide Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move recent security tasks into the left sidebar, restore browser-local Prompt text with original timestamps, show a timestamp on every conversation message, and make the page-guide launcher movable and persistent.

**Architecture:** Keep the server as the source of truth for task state and evidence, while a versioned browser-local store retains only user-visible Prompt text keyed by `task_id`. Drive active task selection from `/super-agent?task=<id>` and let the application shell own the recent-task list so the sidebar and workspace share one view. Isolate guide-launcher geometry and persistence from business state in a small utility module.

**Tech Stack:** React 19, TypeScript, React Router, Vitest, Testing Library, CSS, browser `localStorage`, Pointer Events.

## Global Constraints

- The original Prompt must not be sent to AutoDL beyond the existing task submission call, persisted in server SQLite, copied into events, evidence, reports, or public APIs.
- Browser-local Prompt history is capped at 20 tasks and can be cleared without deleting the server task.
- Recent tasks display at most 8 entries and use the exact status wording and color semantics from `docs/superpowers/specs/2026-09-07-recent-security-tasks-sidebar-design.md`.
- The top horizontal task strip is removed.
- Message time formatting must cover today, yesterday, earlier in the same year, and another year.
- The guide launcher uses a 6px pointer threshold, 12px arrow-key movement, 32px Shift+arrow movement, desktop/mobile storage keys, and viewport clamping.
- Do not change Prompt or Token detection algorithms, thresholds, PCAP parsing rules, or Token detective challenge behavior.

---

### Task 1: Browser-Local Conversation Repository

**Files:**
- Create: `frontend/src/agent/localConversation.ts`
- Test: `frontend/src/agent/localConversation.test.ts`

**Interfaces:**
- Consumes: `AgentMessage` from `frontend/src/agent/types.ts`.
- Produces: `rememberLocalUserMessage(taskId: string, content: string, createdAt: string, storage?: Storage): void`, `mergeLocalConversation(task: AgentTaskSnapshot, storage?: Storage): AgentTaskSnapshot`, and `clearLocalConversation(taskId: string, storage?: Storage): void`.

- [ ] **Step 1: Write failing repository tests**

```ts
it("restores the original browser-only user text with its first timestamp", () => {
  rememberLocalUserMessage("task_1", "原始 Prompt", "2026-09-07T08:10:00.000Z", localStorage);
  const merged = mergeLocalConversation(serverSnapshot("task_1"), localStorage);
  expect(merged.messages[0]).toMatchObject({ role: "user", content: "原始 Prompt", created_at: "2026-09-07T08:10:00.000Z" });
});
```

Add cases for malformed storage, clearing one task, and retaining only the newest 20 task entries.

- [ ] **Step 2: Run the focused test and verify RED**

Run: `npm.cmd test -- frontend/src/agent/localConversation.test.ts`

Expected: FAIL because `localConversation.ts` does not exist.

- [ ] **Step 3: Implement the minimal versioned store**

Use storage key `token-security:local-agent-conversations:v1`. Store only `{ taskId, updatedAt, messages: [{ messageId, content, createdAt }] }`. Parse defensively, ignore invalid records, sort by `updatedAt`, and slice to 20 records. Replace the server's redacted user placeholder while retaining server agent/system messages.

- [ ] **Step 4: Run the focused test and verify GREEN**

Run: `npm.cmd test -- frontend/src/agent/localConversation.test.ts`

Expected: all repository tests PASS.

### Task 2: Recent Security Tasks in the Sidebar

**Files:**
- Create: `frontend/src/agent/taskPresentation.ts`
- Create: `frontend/src/agent/taskPresentation.test.ts`
- Modify: `frontend/src/components/AgentSidebar.tsx`
- Modify: `frontend/src/components/AgentSidebar.test.tsx`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/App.test.tsx`
- Modify: `frontend/src/pages/AgentWorkspacePage.tsx`
- Modify: `frontend/src/AgentWorkspacePage.test.tsx`

**Interfaces:**
- Consumes: `AgentTaskSnapshot[]`, current `location.search`, and `api.listAgentTasks()`.
- Produces: `presentAgentTaskStatus(task: AgentTaskSnapshot): { label: string; tone: "blue" | "green" | "red" | "amber" }`, plus sidebar props `recentTasks`, `activeTaskId`, and `onTaskNavigate`.

- [ ] **Step 1: Write failing status and navigation tests**

```ts
expect(presentAgentTaskStatus(task({ status: "completed", final_status: "risk_found" }))).toEqual({ label: "发现风险", tone: "red" });
expect(screen.getByRole("link", { name: /PCAP 数据集调查.*发现风险/ })).toHaveAttribute("href", "/super-agent?task=task_1");
```

Cover every status in the approved mapping, current-task `aria-current`, maximum 8 entries, no empty section, mobile navigation callback, URL restoration, and absence of `最近安全案件` top navigation.

- [ ] **Step 2: Run focused tests and verify RED**

Run: `npm.cmd test -- frontend/src/agent/taskPresentation.test.ts frontend/src/components/AgentSidebar.test.tsx frontend/src/AgentWorkspacePage.test.tsx frontend/src/App.test.tsx`

Expected: FAIL because the presenter and sidebar task list are missing and the top strip still exists.

- [ ] **Step 3: Implement one shell-owned task list**

Have `Shell` fetch the task list and pass it to both `AgentSidebar` and `AgentWorkspacePage`. Add a refresh callback for task creation and updates. Read `task` from `URLSearchParams`; selection uses React Router navigation to `/super-agent?task=<encoded id>`. Remove `agent-task-strip` from the workspace.

- [ ] **Step 4: Run focused tests and verify GREEN**

Run: `npm.cmd test -- frontend/src/agent/taskPresentation.test.ts frontend/src/components/AgentSidebar.test.tsx frontend/src/AgentWorkspacePage.test.tsx frontend/src/App.test.tsx`

Expected: all focused tests PASS.

### Task 3: Restore Prompt Text and Render Message Times

**Files:**
- Create: `frontend/src/agent/messageTime.ts`
- Create: `frontend/src/agent/messageTime.test.ts`
- Modify: `frontend/src/components/AgentConversation.tsx`
- Create: `frontend/src/components/AgentConversation.test.tsx`
- Modify: `frontend/src/pages/AgentWorkspacePage.tsx`
- Modify: `frontend/src/AgentWorkspacePage.test.tsx`

**Interfaces:**
- Consumes: ISO `created_at`, browser-local messages from Task 1, and task snapshots.
- Produces: `formatAgentMessageTime(value: string, now?: Date): { short: string; full: string; dateTime: string }` and `AgentConversation` props `messages`, `localContentAvailable`, and `onClearLocalConversation`.

- [ ] **Step 1: Write failing formatting and UI tests**

```ts
expect(formatAgentMessageTime("2026-09-07T08:10:00+08:00", new Date("2026-09-07T12:00:00+08:00")).short).toBe("08:10");
expect(formatAgentMessageTime("2026-09-06T08:10:00+08:00", new Date("2026-09-07T12:00:00+08:00")).short).toBe("昨天 08:10");
```

Add same-year and cross-year cases, semantic `<time datetime>` assertions, local privacy label, clear behavior, and refresh restoration with the unchanged original timestamp.

- [ ] **Step 2: Run focused tests and verify RED**

Run: `npm.cmd test -- frontend/src/agent/messageTime.test.ts frontend/src/components/AgentConversation.test.tsx frontend/src/AgentWorkspacePage.test.tsx`

Expected: FAIL because message formatting and local restoration UI do not exist.

- [ ] **Step 3: Implement message merge, timestamps, and clear action**

Record the user message after task creation returns an ID, merge it into every restored/live snapshot, and never rewrite its `createdAt`. Render `<time dateTime={dateTime} title={full}>{short}</time>` beside the role name. Show `原文仅保存在此浏览器` and a `清除本地对话` button only when local content exists.

- [ ] **Step 4: Run focused tests and verify GREEN**

Run: `npm.cmd test -- frontend/src/agent/messageTime.test.ts frontend/src/components/AgentConversation.test.tsx frontend/src/AgentWorkspacePage.test.tsx`

Expected: all focused tests PASS.

### Task 4: Draggable and Persistent Guide Launcher

**Files:**
- Create: `frontend/src/components/guidedTourPosition.ts`
- Create: `frontend/src/components/guidedTourPosition.test.ts`
- Modify: `frontend/src/components/GuidedTour.tsx`
- Modify: `frontend/src/components/GuidedTour.test.tsx`
- Modify: `frontend/src/styles.css`
- Modify: `frontend/src/styles.test.ts`

**Interfaces:**
- Consumes: viewport width/height, launcher width/height, pointer or keyboard deltas, and optional `Storage`.
- Produces: `clampGuidePosition`, `loadGuidePosition`, `saveGuidePosition`, and pointer/keyboard handlers on the launcher.

- [ ] **Step 1: Write failing geometry and interaction tests**

```ts
expect(clampGuidePosition({ x: 2000, y: -20 }, { width: 1280, height: 720 }, { width: 120, height: 44 })).toEqual({ x: 1148, y: 12 });
fireEvent.keyDown(launcher, { key: "ArrowLeft", shiftKey: true });
expect(JSON.parse(localStorage.getItem("token-sentinel-tour-launcher:desktop:v1")!)).toMatchObject({ x: expect.any(Number), y: expect.any(Number) });
```

Add pointer movement below/above 6px, no click after drag, mobile storage key, invalid storage fallback, resize clamping, and Enter/Space replay cases.

- [ ] **Step 2: Run focused tests and verify RED**

Run: `npm.cmd test -- frontend/src/components/guidedTourPosition.test.ts frontend/src/components/GuidedTour.test.tsx frontend/src/styles.test.ts`

Expected: FAIL because geometry helpers and drag behavior are missing.

- [ ] **Step 3: Implement bounded Pointer Events and keyboard movement**

Set pointer capture on press, update fixed `left/top` coordinates while dragging, persist only on release, suppress the following click after movement beyond 6px, and re-clamp on resize. Use media query parity at 760px for desktop/mobile keys. Add `touch-action: none` only to `.guided-tour-launcher` and keep its existing focus ring.

- [ ] **Step 4: Run focused tests and verify GREEN**

Run: `npm.cmd test -- frontend/src/components/guidedTourPosition.test.ts frontend/src/components/GuidedTour.test.tsx frontend/src/styles.test.ts`

Expected: all focused tests PASS.

### Task 5: Integrated Verification

**Files:**
- Modify only files required to correct failures exposed by this verification pass.

**Interfaces:**
- Consumes: all deliverables from Tasks 1-4.
- Produces: a production-buildable and regression-tested frontend with unchanged backend privacy behavior.

- [ ] **Step 1: Run the complete frontend suite**

Run: `npm.cmd test`

Expected: zero failed tests.

- [ ] **Step 2: Run the production build**

Run: `npm.cmd run build`

Expected: exit code 0 with TypeScript and Vite build complete.

- [ ] **Step 3: Run backend Prompt privacy regressions**

Run: `python -m pytest tests/unit/test_security_agent_prompt_runtime.py tests/integration/test_security_agent_api.py -q`

Expected: zero failed tests and no original Prompt in persisted task/event/report fixtures.

- [ ] **Step 4: Inspect the diff**

Run: `git diff --check`

Expected: no whitespace errors. Confirm no Token detective challenge or detection-threshold files changed.

- [ ] **Step 5: Verify desktop and mobile layouts in the running app**

Open `/super-agent` at 1440x900 and 390x844. Confirm the sidebar list is readable, message times do not overlap, the top task strip is absent, and the guide launcher remains inside the viewport after dragging.
