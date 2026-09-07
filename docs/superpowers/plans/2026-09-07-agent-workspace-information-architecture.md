# 安全智能体工作区信息架构 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将安全智能体重组为 Prompt 与 PCAP 两类可新建、可恢复的安全对话，分离专业工作区，并只在安全对话中保留案件检查器。

**Architecture:** 使用 URL 查询参数表达对话模式和实验表面，新增纯函数负责模式归一化、任务分类与 URL 生成。应用壳负责决定三栏或两栏布局；现有 Agent、Prompt、PCAP、Lab 和资源组件继续承担业务逻辑，避免复制检测实现。

**Tech Stack:** React 19、TypeScript、React Router、Vitest、Testing Library、CSS Grid、Lucide React

## Global Constraints

- 底层仍是同一个 Token Security 安全智能体，保留统一规划、工具调用、反馈重规划和跨域案件能力。
- PCAP 文件仍只进入本机 `/pcap-api` 与隔离 Docker，不上传 AutoDL。
- 原始 Prompt 不进入服务器 SQLite、事件、证据或报告。
- 不修改检测算法、阈值、冻结评测数据、Token 侦探挑战规则和 PCAP Docker 隔离路径。
- 切换页面或模式不会取消任务；只有明确取消操作才调用取消接口。
- 移动端主要触控目标不小于 44px。

---

### Task 1: 对话模式与任务分类

**Files:**
- Create: `frontend/src/agent/workspaceMode.ts`
- Create: `frontend/src/agent/workspaceMode.test.ts`

**Interfaces:**
- Produces: `type AgentWorkspaceMode = "prompt" | "pcap"`
- Produces: `resolveAgentWorkspaceMode(search: string, task?: AgentTaskSnapshot | null): AgentWorkspaceMode`
- Produces: `taskWorkspaceMode(task: AgentTaskSnapshot): AgentWorkspaceMode`
- Produces: `agentWorkspaceUrl(mode: AgentWorkspaceMode, taskId?: string | null): string`

- [ ] **Step 1: Write failing tests for mode parsing, PCAP classification and URL preservation**

```ts
expect(resolveAgentWorkspaceMode("?mode=pcap")).toBe("pcap");
expect(taskWorkspaceMode(task("pcap_dataset_investigation"))).toBe("pcap");
expect(taskWorkspaceMode(task("cross_domain_case"))).toBe("prompt");
expect(agentWorkspaceUrl("prompt", "task_1")).toBe("/super-agent?mode=prompt&task=task_1");
```

- [ ] **Step 2: Run the focused test and verify RED**

Run: `npm.cmd test -- src/agent/workspaceMode.test.ts`

Expected: FAIL because `workspaceMode.ts` does not exist.

- [ ] **Step 3: Implement the pure mode helpers**

Use `URLSearchParams`, classify only `pcap_dataset_investigation` as PCAP, and default all text, knowledge and cross-domain tasks to Prompt. Encode task IDs with `encodeURIComponent`.

- [ ] **Step 4: Run the focused test and verify GREEN**

Run: `npm.cmd test -- src/agent/workspaceMode.test.ts`

Expected: all workspace-mode tests pass.

### Task 2: 左侧两类安全对话与专业工作区

**Files:**
- Modify: `frontend/src/components/AgentSidebar.tsx`
- Modify: `frontend/src/components/AgentSidebar.test.tsx`

**Interfaces:**
- Consumes: `taskWorkspaceMode()` and `agentWorkspaceUrl()` from Task 1.
- Produces: two mode links, two `新建对话` links, filtered recent-task lists, Prompt/PCAP professional groups and three resource links.

- [ ] **Step 1: Write failing navigation tests**

Assert that the sidebar contains `Prompt 安全调查`, `PCAP 数据集调查`, `新建 Prompt 对话`, `新建 PCAP 对话`, `Prompt 专业工作区`, `PCAP 专业工作区`, and exactly the resources `安全知识库`, `数据连接器`, `调查报告`. Assert `检测技能` is absent and each recent task appears only in its assigned list.

- [ ] **Step 2: Run the sidebar test and verify RED**

Run: `npm.cmd test -- src/components/AgentSidebar.test.tsx`

Expected: FAIL because the current sidebar has one generic agent entry and four resources.

- [ ] **Step 3: Implement the navigation hierarchy**

Replace the generic agent item with two links:

```tsx
<Link to={agentWorkspaceUrl("prompt")}>Prompt 安全调查</Link>
<Link to={agentWorkspaceUrl("pcap")}>PCAP 数据集调查</Link>
```

Render each mode's new-task link and filtered recent tasks below its parent. Use `/lab?surface=prompt` and `/lab?surface=pcap` for the two lab entries. Remove only the visible `skills` resource entry; do not delete its API.

- [ ] **Step 4: Run the sidebar test and verify GREEN**

Run: `npm.cmd test -- src/components/AgentSidebar.test.tsx`

Expected: all sidebar tests pass.

### Task 3: 对话模式、任务恢复与专用欢迎区

**Files:**
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/pages/AgentWorkspacePage.tsx`
- Modify: `frontend/src/AgentWorkspacePage.test.tsx`
- Modify: `frontend/src/App.test.tsx`

**Interfaces:**
- Consumes: `resolveAgentWorkspaceMode()` and `agentWorkspaceUrl()` from Task 1.
- Produces: `AgentWorkspacePage` prop `mode: AgentWorkspaceMode` and mode-aware new task/navigation behavior.

- [ ] **Step 1: Write failing tests for Prompt and PCAP modes**

Test `/super-agent?mode=prompt` for Prompt examples without a primary PCAP upload prompt. Test `/super-agent?mode=pcap` for PCAP upload and dataset examples. Test that selecting an existing task adds its classified mode to the URL and that changing mode does not issue a cancel request.

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `npm.cmd test -- src/AgentWorkspacePage.test.tsx src/App.test.tsx`

Expected: FAIL because the current workspace has one mixed example set and mode-free URLs.

- [ ] **Step 3: Implement mode-aware rendering and navigation**

Pass the resolved mode into `AgentWorkspacePage`. Split the welcome examples into `promptExamples` and `pcapExamples`; keep the same submit, authorization and PCAP mission code. Update task selection and new-task callbacks to retain `mode` in the URL. Do not add cancellation to mode-change effects.

- [ ] **Step 4: Run focused tests and verify GREEN**

Run: `npm.cmd test -- src/AgentWorkspacePage.test.tsx src/App.test.tsx`

Expected: all mode and restoration tests pass.

### Task 4: 检查器只属于安全对话

**Files:**
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/components/AgentMobileNav.tsx`
- Modify: `frontend/src/components/AgentInspectorShell.test.tsx`
- Modify: `frontend/src/App.test.tsx`
- Modify: `frontend/src/styles.css`

**Interfaces:**
- Produces: `AgentMobileNav` prop `showInspector: boolean`.
- Produces: application-shell class `has-agent-inspector` only for `/super-agent` without a resource query.

- [ ] **Step 1: Write failing shell tests**

Assert that `/super-agent?mode=prompt` and `/super-agent?mode=pcap` render a complementary inspector. Assert `/events`, `/analyze`, `/lab?surface=prompt`, `/lab?surface=pcap`, `/evaluation`, `/challenge`, and `/super-agent?resource=reports` do not render any complementary inspector and do not show `打开检查器`.

- [ ] **Step 2: Run shell tests and verify RED**

Run: `npm.cmd test -- src/App.test.tsx src/components/AgentInspectorShell.test.tsx`

Expected: FAIL because the inspector is currently mounted on every route.

- [ ] **Step 3: Conditionally render the inspector and two-column shell**

Define:

```ts
const showAgentInspector = location.pathname === "/super-agent" && !resource;
```

Only mount `AgentInspectorShell` when true. Hide the mobile inspector command otherwise. Use `.app-shell:not(.has-agent-inspector)` for `240px minmax(0, 1fr)` desktop layout. Remove the resource explanation panel by not mounting the inspector on resource routes.

- [ ] **Step 4: Run shell tests and verify GREEN**

Run: `npm.cmd test -- src/App.test.tsx src/components/AgentInspectorShell.test.tsx`

Expected: all inspector visibility tests pass.

### Task 5: 固定 Prompt 与 PCAP 实验表面

**Files:**
- Modify: `frontend/src/pages/LabPage.tsx`
- Modify: `frontend/src/LabPage.test.tsx`

**Interfaces:**
- Produces: `/lab?surface=prompt` and `/lab?surface=pcap` as mutually exclusive views using the current `LabPage` and `LabPcapWorkspace` logic.

- [ ] **Step 1: Write failing route-surface tests**

Assert Prompt surface renders `自定义 Prompt` and not `PCAP 上传检测`; PCAP surface renders `PCAP 上传检测` and not `自定义 Prompt`; neither surface renders the old `实验输入类型` switch.

- [ ] **Step 2: Run lab tests and verify RED**

Run: `npm.cmd test -- src/LabPage.test.tsx`

Expected: FAIL because the switch is always rendered and owns local state.

- [ ] **Step 3: Derive the surface from `useLocation()`**

Normalize `surface=pcap` to PCAP and every other value to Prompt. Render the corresponding title, readiness and content directly. Remove only the local switch controls; preserve Prompt draft state and all existing PCAP upload authorization behavior.

- [ ] **Step 4: Run lab tests and verify GREEN**

Run: `npm.cmd test -- src/LabPage.test.tsx`

Expected: all Prompt and PCAP lab tests pass after updating legacy switch assertions to route assertions.

### Task 6: 对话双边布局、输入框上限与侧栏覆盖

**Files:**
- Modify: `frontend/src/components/AgentConversation.tsx`
- Modify: `frontend/src/components/AgentConversation.test.tsx`
- Modify: `frontend/src/components/AgentComposer.tsx`
- Modify: `frontend/src/styles.css`
- Modify: `frontend/src/styles.test.ts`

**Interfaces:**
- Produces: user-message DOM order/content that CSS can align right while keeping reading order intact.
- Produces: bounded composer textarea with internal scrolling.

- [ ] **Step 1: Write failing component and CSS-contract tests**

Assert user messages expose `is-user` and place the avatar after the message body in DOM, while assistant messages keep avatar first. Assert CSS contains `resize: none`, a finite textarea `max-height`, full-width navigation anchors, and full-height sidebar background coverage.

- [ ] **Step 2: Run focused tests and verify RED**

Run: `npm.cmd test -- src/components/AgentConversation.test.tsx src/styles.test.ts`

Expected: FAIL because both avatars currently precede content and the textarea is vertically resizable without a maximum.

- [ ] **Step 3: Implement the bounded layouts**

Render the user avatar after its message content, add user-specific right alignment, and retain semantic message order. Set the textarea to a stable minimum height, `max-height: 160px`, `resize: none`, and `overflow-y: auto`. Ensure sidebar links use `width: 100%`, the sidebar retains `height: 100vh`, and active rows use one opaque light-blue surface.

- [ ] **Step 4: Run focused tests and verify GREEN**

Run: `npm.cmd test -- src/components/AgentConversation.test.tsx src/styles.test.ts`

Expected: all conversation and responsive-bound tests pass.

### Task 7: Full verification and rendered QA

**Files:**
- Verify only; fix changed files above if a regression is found.

- [ ] **Step 1: Run the full frontend suite**

Run: `npm.cmd test`

Expected: zero failed tests.

- [ ] **Step 2: Build the production frontend**

Run: `npm.cmd run build`

Expected: TypeScript and Vite exit 0.

- [ ] **Step 3: Check the working diff**

Run: `git diff --check`

Expected: no whitespace errors; line-ending notices are informational.

- [ ] **Step 4: Run the final interface detector**

Run: `node C:\Users\Graci\.codex\skills\impeccable\scripts\detect.mjs --json frontend/src/App.tsx frontend/src/pages/AgentWorkspacePage.tsx frontend/src/pages/LabPage.tsx frontend/src/components/AgentSidebar.tsx frontend/src/components/AgentConversation.tsx frontend/src/components/AgentComposer.tsx frontend/src/styles.css`

Expected: no unexplained findings.

- [ ] **Step 5: Capture and inspect desktop and mobile states**

Inspect Prompt conversation, PCAP conversation, Prompt lab, PCAP upload and report resource routes at `1440x900` and `390x844`. Confirm no resource inspector, correct message sides, bounded composer, complete light-blue sidebar coverage and no horizontal overflow.
