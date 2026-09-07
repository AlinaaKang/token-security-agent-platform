# Recent Agent Task Collapse Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add independently collapsible, persistent Prompt and PCAP recent-task groups to the security-agent sidebar.

**Architecture:** Keep task data and routing unchanged inside `AgentSidebar`. Store one boolean per workspace mode in browser local storage and conditionally render only the corresponding recent-task list. Use an accessible button as each list heading so pointer, touch, and keyboard interaction share one path.

**Tech Stack:** React 19, React Router, TypeScript, Lucide React, Vitest, Testing Library, CSS.

## Global Constraints

- Investigation entries and `新建对话` links remain visible when history is collapsed.
- Prompt and PCAP collapse independently and default to expanded.
- Collapse state survives refresh when local storage is available and safely falls back when it is not.
- Task data, ordering, eight-item display limit, routes, execution state, and inspector behavior do not change.

---

### Task 1: Accessible persistent task groups

**Files:**
- Modify: `frontend/src/components/AgentSidebar.tsx`
- Test: `frontend/src/components/AgentSidebar.test.tsx`

**Interfaces:**
- Consumes: existing `recentTasks`, `taskWorkspaceMode`, and `presentAgentTaskStatus` behavior.
- Produces: buttons named `收起 Prompt 最近任务`, `展开 Prompt 最近任务`, `收起 PCAP 最近任务`, and `展开 PCAP 最近任务`, each with `aria-expanded`.

- [x] **Step 1: Write the failing component tests**

Render both task types, collapse Prompt, assert Prompt history is absent while PCAP remains, remount, and assert the Prompt state is restored from local storage.

- [x] **Step 2: Run the focused test and verify RED**

Run: `npm.cmd test -- --run src/components/AgentSidebar.test.tsx`

Expected: FAIL because the collapse buttons do not exist.

- [x] **Step 3: Implement the minimal component behavior**

Add `ChevronDown` and `ChevronRight`, a mode-specific local-storage key, guarded read/write helpers, local collapse state, and conditional list rendering. Preserve the current task filtering and links.

- [x] **Step 4: Run the focused test and verify GREEN**

Run: `npm.cmd test -- --run src/components/AgentSidebar.test.tsx`

Expected: all `AgentSidebar` tests pass.

### Task 2: Sidebar presentation and verification

**Files:**
- Modify: `frontend/src/styles.css`

**Interfaces:**
- Consumes: `.agent-recent-tasks-toggle` and its count/icon children from Task 1.
- Produces: a full-width, 44px minimum task-group toggle aligned with the existing shallow-blue sidebar.

- [x] **Step 1: Style the toggle without adding a new visual container**

Use the existing sidebar blue and muted tokens, keep the count compact, rotate no custom glyphs, and retain visible focus treatment.

- [x] **Step 2: Run regression verification**

Run: `npm.cmd test`

Expected: all frontend tests pass.

Run: `npm.cmd run build`

Expected: TypeScript and Vite build succeed.

- [x] **Step 3: Inspect desktop and mobile states**

Verify expanded and collapsed Prompt/PCAP groups at 1440x900 and 390x844, including long task titles, no horizontal overflow, and persistent state after reload.

- [ ] **Step 4: Commit the feature**

```powershell
git add frontend/src/components/AgentSidebar.tsx frontend/src/components/AgentSidebar.test.tsx frontend/src/styles.css docs/superpowers/plans/2026-09-07-agent-recent-task-collapse.md
git commit -m "feat: collapse recent agent tasks"
```
