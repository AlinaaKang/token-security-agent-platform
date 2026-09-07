# Agent Resources Main Workspace Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Render all agent resource catalogs in the center workspace instead of the right inspector while hiding the conversation UI.

**Architecture:** Add a dedicated `AgentResourcePage` that owns resource loading and renders the existing `AgentResourceCenter` in page mode. `App.tsx` chooses between the resource page and conversation workspace from the existing `resource` query, while `AgentInspectorShell` renders only static resource-scope guidance.

**Tech Stack:** React 19, React Router, TypeScript, Vitest, Testing Library.

## Global Constraints

- Opening resources must not cancel or mutate Agent tasks or PCAP missions.
- The URL query remains the source of truth for refresh and direct linking.
- Resource content appears once in the center workspace and is not duplicated in the inspector.
- Prompt, PCAP, challenge, detector, and authorization behavior remain unchanged.

---

### Task 1: Resource Workspace Routing

**Files:**
- Create: `frontend/src/pages/AgentResourcePage.tsx`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/components/AgentInspectorShell.tsx`
- Test: `frontend/src/App.test.tsx`

**Interfaces:**
- Produces: `AgentResourcePage({ resource })` with a center-column `main` landmark and `返回安全智能体` link.
- Consumes: existing Agent resource API methods and `AgentResourceCenter`.

- [x] **Step 1: Write a failing route-level test**

```tsx
const workspace = await screen.findByRole("main", { name: "安全知识库资源工作区" });
expect(within(workspace).queryByRole("textbox", { name: "安全任务" })).not.toBeInTheDocument();
expect(within(screen.getByRole("complementary", { name: "资源说明" })).queryByText("提示词注入风险")).not.toBeInTheDocument();
```

- [x] **Step 2: Run the test and verify it fails because resources still render in the inspector**

Run: `npm.cmd test -- src/App.test.tsx`

- [ ] **Step 3: Implement the resource page and route selection**

```tsx
<Route path="/super-agent" element={resource ? <AgentResourcePage resource={resource} /> : <AgentWorkspacePage />} />
```

- [ ] **Step 4: Reduce the resource inspector to static scope guidance**

```tsx
resource ? <div className="agent-inspector-empty"><strong>资源说明</strong><p>资源用于规划、解释和报告，不会自动执行处置。</p></div> : null
```

- [ ] **Step 5: Run the focused test to green**

Run: `npm.cmd test -- src/App.test.tsx`

### Task 2: Main-Column Layout And Navigation State

**Files:**
- Modify: `frontend/src/components/AgentResourceCenter.tsx`
- Modify: `frontend/src/components/AgentSidebar.tsx`
- Modify: `frontend/src/styles.css`
- Test: `frontend/src/components/AgentSidebar.test.tsx`

**Interfaces:**
- Produces: page-density resource rows, responsive center layout, and `aria-current="page"` on the selected resource link.

- [ ] **Step 1: Add a failing selected-resource navigation assertion**

```tsx
expect(screen.getByRole("link", { name: "安全知识库" })).toHaveAttribute("aria-current", "page");
```

- [ ] **Step 2: Implement query-aware resource navigation and page layout styles**

```tsx
const activeResource = new URLSearchParams(location.search).get("resource");
```

- [ ] **Step 3: Run focused component tests, then the full suite and production build**

Run: `npm.cmd test -- src/App.test.tsx src/components/AgentSidebar.test.tsx src/components/AgentResourceCenter.test.tsx`

Run: `npm.cmd test && npm.cmd run build`
