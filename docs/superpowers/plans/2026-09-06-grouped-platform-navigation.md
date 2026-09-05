# Grouped Platform Navigation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reorganize the existing six sidebar links into three labelled groups that explain the operational, validation, and interactive paths without changing routes or page behavior.

**Architecture:** Replace the flat navigation array in `App.tsx` with a typed group structure and render each group as an accessible labelled group inside the existing main navigation. Extend the existing sidebar CSS for quiet desktop headings and a horizontally scrollable grouped mobile navigation that preserves link touch height.

**Tech Stack:** React 19, TypeScript 5.8, React Router 7, Lucide React, CSS, Vitest, Testing Library

## Global Constraints

- Keep the existing route paths, labels, icons, active-route behavior, and page content.
- Group links as `检测与处置`, `验证与评测`, and `互动演示` in that order.
- Order the links as `安全分析`, `自主处置`, `安全事件`, `攻防实验舱`, `评测中心`, and `Token 侦探挑战`.
- Group headings are descriptive text, not links, buttons, or collapsible controls.
- Keep PCAP as a task mode inside `自主处置`; do not add a global PCAP link.
- Do not add the first-use guided tour or browser PCAP upload in this implementation.
- Do not modify backend APIs, stored data, or any page's behavior.
- Preserve keyboard order, visible focus, and React Router's `aria-current="page"` active state.
- Do not add a frontend dependency.

---

## File Structure

- Modify `frontend/src/App.tsx`: define the grouped navigation model and render accessible group wrappers.
- Modify `frontend/src/App.test.tsx`: verify group names, link membership, order, hrefs, and active-route semantics.
- Modify `frontend/src/styles.css`: style desktop group headings and mobile grouped horizontal navigation.

### Task 1: Accessible grouped navigation

**Files:**
- Modify: `frontend/src/App.test.tsx`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/styles.css`

**Interfaces:**
- Consumes: React Router `NavLink` active-route behavior and the six existing route definitions in `Shell`.
- Produces: `navigationGroups`, an internal ordered array of `{ id, label, items }`, and DOM groups named `检测与处置`, `验证与评测`, and `互动演示`.

- [ ] **Step 1: Add a failing navigation structure test**

Add this test near the start of the existing `competition security console` suite in `frontend/src/App.test.tsx`:

```tsx
it("groups the platform navigation by user task without changing routes", async () => {
  render(<App />);

  const navigation = screen.getByRole("navigation", { name: "主导航" });
  const groups = within(navigation).getAllByRole("group");
  expect(groups.map((group) => group.getAttribute("aria-label"))).toEqual([
    "检测与处置",
    "验证与评测",
    "互动演示",
  ]);

  expect(within(groups[0]).getAllByRole("link").map((link) => link.textContent)).toEqual([
    "安全分析",
    "自主处置",
    "安全事件",
  ]);
  expect(within(groups[1]).getAllByRole("link").map((link) => link.textContent)).toEqual([
    "攻防实验舱",
    "评测中心",
  ]);
  expect(within(groups[2]).getAllByRole("link").map((link) => link.textContent)).toEqual([
    "Token 侦探挑战",
  ]);

  expect(screen.getByRole("link", { name: "安全分析" })).toHaveAttribute("href", "/analyze");
  expect(screen.getByRole("link", { name: "自主处置" })).toHaveAttribute("href", "/super-agent");
  expect(screen.getByRole("link", { name: "安全事件" })).toHaveAttribute("href", "/events");
  expect(screen.getByRole("link", { name: "攻防实验舱" })).toHaveAttribute("href", "/lab");
  expect(screen.getByRole("link", { name: "评测中心" })).toHaveAttribute("href", "/evaluation");
  expect(screen.getByRole("link", { name: "Token 侦探挑战" })).toHaveAttribute("href", "/challenge");
  expect(screen.getByRole("link", { name: "安全分析" })).toHaveAttribute("aria-current", "page");
});
```

- [ ] **Step 2: Run the focused test and verify it fails**

Run:

```powershell
cd frontend
npm.cmd test -- App.test.tsx -t "groups the platform navigation"
```

Expected: FAIL because the flat navigation contains no elements with role `group`.

- [ ] **Step 3: Replace the flat navigation model and markup**

Replace `navigation` in `frontend/src/App.tsx` with:

```tsx
const navigationGroups = [
  {
    id: "detection-response",
    label: "检测与处置",
    items: [
      { to: "/analyze", label: "安全分析", icon: ScanLine },
      { to: "/super-agent", label: "自主处置", icon: Workflow },
      { to: "/events", label: "安全事件", icon: FileWarning },
    ],
  },
  {
    id: "validation-evaluation",
    label: "验证与评测",
    items: [
      { to: "/lab", label: "攻防实验舱", icon: FlaskConical },
      { to: "/evaluation", label: "评测中心", icon: BarChart3 },
    ],
  },
  {
    id: "interactive-demo",
    label: "互动演示",
    items: [
      { to: "/challenge", label: "Token 侦探挑战", icon: Gamepad2 },
    ],
  },
] as const;
```

Replace the flat `navigation.map` inside `<nav aria-label="主导航">` with:

```tsx
{navigationGroups.map((group) => (
  <div className="nav-group" role="group" aria-label={group.label} key={group.id}>
    <span className="nav-group-label" aria-hidden="true">{group.label}</span>
    <div className="nav-group-links">
      {group.items.map(({ to, label, icon: Icon }) => (
        <NavLink key={to} to={to} className={({ isActive }) => isActive ? "active" : undefined}>
          <Icon size={18} /> <span>{label}</span>
        </NavLink>
      ))}
    </div>
  </div>
))}
```

Do not change the `<Routes>` block.

- [ ] **Step 4: Add desktop and mobile group styling**

Replace the existing sidebar navigation grid rule in `frontend/src/styles.css` and add focused group styles:

```css
.sidebar nav { display: grid; gap: 18px; }
.nav-group { display: grid; gap: 5px; }
.nav-group-label {
  padding: 0 11px;
  color: #7f938c;
  font-size: 10px;
  font-weight: 700;
  line-height: 1.4;
}
.nav-group-links { display: grid; gap: 5px; }
```

Keep the existing `.sidebar nav a`, hover, active, and focus rules unchanged. In the existing `@media (max-width: 760px)` sidebar block, replace the fixed six-column navigation layout with:

```css
.app-shell {
  grid-template-rows: 82px minmax(0, 1fr);
}
.sidebar {
  height: 82px;
  overflow: hidden;
}
.sidebar nav {
  display: flex;
  gap: 10px;
  overflow-x: auto;
  overscroll-behavior-x: contain;
  scrollbar-width: thin;
}
.nav-group {
  flex: 0 0 auto;
  gap: 3px;
}
.nav-group-label {
  padding: 0 4px;
  font-size: 8px;
  white-space: nowrap;
}
.nav-group-links {
  display: grid;
  grid-auto-flow: column;
  grid-auto-columns: minmax(86px, max-content);
  gap: 3px;
}
```

Remove the later mobile override `.sidebar nav { grid-template-columns: repeat(6, minmax(0, 1fr)); }`. Replace the later `.sidebar nav a { font-size: 8px; }` with `.sidebar nav a { min-width: 86px; font-size: 9px; }` so it complements rather than conflicts with the grouped layout.

- [ ] **Step 5: Run the focused test and verify it passes**

Run:

```powershell
cd frontend
npm.cmd test -- App.test.tsx -t "groups the platform navigation"
```

Expected: PASS with three ordered groups, six unchanged links, and `安全分析` marked as the current page.

- [ ] **Step 6: Run the full frontend regression suite**

Run:

```powershell
cd frontend
npm.cmd test
```

Expected: all frontend tests pass. Existing tests for `/analyze`, `/events`, `/evaluation`, `/lab`, `/super-agent`, and `/challenge` remain green.

- [ ] **Step 7: Build the production frontend**

Run:

```powershell
cd frontend
npm.cmd run build
```

Expected: TypeScript and Vite production build complete without errors.

- [ ] **Step 8: Verify desktop and mobile behavior in the browser**

At desktop width, verify all three headings are visible, all six labels fit, and the active indicator still appears. At 390 px width, verify the 82 px navigation row does not overlap page content, each link remains at least 48 px high and 86 px wide, and horizontal scrolling reaches all three groups.

- [ ] **Step 9: Commit the implementation**

```powershell
git add frontend/src/App.tsx frontend/src/App.test.tsx frontend/src/styles.css
git commit -m "feat: group platform navigation by task"
```

