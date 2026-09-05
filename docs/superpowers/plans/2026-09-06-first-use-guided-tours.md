# First-Use Guided Tours Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add replayable first-use tours to the four interactive routes using the approved hybrid progression model without triggering business actions.

**Architecture:** A reusable `GuidedTour` component owns persistence, target discovery, focus, geometry, keyboard control, and click-based progression. `tourConfig.ts` provides static route-specific copy and selectors, `App.tsx` selects the active route and renders one global tour plus its replay launcher, and page components expose stable `data-tour` targets only.

**Tech Stack:** React 19, React Router 7, TypeScript 5.8, lucide-react, CSS, Vitest, Testing Library, Playwright CLI with Microsoft Edge.

## Global Constraints

- Tours exist only on `/analyze`, `/lab`, `/super-agent`, and `/challenge`; `/events` and `/evaluation` never auto-open a tour.
- Use storage keys in the exact format `token-sentinel-tour:<route>:v1`.
- Local UI actions may auto-advance; Prompt submission, PCAP parsing, model inference, Docker execution, network calls, and form submission never auto-run.
- Tour copy and metadata must not expose Prompt text, Token text, PCAP payloads, IP addresses, paths, protected sample values, raw model output, or hidden chain of thought.
- Replaying or closing a tour must not clear page input, result, mission, or challenge state.
- Do not add a frontend dependency.
- Desktop and 390 px layouts must keep the panel inside the viewport and off the mobile navigation.

---

### Task 1: Guided tour state and interaction component

**Files:**
- Create: `frontend/src/components/GuidedTour.tsx`
- Create: `frontend/src/components/GuidedTour.test.tsx`

**Interfaces:**
- Consumes: `route: string`, `steps: GuidedTourStep[]`, and optional `storage?: Storage`.
- Produces: `GuidedTourStep { id: string; target: string; title: string; description: string; advanceOnClick?: boolean }` and `GuidedTour({ route, steps })`.

- [ ] **Step 1: Write failing component tests**

Cover first-visit open, exact per-route/version persistence, next/back, skip, Escape, replay, user-click auto-advance, no synthesized target click, missing-target skip, failed storage access, and focus restoration. Render real target buttons and assert observable dialog/button behavior.

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `npm.cmd test -- src/components/GuidedTour.test.tsx`

Expected: FAIL because `GuidedTour.tsx` does not exist.

- [ ] **Step 3: Implement the minimal reusable component**

Use `useLayoutEffect` to resolve the active `[data-tour]` element and compute its `getBoundingClientRect()`. Listen for resize, capture-phase scroll, and real target clicks; only a target with `advanceOnClick: true` advances automatically. Render `role="dialog"`, `aria-modal="false"`, progress, previous/next/skip/finish controls, a fixed spotlight, and a fixed replay button labeled `打开本页使用引导`. Catch storage errors, skip absent targets, trap Tab within the panel, close on Escape, and restore prior focus.

- [ ] **Step 4: Run focused tests and verify GREEN**

Run: `npm.cmd test -- src/components/GuidedTour.test.tsx`

Expected: all guided-tour component tests PASS with no unhandled errors.

- [ ] **Step 5: Commit the component**

```bash
git add frontend/src/components/GuidedTour.tsx frontend/src/components/GuidedTour.test.tsx
git commit -m "feat: add reusable first-use tour"
```

### Task 2: Route configuration and stable page targets

**Files:**
- Create: `frontend/src/tourConfig.ts`
- Create: `frontend/src/tourConfig.test.ts`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/App.test.tsx`
- Modify: `frontend/src/pages/AnalyzePage.tsx`
- Modify: `frontend/src/pages/LabPage.tsx`
- Modify: `frontend/src/pages/SuperAgentPage.tsx`
- Modify: `frontend/src/pages/ChallengePage.tsx`

**Interfaces:**
- Consumes: `GuidedTourStep` from `components/GuidedTour` and `useLocation()` from React Router.
- Produces: `TOURS: Partial<Record<string, GuidedTourStep[]>>` and stable targets named `<route>-<purpose>`.

- [ ] **Step 1: Write failing route and application tests**

Assert four steps exist for every supported route, none exist for `/events` or `/evaluation`, all selectors resolve on their route's initial render, the route-specific dialog auto-opens only when unseen, the help launcher remains available after completion, and navigation closes the old tour before opening the new route's tour. Assert clicking a local selector can advance, while clicking `下一步` on a command step produces zero analyze/lab/challenge/PCAP execution requests.

- [ ] **Step 2: Run route tests and verify RED**

Run: `npm.cmd test -- src/tourConfig.test.ts src/App.test.tsx`

Expected: FAIL because route configuration and targets are missing.

- [ ] **Step 3: Add static route definitions and page target attributes**

Define four privacy-safe steps per route. Add `data-tour` only to existing containers or controls: Analyze input/mode groups and detection command; Lab scenario/custom input/mode/command; SuperAgent task switch/scope/execution/start authorization; Challenge setup/mode controls/evidence-order explanation/start. Mark only local selectors with `advanceOnClick`; command steps stay manual and skippable.

- [ ] **Step 4: Mount one route-aware tour in the application shell**

Use `useLocation()` in `Shell`, look up `TOURS[location.pathname]`, and render `GuidedTour` after the route content with `key={location.pathname}`. Unsupported routes render neither dialog nor launcher.

- [ ] **Step 5: Run route and regression tests and verify GREEN**

Run: `npm.cmd test -- src/tourConfig.test.ts src/App.test.tsx`

Expected: all tests PASS, and existing request-body/state assertions remain unchanged.

- [ ] **Step 6: Commit route integration**

```bash
git add frontend/src/tourConfig.ts frontend/src/tourConfig.test.ts frontend/src/App.tsx frontend/src/App.test.tsx frontend/src/pages/AnalyzePage.tsx frontend/src/pages/LabPage.tsx frontend/src/pages/SuperAgentPage.tsx frontend/src/pages/ChallengePage.tsx
git commit -m "feat: guide first-time users across core workflows"
```

### Task 3: Responsive presentation, accessibility, and release verification

**Files:**
- Modify: `frontend/src/styles.css`
- Modify: `frontend/src/components/GuidedTour.test.tsx`

**Interfaces:**
- Consumes: `.guided-tour-*` class names and inline target geometry from `GuidedTour`.
- Produces: clamped desktop popover, 390 px bottom sheet, visible non-interactive spotlight, and reduced-motion behavior.

- [ ] **Step 1: Write failing layout/accessibility assertions**

Assert the spotlight is `aria-hidden`, the dialog retains an accessible title and progress, and geometry exposes placement/clamping styles without changing the highlighted element. Keep behavioral assertions in Testing Library; visual bounds are verified in Step 4.

- [ ] **Step 2: Run focused tests and verify RED**

Run: `npm.cmd test -- src/components/GuidedTour.test.tsx`

Expected: FAIL on missing presentation attributes or class contracts.

- [ ] **Step 3: Implement responsive and reduced-motion CSS**

Style a fixed high-contrast help icon, pointer-transparent spotlight with outline and large masking shadow, compact anchored dialog at desktop sizes, and a bottom sheet above mobile navigation at `max-width: 760px`. Add focus-visible states and disable optional transitions under `prefers-reduced-motion: reduce`.

- [ ] **Step 4: Run the complete automated suite and build**

Run: `npm.cmd test`

Run: `npm.cmd run build`

Expected: all tests PASS and Vite production build completes without TypeScript errors.

- [ ] **Step 5: Verify desktop and mobile behavior in Edge**

Clear the route storage key, capture `/analyze`, `/lab`, `/super-agent`, and `/challenge` at 1440x900 and 390x844, and verify: target is visible, dialog is fully inside the viewport, mobile navigation is not covered, controls remain clickable, command steps do not submit, and replay preserves page state.

- [ ] **Step 6: Commit styling and verification adjustments**

```bash
git add frontend/src/styles.css frontend/src/components/GuidedTour.test.tsx
git commit -m "style: polish guided tour presentation"
```

