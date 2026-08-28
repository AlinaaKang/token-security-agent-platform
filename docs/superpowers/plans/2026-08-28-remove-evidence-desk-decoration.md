# Remove Evidence Desk Decoration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the misleading central `ScanSearch` decoration from the challenge mascot lineup without changing detective interaction, motion, evidence, or scoring behavior.

**Architecture:** Keep `MascotTeam` responsible for the three detective controls and their state-driven presentation. Remove the isolated decorative node and its isolated CSS; protect the user-visible absence with the existing real component test.

**Tech Stack:** React 19, TypeScript, Lucide React, CSS, Vitest, Testing Library, Vite

## Global Constraints

- Preserve all three detective controls, state icons, motion mappings, interaction order, and the real investigation evidence panel.
- Do not modify the backend, API, samples, scoring, investigation state, or other pages.
- Remove both desktop and mobile CSS that only targets `.challenge-evidence-desk`.

---

### Task 1: Remove The Misleading Central Decoration

**Files:**
- Modify: `frontend/src/components/MascotTeam.test.tsx:177-185`
- Modify: `frontend/src/components/MascotTeam.tsx:1,110-112`
- Modify: `frontend/src/styles.css:43-57,682`

**Interfaces:**
- Consumes: `MascotTeam(props: MascotTeamProps)` and the existing `[data-evidence-desk]` selector.
- Produces: the same `MascotTeam` public props and detective controls, with no central decorative evidence-desk element.

- [ ] **Step 1: Write the failing component test**

Replace the combined conflict/decoration test with a behavior test that preserves captain conflict and rejects the misleading central decoration:

```tsx
it("uses conflict only for the captain without a misleading central decoration", () => {
  const { container } = render(
    <MascotTeam phase="revealed" replayStageId="fixed_fusion" evidenceConflict />,
  );
  expect(screen.getByRole("button", { name: "Agent 小队队长" }).closest("figure"))
    .toHaveAttribute("data-motion", "conflict");
  expect(container.querySelector("[data-evidence-desk]")).not.toBeInTheDocument();
});
```

- [ ] **Step 2: Run the focused test and verify RED**

Run:

```powershell
npm.cmd test -- src/components/MascotTeam.test.tsx --no-file-parallelism
```

Expected: FAIL because `[data-evidence-desk]` is still rendered. This proves the test catches reintroduction of the misleading pseudo-control while exercising the real component.

- [ ] **Step 3: Remove the minimal production markup**

Change the Lucide import to:

```tsx
import { Activity, BadgeCheck, ShieldCheck } from "lucide-react";
```

Delete this node from `MascotTeam`:

```tsx
<div className="challenge-evidence-desk" data-evidence-desk aria-hidden="true">
  <ScanSearch size={22} strokeWidth={2} />
</div>
```

- [ ] **Step 4: Remove the orphaned styles**

Delete the full desktop `.challenge-evidence-desk` rule and the mobile override:

```css
.challenge-evidence-desk { bottom: 44px; width: 46px; }
```

Do not adjust mascot grid columns or travel variables because the decoration is absolutely positioned and does not participate in layout.

- [ ] **Step 5: Verify GREEN and regression coverage**

Run:

```powershell
npm.cmd test -- src/components/MascotTeam.test.tsx --no-file-parallelism
npm.cmd test -- --no-file-parallelism
npm.cmd run build
```

Expected: the focused component test passes, all 121 frontend tests pass including the changed absence expectation, and the TypeScript/Vite production build completes.

- [ ] **Step 6: Verify the rendered page**

Open `http://127.0.0.1:5175/challenge`, force refresh, and confirm at desktop and 390px mobile width:

- the central magnifier and gray base are absent;
- all three detectives remain aligned and clickable in the same order;
- interactive and automatic presentation modes still progress;
- there is no global horizontal overflow or console error.

- [ ] **Step 7: Commit and update the existing PR**

```powershell
git add frontend/src/components/MascotTeam.test.tsx frontend/src/components/MascotTeam.tsx frontend/src/styles.css
git commit -m "fix: remove misleading evidence desk decoration"
git push origin feature/interactive-detective-investigation
```

Confirm Pull Request #1 still targets `feature/basic-platform-foundation`.
