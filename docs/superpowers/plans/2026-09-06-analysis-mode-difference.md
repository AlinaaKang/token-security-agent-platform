# Analysis Mode Difference Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the `/analyze` page explain and demonstrate the policy difference between 安全分析 and 在线防护 before and after one detection request.

**Architecture:** Add one pure frontend policy mirror with exhaustive tests against the backend fusion table, then render a dedicated mode selector/preview and a result comparison from the submitted-mode snapshot. The server response remains authoritative; no comparison action sends a second request.

**Tech Stack:** React 19, TypeScript 5.8, Lucide React, Vitest, Testing Library, CSS.

## Global Constraints

- Do not modify backend `EvidenceFusionPolicy`, API contracts, detection thresholds, knowledge behavior, audit behavior, or request counts.
- A completed custom analysis stores the mode submitted with that request; later selector changes affect only the next request.
- Frozen demo analysis always records `analysis`, because `/api/v1/demo-samples/{sample_id}/analyze` is server-fixed to that mode.
- The actual response `decision` is authoritative. A frontend mismatch must be labelled and must never overwrite it.
- Do not expose Prompt content, Token text, model raw output, hidden reasoning, suffixes, paths, or private errors.
- The comparison UI must use text in addition to color, support keyboard operation, fit at 390px, and respect reduced motion.

---

### Task 1: Pure Mode Policy Comparison

**Files:**
- Create: `frontend/src/analyze/modePolicy.ts`
- Create: `frontend/src/analyze/modePolicy.test.ts`

**Interfaces:**
- Consumes: `Mode`, `SemanticSeverity`, `DetectorStatus`, and `Decision` from `frontend/src/types.ts`.
- Produces: `expectedModeDecision(mode, semantic, detectorStatus): "allow" | "review" | "block"`.
- Produces: `compareModeDecision(resultMode, semantic, detectorStatus, actualDecision): ModeDecisionComparison`.

- [ ] **Step 1: Write the exhaustive failing policy test**

Create a table covering all 16 combinations of two modes, four semantic states, and two detector states. Assert the exact backend policy:

```ts
const cases = [
  ["analysis", "unsafe", "no_token_anomaly", "block"],
  ["gateway", "unsafe", "token_anomaly_candidate", "block"],
  ["analysis", "controversial", "no_token_anomaly", "review"],
  ["gateway", "controversial", "token_anomaly_candidate", "review"],
  ["analysis", "safe", "no_token_anomaly", "allow"],
  ["gateway", "safe", "no_token_anomaly", "allow"],
  ["analysis", "safe", "token_anomaly_candidate", "block"],
  ["gateway", "safe", "token_anomaly_candidate", "review"],
  ["analysis", "unavailable", "no_token_anomaly", "allow"],
  ["gateway", "unavailable", "no_token_anomaly", "review"],
  ["analysis", "unavailable", "token_anomaly_candidate", "block"],
  ["gateway", "unavailable", "token_anomaly_candidate", "review"],
] as const;
```

Use duplicated unsafe/controversial detector variants through `it.each`, so every Cartesian combination is asserted. Also assert comparison swaps to the other mode and sets `matchesActual` false for an intentionally inconsistent response.

- [ ] **Step 2: Run the focused test and verify RED**

Run:

```powershell
Set-Location frontend
npm.cmd test -- --run src/analyze/modePolicy.test.ts
```

Expected: FAIL because `modePolicy.ts` does not exist.

- [ ] **Step 3: Implement the policy mirror**

Implement the same branch ordering as `backend/app/agent/fusion.py`:

```ts
export function expectedModeDecision(
  mode: Mode,
  semantic: SemanticSeverity,
  detectorStatus: DetectorStatus,
): "allow" | "review" | "block" {
  const cpdAlarm = detectorStatus === "token_anomaly_candidate";
  if (semantic === "unsafe") return "block";
  if (semantic === "controversial") return "review";
  if (semantic === "safe" && !cpdAlarm) return "allow";
  if (cpdAlarm) return mode === "analysis" ? "block" : "review";
  return mode === "gateway" ? "review" : "allow";
}
```

Return comparison data containing `resultMode`, `alternateMode`, `expectedCurrent`, `expectedAlternate`, `actualDecision`, `matchesActual`, and `changesAction`.

- [ ] **Step 4: Run the focused test and verify GREEN**

Run the Task 1 command. Expected: all table rows and mismatch behavior PASS.

- [ ] **Step 5: Commit Task 1**

```powershell
git add frontend/src/analyze/modePolicy.ts frontend/src/analyze/modePolicy.test.ts
git commit -m "feat: model analyze mode policy comparison"
```

---

### Task 2: Mode Selector, Preview, And Result Impact

**Files:**
- Create: `frontend/src/components/AnalyzeModeControl.tsx`
- Create: `frontend/src/components/AnalyzeModeControl.test.tsx`
- Modify: `frontend/src/pages/AnalyzePage.tsx`
- Modify: `frontend/src/App.test.tsx`
- Modify: `frontend/src/styles.css`
- Modify: `frontend/src/styles.test.ts`

**Interfaces:**
- Consumes: `expectedModeDecision` and `compareModeDecision` from Task 1.
- Produces: `AnalyzeModeControl({ value, onChange, disabled? })` with accessible buttons `安全分析` and `在线防护`.
- Produces: `AnalyzeModeImpact({ result, resultMode })` that never invokes a callback or fetch.

- [ ] **Step 1: Write failing interaction and isolation tests**

Test that the selector exposes two `aria-pressed` buttons, shows the three differing policy rows, and calls `onChange("gateway")` only after the user clicks 在线防护. Test the result component with safe + CPD evidence:

```tsx
<AnalyzeModeImpact result={safeCpdResult} resultMode="gateway" />
```

Assert it displays `当前模式：在线防护`, `本次实际动作：人工复核`, and `安全分析将采取：拦截`. Add an inconsistent fixture and assert `策略版本不一致` while the actual response action remains unchanged.

In `App.test.tsx`, replace the two select-change operations with button clicks. Record analyze request counts before and after selector changes and opening help; assert no new request. Add a test that starts an analysis in `analysis`, changes the selector after completion, and still sees `当前模式：安全分析`. Add a demo test that selects 在线防护, runs a frozen sample, and still sees `当前模式：安全分析`.

- [ ] **Step 2: Run focused tests and verify RED**

Run:

```powershell
Set-Location frontend
npm.cmd test -- --run src/components/AnalyzeModeControl.test.tsx src/App.test.tsx src/styles.test.ts
```

Expected: FAIL because the new components and mode snapshot do not exist.

- [ ] **Step 3: Implement the accessible selector and compact preview**

Use a `role="group"` labelled `工作模式` with two text buttons. Each option contains a short purpose line. Render a compact three-row comparison below it with explicit `拦截`, `人工复核`, and `降级放行` text. Do not add another submit button or another disclosure around the selector.

- [ ] **Step 4: Capture the submitted mode without changing requests**

In `AnalyzePage`, add:

```ts
const [resultMode, setResultMode] = useState<Mode | null>(null);
```

For custom analysis, capture `const submittedMode = mode` before awaiting `api.analyze`, then assign both result and `submittedMode` after the request resolves. For frozen demo results assign `analysis` explicitly. Clear `resultMode` whenever the corresponding result is cleared by a new request or failure.

Pass `resultMode` to `ResultPanel`. Render `AnalyzeModeImpact` after the three-node evidence chain and before detailed metrics. If `resultMode` is null, omit the comparison.

- [ ] **Step 5: Add responsive and state styling**

Create stable two-column mode buttons on desktop and one-column buttons at `max-width: 760px`. Use existing `--trusted`, `--review`, `--blocked`, `--line`, and surface tokens. Keep corners at 6px or below, letter spacing at zero, and text wrapping enabled. Style mode impact as one unframed result band, not nested cards. Add focus-visible and reduced-motion coverage.

- [ ] **Step 6: Run focused tests and verify GREEN**

Run the Task 2 command and:

```powershell
npm.cmd run build
```

Expected: component tests and existing application tests PASS; TypeScript and Vite build exit 0.

- [ ] **Step 7: Commit Task 2**

```powershell
git add frontend/src/components/AnalyzeModeControl.tsx frontend/src/components/AnalyzeModeControl.test.tsx frontend/src/pages/AnalyzePage.tsx frontend/src/App.test.tsx frontend/src/styles.css frontend/src/styles.test.ts
git commit -m "feat: explain analyze mode policy impact"
```

---

### Task 3: Documentation And Final Verification

**Files:**
- Modify: `docs/competition-delivery-guide.md`
- Modify: `docs/superpowers/specs/2026-09-06-analysis-mode-difference-design.md` only if implementation exposes a verified wording mismatch.

**Interfaces:**
- Consumes the verified UI behavior from Tasks 1 and 2.
- Produces reviewer-facing mode comparison instructions and fresh verification evidence.

- [ ] **Step 1: Update the usage manual**

Document the three differing conditions, the submitted-mode snapshot, and the meaning of “策略版本不一致”. State that the comparison is local explanation over returned public states and does not perform a second inference.

- [ ] **Step 2: Run complete regression and static checks**

Run:

```powershell
Set-Location frontend
npm.cmd test -- --run
npm.cmd run build
Set-Location ..
git diff --check
```

Expected: every frontend test passes, production build succeeds, and no whitespace errors appear.

- [ ] **Step 3: Perform one bounded browser QA pass**

At `1440x900` and `390x844`, verify `/analyze` has no horizontal overflow; both mode controls are readable and keyboard reachable; the three policy differences fit; a completed result identifies its submitted mode; changing the selector after completion does not relabel that result; and browser console/page errors remain empty. Use only synthetic input or mocked responses during screenshots.

- [ ] **Step 4: Run the UI detector once**

Run:

```powershell
node E:\CodexData\codex-skills\impeccable\scripts\detect.mjs --json frontend/src/components/AnalyzeModeControl.tsx frontend/src/pages/AnalyzePage.tsx frontend/src/styles.css
```

Fix warnings introduced by this feature in one batch; do not refactor unrelated incumbent styles.

- [ ] **Step 5: Record evidence and commit**

Append the current test count, build result, two viewport outcomes, and known GPU runtime boundary to `docs/competition-delivery-guide.md`, then:

```powershell
git add docs/competition-delivery-guide.md
git commit -m "docs: explain analyze mode differences"
```

- [ ] **Step 6: Final state check**

Run `git status --short`, confirm `http://127.0.0.1:5173/analyze` serves the updated source, and report any unavailable Prompt or PCAP backend honestly.
