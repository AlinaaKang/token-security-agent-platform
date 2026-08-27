# Token Detective Challenge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an isolated, mascot-led `/challenge` game mode that scores a player's action, evidence-relation, and Token-onset guesses against real redacted Security Lab results without changing the stable product pages or professional lab workflow.

**Architecture:** The challenge is frontend-only and reuses `GET /api/v1/lab/scenarios` plus `POST /api/v1/lab/runs`; it adds no model, database, or backend route. Pure modules own catalog resolution, session transitions, and deterministic scoring, while a new page composes those modules with reusable signal geometry and three local Detective Academy mascot assets. Challenge state remains in React memory, and the full lab result is progressively revealed as a recorded replay rather than represented as streaming execution.

**Tech Stack:** React 19, TypeScript 5.8, React Router 7, Vitest 3, Testing Library, Vite 7, CSS, Lucide React, local transparent PNG/WebP assets, Playwright for visual QA.

## Global Constraints

- Do not change the request, response, persistence, or user-visible behavior of `/analyze`, `/events`, `/evaluation`, or the professional `/lab` investigation flow.
- Do not add a model, backend route, database, account, leaderboard, telemetry endpoint, attack generator, PCAP integration, or real external response action.
- Every challenge run sends `mode: "analysis"`; a returned `sanitize_recheck` action is scored as the player's `review` choice while the reveal keeps the original label.
- Frozen attacks send only `scenario_kind`, `sample_id`, and `mode`; never return, render, persist, log, screenshot, or commit `prompt`, `suffix`, `token_text`, `token_id`, `query_text`, `raw_output`, or `guard_raw_output`.
- Keep game progress, answers, score, and combo in React memory only; do not use localStorage, sessionStorage, IndexedDB, cookies, or the formal event store.
- Game score measures agreement with the current system result, not model accuracy, attack coverage, recall, F1, or CPD localization accuracy.
- The three mascots are Guard Detective (green shield hat badge), CPD Detective (blue change-line hat badge), and Agent Captain (yellow round captain badge), using big heads, short limbs, round silhouettes, eye highlights, subtle blush, and small detective hats.
- Mascot animation is a recorded replay driven by returned `LabStage` order; it is not live streaming, parallel execution, chain-of-thought, or causal proof.
- Use local transparent bitmap mascot assets; do not use remote URLs, hand-drawn SVG characters, or emoji as final character art.
- GCG, AutoDAN, and AdvPrompter are the only protected attack families in scope. Do not claim direct-unsafe, BEAST, or AutoDAN-HGA challenge coverage.
- `prefers-reduced-motion: reduce` must eliminate character travel, bounce, and combo animation.
- Desktop and mobile layouts must have stable dimensions, no incoherent overlap, and no global horizontal overflow; charts may scroll only inside their own container.

## File Structure

- `frontend/src/challenge/types.ts`: challenge-only type contracts.
- `frontend/src/challenge/scoring.ts`: pure evidence mapping and deterministic score calculation.
- `frontend/src/challenge/definitions.ts`: speed/full challenge definitions and privacy-safe scenario catalog resolution.
- `frontend/src/challenge/session.ts`: pure in-memory state machine and reducer.
- `frontend/src/challenge/*.test.ts`: focused unit tests for the three pure modules.
- `frontend/public/mascots/guard-detective.webp`: green Detective Academy mascot.
- `frontend/public/mascots/cpd-detective.webp`: blue Detective Academy mascot.
- `frontend/public/mascots/agent-captain.webp`: yellow Detective Academy mascot.
- `frontend/public/mascots/README.md`: asset dimensions, generation provenance, and allowed use.
- `frontend/src/components/MascotTeam.tsx`: accessible three-character state rendering.
- `frontend/src/components/MascotTeam.test.tsx`: role, alt text, and state behavior.
- `frontend/src/components/signalGeometry.ts`: shared deterministic SVG coordinate and path helpers.
- `frontend/src/components/ChallengeSignalPicker.tsx`: keyboard/click Token onset selection.
- `frontend/src/components/ChallengeSignalPicker.test.tsx`: selection and sparse-index behavior.
- `frontend/src/components/LabModeSwitch.tsx`: professional/challenge mode links.
- `frontend/src/pages/ChallengePage.tsx`: setup, round orchestration, replay, answering, reveal, and summary.
- `frontend/src/ChallengePage.test.tsx`: route, privacy, full-session, failure, and accessibility behavior.
- `frontend/src/App.tsx`, `frontend/src/App.test.tsx`: isolated route and stable-page regression assertions.
- `frontend/src/pages/LabPage.tsx`, `frontend/src/LabPage.test.tsx`: mode switch only; existing investigation assertions remain.
- `frontend/src/components/LabSignalChart.tsx`: imports shared geometry without contract changes.
- `frontend/src/styles.css`: `.challenge-*` and mascot styles plus a minimal shared mode-switch block.
- `docs/token-detective-challenge.md`: operation, scoring, privacy, limits, and verified demonstration script.
- `docs/security-lab.md`: link to the challenge guide and record final challenge verification.

---

### Task 1: Challenge Contracts and Deterministic Scoring

**Files:**
- Create: `frontend/src/challenge/types.ts`
- Create: `frontend/src/challenge/scoring.ts`
- Create: `frontend/src/challenge/scoring.test.ts`

**Interfaces:**
- Consumes: `Decision`, `LabRunResult` from `frontend/src/types.ts`.
- Produces: `PlayerDecision`, `EvidenceRelation`, `ChallengeAnswer`, `RoundScoreBreakdown`, `scorableDecision(decision)`, `expectedEvidenceRelation(run)`, and `scoreChallengeRound(answer, run)`.

- [x] **Step 1: Write literal failing score tests**

Create `frontend/src/challenge/scoring.test.ts` with a complete redacted `LabRunResult` fixture and these literal cases:

```ts
it.each([
  [0, 30], [3, 30], [4, 15], [8, 15], [9, 0],
])("scores onset distance %s", (distance, expected) => {
  const scored = scoreChallengeRound(
    { decision: "block", evidenceRelation: "dual_risk", onsetIndex: 20 + distance },
    runWith({ decision: "block", severity: "unsafe", detector: "token_anomaly_candidate", onset: 20 }),
  );
  expect(scored.onsetPoints).toBe(expected);
});

it("normalizes a no-onset round over the applicable 70 points", () => {
  const scored = scoreChallengeRound(
    { decision: "allow", evidenceRelation: "dual_normal", onsetIndex: null },
    runWith({ decision: "allow", severity: "safe", detector: "no_token_anomaly", onset: null }),
  );
  expect(scored).toMatchObject({ earnedPoints: 70, applicablePoints: 70, normalizedScore: 100 });
});

it("scores sanitize-and-recheck as the review player category without mutating the run", () => {
  const source = runWith({ decision: "sanitize_recheck", severity: "safe", detector: "token_anomaly_candidate", onset: 12 });
  const before = structuredClone(source);
  expect(scoreChallengeRound(
    { decision: "review", evidenceRelation: "distribution_only", onsetIndex: 12 },
    source,
  ).decisionPoints).toBe(50);
  expect(source).toEqual(before);
  expect(source.detection.decision).toBe("sanitize_recheck");
});
```

Also assert the four exact evidence mappings, `controversial`/`unavailable` evidence non-applicability, missing player onset scoring zero when an onset exists, and combo values having no input to the scorer.

- [x] **Step 2: Run the focused test and verify RED**

Run:

```powershell
cd frontend
npm.cmd test -- src/challenge/scoring.test.ts
```

Expected: collection fails because `./scoring` and `./types` do not exist.

- [x] **Step 3: Implement exact challenge types and pure scoring**

Define the contracts in `types.ts`:

```ts
export type PlayerDecision = "allow" | "review" | "block";
export type EvidenceRelation = "dual_normal" | "semantic_only" | "distribution_only" | "dual_risk";

export interface ChallengeAnswer {
  decision: PlayerDecision;
  evidenceRelation: EvidenceRelation | null;
  onsetIndex: number | null;
}

export interface RoundScoreBreakdown {
  decisionPoints: 0 | 50;
  evidencePoints: 0 | 20;
  onsetPoints: 0 | 15 | 30;
  earnedPoints: number;
  applicablePoints: 50 | 70 | 80 | 100;
  normalizedScore: number;
}
```

Implement in `scoring.ts`:

```ts
export function scorableDecision(decision: Decision): PlayerDecision {
  return decision === "sanitize_recheck" ? "review" : decision;
}

export function expectedEvidenceRelation(run: LabRunResult): EvidenceRelation | null {
  const severity = run.detection.semantic_severity;
  const detector = run.detection.detector_status;
  if (severity !== "safe" && severity !== "unsafe") return null;
  if (detector !== "no_token_anomaly" && detector !== "token_anomaly_candidate") return null;
  if (severity === "safe" && detector === "no_token_anomaly") return "dual_normal";
  if (severity === "unsafe" && detector === "no_token_anomaly") return "semantic_only";
  if (severity === "safe") return "distribution_only";
  return "dual_risk";
}
```

`scoreChallengeRound` derives `applicablePoints`, computes onset distance against `suspicious_span.token_start`, and returns `Math.round(earnedPoints / applicablePoints * 100)`. It must not accept session score or combo parameters.

- [x] **Step 4: Run score tests and TypeScript build**

Run:

```powershell
npm.cmd test -- src/challenge/scoring.test.ts
npm.cmd run build
```

Expected: all scoring tests pass and the build has no TypeScript errors.

- [x] **Step 5: Commit the score contract**

```powershell
git add frontend/src/challenge/types.ts frontend/src/challenge/scoring.ts frontend/src/challenge/scoring.test.ts
git commit -m "feat: add deterministic challenge scoring"
```

### Task 2: Privacy-Safe Challenge Definitions and Catalog Resolution

**Files:**
- Create: `frontend/src/challenge/definitions.ts`
- Create: `frontend/src/challenge/definitions.test.ts`

**Interfaces:**
- Consumes: `LabScenario` from `frontend/src/types.ts`.
- Produces: `ChallengeMode`, `ResolvedChallengeRound`, `ChallengeResolution`, `resolveChallenge(mode, scenarios)`.

- [x] **Step 1: Write failing catalog resolution tests**

Use literal scenario metadata only:

```ts
const catalog: LabScenario[] = [
  { scenario_id: "synthetic_safe", label: "普通无害", scenario_kind: "synthetic", attack_family: null, ready: true },
  { scenario_id: "synthetic_shift", label: "无害格式突变", scenario_kind: "synthetic", attack_family: null, ready: true },
  { scenario_id: "gcg_01", label: "GCG", scenario_kind: "protected", attack_family: "gcg", ready: true },
  { scenario_id: "autodan_01", label: "AutoDAN", scenario_kind: "protected", attack_family: "AutoDAN", ready: true },
  { scenario_id: "adv_01", label: "AdvPrompter", scenario_kind: "protected", attack_family: "advprompter", ready: true },
];

it("resolves the three-round speed challenge with AutoDAN preference", () => {
  expect(resolveChallenge("speed", catalog).rounds.map((item) => item.scenarioId)).toEqual([
    "synthetic_safe", "synthetic_shift", "autodan_01",
  ]);
});

it("resolves full challenge families case-insensitively in fixed order", () => {
  expect(resolveChallenge("full", catalog).rounds.map((item) => item.family)).toEqual([
    null, null, "gcg", "autodan", "advprompter",
  ]);
});
```

Also assert speed fallback order AutoDAN → GCG → AdvPrompter, unavailable scenarios are ignored, a missing full-mode family appears in `missingFamilies`, and no returned object contains any of the seven forbidden field names.

- [x] **Step 2: Run focused tests and verify RED**

Run:

```powershell
npm.cmd test -- src/challenge/definitions.test.ts
```

Expected: import failure for `./definitions`.

- [x] **Step 3: Implement literal definitions and resolver**

Define:

```ts
export type ChallengeMode = "speed" | "full";

export interface ResolvedChallengeRound {
  roundId: "safe" | "shift" | "gcg" | "autodan" | "advprompter";
  scenarioId: string;
  label: string;
  family: "gcg" | "autodan" | "advprompter" | null;
}

export interface ChallengeResolution {
  mode: ChallengeMode;
  rounds: ResolvedChallengeRound[];
  missingFamilies: Array<"gcg" | "autodan" | "advprompter">;
  ready: boolean;
}
```

Normalize `attack_family` with `.trim().toLocaleLowerCase("en-US")`. Never derive a round from labels or sample ID text. Full mode is ready only with both synthetic IDs and all three protected families. Speed mode is ready with both synthetic IDs and at least one protected family.

- [x] **Step 4: Run definitions tests and the frontend suite**

Run:

```powershell
npm.cmd test -- src/challenge/definitions.test.ts
npm.cmd test
```

Expected: focused and existing tests pass.

- [x] **Step 5: Commit challenge resolution**

```powershell
git add frontend/src/challenge/definitions.ts frontend/src/challenge/definitions.test.ts
git commit -m "feat: resolve privacy-safe challenge rounds"
```

### Task 3: In-Memory Challenge Session State Machine

**Files:**
- Create: `frontend/src/challenge/session.ts`
- Create: `frontend/src/challenge/session.test.ts`

**Interfaces:**
- Consumes: `ResolvedChallengeRound`, `ChallengeAnswer`, `RoundScoreBreakdown`, `LabRunResult`.
- Produces: `ChallengePhase`, `ChallengeSessionState`, `ChallengeSessionAction`, `createChallengeSetup()`, `createChallengeSession(rounds)`, and `challengeSessionReducer(state, action)`.

- [x] **Step 1: Write failing transition tests**

Cover the exact state sequence and illegal transition stability:

```ts
it("runs a round through loading, guessing, reveal, and next", () => {
  let state = createChallengeSession(rounds);
  state = challengeSessionReducer(state, { type: "start_round" });
  expect(state.phase).toBe("investigating");
  state = challengeSessionReducer(state, { type: "receive_run", run });
  expect(state.phase).toBe("guessing");
  state = challengeSessionReducer(state, { type: "submit_answer", answer, score });
  expect(state.phase).toBe("revealed");
  state = challengeSessionReducer(state, { type: "advance" });
  expect(state.roundIndex).toBe(1);
  expect(state.phase).toBe("ready");
});
```

Also prove: `createChallengeSetup()` returns `phase: "setup"` with empty rounds and no current data; `createChallengeSession(rounds)` returns `phase: "ready"` with the supplied rounds; API failure moves to `round_error` without adding score; retry returns to `investigating`; submitting cannot happen before a run exists; combo increments only after a 100-point round and resets otherwise; total score is the rounded arithmetic mean of completed round normalized scores; final advance yields `complete`; `exit` returns `createChallengeSetup()` with no run, answer, score, or completed rounds.

- [x] **Step 2: Run focused tests and verify RED**

Run:

```powershell
npm.cmd test -- src/challenge/session.test.ts
```

Expected: import failure for `./session`.

- [x] **Step 3: Implement a discriminated reducer with no storage side effects**

Use these phases:

```ts
export type ChallengePhase =
  | "setup" | "ready" | "investigating" | "guessing"
  | "revealed" | "round_error" | "complete";
```

The state holds `rounds`, `roundIndex`, `currentRun`, `currentAnswer`, `currentScore`, `completedScores`, `combo`, and fixed `errorCode: "challenge_run_failed" | null`. Do not read or write `window`, storage APIs, network, timers, or document state in this module.

`createChallengeSetup()` is the sole constructor for the empty `phase: "setup"` state. `createChallengeSession(rounds)` starts a configured session in `phase: "ready"`. The `exit` reducer action returns `createChallengeSetup()` so leaving a challenge cannot retain prior round data.

- [x] **Step 4: Run session tests and all pure challenge tests**

Run:

```powershell
npm.cmd test -- src/challenge/scoring.test.ts src/challenge/definitions.test.ts src/challenge/session.test.ts
```

Expected: all pure module tests pass.

- [x] **Step 5: Commit session logic**

```powershell
git add frontend/src/challenge/session.ts frontend/src/challenge/session.test.ts
git commit -m "feat: add in-memory challenge session"
```

### Task 4: Detective Academy Bitmap Assets and Mascot Team

**Files:**
- Create: `frontend/public/mascots/guard-detective.webp`
- Create: `frontend/public/mascots/cpd-detective.webp`
- Create: `frontend/public/mascots/agent-captain.webp`
- Create: `frontend/public/mascots/README.md`
- Create: `frontend/src/components/MascotTeam.tsx`
- Create: `frontend/src/components/MascotTeam.test.tsx`
- Modify: `frontend/src/styles.css`

**Interfaces:**
- Consumes: returned `LabStage[]`, current challenge phase, evidence conflict flag, `prefers-reduced-motion` CSS.
- Produces: `<MascotTeam phase replayStageId evidenceConflict />` with stable role labels and accessible images.

- [x] **Step 1: Write failing mascot component tests**

Create tests that assert exact roles and state classes:

```tsx
render(<MascotTeam phase="investigating" replayStageId="entropy_cpd" evidenceConflict={false} />);
expect(screen.getByRole("img", { name: "Guard 语义侦探" })).toHaveAttribute("src", "/mascots/guard-detective.webp");
expect(screen.getByRole("img", { name: "CPD 曲线侦探" }).closest("figure")).toHaveClass("active");
expect(screen.getByRole("img", { name: "Agent 小队队长" }).closest("figure")).not.toHaveClass("active");
```

Also assert semantic stage activates Guard, fixed-fusion/knowledge stages activate Agent, `evidenceConflict` renders text “证据分歧”, all three figures remain mounted across phases, and decorative status icons have `aria-hidden="true"`.

- [x] **Step 2: Run the test and verify RED**

Run:

```powershell
npm.cmd test -- src/components/MascotTeam.test.tsx
```

Expected: import failure because `MascotTeam` is absent.

- [x] **Step 3: Export and verify the three transparent mascot bitmaps**

Use the `imagegen` skill workflow. Prefer the user-approved `detective_academy` visual-study source when it is available; otherwise generate a coherent three-character set with this content requirement:

```text
Three separate full-body chibi detective academy mascots on transparent backgrounds,
large head and short limbs, rounded soft vinyl silhouette, eye highlights and subtle blush,
small detective hats, quiet professional cyber-security styling, no text and no logos.
Guard is green with a shield hat badge; CPD is blue with a change-point line hat badge;
Agent Captain is yellow with a round captain badge. Consistent front three-quarter pose,
soft studio lighting, clean edges, suitable for a work-focused security dashboard.
```

Export each character as a separate 512×512 transparent WebP under `frontend/public/mascots/`. Use `view_image` to verify the background is transparent, characters are not cropped, faces are distinct, badges match roles, and no text or unintended symbols appear. Record generation date, dimensions, intended role, and the prompt summary in `frontend/public/mascots/README.md`; do not add remote source URLs.

- [x] **Step 4: Implement the stable mascot component and scoped styles**

`MascotTeam` uses a literal role table and renders all three figures at fixed aspect ratio. Add only `.challenge-mascot-*` selectors. Waiting, active, evidence, conflict, and celebration states use opacity, transform, filter, Lucide status icons, and fixed text labels; do not swap image sources or dimensions between states.

- [x] **Step 5: Run mascot tests, build, and asset checks**

Run:

```powershell
npm.cmd test -- src/components/MascotTeam.test.tsx
npm.cmd run build
Get-ChildItem public/mascots/*.webp | Select-Object Name,Length
```

Expected: tests/build pass and exactly three non-empty WebP files are listed.

- [x] **Step 6: Commit the approved character set**

```powershell
git add frontend/public/mascots frontend/src/components/MascotTeam.tsx frontend/src/components/MascotTeam.test.tsx frontend/src/styles.css
git commit -m "feat: add detective academy mascot team"
```

### Task 5: Isolated Challenge Route, Mode Switch, and Setup Screen

**Files:**
- Create: `frontend/src/components/LabModeSwitch.tsx`
- Create: `frontend/src/pages/ChallengePage.tsx`
- Create: `frontend/src/ChallengePage.test.tsx`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/App.test.tsx`
- Modify: `frontend/src/pages/LabPage.tsx`
- Modify: `frontend/src/LabPage.test.tsx`
- Modify: `frontend/src/styles.css`

**Interfaces:**
- Consumes: `api.health()`, `api.labScenarios()`, `resolveChallenge`, `createChallengeSession`, `MascotTeam`.
- Produces: `/challenge`, an accessible professional/challenge switch, speed/full setup selection, missing-family and unavailable states.

- [ ] **Step 1: Write failing route and stability tests**

In `ChallengePage.test.tsx`, mock only `/health` and `/api/v1/lab/scenarios`, then assert:

```tsx
window.history.pushState({}, "", "/challenge");
render(<App />);
expect(await screen.findByRole("main", { name: "Token 侦探挑战" })).toBeInTheDocument();
expect(screen.getByRole("img", { name: "Guard 语义侦探" })).toBeInTheDocument();
expect(screen.getByRole("button", { name: "三关速战" })).toBeEnabled();
expect(screen.getByRole("button", { name: "五关完整挑战" })).toBeEnabled();
```

Add cases for `health.lab.ready=false`, missing GCG disabling only full mode with visible missing-family text, and legacy health without `lab`. Extend `App.test.tsx` to assert `/analyze`, `/events`, `/evaluation`, and `/lab` still render their existing main landmarks. Extend `LabPage.test.tsx` only to assert the mode switch links to `/challenge` and the professional tab remains selected on `/lab`.

- [ ] **Step 2: Run the focused UI tests and verify RED**

Run:

```powershell
npm.cmd test -- src/ChallengePage.test.tsx src/App.test.tsx src/LabPage.test.tsx
```

Expected: failures for the absent route, switch, and challenge page; existing stable-page assertions continue to pass.

- [ ] **Step 3: Add the isolated route and minimal setup page**

Add `Gamepad2` from Lucide to the navigation and route table:

```tsx
{ to: "/challenge", label: "Token 侦探挑战", icon: Gamepad2 }
<Route path="/challenge" element={<ChallengePage />} />
```

`LabModeSwitch` renders two `NavLink`s for `/lab` and `/challenge`. `ChallengePage` loads health then scenarios, derives both resolutions, and renders fixed-size mode buttons plus `<MascotTeam phase="setup" ... />`. It must not call `api.createLabRun` before the player starts a session.

- [ ] **Step 4: Add scoped setup and degraded-state styles**

Use `.challenge-*` selectors, 8px maximum radii, fixed button heights, 44px touch targets, no viewport-scaled font sizes, no decorative gradient/orbs, and a stable mascot stage aspect ratio. Keep the existing `.lab-*` declarations unchanged except the small shared mode switch placement.

- [ ] **Step 5: Run focused tests and full frontend tests**

Run:

```powershell
npm.cmd test -- src/ChallengePage.test.tsx src/App.test.tsx src/LabPage.test.tsx
npm.cmd test
```

Expected: route/setup tests and all prior UI tests pass.

- [ ] **Step 6: Commit the isolated challenge shell**

```powershell
git add frontend/src/components/LabModeSwitch.tsx frontend/src/pages/ChallengePage.tsx frontend/src/ChallengePage.test.tsx frontend/src/App.tsx frontend/src/App.test.tsx frontend/src/pages/LabPage.tsx frontend/src/LabPage.test.tsx frontend/src/styles.css
git commit -m "feat: add isolated token detective challenge"
```

### Task 6: Signal Picker, Player Answers, Scoring, and Reveal

**Files:**
- Create: `frontend/src/components/signalGeometry.ts`
- Create: `frontend/src/components/ChallengeSignalPicker.tsx`
- Create: `frontend/src/components/ChallengeSignalPicker.test.tsx`
- Modify: `frontend/src/components/LabSignalChart.tsx`
- Modify: `frontend/src/LabPage.test.tsx`
- Modify: `frontend/src/pages/ChallengePage.tsx`
- Modify: `frontend/src/ChallengePage.test.tsx`
- Modify: `frontend/src/styles.css`

**Interfaces:**
- Consumes: `LabPublicSignal[]`, `ChallengeAnswer`, `scoreChallengeRound`, challenge reducer, `api.createLabRun({scenario_kind:"frozen", sample_id, mode:"analysis"})`.
- Produces: keyboard/click onset selection, evidence/action controls, deterministic score reveal, next round, and final average.

- [ ] **Step 1: Write failing shared geometry and picker tests**

Assert sparse Token indexes use observation position for geometry but emit real Token index:

```tsx
const onSelect = vi.fn();
render(<ChallengeSignalPicker signals={[
  { index: 10, entropy: 1, nll: 1, cpd_entropy: 0, cpd_nll: 0, risk: .1 },
  { index: 20, entropy: 2, nll: 2, cpd_entropy: 2, cpd_nll: 0, risk: .8 },
]} selectedIndex={null} onSelect={onSelect} />);
fireEvent.click(screen.getByRole("button", { name: "选择 Token 20" }));
expect(onSelect).toHaveBeenCalledWith(20);
```

Keep the existing `LabSignalChart` sparse cursor assertion unchanged. Add a picker test for ArrowLeft/ArrowRight moving selection, Enter confirming the focused Token, nonblank three paths, and a two-signal minimum fallback.

- [ ] **Step 2: Write failing full-round interaction tests**

In `ChallengePage.test.tsx`, use the complete redacted fixture from `LabPage.test.tsx` and assert:

- starting speed mode sends the first scenario with exactly `{scenario_kind:"frozen", sample_id:"synthetic_safe", mode:"analysis"}`;
- guessing shows semantic severity and curves but hides “基础动作”, fusion reason, counterfactual interpretation, knowledge IDs, and score;
- the player can choose evidence relation, action, and Token onset;
- submit reveals player/system actions, exact score breakdown, original `sanitize_recheck` label when applicable, “调查过程回放”, and the non-performance limitation;
- advance starts the next configured round;
- after all speed rounds the page shows the arithmetic mean and clears current run data on exit;
- serialized request bodies for protected rounds contain none of the seven forbidden keys.

- [ ] **Step 3: Run focused tests and verify RED**

Run:

```powershell
npm.cmd test -- src/components/ChallengeSignalPicker.test.tsx src/ChallengePage.test.tsx src/LabPage.test.tsx
```

Expected: missing picker and missing gameplay controls fail; professional chart assertions still pass.

- [ ] **Step 4: Extract geometry without changing the professional chart contract**

Move these pure values/functions to `signalGeometry.ts` and export them:

```ts
export const SIGNAL_CHART_WIDTH = 920;
export const SIGNAL_CHART_HEIGHT = 236;
export const SIGNAL_CHART_PAD_X = 42;
export const SIGNAL_CHART_PAD_Y = 24;
export type SignalSeriesKey = "entropy" | "nll" | "cpd_entropy";
export function xAtPosition(position: number, count: number): number;
export function signalSeriesPath(signals: LabPublicSignal[], key: SignalSeriesKey): string;
```

`LabSignalChart` imports those helpers but retains the same props, classes, ARIA labels, readout, and focus behavior.

- [ ] **Step 5: Implement picker and full round orchestration**

`ChallengeSignalPicker` renders three SVG paths plus actual `<button>` hit targets in a fixed overlay grid. It emits `signal.index`, not the array position. In `ChallengePage`, call `api.createLabRun` only from the reducer's `ready`/retry command, hold the returned run in memory, and submit a `ChallengeAnswer` to `scoreChallengeRound`. Hide answer fields with conditional rendering, not CSS-only visibility.

The reveal shows:

```text
玩家动作 / 系统原始动作 / 动作得分
玩家证据关系 / 系统证据关系 / 证据得分或不适用
玩家起点 / CPD 起点 / 定位得分或不适用
本关百分制分数
```

It labels counterfactual output as sensitivity evidence and never strict causality.

- [ ] **Step 6: Run focused tests, full suite, and build**

Run:

```powershell
npm.cmd test -- src/components/ChallengeSignalPicker.test.tsx src/ChallengePage.test.tsx src/LabPage.test.tsx
npm.cmd test
npm.cmd run build
```

Expected: all tests pass and Vite builds without TypeScript errors.

- [ ] **Step 7: Commit playable challenge rounds**

```powershell
git add frontend/src/components/signalGeometry.ts frontend/src/components/ChallengeSignalPicker.tsx frontend/src/components/ChallengeSignalPicker.test.tsx frontend/src/components/LabSignalChart.tsx frontend/src/LabPage.test.tsx frontend/src/pages/ChallengePage.tsx frontend/src/ChallengePage.test.tsx frontend/src/styles.css
git commit -m "feat: add playable token evidence rounds"
```

### Task 7: Recorded Stage Replay, Failure Recovery, Responsive Polish

**Files:**
- Modify: `frontend/src/pages/ChallengePage.tsx`
- Modify: `frontend/src/ChallengePage.test.tsx`
- Modify: `frontend/src/components/MascotTeam.tsx`
- Modify: `frontend/src/components/MascotTeam.test.tsx`
- Modify: `frontend/src/styles.css`

**Interfaces:**
- Consumes: returned `LabStage[]`, reducer `round_error`/retry actions, `window.matchMedia("(prefers-reduced-motion: reduce)")` through CSS.
- Produces: skippable recorded replay, stable fixed dimensions, retry without penalty, keyboard-complete workflow, responsive/reduced-motion behavior.

- [ ] **Step 1: Write failing replay, error, and accessibility tests**

Use fake timers to prove replay is presentation-only:

```tsx
vi.useFakeTimers();
// Resolve POST with a run whose stages have five returned items.
expect(screen.getByText("调查过程回放")).toBeInTheDocument();
expect(screen.getByRole("img", { name: "Guard 语义侦探" }).closest("figure")).toHaveClass("active");
await vi.advanceTimersByTimeAsync(350);
expect(screen.getByRole("img", { name: "CPD 曲线侦探" }).closest("figure")).toHaveClass("active");
```

Also assert “跳过回放” immediately enters guessing, displayed stage latency is the server value rather than 350ms, a rejected POST shows fixed “本关调查失败” and retry without score loss, all answer groups have accessible names, keyboard activation completes a round, and an unavailable knowledge stage does not block scoring.

- [ ] **Step 2: Run focused tests and verify RED**

Run:

```powershell
npm.cmd test -- src/ChallengePage.test.tsx src/components/MascotTeam.test.tsx
```

Expected: failures for absent replay progression, skip, and recovery behavior.

- [ ] **Step 3: Implement replay controller and deterministic failure copy**

After `receive_run`, replay returned stages at a fixed 350ms presentation interval, store only the current stage index, and expose a “跳过回放” button. The replay never delays API invocation or changes `LabStage.latency_ms`. Clear timers on round change, retry, exit, and unmount. Map any request exception to the fixed `challenge_run_failed` UI without rendering the exception body.

- [ ] **Step 4: Implement responsive and reduced-motion styles**

Add stable min/max dimensions for header, mascot stage, chart/picker, answer controls, reveal, and summary. At 760px stack in progress → mascots → chart → answers order. Put chart overflow on `.challenge-chart-scroll`. Under `@media (prefers-reduced-motion: reduce)`, set challenge transition/animation durations to `0.01ms`, disable transform travel/bounce, and retain text/icon state changes.

- [ ] **Step 5: Run frontend tests and production build**

Run:

```powershell
npm.cmd test
npm.cmd run build
```

Expected: complete frontend suite and build pass with no console warnings from tests.

- [ ] **Step 6: Commit replay and polish**

```powershell
git add frontend/src/pages/ChallengePage.tsx frontend/src/ChallengePage.test.tsx frontend/src/components/MascotTeam.tsx frontend/src/components/MascotTeam.test.tsx frontend/src/styles.css
git commit -m "feat: polish token detective challenge replay"
```

### Task 8: Documentation, Privacy Regression, Visual QA, and AutoDL Acceptance

**Files:**
- Create: `docs/token-detective-challenge.md`
- Modify: `docs/security-lab.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: final `/challenge`, existing privacy verifier, local Vite server, AutoDL tunnel, protected scenario IDs.
- Produces: verified operation guide, actual test/build counts, browser outcomes, protected-family statuses, latency, and explicit limitations.

- [ ] **Step 1: Write the operation and demonstration guide**

Document:

- `/challenge` entry and Detective Academy roles;
- three-round and five-round definitions;
- exact 50/20/30 scoring plus applicable-point normalization;
- `sanitize_recheck` review-category mapping;
- recorded replay vs real `latency_ms`;
- no storage and refresh-clears-session behavior;
- protected sample-ID boundary and seven forbidden fields;
- 2–3 minute competition script;
- score-is-not-performance limitation;
- missing-family, GPU unavailable, retry, no-onset, evidence-unavailable, and reduced-motion behavior.

Link the guide from `README.md` and `docs/security-lab.md` without changing previously recorded frozen metrics.

- [ ] **Step 2: Run complete automated regression and privacy checks**

Run from the repository root:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
cd frontend
npm.cmd test
npm.cmd run build
cd ..
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File scripts/verify_lab_privacy.ps1
git diff --check
git diff --name-only -- configs data knowledge
```

Expected: backend has zero failures with only the existing unconfigured local GPU test skipped; frontend has zero failures; build succeeds; privacy counts are all zero; no calibration, frozen report, source data, or knowledge snapshot file is changed.

- [ ] **Step 3: Start the local product and perform desktop/mobile Playwright QA**

Keep the established tunnel `127.0.0.1:18000 → AutoDL 127.0.0.1:8000` and Vite URL. At 1440×900 and 390×844 verify:

- `/analyze` and `/lab` have no visual regression or console error;
- `/challenge` setup, speed mode, full mode, guessing, reveal, retry, and summary have no overlap/global overflow;
- mascot images are nonblank, uncropped, and retain stable dimensions;
- all three chart paths have nonzero geometry;
- chart scrolling is local on mobile;
- Tab/Arrow/Enter can complete a round;
- reduced-motion disables mascot travel and replay transition;
- screenshots use only synthetic benign rounds or protected sample IDs, never attack text.

Use screenshot and canvas/image-pixel checks to prove all three bitmap assets render nonblank on desktop and mobile.

- [ ] **Step 4: Run real protected challenge acceptance through AutoDL**

Capture the base `/health` SHA-256, then complete one speed challenge and one full challenge. Ensure GCG, AutoDAN, and AdvPrompter each execute by protected sample ID. For every returned run record only family, sample ID, decision, detector status, CPD onset, score, counterfactual interpretation, report status, latency, forbidden-key count, and unknown-citation count.

Required assertions:

```text
protected family count = 3
forbidden-key hits = 0
unknown citations = 0
base health before/after hash unchanged
challenge request mode = analysis
protected requests contain sample_id and no source text
```

Do not claim every decision must be block; record the actual action and score. Do not create or copy a protected response file to Git.

- [ ] **Step 5: Update the guide with actual verification evidence**

Record actual backend/frontend test counts, build module count, privacy counts, viewport outcomes, AutoDL family statuses, P50/P95, failures, and the current limitations. Keep browser screenshots under ignored `tmp/` and do not commit them.

- [ ] **Step 6: Rerun documentation-adjacent checks**

Run:

```powershell
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File scripts/verify_lab_privacy.ps1
.\.venv\Scripts\python.exe -m pytest tests/unit/test_verify_lab_privacy.py -q
cd frontend
npm.cmd test -- src/ChallengePage.test.tsx src/App.test.tsx src/LabPage.test.tsx
npm.cmd run build
```

Expected: privacy counts are zero, focused tests pass, and build succeeds.

- [ ] **Step 7: Commit final challenge verification**

```powershell
git add README.md docs/token-detective-challenge.md docs/security-lab.md
git commit -m "docs: verify token detective challenge"
```

## Final Review Checklist

- [ ] Every production behavior had a focused failing test before implementation.
- [ ] Score mappings, onset boundaries, normalization, and sanitize/recheck mapping use literal tests.
- [ ] The challenge sends all runs in analysis mode and protected runs by sample ID only.
- [ ] No challenge state is stored outside React memory.
- [ ] Player answers and system answers are separated until explicit submission.
- [ ] Mascot animation is labelled recorded replay and uses returned stage order.
- [ ] The approved Detective Academy assets are local, transparent, uncropped, and nonblank.
- [ ] Existing product pages and the professional lab retain their contracts and visual behavior.
- [ ] Full backend/frontend suites, production build, privacy scan, and Git diff checks pass.
- [ ] Desktop/mobile, keyboard, reduced-motion, and local chart scrolling QA pass.
- [ ] AutoDL speed/full runs cover GCG, AutoDAN, and AdvPrompter by protected ID with zero forbidden-key hits.
- [ ] Documentation states that game score is not detection performance and preserves all coverage limitations.
