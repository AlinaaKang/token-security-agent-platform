# Contextual Page Guidance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add reopenable first-use guidance and concise result interpretation to every primary page, including state-aware Token Detective coaching that teaches anomaly-onset selection without revealing the answer.

**Architecture:** Preserve the existing `GuidedTour` as the only spotlight implementation, extend its launcher presentation, and add one native-disclosure `ResultGuide` component for contextual result vocabulary. Static route tours remain in `tourConfig.ts`; Challenge mounts phase-specific `GuidedTour` instances so targets exist when explained and no tour action can submit or call a backend.

**Tech Stack:** React 19, TypeScript 5.8, React Router, Lucide React, native `<details>`, Vitest, Testing Library, CSS.

## Global Constraints

- Do not change routes, API contracts, detection models, thresholds, fusion, scoring, authorization, or backend topology.
- Guidance must never submit a Prompt, create a Lab run or mission, authorize or upload PCAP, execute Docker, execute a tool, or submit a challenge answer.
- Preserve all mascots and the existing Prompt and PCAP workflows.
- Never expose protected Prompt content, suffixes, Token text or vocabulary IDs, raw model output, hidden reasoning, PCAP payloads, network identities, file identities, paths, hashes, or private errors.
- Challenge coaching must not expose `suspicious_span.token_start`, the expected evidence relation, or the system action before submission.
- Red, green, and yellow meanings must always include text; color cannot be the only signal.
- Mobile guidance must not cover the required command, selected signal flag, or submit button.
- Reduced-motion mode removes transitions without hiding information.

---

## File Structure

- Create `frontend/src/components/ResultGuide.tsx`: reusable compact result interpretation disclosure.
- Create `frontend/src/components/ResultGuide.test.tsx`: component accessibility and state-isolation tests.
- Modify `frontend/src/components/GuidedTour.tsx`: visible launcher label and optional accessible launcher text.
- Modify `frontend/src/components/GuidedTour.test.tsx`: launcher and no-action regressions.
- Modify `frontend/src/tourConfig.ts`: add reading tours for `/events` and `/evaluation`; retain action-page tours.
- Modify `frontend/src/tourConfig.test.ts`: require all six primary routes and exact public guidance boundaries.
- Modify page files under `frontend/src/pages/`: add stable tour targets and contextual result guides.
- Modify `frontend/src/pages/ChallengePage.tsx`: mount setup, investigation, answer, and reveal guidance only in matching phases.
- Modify `frontend/src/components/ChallengeSignalPicker.tsx`: add fixed instructional text and selected-onset wording.
- Modify existing page tests plus `frontend/src/ChallengePage.test.tsx` and `frontend/src/components/ChallengeSignalPicker.test.tsx`.
- Modify `frontend/src/styles.css` and `frontend/src/styles.test.ts`: shared disclosure, labelled launcher, responsive and reduced-motion styling.
- Modify `docs/token-detective-challenge.md`, `docs/security-lab.md`, and `docs/competition-delivery-guide.md`: document the visible guidance and video-delivery boundary.

---

### Task 1: Shared Result Interpretation Component

**Files:**
- Create: `frontend/src/components/ResultGuide.tsx`
- Create: `frontend/src/components/ResultGuide.test.tsx`
- Modify: `frontend/src/components/GuidedTour.tsx`
- Modify: `frontend/src/components/GuidedTour.test.tsx`
- Modify: `frontend/src/styles.css`
- Modify: `frontend/src/styles.test.ts`

**Interfaces:**
- Produces: `ResultGuide({ title, summary, items }: ResultGuideProps): JSX.Element`
- Produces: `ResultGuideItem = { term: string; explanation: string }`
- Preserves: `GuidedTour({ route, steps, storage? })`

- [ ] **Step 1: Write failing component tests**

Add tests that render:

```tsx
<ResultGuide
  title="如何理解本次结果"
  summary="这些结论来自当前检测范围。"
  items={[
    { term: "异常候选", explanation: "表示现有证据命中，不代表攻击已经成功。" },
    { term: "工具失败", explanation: "表示没有形成可验证结果。" },
  ]}
/>
```

Assert the native disclosure is labelled `如何理解本次结果`, is closed initially, opens without invoking any supplied page action, and exposes both term/explanation pairs. Extend `GuidedTour.test.tsx` to require visible launcher text `本页引导`, the existing accessible name `打开本页使用引导`, and focus restoration after Escape.

- [ ] **Step 2: Run the focused tests and verify RED**

Run:

```powershell
npm.cmd test -- --run src/components/ResultGuide.test.tsx src/components/GuidedTour.test.tsx
```

Expected: FAIL because `ResultGuide` does not exist and the launcher has no visible label.

- [ ] **Step 3: Implement the minimal shared components**

Implement `ResultGuide` with a native `<details className="result-guide">`, a `<summary>` containing `CircleHelp`, title and summary, and a `<dl>` containing the supplied terms. Do not add local storage, effects, fetch calls, or callbacks.

Update the existing launcher body to:

```tsx
<CircleHelp size={20} aria-hidden="true" />
<span>本页引导</span>
```

Keep its existing accessible name and `title`.

- [ ] **Step 4: Add stable, responsive styling**

Style `.result-guide` as an unframed or single-border explanatory region with a maximum readable line length, 6px-or-less corners, native focus visibility, and no nested card. Change `.guided-tour-launcher` from a fixed circle to an icon-plus-label control with stable height and width. At `max-width: 760px`, keep the launcher within the viewport and make the tour panel a bounded bottom sheet with `max-height: min(70vh, 520px); overflow-y: auto`. Add reduced-motion rules for both components.

- [ ] **Step 5: Run focused tests and verify GREEN**

Run the command from Step 2 and `npm.cmd run build`. Expected: all focused tests PASS and the TypeScript production build exits 0.

- [ ] **Step 6: Commit**

```powershell
git add frontend/src/components/ResultGuide.tsx frontend/src/components/ResultGuide.test.tsx frontend/src/components/GuidedTour.tsx frontend/src/components/GuidedTour.test.tsx frontend/src/styles.css frontend/src/styles.test.ts
git commit -m "feat: add reusable result guidance"
```

---

### Task 2: Events And Evaluation Reading Guidance

**Files:**
- Create: `frontend/src/ReadOnlyGuidance.test.tsx`
- Modify: `frontend/src/tourConfig.ts`
- Modify: `frontend/src/tourConfig.test.ts`
- Modify: `frontend/src/pages/EventsPage.tsx`
- Modify: `frontend/src/pages/EvaluationPage.tsx`
- Modify: `frontend/src/styles.css`

**Interfaces:**
- Consumes: `ResultGuide`
- Produces tour targets: `events-summary`, `events-table`, `evaluation-scope`, `evaluation-methods`, `evaluation-limits`

- [ ] **Step 1: Write failing route tests**

Add `/events` and `/evaluation` mocked API fixtures to `ReadOnlyGuidance.test.tsx`. Assert:

```ts
expect(screen.getByRole("button", { name: "打开本页使用引导" })).toBeInTheDocument();
expect(screen.getByText("这是脱敏审计记录，不包含原始 Prompt。" )).toBeInTheDocument();
expect(screen.getByText("FPR 越低，代表无害样本被误报的比例越低。" )).toBeInTheDocument();
```

Also assert that opening, advancing, and closing either guide performs only the initial GET requests and never issues a POST.

- [ ] **Step 2: Verify RED**

Run:

```powershell
npm.cmd test -- --run src/ReadOnlyGuidance.test.tsx src/tourConfig.test.ts
```

Expected: FAIL because read-only routes currently have no tours or result help.

- [ ] **Step 3: Add exact route tours and targets**

Add `/events` steps for the event summary and audit table. Add `/evaluation` steps for evaluation scope, method table, and limitations. Remove the old test assumption that read-only routes must not have automatic tours; replace it with the no-POST behavioral assertion.

Add `data-tour` targets to the existing regions without changing layout or API calls.

- [ ] **Step 4: Add contextual result guides**

Events terms: `请求标识`, `语义状态`, `Token 状态`, `动作`, `校准版本`. Evaluation terms: `Precision`, `Recall`, `F1`, `FPR`, `AUROC`, `P50/P95`, `冻结评测`, `工作点`. Include the exact limitations from the design, including the difference between classification and CPD localization.

- [ ] **Step 5: Verify and commit**

Run the Task 2 focused tests and `npm.cmd run build`. Then:

```powershell
git add frontend/src/ReadOnlyGuidance.test.tsx frontend/src/tourConfig.ts frontend/src/tourConfig.test.ts frontend/src/pages/EventsPage.tsx frontend/src/pages/EvaluationPage.tsx frontend/src/styles.css
git commit -m "feat: explain audit and evaluation results"
```

---

### Task 3: Analyze, Lab, And SuperAgent Result Guidance

**Files:**
- Modify: `frontend/src/pages/AnalyzePage.tsx`
- Modify: `frontend/src/App.test.tsx`
- Modify: `frontend/src/pages/LabPage.tsx`
- Modify: `frontend/src/LabPage.test.tsx`
- Modify: `frontend/src/pages/LabPcapWorkspace.tsx`
- Modify: `frontend/src/pages/LabPcapWorkspace.test.tsx`
- Modify: `frontend/src/pages/SuperAgentPage.tsx`
- Modify: `frontend/src/SuperAgentPage.test.tsx`
- Modify: `frontend/src/pages/PcapSuperAgentWorkspace.tsx`
- Modify: `frontend/src/PcapSuperAgentWorkspace.test.tsx`
- Modify: `frontend/src/pages/PcapReconWorkspace.tsx`
- Modify: `frontend/src/PcapReconWorkspace.test.tsx`
- Modify: `frontend/src/pages/PcapDetectionWorkspace.tsx`
- Modify: `frontend/src/pages/PcapDetectionWorkspace.test.tsx`

**Interfaces:**
- Consumes: `ResultGuide`
- Preserves all existing page props, API calls, storage keys, and mission state.

- [ ] **Step 1: Add failing interpretation tests**

For each existing page test fixture, assert the corresponding result guide appears only beside the relevant result or workspace. Required copy assertions:

```text
Token 异常候选不是已经确认的越狱攻击。
知识证据用于解释，不会改写基础动作。
反事实敏感性不是严格因果证明。
数据勘察只形成聚合画像，不判断攻击。
当前范围未命中不等于文件全部安全。
工具失败既不能计为安全，也不能计为异常。
```

Record fetch/mission/upload/tool call counts before and after opening help; assert all counts are unchanged.

- [ ] **Step 2: Verify RED**

Run:

```powershell
npm.cmd test -- --run src/App.test.tsx src/LabPage.test.tsx src/pages/LabPcapWorkspace.test.tsx src/SuperAgentPage.test.tsx src/PcapSuperAgentWorkspace.test.tsx src/PcapReconWorkspace.test.tsx src/pages/PcapDetectionWorkspace.test.tsx
```

Expected: FAIL on missing interpretation disclosures.

- [ ] **Step 3: Add Analyze and Lab guides**

Place one `ResultGuide` below the Analyze evidence chain and before detailed metrics. Place Prompt Lab help beside completed stage/counterfactual output, and PCAP Lab help beside the upload/detection outcome. Empty forms must remain concise; help must not add a second submit control.

- [ ] **Step 4: Add Prompt and PCAP SuperAgent guides**

Prompt terms explain bounded plan, actor trace, tool receipts, one-replan limit, and final action. PCAP mode-level help remains visible while switching among triage, reconnaissance, and anomaly detection. Terminal-result help must use red/green/yellow text meanings and retain the current status labels.

- [ ] **Step 5: Verify and commit**

Run the focused tests and `npm.cmd run build`. Then:

```powershell
git add frontend/src/pages frontend/src/App.test.tsx frontend/src/LabPage.test.tsx frontend/src/SuperAgentPage.test.tsx frontend/src/PcapSuperAgentWorkspace.test.tsx frontend/src/PcapReconWorkspace.test.tsx
git commit -m "feat: explain analysis and agent outcomes"
```

---

### Task 4: State-Aware Token Detective Coaching

**Files:**
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/tourConfig.ts`
- Modify: `frontend/src/pages/ChallengePage.tsx`
- Modify: `frontend/src/ChallengePage.test.tsx`
- Modify: `frontend/src/components/ChallengeSignalPicker.tsx`
- Modify: `frontend/src/components/ChallengeSignalPicker.test.tsx`
- Modify: `frontend/src/styles.css`

**Interfaces:**
- Consumes: `GuidedTour`, `ResultGuide`
- Produces challenge targets: `challenge-input`, `challenge-team`, `challenge-clues`, `challenge-onset`, `challenge-evidence`, `challenge-action`, `challenge-submit`, `challenge-reveal`
- Uses storage scopes: `/challenge`, `/challenge/investigation`, `/challenge/answer`, `/challenge/reveal`

- [ ] **Step 1: Write failing phase-guidance tests**

Extend the challenge test fixture to assert:

- setup guidance exists before entry;
- interactive investigation explains the required Guard → CPD → Agent order;
- the answer coach appears only after investigation completes;
- the chart says `选择最早开始持续变化的位置，不是曲线最高点`;
- selecting Token 2 says `已选择 Token #2`;
- pre-submit document text does not contain `CPD 起点 T2`, `系统证据关系`, or `系统原始动作`;
- opening and completing all guides does not increase Lab Run requests or submit the answer;
- reveal help appears only after the user explicitly submits.

- [ ] **Step 2: Verify RED**

Run:

```powershell
npm.cmd test -- --run src/ChallengePage.test.tsx src/components/ChallengeSignalPicker.test.tsx
```

Expected: FAIL because only setup targets and the old selected-token wording exist.

- [ ] **Step 3: Mount phase-specific tours**

Prevent `App.tsx` from mounting a second route-level challenge tour. In `ChallengePage`, render exactly one `GuidedTour` for the active phase:

```tsx
{session.phase === "setup" ? <GuidedTour route="/challenge" steps={CHALLENGE_SETUP_STEPS} /> : null}
{session.phase === "guessing" && !investigationComplete
  ? <GuidedTour route="/challenge/investigation" steps={CHALLENGE_INVESTIGATION_STEPS} />
  : null}
{session.phase === "guessing" && investigationComplete
  ? <GuidedTour route="/challenge/answer" steps={CHALLENGE_ANSWER_STEPS} />
  : null}
{session.phase === "revealed"
  ? <GuidedTour route="/challenge/reveal" steps={CHALLENGE_REVEAL_STEPS} />
  : null}
```

Define and export the four fixed step arrays from `tourConfig.ts`. Mark only local selection controls with `advanceOnClick`; never mark `challenge-command` or `challenge-submit` for automatic progression.

- [ ] **Step 4: Teach onset selection without leaking the answer**

Add a visible instruction above the chart and change selected wording to `已选择 Token #<index>`. Keep each existing flag button and vertical selection line. Add tour targets around evidence relation and action groups. The coach describes the red CPD cumulative line and earliest sustained change but does not read or interpolate the server onset.

- [ ] **Step 5: Add reveal interpretation**

Add `ResultGuide` after the existing reveal score table. Explain 50/20/30 scoring, normalized per-round score, player-versus-system onset, and the limitation that challenge score is not model accuracy.

- [ ] **Step 6: Verify and commit**

Run the Task 4 focused tests and `npm.cmd run build`. Then:

```powershell
git add frontend/src/App.tsx frontend/src/tourConfig.ts frontend/src/pages/ChallengePage.tsx frontend/src/ChallengePage.test.tsx frontend/src/components/ChallengeSignalPicker.tsx frontend/src/components/ChallengeSignalPicker.test.tsx frontend/src/styles.css
git commit -m "feat: guide Token Detective investigations"
```

---

### Task 5: Documentation, Full Regression, And Visual Acceptance

**Files:**
- Modify: `docs/token-detective-challenge.md`
- Modify: `docs/security-lab.md`
- Modify: `docs/competition-delivery-guide.md`
- Modify: `frontend/src/styles.test.ts`

**Interfaces:**
- Consumes all guidance behavior from Tasks 1-4.
- Produces reviewer-facing instructions and verified acceptance records.

- [ ] **Step 1: Update user documentation**

Document how to reopen page guidance, how to choose the earliest sustained CPD change, and how result meanings differ. Add a video-delivery checklist that shows service health, explicit user action, returned result, and interpretation help. State explicitly that real Prompt inference requires a compatible GPU service and recorded results are not offline inference.

- [ ] **Step 2: Run privacy and static checks**

Run:

```powershell
git diff --check
& '.\.venv\Scripts\python.exe' -m pytest tests/unit/test_verify_lab_privacy.py tests/unit/test_verify_pcap_agent_privacy.py -q
```

Expected: no whitespace errors and all privacy tests PASS.

- [ ] **Step 3: Run the complete frontend suite and build**

Run:

```powershell
Set-Location frontend
npm.cmd test -- --run
npm.cmd run build
```

Expected: every test file passes and the production build exits 0.

- [ ] **Step 4: Perform one bounded browser QA pass**

Use Playwright at `1440x900` and `390x844` for all six routes. Complete one interactive challenge round and inspect one Analyze, Evaluation, Lab PCAP, and SuperAgent terminal-result state. Assert document `scrollWidth <= clientWidth`, no overlapping required controls, no console/page/resource errors, help can reopen, and reduced-motion removes guidance transitions. Do not upload a real PCAP or expose a protected Prompt during screenshots.

- [ ] **Step 5: Fix all visual defects in one batch and confirm once**

If the first QA pass finds defects, make one grouped CSS/markup correction, rerun affected tests/build, and run one final desktop/mobile screenshot pass. Do not perform open-ended visual polishing.

- [ ] **Step 6: Record fresh verification evidence and commit**

Append exact current test counts, build outcome, viewport results, and known limitations to the three documentation files. Then:

```powershell
git add docs/token-detective-challenge.md docs/security-lab.md docs/competition-delivery-guide.md frontend/src/styles.test.ts
git commit -m "docs: explain guided competition workflows"
```

- [ ] **Step 7: Final state check**

Run `git status --short`, verify only intentional or pre-existing user changes remain, confirm `http://127.0.0.1:5173/` and both API backends are reachable, and report any unavailable runtime honestly.
