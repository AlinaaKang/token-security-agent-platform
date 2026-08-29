# Challenge Public Input Card Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Show a deterministic public task card for the current `/challenge` round while ensuring protected attack text never reaches the browser or persisted run results.

**Architecture:** The backend scenario catalog owns a validated `public_input` disclosure object built only from reviewed constants. The frontend copies that object through an explicit whitelist into each resolved round and renders it with a stateless component; invalid or missing data degrades to a non-blocking fallback. `LabRunResult`, scoring, execution requests, storage, and the detection pipeline remain unchanged.

**Tech Stack:** Python 3.11, FastAPI, Pydantic 2, pytest, React 19, TypeScript 5.8, Vitest, Testing Library, Vite, CSS.

## Global Constraints

- `FORBIDDEN_PUBLIC_KEYS` remains exactly `prompt`, `suffix`, `token_text`, `token_id`, `query_text`, `raw_output`, `guard_raw_output`, and `hidden_reasoning`.
- `LabRunResult` must not gain `public_input` or any source-text field.
- Protected cards use static family-level descriptions only; they must never read, truncate, clean, summarize, or derive content from protected dataset text.
- Every redacted card uses the exact notice `[对抗攻击内容已隐藏]`.
- Missing or invalid frontend card data renders `公开材料暂不可用` and never blocks challenge execution, scoring, retry, or navigation.
- The task card does not issue API requests, mutate challenge state, affect scoring, or persist data.
- Do not expose real GCG, AutoDAN, or AdvPrompter inputs, suffixes, private paths, model output, or token text in source, tests, logs, screenshots, or Git history.
- Preserve `/analyze`, `/lab`, and `/super-agent` behavior and prioritize base-page stability.

---

## File Structure

- `backend/app/lab/models.py`: define and validate the public scenario disclosure contract.
- `backend/app/lab/service.py`: map reviewed synthetic input and static protected-family descriptions into the scenario catalog.
- `tests/unit/test_lab_models.py`: lock validation rules and the unchanged forbidden-key contract.
- `tests/unit/test_lab_service.py`: verify catalog mappings, privacy, and `LabRunResult` isolation.
- `frontend/src/types.ts`: describe the scenario API response.
- `frontend/src/challenge/definitions.ts`: validate and whitelist-copy catalog data into resolved rounds.
- `frontend/src/challenge/definitions.test.ts`: test mapping, malformed fallback, and serialization privacy.
- `frontend/src/components/ChallengeInputCard.tsx`: render the stateless full, redacted, and unavailable states.
- `frontend/src/components/ChallengeInputCard.test.tsx`: test accessible labels and disclosure-specific copy.
- `frontend/src/pages/ChallengePage.tsx`: place the current-round card between progress and the detective team.
- `frontend/src/ChallengePage.test.tsx`: test round switching, retry, exit/re-entry, request count, and protected privacy.
- `frontend/src/styles.css`: implement the compact desktop band and mobile stacking without overflow.
- `docs/token-detective-challenge.md`: document what is displayed and why protected content remains hidden.

---

### Task 1: Backend Public Scenario Contract

**Files:**
- Modify: `backend/app/lab/models.py`
- Modify: `backend/app/lab/service.py`
- Test: `tests/unit/test_lab_models.py`
- Test: `tests/unit/test_lab_service.py`

**Interfaces:**
- Consumes: existing `NonEmptyText`, `_SYNTHETIC_SCENARIOS`, `_PROTECTED_FAMILY_ORDER`, `LabScenario`, and `assert_public_payload`.
- Produces: `REDACTED_INPUT_NOTICE: str`, `LabPublicInput`, and required `LabScenario.public_input: LabPublicInput`.
- Preserves: the complete field set of `LabRunResult` and the exact value of `FORBIDDEN_PUBLIC_KEYS`.

- [ ] **Step 1: Add failing model contract tests**

Import `LabPublicInput`, `LabScenario`, and `REDACTED_INPUT_NOTICE` in `tests/unit/test_lab_models.py`, then add tests equivalent to:

```python
def test_lab_public_input_enforces_disclosure_contract() -> None:
    full = LabPublicInput(
        disclosure="full",
        content="Reviewed safe input",
        intent_summary="解释安全输入",
        redaction_notice=None,
    )
    redacted = LabPublicInput(
        disclosure="redacted",
        content="受保护对抗样本，具体内容已隐藏。",
        intent_summary="识别受保护对抗请求",
        redaction_notice=REDACTED_INPUT_NOTICE,
    )
    assert full.redaction_notice is None
    assert redacted.redaction_notice == "[对抗攻击内容已隐藏]"


@pytest.mark.parametrize(
    "payload",
    [
        {
            "disclosure": "full",
            "content": "Reviewed safe input",
            "intent_summary": "解释安全输入",
            "redaction_notice": "[对抗攻击内容已隐藏]",
        },
        {
            "disclosure": "redacted",
            "content": "受保护对抗样本，具体内容已隐藏。",
            "intent_summary": "识别受保护对抗请求",
            "redaction_notice": None,
        },
        {
            "disclosure": "redacted",
            "content": "受保护对抗样本，具体内容已隐藏。",
            "intent_summary": "识别受保护对抗请求",
            "redaction_notice": "其他遮罩",
        },
    ],
)
def test_lab_public_input_rejects_inconsistent_disclosure(payload: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        LabPublicInput.model_validate(payload)
```

Also construct a `LabScenario` with `public_input=full`, call `assert_public_payload(scenario)`, and retain the existing exact `FORBIDDEN_PUBLIC_KEYS` assertion unchanged.

- [ ] **Step 2: Run the model tests and verify RED**

Run:

```powershell
python -m pytest tests/unit/test_lab_models.py -q
```

Expected: collection fails because `LabPublicInput` and `REDACTED_INPUT_NOTICE` do not exist.

- [ ] **Step 3: Implement the validated Pydantic contract**

In `backend/app/lab/models.py`, add:

```python
REDACTED_INPUT_NOTICE = "[对抗攻击内容已隐藏]"


class LabPublicInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    disclosure: Literal["full", "redacted"]
    content: NonEmptyText
    intent_summary: NonEmptyText
    redaction_notice: NonEmptyText | None = None

    @model_validator(mode="after")
    def validate_disclosure(self) -> LabPublicInput:
        if self.disclosure == "full" and self.redaction_notice is None:
            return self
        if (
            self.disclosure == "redacted"
            and self.redaction_notice == REDACTED_INPUT_NOTICE
        ):
            return self
        raise ValueError("public input disclosure does not match redaction notice")
```

Add `public_input: LabPublicInput` to `LabScenario` only. Do not modify `LabRunResult`.

- [ ] **Step 4: Run the model tests and verify GREEN**

Run:

```powershell
python -m pytest tests/unit/test_lab_models.py -q
```

Expected: all tests in the file pass.

- [ ] **Step 5: Add failing catalog and isolation tests**

Replace the old “without text” catalog assertion in `tests/unit/test_lab_service.py` with exact checks for:

```python
safe, shift, direct, gcg, autodan, adv = service.list_scenarios()
assert safe.public_input.model_dump() == {
    "disclosure": "full",
    "content": "Explain why input validation is useful in a web application.",
    "intent_summary": "解释 Web 应用输入校验的价值",
    "redaction_notice": None,
}
assert shift.public_input.disclosure == "full"
assert shift.public_input.content == (
    "Summarize input validation:\n\n### CHECKLIST ###\n"
    "1. Types\n2. Lengths\n3. Encoding"
)
assert shift.public_input.intent_summary == "总结输入校验并处理明显格式变化"
assert {
    item.attack_family: item.public_input.content
    for item in (direct, gcg, autodan, adv)
} == {
    "direct_unsafe": "直接请求危险或违规内容，具体目标已隐藏。",
    "gcg": "正常请求结构后附加了优化生成的对抗字符串。",
    "autodan": "自然语言角色与指令包装试图改变模型安全边界。",
    "advprompter": "自动化提示生成器构造了对抗性请求。",
}
assert all(
    item.public_input.redaction_notice == "[对抗攻击内容已隐藏]"
    for item in (direct, gcg, autodan, adv)
)
```

Make `ProtectedDemoService.list_samples()` include the private sentinel attribute `source_text="PRIVATE_PROTECTED_SENTINEL"`; serialize the returned scenario tuple and assert the sentinel and every `FORBIDDEN_PUBLIC_KEYS` key are absent. Import `_protected_public_input` in this test module, call `_protected_public_input("unknown_family")`, and assert its content is `受保护对抗样本，具体内容已隐藏。`, its intent summary is `识别受保护的对抗请求`, and its redaction notice is fixed. This direct helper test avoids manufacturing a catalog family that `_PROTECTED_FAMILY_ORDER` intentionally does not request.

In the synthetic run test, assert:

```python
assert set(run.model_fields) == set(LabRunResult.model_fields)
assert "public_input" not in run.model_dump(mode="json")
assert "Explain why input validation" not in run.model_dump_json()
```

- [ ] **Step 6: Run the service tests and verify RED**

Run:

```powershell
python -m pytest tests/unit/test_lab_service.py -q
```

Expected: catalog construction fails because required `public_input` values are not provided.

- [ ] **Step 7: Implement static scenario mappings**

In `backend/app/lab/service.py`:

1. Import `LabPublicInput` and `REDACTED_INPUT_NOTICE`.
2. Expand each `_SYNTHETIC_SCENARIOS` tuple to `(label, source, intent_summary)` using the exact two Chinese summaries in the global design.
3. Define a static dictionary with the four exact protected descriptions and a separate static intent-summary dictionary, using family names only as keys. The intent summaries are exactly `直接危险或违规请求识别` for `direct_unsafe`, `优化生成的对抗后缀识别` for `gcg`, `自然语言包装的越狱指令识别` for `autodan`, and `自动生成的对抗提示识别` for `advprompter`.
4. Add `_protected_public_input(family: str) -> LabPublicInput` that returns a redacted object from those dictionaries and falls back to content `受保护对抗样本，具体内容已隐藏。` with intent summary `识别受保护的对抗请求`.
5. Construct a full `LabPublicInput` for synthetic catalog rows and a redacted object for protected catalog rows.
6. Update `create_run()` tuple unpacking to `scenario_label, source, _intent_summary`; the intent is intentionally unused during execution.
7. Call the existing public-payload validation path for the finished catalog tuple before returning it.

The protected helper must receive only `selected.family`; it must never inspect any other sample attribute.

- [ ] **Step 8: Run focused backend tests and verify GREEN**

Run:

```powershell
python -m pytest tests/unit/test_lab_models.py tests/unit/test_lab_service.py -q
```

Expected: both files pass, including exact privacy and run-isolation assertions.

- [ ] **Step 9: Commit the backend contract**

```powershell
git add backend/app/lab/models.py backend/app/lab/service.py tests/unit/test_lab_models.py tests/unit/test_lab_service.py
git commit -m "feat: publish redacted challenge input metadata"
```

---

### Task 2: Frontend Whitelist Mapping

**Files:**
- Modify: `frontend/src/types.ts`
- Modify: `frontend/src/challenge/definitions.ts`
- Test: `frontend/src/challenge/definitions.test.ts`

**Interfaces:**
- Consumes: `LabScenario.public_input` from Task 1.
- Produces: `ChallengePublicInput` and `ResolvedChallengeRound.publicInput`.
- Guarantees: only `disclosure`, `content`, `intentSummary`, and `redactionNotice` cross the challenge definition boundary.

- [ ] **Step 1: Add failing resolution and privacy tests**

Update catalog fixtures with `public_input`, then assert exact mapping:

```ts
expect(resolution.rounds[0].publicInput).toEqual({
  available: true,
  disclosure: "full",
  content: "Explain why input validation is useful in a web application.",
  intentSummary: "解释 Web 应用输入校验的价值",
  redactionNotice: null,
});
```

Add table-driven malformed cases for a missing object, blank content, blank summary, invalid disclosure, a `full` object with a notice, and a `redacted` object without the exact fixed notice. Each must resolve the round normally but produce `{ available: false }`.

Give a protected fixture an extra private sentinel property and assert:

```ts
const serialized = JSON.stringify(resolution.rounds);
expect(serialized).not.toContain("PRIVATE_PROTECTED_SENTINEL");
for (const key of [
  "prompt", "suffix", "token_text", "token_id", "query_text",
  "raw_output", "guard_raw_output", "hidden_reasoning",
]) {
  expect(serialized).not.toContain(`\"${key}\"`);
}
```

- [ ] **Step 2: Run definition tests and verify RED**

Run:

```powershell
Set-Location frontend
npm.cmd test -- src/challenge/definitions.test.ts
```

Expected: assertions fail because `publicInput` is absent.

- [ ] **Step 3: Add API and resolved types**

In `frontend/src/types.ts`, add:

```ts
export interface LabScenarioPublicInput {
  disclosure: "full" | "redacted";
  content: string;
  intent_summary: string;
  redaction_notice: string | null;
}
```

Add `public_input?: LabScenarioPublicInput` to `LabScenario`; it remains optional at the network boundary so stale or malformed backends degrade instead of crashing the challenge.

In `frontend/src/challenge/definitions.ts`, add:

```ts
export type ChallengePublicInput =
  | {
      available: true;
      disclosure: "full" | "redacted";
      content: string;
      intentSummary: string;
      redactionNotice: string | null;
    }
  | { available: false };
```

Add `publicInput: ChallengePublicInput` to `ResolvedChallengeRound`.

- [ ] **Step 4: Implement strict field-level parsing**

Add a `resolvePublicInput(scenario: LabScenario): ChallengePublicInput` helper. It must:

1. Read only `scenario.public_input.disclosure`, `.content`, `.intent_summary`, and `.redaction_notice`.
2. Trim only for non-empty validation; preserve the original `content` so the multiline synthetic input remains exact.
3. Accept `full` only when the notice is `null`.
4. Accept `redacted` only when the notice equals `[对抗攻击内容已隐藏]`.
5. Construct a new object field by field, never with object spread.
6. Return `{ available: false }` for every invalid shape.

Call it from both `syntheticRound()` and `familyRound()`.

- [ ] **Step 5: Run definition tests and verify GREEN**

Run:

```powershell
npm.cmd test -- src/challenge/definitions.test.ts
```

Expected: mapping, malformed fallback, and privacy tests all pass.

- [ ] **Step 6: Commit the frontend mapping**

```powershell
Set-Location ..
git add frontend/src/types.ts frontend/src/challenge/definitions.ts frontend/src/challenge/definitions.test.ts
git commit -m "feat: resolve challenge input disclosures"
```

---

### Task 3: Public Input Card and Challenge Integration

**Files:**
- Create: `frontend/src/components/ChallengeInputCard.tsx`
- Create: `frontend/src/components/ChallengeInputCard.test.tsx`
- Modify: `frontend/src/pages/ChallengePage.tsx`
- Modify: `frontend/src/ChallengePage.test.tsx`
- Modify: `frontend/src/styles.css`
- Modify: `docs/token-detective-challenge.md`

**Interfaces:**
- Consumes: `ChallengePublicInput` from Task 2 and `session.rounds[session.roundIndex]` from the existing reducer state.
- Produces: an accessible `region` named `本关待检输入` with full, redacted, or unavailable presentation.
- Preserves: existing Lab Run request body `{ scenario_kind, sample_id, mode }` and request count.

- [ ] **Step 1: Add failing component tests**

Create `frontend/src/components/ChallengeInputCard.test.tsx` with three cases:

```tsx
render(<ChallengeInputCard publicInput={{
  available: true,
  disclosure: "full",
  content: "Line one\nLine two",
  intentSummary: "测试多行安全输入",
  redactionNotice: null,
}} />);
expect(screen.getByRole("region", { name: "本关待检输入" })).toHaveTextContent("公开安全样本");
expect(screen.getByText(/Line one/)).toHaveTextContent("Line one Line two");
expect(screen.queryByText("[对抗攻击内容已隐藏]")).not.toBeInTheDocument();
```

The redacted case must show `受保护样本`, the static content, and the exact notice. The unavailable case must show only `公开材料暂不可用` and no disclosure badge.

- [ ] **Step 2: Run component tests and verify RED**

Run:

```powershell
Set-Location frontend
npm.cmd test -- src/components/ChallengeInputCard.test.tsx
```

Expected: collection fails because the component does not exist.

- [ ] **Step 3: Implement the stateless component**

Create a component with this public signature:

```tsx
interface ChallengeInputCardProps {
  publicInput: ChallengePublicInput;
}

export function ChallengeInputCard({ publicInput }: ChallengeInputCardProps) {
  // Render one accessible region; no hooks, effects, fetch calls, storage, or callbacks.
}
```

Required markup behavior:

- `<section className="challenge-input-card" aria-label="本关待检输入">` is the only outer region.
- Header text is `本关待检输入`.
- Full badge text is `公开安全样本`; content uses a `<pre>` with wrapping enabled by CSS.
- Redacted badge text is `受保护样本`; content uses normal paragraph text and the notice uses a separate element.
- Unavailable state contains `公开材料暂不可用` and no partial field values.
- Visible field labels are `任务意图` and `输入材料`.

- [ ] **Step 4: Run component tests and verify GREEN**

Run:

```powershell
npm.cmd test -- src/components/ChallengeInputCard.test.tsx
```

Expected: all three disclosure-state tests pass.

- [ ] **Step 5: Add failing page-flow tests**

Update the `scenarios` fixture in `frontend/src/ChallengePage.test.tsx` with reviewed public-input values. Add tests that verify:

1. The first card is visible immediately after `beginChallengeWhenReady()` while the Lab Run request is still pending.
2. Completing the first round and clicking `下一关` changes the card to the shift intent and multiline safe content.
3. A protected round shows only its static description and fixed notice; a private fixture sentinel and forbidden field names are absent from `document.body.textContent`.
4. `重试本关` retains the same card and creates exactly one additional `/api/v1/lab/runs` request.
5. Exiting and starting again returns to the first card without stale protected content.
6. A scenario with missing `public_input` shows `公开材料暂不可用`, while the run can still reach `本关线索` and be scored.
7. Adding the card does not change the existing POST body assertion or create any request besides health, scenario catalog, and the expected one Lab Run per attempt.

- [ ] **Step 6: Run page tests and verify RED**

Run:

```powershell
npm.cmd test -- src/ChallengePage.test.tsx
```

Expected: the new `本关待检输入` region assertions fail.

- [ ] **Step 7: Integrate the current-round card**

In `frontend/src/pages/ChallengePage.tsx`:

1. Import `ChallengeInputCard`.
2. Read the current round once with `const currentRound = session.rounds[session.roundIndex];` near other derived state.
3. Keep existing optional guards for setup/complete transitions.
4. Render `<ChallengeInputCard publicInput={currentRound.publicInput} />` immediately after `.challenge-progress` and before `<MascotTeam>` whenever `currentRound` exists.
5. Do not add an effect, request, event handler, or state field for the card.

- [ ] **Step 8: Add stable responsive styling**

In `frontend/src/styles.css`, create scoped rules for:

```css
.challenge-input-card { width: 100%; min-width: 0; }
.challenge-input-card__body { display: grid; grid-template-columns: minmax(7rem, auto) minmax(0, 1fr); }
.challenge-input-card pre,
.challenge-input-card p { min-width: 0; overflow-wrap: anywhere; white-space: pre-wrap; }
```

Use existing challenge tokens, borders, typography, and radii. Keep it a full-width information band, not a card nested inside another card. At `max-width: 760px`, change the body to one column and ensure every grid child has `min-width: 0`. Do not animate the card or change global layout selectors.

- [ ] **Step 9: Update challenge documentation**

In `docs/token-detective-challenge.md`:

- Add the input card as the first visible item after a round starts.
- State that reviewed synthetic samples are shown in full.
- State that protected rounds show a static family-level description plus `[对抗攻击内容已隐藏]`.
- Replace the outdated claim that protected scenarios “只展示样本 ID 和数值” with the exact new boundary.
- Retain the statement that no real attack input, suffix, token text/ID, raw model output, or hidden reasoning reaches the browser.
- Clarify that the card is teaching context and does not prove attack coverage or affect scoring.

- [ ] **Step 10: Run focused frontend tests and verify GREEN**

Run:

```powershell
npm.cmd test -- src/components/ChallengeInputCard.test.tsx src/challenge/definitions.test.ts src/ChallengePage.test.tsx
```

Expected: all focused component, mapping, flow, retry, and privacy tests pass.

- [ ] **Step 11: Commit the UI integration**

```powershell
Set-Location ..
git add frontend/src/components/ChallengeInputCard.tsx frontend/src/components/ChallengeInputCard.test.tsx frontend/src/pages/ChallengePage.tsx frontend/src/ChallengePage.test.tsx frontend/src/styles.css docs/token-detective-challenge.md
git commit -m "feat: show public challenge input cards"
```

---

### Task 4: Full Regression and Live Acceptance

**Files:**
- Verify only; change product files only when a failing check identifies a defect in Tasks 1-3.
- Record final verification facts in: `docs/token-detective-challenge.md`

**Interfaces:**
- Consumes: completed backend contract, frontend mapping, and UI component.
- Produces: reproducible evidence that privacy, behavior, responsiveness, and unaffected routes remain stable.

- [ ] **Step 1: Run the complete automated suites**

From the repository root, run:

```powershell
python -m pytest -q
Set-Location frontend
npm.cmd test -- --no-file-parallelism
npm.cmd run build
Set-Location ..
```

Expected: backend suite passes with only the already-declared GPU skip when no explicit GPU test model is configured; all frontend tests and the production build pass.

- [ ] **Step 2: Run repository privacy and patch checks**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/verify_lab_privacy.ps1
git diff --check
```

Expected: privacy verifier exits `0`; `git diff --check` reports no whitespace errors.

- [ ] **Step 3: Deploy only changed backend files to the active AutoDL service**

Use the repository's existing approved SSH/SCP deployment procedure and existing secret-key file. Copy only `backend/app/lab/models.py` and `backend/app/lab/service.py`, restart the existing API process, and verify `/health` plus `/api/v1/lab/scenarios` return successfully. Never print or document remote credentials, private paths, or protected sample text.

Expected catalog checks:

- `synthetic_safe.public_input.disclosure` is `full`.
- `autodan.public_input.disclosure` is `redacted`.
- Protected serialized rows contain the fixed notice and no forbidden keys.

- [ ] **Step 4: Start or refresh the local production frontend**

Run the existing local preview command on an unused loopback port. Confirm the browser loads the built frontend and proxies API calls to the active AutoDL tunnel. Do not replace an unrelated process on an occupied port.

- [ ] **Step 5: Perform desktop challenge acceptance at 1440x900**

Verify in both `互动调查` and `自动演示`:

- The first-round task card appears before the run response completes.
- Full safe content wraps and preserves the checklist line breaks.
- Advancing rounds changes the card exactly once and to the correct scenario.
- Protected rounds show only static public description and the fixed notice.
- Retry retains the same card; exit and re-entry resets to round one.
- Network inspection shows no additional analyze or Lab Run request caused by the card.
- The page has no horizontal overflow, overlap, console error, or failed resource.

- [ ] **Step 6: Perform mobile acceptance at 390x844**

Verify the task card stacks vertically, long text wraps within the viewport, the fixed notice remains readable, detective controls remain clickable, and `document.documentElement.scrollWidth === document.documentElement.clientWidth`.

- [ ] **Step 7: Recheck unaffected routes**

Open `/analyze`, `/lab`, and `/super-agent`. Confirm each loads, retains its existing layout and behavior, emits no new console errors, and has no new API requests attributable to the challenge card.

- [ ] **Step 8: Append objective verification facts**

Add a dated subsection to `docs/token-detective-challenge.md` containing only observed command totals, build status, desktop/mobile viewport results, request-count result, privacy-verifier result, and any declared skip. Do not claim accuracy, coverage, recall, or F1 from this feature.

- [ ] **Step 9: Commit verification documentation**

```powershell
git add docs/token-detective-challenge.md
git commit -m "docs: record challenge input card verification"
```

- [ ] **Step 10: Stop before remote integration**

Show `git status --short --branch` and the new commit list. Do not push, merge, or delete the worktree until the user explicitly confirms the integration action.
