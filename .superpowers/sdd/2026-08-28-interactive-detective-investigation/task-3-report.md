# Task 3 Report: Interactive Detective Mascots

## Scope

Implemented interactive mascot controls and first-visit presentation motion. The component accepts optional investigation interaction state, renders native named controls, locks unavailable roles, and preserves the prior automatic replay behavior when no interaction is supplied.

## Files Changed

- `frontend/src/components/MascotTeam.tsx`
- `frontend/src/components/MascotTeam.test.tsx`
- `frontend/src/styles.css`
- `frontend/src/ChallengePage.test.tsx` (authorized accessibility-test migration only: named mascot image queries became named button queries; page behavior was unchanged)

## RED Evidence

Before production changes, ran:

```powershell
npm.cmd test -- src/components/MascotTeam.test.tsx
```

Result: `1` test file failed, with `5 failed | 18 passed` tests. Each new test failed because the component had no role buttons or `interaction` state mapping. The first failure was unable to find a button named `Guard 语义侦探` with `可以汇报`, confirming the intended missing behavior rather than a test setup error.

## GREEN Evidence

After implementation, ran:

```powershell
npm.cmd test -- src/components/MascotTeam.test.tsx
```

Result: `1` test file passed, `23 passed` tests.

## Verification

```powershell
npm.cmd test -- src/components/ChallengeSignalPicker.test.tsx src/components/InvestigationDesk.test.tsx
```

Result: `2` test files passed, `14 passed` tests.

```powershell
npm.cmd test
```

Result: `10` test files passed, `112 passed` tests.

```powershell
npm.cmd run build
```

Result: `tsc -b && vite build` completed successfully. Vite transformed `1606` modules and emitted the production bundle.

`git diff --check` reported no whitespace errors.

## Self-Review

- Interactive roles derive `ready`, `locked`, `presenting`, and `visited` from Task 1 helpers without duplicating investigation flow logic.
- Locked roles are disabled native buttons; ready and visited roles remain selectable. Buttons expose role plus fixed state status through `aria-label` and selected roles expose `aria-pressed`.
- First visits use role-specific motion; reviews always map to `idle`, never `approach`.
- The no-interaction branch retains the existing `motionFor()` mapping, active classes, conflict state, completion animation, and three mounted figures.
- Images and status icons are decorative so controls, rather than nested images, own the accessible role name.
- Existing reduced-motion selectors already disable mascot and image-wrap animation/transform; the added presentation transform uses the mascot selector and remains covered.

## Concerns

Independent review found no Critical or Important issues and approved the change. It noted one minor test-description gap: the prescribed mouse-or-keyboard activation case invokes click only. The control is a native `button`, so browser keyboard activation is provided by platform semantics; no unsupported keyboard test utility was introduced.

## Fix Round 1 Evidence

Addressed the independent review's two test gaps without changing production code or adding keyboard handlers/dependencies:

- Renamed the click-only selection test to `emits the selected role from click activation`.
- Added a native-control characterization that finds `Guard 语义侦探，可以汇报`, verifies it is an enabled `HTMLButtonElement` with `type="button"` and `aria-pressed="false"`, then verifies it receives focus. These are the platform semantics that provide Enter/Space activation in a browser.
- Added a locked-boundary characterization that attempts clicks on both locked CPD and Agent controls and verifies `onSelect` is never called.

Ran before changing production code:

```powershell
npm.cmd test -- src/components/MascotTeam.test.tsx
```

Result: `1` test file passed, `25 passed` tests. Both new tests are characterization tests: the prior implementation already used an enabled native `button` for the ready role and disabled native buttons for locked roles. No truthful RED failure exists without either breaking a correct implementation or asserting JSDOM keyboard emulation that does not represent native browser activation; no such artificial failure was introduced.

Final fix-round verification:

```powershell
npm.cmd test
```

Result: `10` test files passed, `114 passed` tests.

```powershell
npm.cmd run build
```

Result: `tsc -b && vite build` completed successfully; Vite transformed `1606` modules.
