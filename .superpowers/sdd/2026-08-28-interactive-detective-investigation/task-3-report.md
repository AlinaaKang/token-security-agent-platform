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
