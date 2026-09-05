# First-Use Guided Tours Design

## Objective

Help first-time users complete the core workflow on the four interactive pages without changing the underlying Prompt, PCAP, lab, SuperAgent, or challenge behavior.

The tour uses a hybrid progression model: local interface actions may advance automatically, while steps that depend on AutoDL, Docker, PCAP parsing, or another backend always remain skippable.

## Scope

Tours are available on:

- `安全分析` (`/analyze`)
- `攻防实验舱` (`/lab`)
- `自主处置` (`/super-agent`)
- `Token 侦探挑战` (`/challenge`)

`安全事件` and `评测中心` remain read-only destinations and do not auto-open tours.

## Shared Interaction

- Auto-open once on the first visit to each supported route.
- Store completion independently per route and tour version in browser local storage.
- Show a compact fixed help icon on supported routes so the tour can be replayed.
- Highlight one existing target at a time with a non-destructive spotlight and anchored floating panel.
- Provide `上一步`, `下一步`, `跳过引导`, and `完成` controls as appropriate.
- Display the current position as `步骤 n / total`.
- Local tab, selector, or mode-switch clicks may advance the relevant step automatically.
- Prompt submission, PCAP parsing, model inference, Docker execution, and network-dependent steps never block progression.
- `Escape` closes the tour and records it as seen so it does not reopen on the next page load.
- Replaying from the help icon never clears user inputs, results, mission state, or challenge progress.

## Route Steps

### Safety analysis

1. Explain the Prompt input surface.
2. Explain knowledge enhancement modes.
3. Explain analysis versus gateway mode.
4. Point to the detection command and clarify that inference may require the remote model service.

### Security lab

1. Explain frozen versus custom scenarios.
2. Explain the custom Prompt input.
3. Explain analysis versus gateway experiment mode.
4. Point to `开始调查` and clarify that lab runs do not enter the formal event store.

### SuperAgent

1. Explain the Prompt and PCAP task switch.
2. Explain scenario or PCAP scope selection.
3. Explain bounded autonomous execution.
4. Point to the start or authorization control and clarify that external-service steps remain skippable.

The tour must describe PCAP as a mode inside SuperAgent, not as part of the lab or detective challenge.

### Token detective challenge

1. Explain challenge setup.
2. Explain difficulty and round controls.
3. Explain the evidence-first interaction order.
4. Point to the challenge start command.

The tour explains the game controls only. It must not reveal answers, labels, protected Prompt text, Token text, or hidden reasoning.

## Component Boundary

Create one reusable `GuidedTour` component that owns:

- active step state;
- target measurement and viewport clamping;
- spotlight and floating-panel rendering;
- keyboard handling;
- completion persistence;
- missing-target fallback.

Route pages provide declarative step definitions and stable `data-tour` target attributes. They do not implement their own overlay logic.

The application shell owns the per-route configuration and replay launcher so page-specific business components remain focused.

## Positioning And Responsive Behavior

- Prefer placement below the target, then above it when lower space is insufficient.
- Clamp the panel inside the viewport with a 12 px edge margin.
- Recalculate on scroll, resize, route change, and step change.
- On narrow screens, use a bottom sheet no wider than the viewport while retaining the target spotlight.
- The spotlight is visual only and does not resize or reflow the highlighted element.
- The help launcher must not cover primary fixed controls or mobile navigation.

## Accessibility

- Use `role="dialog"`, an accessible title, and `aria-modal="false"` because the highlighted control remains usable.
- Move keyboard focus into the tour panel on open and restore it to the launcher or prior element on close.
- Support `Escape`, `Tab`, `Shift+Tab`, Enter, and Space.
- Respect `prefers-reduced-motion`; motion is optional and never required to understand progression.
- Do not rely on color alone for the spotlight or progress indicator.

## Persistence And Failure Handling

- Storage keys use `token-sentinel-tour:<route>:v1`.
- Treat storage read/write failures as non-fatal; the current tour remains usable.
- If a target is absent, advance to the next available step. If no targets exist, close without recording a runtime error.
- Route changes close the current tour before the next route decides whether to auto-open.
- Tour rendering must not depend on backend health.

## Privacy And Safety

- Tour copy is static and contains no user Prompt, PCAP payload, IP address, path, model raw output, protected sample value, or hidden chain of thought.
- Target metadata contains only public UI identifiers.
- Tour actions never submit a form on the user's behalf.
- A click-triggered advance observes a user action but does not synthesize that action.

## Verification

- Unit tests cover first-visit auto-open, per-route persistence, replay, next/back/skip, Escape, click advancement, and missing targets.
- App tests cover all four supported routes and confirm no auto-tour on events or evaluation.
- Existing page tests confirm the tour does not change submissions, mission state, challenge answers, or event persistence.
- Production build must pass.
- Browser screenshots at desktop and 390 px verify target visibility, panel clamping, no overlap with mobile navigation, and reduced-motion stability.

