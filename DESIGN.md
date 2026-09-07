# Token Security Interface System

## Direction

The product is an operational security case desk, not a marketing dashboard. Its visual signature is a continuous blue audit rail connecting a conversational objective to plans, evidence, hypotheses, tool observations, and reports.

## Tokens

- Canvas: `#f4f8fc`
- Translucent navigation: `rgba(229, 241, 250, .94)`
- Primary blue: `#347fbe`
- Strong blue: `#246da9`
- Ink: `#20354a`
- Muted text: `#5d7184`
- Risk: `#c54b55`
- Success: `#2e7d62`
- Failure or review: `#a96f20`

Red means detected risk, green means successful execution, and amber means failure or review. The structured reasoning chain remains blue so stage decoration is never confused with status.

## Layout

Desktop uses a 240px navigation column, a flexible conversation workspace, and a 360px inspector. Below 1100px the inspector becomes a drawer. Below 760px the interface becomes a single column with 44px minimum command controls.

## Components

- Navigation groups use larger semantic headings than route items.
- Messages are unframed transcript rows; user and agent identity are distinguished by icon treatment.
- Plans and authorization dialogs are bounded operational surfaces, not decorative cards.
- Evidence always includes source authenticity and a textual outcome.
- Hypotheses always show support, counter-evidence, confidence changes, and limitations when present.
- Tool failures use recoverable language that names the failed step and next action.

## Motion And Accessibility

Only active progress indicators and drawer transitions move. `prefers-reduced-motion` disables nonessential animation. Focus indicators use a high-contrast blue outline. Long Chinese text, IDs, filters, and source references wrap without horizontal overflow.
