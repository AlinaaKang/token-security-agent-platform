# Navigation Information Architecture Design

## Objective

Make the relationship between the platform's six existing pages understandable from the sidebar without merging pages or changing their responsibilities.

The navigation will communicate three distinct product paths:

1. Detection and response for operational work.
2. Validation and evaluation for controlled experiments and frozen metrics.
3. Interactive demonstration for the game experience.

## Confirmed Structure

### Detection and response

1. `安全分析` (`/analyze`): run a direct Prompt safety analysis.
2. `自主处置` (`/super-agent`): coordinate Prompt or PCAP evidence triage and internal response.
3. `安全事件` (`/events`): inspect recorded detection and response events.

This ordering expresses the operational flow: analyze, coordinate a response, then inspect the audit record.

### Validation and evaluation

1. `攻防实验舱` (`/lab`): investigate Prompt evidence, counterfactual sensitivity, and simulated tool actions.
2. `评测中心` (`/evaluation`): inspect frozen benchmark aggregates and readiness boundaries.

The lab remains an engineering investigation surface. It must not contain the detective game or claim frozen benchmark performance.

### Interactive demonstration

1. `Token 侦探挑战` (`/challenge`): play the independent, game-oriented challenge experience.

The challenge may reuse the same protected detection services, but it does not become an operational detection or evaluation page.

## Sidebar Presentation

- Keep the existing route paths, labels, icons, active-route behavior, and page content.
- Add a quiet text heading above each navigation group.
- Separate groups with spacing rather than decorative cards or heavy borders.
- Preserve the established sidebar width and dark visual language.
- Keep every navigation item directly clickable; group headings are not links and do not collapse.
- Do not place the PCAP upload entry directly in the global navigation. PCAP remains a task mode inside `自主处置`.

## Responsive Behavior

- Desktop sidebar shows all three group headings and six links.
- The mobile navigation preserves the same group order and accessible labels.
- Group headings must not truncate page labels or reduce the link target below the existing touch size.
- The active page remains identifiable by more than color alone through the existing active indicator.

## Accessibility

- Render each group as a labelled navigation section or equivalent semantic list grouping.
- Group headings are descriptive text, not disabled buttons.
- Preserve keyboard order exactly as the visual order.
- Preserve visible focus styles and `aria-current="page"` on the active route.

## Scope Boundaries

This change does not:

- merge or rename routes;
- change analysis, event, evaluation, lab, SuperAgent, challenge, Prompt, or PCAP behavior;
- add the first-use guided tour;
- add browser PCAP upload;
- move the detective challenge into the lab;
- change backend APIs or stored data.

The guided tour and PCAP upload are separate features with separate designs and implementation plans.

## Verification

- Component tests assert the three group headings and the six links in the confirmed order.
- Routing tests assert every link still opens its existing route and reports the correct active state.
- Keyboard tests assert logical tab order and visible focus.
- Responsive browser checks cover desktop and mobile sidebar states.
- Existing page tests must remain unchanged except for navigation grouping assertions.

