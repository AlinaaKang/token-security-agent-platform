# Contextual Page Guidance Design

## Goal

Make every primary product surface understandable to a first-time reviewer without changing detection, scoring, authorization, privacy, or execution behavior. The interface must explain both how to operate a workflow and how to interpret its returned result. Token Detective Challenge additionally teaches how to select an estimated anomaly onset without revealing the system answer before submission.

## Scope

The change covers `/analyze`, `/events`, `/evaluation`, `/lab`, `/super-agent`, and `/challenge`.

- Action-oriented pages use the existing first-use guided-tour language and launcher.
- Result-oriented regions add compact, contextual interpretation help beside the result they explain.
- Challenge gains state-aware coaching after a round begins.
- The existing mascots, Prompt and PCAP workflows, routes, API contracts, thresholds, scoring rules, authorization gates, and backend topology remain unchanged.
- No offline fake inference, recorded-response substitution, model packaging, server deployment, or PCAP detector change is included.

## Interaction Model

### Shared guidance

Every covered page exposes a persistent `本页引导` launcher. First-use guidance may open automatically according to the existing local-only seen-state behavior. Closing or completing guidance records only that the explanation was seen; it never stores input, results, answers, sample identifiers, or authorization data.

Tour progression may follow local UI selection, but it must never submit a Prompt, create a Lab run, start a SuperAgent mission, authorize a PCAP operation, upload a file, execute Docker, or submit a challenge answer.

### Contextual result help

Result help is short and placed next to the relevant output rather than collected in a long manual. It uses a consistent `如何理解` disclosure that is keyboard accessible and collapsed by default after first use. Opening help does not alter the surrounding component state.

The copy must explain the current result vocabulary, not make new security claims. Dynamic wording may use already-public result fields, but must not expose Prompt text, protected attack content, Token text or IDs, payloads, network identities, file identities, paths, hashes, raw model output, private errors, or hidden reasoning.

## Page Content

### Analyze

The existing tour continues to cover input, knowledge mode, work mode, and the explicit start command. Result help explains:

- semantic severity describes content risk;
- `token_anomaly_candidate` is a distribution-change candidate, not a confirmed jailbreak;
- the CPD onset is an estimated local start position;
- the final action is produced by the fixed fusion policy;
- knowledge evidence can explain but cannot rewrite the base action.

### Events

The page receives a non-automatic reading guide. It explains request identity, time, semantic state, detector state, score, action, and calibration version. It states that the table is a redacted audit log and does not contain the original Prompt.

### Evaluation

The reading guide explains Precision, Recall, F1, FPR, AUROC, latency, frozen test data, and operating points. It explicitly states:

- higher Precision, Recall, F1, and AUROC are generally better;
- lower FPR and latency are generally better;
- a development-selected constraint is not automatically satisfied on frozen test data;
- Entropy-CPD localization value is separate from prompt-level classification quality;
- unavailable knowledge or agent-ablation attachments must be shown as unavailable, not inferred from base metrics.

### Lab

The existing input, boundary, and command guidance remains. Prompt result help explains stage status, counterfactual sensitivity, evidence agreement or conflict, tool dry-run versus confirmed execution, and report status. PCAP result help explains upload progress, Docker isolation, localized evidence, and terminal outcomes.

### SuperAgent

The existing task, scope, bounds, and authorization guidance remains. Prompt help explains the bounded plan, actor trace, tool receipts, one-replan limit, and final action. PCAP help distinguishes:

- batch triage: evidence availability classification;
- reconnaissance: aggregate corpus characterization, not attack detection;
- anomaly detection: rule or behavior candidates with Request/Packet localization;
- red evidence: detection succeeded and localized an anomaly candidate;
- green zero-evidence: current rules did not find a candidate, not proof of complete safety;
- yellow failure: no verifiable tool result, neither safe nor malicious.

### Token Detective Challenge

Setup guidance continues to cover challenge length, interactive versus automatic presentation, and the explicit start command. A separate round coach follows the live phase:

1. Identify the reviewed input card.
2. In interactive mode, visit Guard, CPD, and Agent in the enforced order; automatic mode explains replay and skip.
3. Read semantic and distribution clues only after investigation completes.
4. Select an estimated onset on the signal chart when localization applies.
5. Select evidence relation and response action.
6. Submit, then compare the player answer with the system result and per-item score.

The onset explanation states: choose the earliest position where the CPD cumulative signal begins a sustained change, not simply the highest point. Each selectable position remains a real button. Selection displays `已选择 Token #<index>` and a visible vertical marker. Arrow keys move between observations; Enter or Space confirms the focused position.

The coach must never expose `suspicious_span.token_start`, the expected evidence relation, or the system action before submission. After submission, the existing reveal may continue to show the player onset and CPD onset.

## Visual Behavior

Guidance preserves the existing restrained green, ink, white, red-evidence, and yellow-failure visual language. Help is subordinate to the operational surface: no nested cards, oversized headings, decorative gradients, or mascot replacement.

Desktop guidance anchors beside or around the target while keeping the active control visible. At narrow widths it becomes a bottom sheet with bounded height and internal scrolling. It must not cover the currently required command, selected signal flag, or challenge submit button. Text uses zero letter spacing and stable responsive dimensions.

Reduced-motion mode removes guidance transitions and spotlight animation without hiding information. Focus returns to the launcher when guidance closes.

## State And Failure Handling

- If a target is not mounted for the current phase, the coach advances to the next valid phase target or waits without firing an action.
- Route changes close the current panel and load only the destination page guidance.
- Backend unavailable states remain visible and receive explanatory copy; guidance never fabricates a successful state.
- Challenge retry keeps the coach aligned with the retried round and does not preserve or infer a previous answer.
- Empty, insufficient-signal, not-applicable, unavailable, cancelled, degraded, and failed states each retain their existing product behavior.

## Accessibility

- Launchers, disclosures, close controls, previous/next controls, signal flags, and submit controls remain native buttons.
- Guidance panels use dialog or region semantics with a labelled heading.
- Spotlight decoration is hidden from assistive technology.
- Status narration is concise and does not continuously re-announce static help.
- Keyboard focus order follows visual order; Escape closes non-blocking help.
- Color is never the only status indicator: every red, green, or yellow meaning includes text and an icon or label.

## Privacy And Safety

Guidance consumes only fixed reviewed copy and public result enums. It does not add network calls, analytics, telemetry, storage of result content, or new backend endpoints. It cannot trigger model inference, Docker execution, uploads, mission creation, tool execution, or challenge submission.

Protected Prompt content, attack suffixes, Token text, vocabulary IDs, raw model output, hidden reasoning, PCAP payloads, addresses, ports, filenames, paths, hashes, and private errors remain outside the public UI.

## Verification

Automated tests must prove:

- every covered route exposes reopenable guidance;
- read-only page help does not auto-run operations;
- action-page tours never submit, authorize, upload, or execute;
- each result vocabulary is explained with the correct limitations;
- challenge coaching follows setup, investigation, clue, onset, answer, and reveal phases;
- challenge onset guidance teaches sustained-change onset and does not expose the correct index before submission;
- selecting a flag shows the real sparse Token index and does not move layout;
- existing scoring, retry, auto replay, mascot order, and protected-content privacy tests still pass;
- desktop and mobile layouts have no global horizontal overflow or incoherent overlap;
- reduced-motion and keyboard navigation remain functional.

Run the focused frontend tests, the complete frontend suite, the production build, the backend privacy regression relevant to public outputs, and bounded browser checks at desktop and mobile widths. Existing Prompt, PCAP, Lab, SuperAgent, and Challenge outcomes must remain unchanged.

## Delivery Note

Competition submission may use a recorded full-mode demonstration backed by AutoDL. The recording should show health readiness, the explicit user action, the returned result, and the interpretation help. Documentation must state that live Prompt inference requires a compatible GPU service. This design does not create an offline mode that pretends recorded output is live inference.
