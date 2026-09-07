# Agent Prompt And Resources Design

## Goal

Make the unified security-agent workspace handle conversational greetings and real Prompt investigations, expose useful resource content, and keep the page guide clear of the composer.

## Interaction Design

- `hi`, `hello`, `hey`, and common Chinese greetings receive the existing short security-agent welcome without creating a tool plan.
- A command such as `检测这个 Prompt：...` creates a Prompt investigation, shows the bounded plan, and asks for `prompt:analyze` authorization.
- The welcome examples include a Prompt investigation so the capability is discoverable alongside PCAP and cross-domain work.
- The guide launcher stays in the main workspace's upper-right safe area on desktop and above the bottom composer on narrow screens. It must never cover the send button.

## Prompt Privacy And Execution

The coordinator extracts the content after the Prompt investigation command and stores it only in a process-local transient input store keyed by task ID. The SQLite snapshot, conversation, events, evidence, report, and API responses never contain the raw Prompt. `analyze_prompt` calls the existing `BasicSecurityWorkflow`; `counterfactual_recheck` reuses its preceding analysis result. Both handlers return an explicitly public summary that the existing security-agent adapter converts into evidence. Transient values are removed after terminal completion, cancellation, or coordinator shutdown.

If the Prompt connector is unavailable, the capability state remains unavailable and the task degrades with a recoverable tool observation instead of claiming a result.

## Resource Center

- Selecting an agent resource changes the center column into a dedicated resource workspace. The conversation, plan, PCAP result, authorization surfaces, and composer are not rendered while a resource is selected.
- The resource workspace provides a clear title, the full catalog content, and a `返回安全智能体` link. The resource query remains in the URL so refresh and direct links restore the same view.
- The right column shows only a short resource-scope explanation. It must not duplicate the resource catalog.
- The selected resource link is visibly and accessibly marked in the left navigation.
- Security knowledge displays the approved built-in source catalog and its role in grounded explanations.
- Data connectors use the dedicated connector endpoint and show loading, populated, empty, and unavailable states.
- Investigation reports list report metadata from recent tasks, let the user select an item, and fetch the generated Markdown through the existing report endpoint.
- Empty states state why no data exists and what action creates it.

## Constraints

- Do not change the frozen Prompt/Token detector, calibration, thresholds, or Token Detective challenge.
- Do not persist raw Prompt text or return it from any API.
- Red, green, and amber retain their existing risk, success, and review meanings.
- Existing PCAP task execution and explicit authorization remain unchanged.
- Opening a resource must not cancel or mutate the current Agent task or PCAP mission.

## Verification

Add unit and integration coverage for English greetings, Prompt extraction and non-persistence, real workflow execution, transient cleanup, resource API responses, report listing, and guide/composer layout contracts. Verify desktop and mobile screenshots, full backend tests, full frontend tests, production build, and privacy checks.
