# Agent Prompt And Resources Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore real Prompt investigation and everyday greetings in the unified agent, populate its resource center, and move the guide launcher away from the composer.

**Architecture:** Add a process-local transient Prompt store owned by `SecurityAgentCoordinator`, wire existing analysis and counterfactual services into registered agent tools, and expose read-only resource indexes through `/api/v1/agent`. Keep the React resource center state-driven and position the guide relative to the main stage instead of the viewport bottom.

**Tech Stack:** FastAPI, Pydantic, SQLite task store, React, TypeScript, Vitest, pytest.

## Global Constraints

- Raw Prompt content must never be written to SQLite, task snapshots, events, reports, or API responses.
- Frozen detector logic, thresholds, and Token Detective behavior must remain unchanged.
- Prompt and PCAP reads require their existing explicit authorization scopes.
- Empty, loading, unavailable, and populated resource states must be distinguishable without relying on color alone.

---

### Task 1: Conversation And Prompt Intent

**Files:**
- Modify: `backend/app/security_agent/intent.py`
- Test: `tests/unit/test_security_agent_intent.py`

**Interfaces:**
- Produces: `parse_intent(message, context)` recognizes English greetings and preserves Prompt investigation intent when the submitted sample contains adversarial phrases.

- [ ] Add failing parameterized tests for `hi`, `hello`, and an explicit adversarial Prompt investigation command.
- [ ] Run the focused intent tests and confirm the new cases fail for the intended branches.
- [ ] Reorder explicit task-command recognition ahead of sample-content safety screening and add English greeting markers.
- [ ] Run the focused tests to green.

### Task 2: Private Prompt Tool Bridge

**Files:**
- Modify: `backend/app/security_agent/coordinator.py`
- Modify: `backend/app/main.py`
- Modify: `backend/app/security_agent/adapters.py`
- Test: `tests/unit/test_security_agent_coordinator.py`
- Test: `tests/integration/test_security_agent_api.py`

**Interfaces:**
- Produces: transient Prompt lookup by `transient:<task_id>` and real handlers for `analyze_prompt` and `counterfactual_recheck`.

- [ ] Add failing tests proving raw Prompt non-persistence, authorized real-tool success, public evidence creation, and cleanup after completion/cancellation.
- [ ] Run focused unit and integration tests and confirm failures identify missing transient handlers.
- [ ] Implement the in-memory transient store and real workflow/counterfactual adapters with terminal cleanup.
- [ ] Run focused tests to green and run the existing privacy verifier.

### Task 3: Resource Catalog And Reports

**Files:**
- Modify: `backend/app/api/agent.py`
- Modify: `frontend/src/api.ts`
- Modify: `frontend/src/agent/types.ts`
- Modify: `frontend/src/components/AgentInspectorShell.tsx`
- Modify: `frontend/src/components/AgentResourceCenter.tsx`
- Test: `tests/integration/test_security_agent_api.py`
- Test: `frontend/src/components/AgentResourceCenter.test.tsx`

**Interfaces:**
- Produces: connector catalog, knowledge catalog, and recent report metadata for the inspector.

- [ ] Add failing API and component tests for populated, loading, empty, and error states.
- [ ] Run focused tests and confirm the missing contracts fail.
- [ ] Add read-only endpoints and typed frontend loaders; render resource rows and report links/previews.
- [ ] Run focused backend and frontend tests to green.

### Task 4: Discoverability And Guide Placement

**Files:**
- Modify: `frontend/src/pages/AgentWorkspacePage.tsx`
- Modify: `frontend/src/styles.css`
- Test: `frontend/src/AgentWorkspacePage.test.tsx`
- Test: `frontend/src/styles.test.ts`

**Interfaces:**
- Produces: visible Prompt investigation example and a guide launcher that does not overlap the composer at desktop or mobile widths.

- [ ] Add failing component and CSS contract tests for the Prompt example and launcher safe-area placement.
- [ ] Run focused tests and confirm the new expectations fail.
- [ ] Add the Prompt example and adjust launcher positioning with responsive constraints.
- [ ] Run focused tests to green.

### Task 5: End-To-End Verification

**Files:**
- Verify only.

- [ ] Run all backend tests and privacy verification.
- [ ] Run all frontend tests and the production build.
- [ ] Capture desktop and mobile `/super-agent` screenshots and inspect resource, Prompt, conversation, and guide states.
- [ ] Run `git diff --check`, inspect the final source diff, and commit the implementation.
