# Grounded Contextual Dialogue Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace keyword-only follow-up handling with evidence-grounded, context-aware Prompt and PCAP conversation backed by the already loaded Qwen2.5 runtime.

**Architecture:** A new dialogue service receives only the current question and a bounded public case snapshot, calls the existing structured generation runtime, and returns a grounded answer. The deterministic intent router keeps control, authorization, and tool-start commands, while every remaining message inside an existing case becomes a contextual case question. Generation failures fall back to deterministic evidence summaries.

**Tech Stack:** FastAPI, Pydantic, Qwen2.5 structured generation, pytest.

## Global Constraints

- Prompt and PCAP detector outputs remain the only sources of case facts.
- The dialogue model never receives raw PCAP payloads, paths, addresses, credentials, hidden reasoning, or private tool output.
- Model text cannot create tool IDs, alter authorization, or overwrite task conclusions.
- Existing tasks and API payloads remain backward compatible.
- Preserve unrelated dirty-worktree changes.

---

### Task 1: Context-Aware Follow-Up Intent

**Files:**
- Modify: `backend/app/security_agent/models.py`
- Modify: `backend/app/security_agent/intent.py`
- Test: `tests/unit/test_security_agent_intent.py`

**Interfaces:**
- Produces: `AgentIntent.kind == "case_question"` for non-control follow-ups when an `AgentTaskSnapshot` exists.

- [ ] Add a failing test proving `可能是什么攻击类型？` in a PCAP task is a case question.
- [ ] Run the focused test and confirm it fails as `out_of_scope`.
- [ ] Preserve explicit cancellation, authorization, investigation, and unsafe-request routing; route otherwise-unmatched current-case messages to `case_question`.
- [ ] Run the intent tests.

### Task 2: Evidence-Grounded Qwen Dialogue Service

**Files:**
- Create: `backend/app/security_agent/dialogue.py`
- Test: `tests/unit/test_security_agent_dialogue.py`

**Interfaces:**
- Produces: `GroundedDialogueService.answer(question: str, task: AgentTaskSnapshot) -> AgentMessage`.
- Consumes: a runtime implementing `generate_structured(messages, max_new_tokens, max_time_seconds)`.

- [ ] Add failing tests for bounded context, evidence references, no-evidence answers, model output, and runtime failure fallback.
- [ ] Run the focused tests and confirm the module is missing.
- [ ] Build a public context containing task type, status, objective, observations, evidence summaries, uncertainty, limitations, and recent agent replies only.
- [ ] Generate a concise Chinese answer with Qwen2.5; attach evidence references deterministically rather than trusting model-supplied IDs.
- [ ] Fall back to a deterministic answer that distinguishes evidence present, evidence absent, and tool failure.
- [ ] Run the dialogue tests.

### Task 3: Coordinator and Runtime Wiring

**Files:**
- Modify: `backend/app/security_agent/coordinator.py`
- Modify: `backend/app/main.py`
- Test: `tests/unit/test_security_agent_coordinator.py`
- Test: `tests/integration/test_security_agent_api.py`

**Interfaces:**
- `SecurityAgentCoordinator(..., dialogue: GroundedDialogueService | None = None)`.
- Existing `POST /api/v1/agent/tasks/{task_id}/messages` returns the contextual answer in the same conversation.

- [ ] Add failing coordinator and API tests for PCAP attack-type phrasing and Prompt paraphrases.
- [ ] Route `case_question` through the dialogue service and deterministic fallback.
- [ ] Initialize the dialogue service from `analysis_workflow.runtime` without loading a second model.
- [ ] Add capability state `grounded_dialogue` as available or unavailable.
- [ ] Run focused backend tests.

### Task 4: Verification and Deployment

**Files:**
- Modify only defects discovered by verification.

- [ ] Run all security-agent unit and integration tests.
- [ ] Run the full backend suite.
- [ ] Run PCAP privacy verification.
- [ ] Synchronize the bounded backend changes to AutoDL and restart the API.
- [ ] Verify a real PCAP task answers `可能是什么攻击类型？` without returning `out_of_scope`.
- [ ] Verify model-unavailable fallback and `git diff --check`.
