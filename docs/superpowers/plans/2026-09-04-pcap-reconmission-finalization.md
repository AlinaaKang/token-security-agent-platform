# PCAP Reconnaissance Finalization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Close failed or timed-out PCAP reconnaissance missions deterministically and give the UI a visible retry path.

**Architecture:** Keep the existing serial Docker executor and public aggregate schema. Harden the coordinator's terminal transition, then add a small frontend state presentation layer that treats degraded missions as terminal and starts retries through the existing authorization API.

**Tech Stack:** FastAPI, Pydantic, Python `pytest`, React 19, TypeScript, Vitest.

## Global Constraints

- Never read real PCAP content in tests or diagnostics.
- Keep the fixed reconnaissance sample limit at 20.
- Do not expose paths, filenames, payloads, Token text, or raw exceptions.
- Do not modify Prompt, CPD, Token, triage, challenge, or mascot behavior.

### Task 1: Backend terminal finalization

**Files:**
- Modify: `backend/app/superagent/pcap_coordinator.py`
- Test: `tests/integration/test_superagent_api.py`

**Interfaces:**
- Consumes the existing `PcapReconExecutor.execute()` failure contract.
- Produces a terminal `degraded` `PcapReconMissionResult` with deterministic public narratives.

- [ ] Write a failing test proving an executor timeout produces `degraded`, not `running`, and releases the active slot.
- [ ] Run the focused test and verify it fails for the current implementation.
- [ ] Implement the smallest coordinator transition covering timeout and `PcapReconToolFailed`.
- [ ] Run the focused test and verify it passes.
- [ ] Run the existing reconnaissance integration tests.
- [ ] Commit: `fix: finalize failed pcap reconnaissance missions`.

### Task 2: Frontend degraded state and retry

**Files:**
- Modify: `frontend/src/pages/PcapReconWorkspace.tsx`
- Test: `frontend/src/PcapReconWorkspace.test.tsx`

**Interfaces:**
- Consumes the existing `PcapReconMissionResult` status and authorization API.
- Produces visible phase text, bounded elapsed warning, and fresh retry action.

- [ ] Write a failing test for a degraded mission showing an error state and retry button.
- [ ] Run the focused Vitest test and verify it fails.
- [ ] Add explicit degraded rendering and a retry handler that requests a new authorization.
- [ ] Add an elapsed-time warning without changing polling semantics.
- [ ] Run the focused Vitest test and verify it passes.
- [ ] Run the full frontend tests and production build.
- [ ] Commit: `fix: expose pcap reconnaissance retry state`.

### Task 3: Verification and documentation

**Files:**
- Modify: `docs/pcap-superagent.md`
- Modify: `README.md`

**Interfaces:**
- Documents the deterministic degraded state and retry behavior for operators.

- [ ] Add operator guidance for degraded missions and fresh authorization.
- [ ] Run full backend pytest with `PYTHONPATH=backend;.`.
- [ ] Run frontend tests and build.
- [ ] Run only synthetic Docker/privacy verifiers.
- [ ] Commit: `docs: explain pcap reconnaissance finalization`.
