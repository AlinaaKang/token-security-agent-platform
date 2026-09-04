# PCAP Reconnaissance Finalization Design

## Goal

Ensure a PCAP reconnaissance mission cannot remain indefinitely in a misleading
"forming aggregate profile" state when the worker times out, fails, or loses its
process, while preserving the fixed 20-sample and Docker-isolation contracts.

## Scope and Constraints

- Applies only to the PCAP reconnaissance mode.
- Prompt, CPD, Token, triage, challenge, and mascot behavior remain unchanged.
- A reconnaissance result is still aggregate-only and contains no capture identity,
  path, payload, or raw exception text.
- The backend remains bounded at 20 samples and serial Docker child execution.

## Design

The coordinator converts executor timeout and tool failure into a deterministic
terminal `degraded` mission with a public `method_selection_checkpoint_ready` trace
event and no partial private data in the response. The worker always releases its
admission slot in a `finally` path. The frontend renders explicit phases for queued,
running, degraded, and completed states, displays a bounded elapsed-time warning, and
offers a retry action only after a terminal failure. Retry starts a fresh authorization
and mission; it never reuses an old receipt.

## Verification

Add backend tests for timeout/failure finalization and slot release. Add frontend tests
for degraded status, elapsed-time warning, and retry authorization. Run the focused
suites, full backend pytest with the project PYTHONPATH, frontend tests, and production
build. No real PCAP is used in tests.
