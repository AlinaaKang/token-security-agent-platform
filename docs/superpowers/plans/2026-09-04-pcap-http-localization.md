# PCAP HTTP Localized Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detect at least one real Web attack family in the authorized PCAP corpus and localize evidence to a Request or Packet interval without exposing payload or identity fields.

**Architecture:** The real reconnaissance profile is dominated by short plaintext HTTP captures: 19/20 successful samples contain HTTP, 15/20 contain at most 15 packets, and only one sample is long-sequence eligible. The MVP therefore routes short captures to a deterministic Docker-contained HTTP rule detector, returns only closed-enum localized evidence, and reserves behavior/CPD analysis for the small long-sequence subset.

**Tech Stack:** Python 3.11, FastAPI, Pydantic, Windows PowerShell 5.1, Docker Desktop, Tshark, React 19, TypeScript, Vitest, pytest.

## Global Constraints

- Prompt, CPD, Token, triage, challenge, mascot, and existing API behavior remain unchanged.
- Real PCAP is read only after a fresh UI authorization and only inside the existing Docker boundary.
- Tests use generated synthetic captures only.
- Public output never contains filename, path, IP, port, MAC, payload, URI, headers, body, stable hash, stderr, or model chain-of-thought.
- `ip` may appear only as an aggregate protocol label, never as an address field.
- Short HTTP attacks use Request/Packet localization; CPD must not be fabricated.

---

### Task 1: Closed localized evidence contract

**Files:**
- Create: `backend/app/pcap/detection_models.py`
- Test: `tests/unit/test_pcap_detection_models.py`

**Interfaces:**
- Produces `PcapLocalizedEvidence`, `PcapDetectionSummary`, and closed enums for granularity, attack candidate, detector, and supporting signal.
- Evidence has random `evidence_id`, validated packet interval, relative offsets, bounded confidence, and no private fields.

- [ ] Write failing model tests for valid Request/Packet evidence, interval bounds, closed enums, and recursive private-field rejection.
- [ ] Run the focused tests and verify RED.
- [ ] Implement the minimal frozen Pydantic models and validators.
- [ ] Run focused tests and verify GREEN.
- [ ] Commit `feat: define localized pcap evidence contract`.

### Task 2: Docker-contained HTTP rule detector

**Files:**
- Create: `pcap-inspector/detect_http.py`
- Modify: `pcap-inspector/Dockerfile`
- Modify: `scripts/inspect_pcap.ps1`
- Create: `scripts/new_attack_pcap_fixtures.py`
- Test: `tests/unit/test_pcap_http_detector.py`
- Test: `tests/unit/test_inspect_pcap_script.py`

**Interfaces:**
- Consumes one read-only mounted capture at `/input/capture`.
- Produces aggregate JSON with fixed categories such as `sql_injection`, `command_injection`, `path_traversal`, or `none`, plus Packet/Request intervals and fixed supporting signals.
- Does not emit matched text, URI, addresses, ports, or raw parser errors.

- [ ] Generate synthetic benign HTTP and attack captures with known packet positions.
- [ ] Write failing tests for benign allow, SQL injection candidate, command injection candidate, and payload non-disclosure.
- [ ] Run focused tests and verify RED.
- [ ] Implement bounded Tshark extraction and deterministic normalized rule matching inside the container.
- [ ] Validate output against a closed schema in `inspect_pcap.ps1`.
- [ ] Run focused tests and the synthetic Docker sandbox verifier.
- [ ] Commit `feat: detect localized http attacks in pcap sandbox`.

### Task 3: Authorized detection mission and SuperAgent fusion

**Files:**
- Create: `backend/app/pcap/detection_executor.py`
- Create: `backend/app/superagent/pcap_detection_coordinator.py`
- Modify: `backend/app/api/superagent.py`
- Modify: `backend/app/main.py`
- Modify: `backend/app/superagent/service.py`
- Test: `tests/unit/test_pcap_detection_executor.py`
- Test: `tests/integration/test_superagent_api.py`

**Interfaces:**
- Adds a distinct `detect_pcap_anomalies` objective with a fresh purpose-bound authorization.
- Produces confirmed, candidate, unknown, and recommended-action narratives grounded only in returned evidence IDs.
- Partial file failures are counted and do not suppress valid evidence from other files.

- [ ] Write failing authorization, lifecycle, partial failure, cancellation, and privacy tests.
- [ ] Run focused tests and verify RED.
- [ ] Implement the fixed-parameter executor and one-worker coordinator.
- [ ] Add deterministic evidence fusion and fail-closed public errors.
- [ ] Run focused integration tests and verify GREEN.
- [ ] Commit `feat: orchestrate localized pcap detection`.

### Task 4: PCAP detective UI

**Files:**
- Create: `frontend/src/pages/PcapDetectionWorkspace.tsx`
- Create: `frontend/src/components/PcapDetectionTimeline.tsx`
- Modify: `frontend/src/pages/PcapSuperAgentWorkspace.tsx`
- Modify: `frontend/src/api.ts`
- Modify: `frontend/src/types.ts`
- Modify: `frontend/src/styles.css`
- Test: `frontend/src/PcapDetectionWorkspace.test.tsx`

**Interfaces:**
- Adds a third PCAP mode `异常检测` without changing `批量分诊` or `数据勘察`.
- Shows rule detective, sequence detective, team leader, and Packet timeline using only public localized evidence.
- Shows `无需调用 CPD` for short rule-localized requests.

- [ ] Write failing tests for authorization gating, benign evidence, localized attack evidence, partial failure, and mobile overflow.
- [ ] Run focused tests and verify RED.
- [ ] Implement the workspace, fixed labels, timeline, and mascot state mapping.
- [ ] Run focused tests and verify GREEN.
- [ ] Run all frontend tests and production build.
- [ ] Commit `feat: visualize localized pcap detection`.

### Task 5: Synthetic evaluation and non-regression

**Files:**
- Create: `backend/app/evaluation/pcap_detection.py`
- Create: `tests/unit/test_pcap_detection_evaluation.py`
- Modify: `scripts/verify_pcap_agent_privacy.py`
- Modify: `docs/pcap-superagent.md`
- Modify: `README.md`

**Interfaces:**
- Produces aggregate precision, recall, F1, false-positive rate, localization hit rate, and rule-only versus behavior-only versus fused ablation metrics.
- Extends privacy verification to every new response surface.

- [ ] Write failing synthetic evaluation and recursive privacy tests.
- [ ] Run focused tests and verify RED.
- [ ] Implement deterministic aggregate evaluation and privacy checks.
- [ ] Document that real-corpus labels remain weak until separately audited.
- [ ] Run full backend and frontend suites, build, Docker verifier, and privacy verifier.
- [ ] Commit `test: verify localized pcap detection`.

### Task 6: Real-data acceptance gate

**Files:**
- Modify only the private quarantine state/output created by the authorized tool.

**Interfaces:**
- Requires a fresh UI click for `异常检测`.
- Returns only aggregate counts and public localized evidence.

- [ ] Stop before reading real captures and ask the user to click the two-stage authorization.
- [ ] Verify at least one real Web attack candidate is localized to Request or Packet, or report that the current sample contains no sufficient evidence.
- [ ] Verify normal/evidence-insufficient samples are not forced into an alert.
- [ ] Record aggregate acceptance metrics without filename-derived claims.
