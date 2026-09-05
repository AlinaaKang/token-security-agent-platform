# PCAP Detection Contract Synchronization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve strict PCAP report validation while accepting every current public evidence shape and reporting partial scans honestly.

**Architecture:** Keep Docker as the only PCAP content reader. Synchronize the Windows launcher allowlist and stable serializer with the existing Python evidence contract, then derive the frontend terminal conclusion from evidence and failure counts.

**Tech Stack:** Windows PowerShell 5.1, Python/pytest, React/TypeScript, Vitest.

## Global Constraints

- Unknown report fields and enum values remain rejected.
- Raw request text, payloads, file names, paths, IP addresses, ports, stderr, and private reasoning remain unavailable.
- Prompt analysis, Entropy-CPD, Challenge scoring, mascots, routing, and PCAP selection do not change.

---

### Task 1: Synchronize the strict Windows report gate

**Files:**
- Modify: `scripts/inspect_pcap.ps1:285`
- Test: `tests/unit/test_inspect_pcap_script.py`

**Interfaces:**
- Consumes: schema version 1 JSON from `pcap-inspector/detect_http.py`.
- Produces: validated schema version 1 JSON for `PcapDetectionExecutor`.

- [ ] **Step 1: Write failing launcher tests**

Add representative request evidence containing `web_injection`,
`purpose_candidates`, and `xss_pattern`, plus packet evidence containing
`attack_candidate=none` and `detector=behavior_anomaly`. Assert the launcher
returns zero and persists exactly the public fields.

- [ ] **Step 2: Verify the tests fail**

Run:

```powershell
$env:PYTHONPATH='backend;.'
.\.venv\Scripts\python.exe -m pytest -q tests/unit/test_inspect_pcap_script.py -k 'current_request_evidence or behavior_evidence'
```

Expected: both new cases fail with `pcap_preflight_error=invalid_report_schema`.

- [ ] **Step 3: Implement the minimal strict allowlist update**

Allow only the current evidence keys, candidates, detectors, purposes, and
supporting signals. Validate request and packet granularity as paired contracts.
Serialize `purpose_candidates` only where the contract supplies it.

- [ ] **Step 4: Verify launcher behavior and privacy rejection**

Run:

```powershell
$env:PYTHONPATH='backend;.'
.\.venv\Scripts\python.exe -m pytest -q tests/unit/test_inspect_pcap_script.py tests/unit/test_pcap_detection_executor.py tests/unit/test_pcap_http_detector.py
```

Expected: all pass, including private-field rejection.

### Task 2: Distinguish incomplete scans in the UI

**Files:**
- Modify: `frontend/src/pages/PcapDetectionWorkspace.tsx:85`
- Test: `frontend/src/pages/PcapDetectionWorkspace.test.tsx`

**Interfaces:**
- Consumes: `PcapDetectionSummary.evidence` and `PcapDetectionSummary.failed_count`.
- Produces: one of `发现异常候选`, `未发现可定位异常`, or `检测不完整，存在未完成样本`.

- [ ] **Step 1: Write a failing partial-result test**

Return a completed mission with zero evidence, one successful sample, and one
failed sample. Assert the incomplete conclusion is visible and the all-clear
conclusion is absent.

- [ ] **Step 2: Verify the frontend test fails**

Run:

```powershell
Set-Location frontend
npm.cmd test -- --run src/pages/PcapDetectionWorkspace.test.tsx
```

Expected: the new incomplete conclusion is missing.

- [ ] **Step 3: Implement a small terminal-conclusion helper**

Prioritize evidence, then failures, then the no-evidence conclusion. Reuse it in
the completed status banner without changing layout or animation.

- [ ] **Step 4: Verify frontend behavior**

Run:

```powershell
npm.cmd test -- --run src/pages/PcapDetectionWorkspace.test.tsx
npm.cmd run build
```

Expected: tests and production build pass.

### Task 3: Verify the real failure path and full regression surface

**Files:**
- No source changes expected.

**Interfaces:**
- Consumes: the two previously authorized failed sample positions.
- Produces: structured candidate evidence through the existing Docker gate.

- [ ] **Step 1: Run full automated verification**

Run backend pytest and frontend Vitest suites. Both must exit zero.

- [ ] **Step 2: Rebuild the Docker inspector image**

Build `token-security-pcap-preflight:local`, then run the repository sandbox
verification script. It must report `pcap_sandbox_verification=passed`.

- [ ] **Step 3: Re-run only the previously failed authorized positions**

Use the existing `inspect_pcap.ps1` sandbox launcher and report only structured
candidate categories, counts, packet ranges, and fixed purpose candidates. Do
not print capture paths, file names, request content, endpoints, or stderr.

- [ ] **Step 4: Restart the local PCAP service and verify proxies**

Verify `/health`, `/api/v1/superagent/capabilities`, and
`/pcap-api/v1/superagent/pcap/detection/overview` through port 5173.

- [ ] **Step 5: Commit the implementation**

```powershell
git add scripts/inspect_pcap.ps1 tests/unit/test_inspect_pcap_script.py frontend/src/pages/PcapDetectionWorkspace.tsx frontend/src/pages/PcapDetectionWorkspace.test.tsx
git commit -m "fix: preserve current pcap anomaly evidence"
```
