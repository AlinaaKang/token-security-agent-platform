# Prompt Whitespace Normalization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent leading or trailing Windows line endings and whitespace from changing Prompt security decisions.

**Architecture:** Canonicalize `AnalysisRequest.prompt` once at the Pydantic API boundary, before the semantic Guard, model runtime, Entropy-CPD, knowledge service, or audit store receives it. Normalize line endings, strip surrounding whitespace, preserve internal content, and retain the existing raw transport-length limit.

**Tech Stack:** Python 3.11, Pydantic 2, FastAPI, pytest, AutoDL Qwen2.5-7B and Qwen3Guard.

## Global Constraints

- Convert `CRLF` and lone `CR` line endings to `LF`.
- Remove leading and trailing Unicode whitespace.
- Preserve internal text and internal whitespace after newline normalization.
- Semantic Guard, model scoring, Entropy-CPD, knowledge enhancement, and audit hashing/counting consume one canonical Prompt.
- Reject normalized blank input.
- Keep the 32,768-character raw transport bound fail-closed.
- Do not change models, thresholds, fusion rules, routes, challenges, mascots, PCAP workflows, or AutoDL topology.
- Do not expose Prompt text, Token text, private model output, or credentials in tests, logs, reports, or commits.

---

### Task 1: Canonicalize Prompt Input At The Request Boundary

**Files:**
- Modify: `backend/app/schemas.py:34-43`
- Test: `tests/unit/test_schemas.py`
- Test: `tests/integration/test_basic_workflow.py`

**Interfaces:**
- Consumes: `AnalysisRequest(prompt: str, model_id: str, mode: str, knowledge_mode: str)`.
- Produces: `AnalysisRequest.prompt: str` containing the canonical Prompt used by every downstream component.

- [ ] **Step 1: Write failing request-model tests**

Add these tests to `tests/unit/test_schemas.py`:

```python
def test_analysis_request_canonicalizes_surrounding_whitespace_and_line_endings() -> None:
    request = AnalysisRequest(
        prompt="\r\n\r\nfirst\r\n\rsecond\nlast\r\n",
        model_id="qwen2.5-7b",
    )

    assert request.prompt == "first\n\nsecond\nlast"


def test_analysis_request_checks_raw_length_before_canonicalization() -> None:
    with pytest.raises(ValidationError):
        AnalysisRequest(
            prompt=(" " * 32_768) + "x",
            model_id="qwen2.5-7b",
        )
```

- [ ] **Step 2: Record downstream Prompt arguments and write a failing workflow test**

Extend the existing test doubles in `tests/integration/test_basic_workflow.py`:

```python
class StaticRuntime:
    def __init__(self, entropies: list[float]) -> None:
        self.entropies = entropies
        self.calls = 0
        self.seen_user_prompt: str | None = None

    def score_prompt(self, system_prompt: str, user_prompt: str) -> ModelObservation:
        self.calls += 1
        self.seen_user_prompt = user_prompt
        tokens = tuple(
            ObservedUserToken(
                user_index=index,
                full_index=index + 1,
                token_id=index + 10,
                token_text=f"token-{index}",
                char_start=index * 5,
                char_end=(index + 1) * 5,
                entropy=entropy,
                nll=1.0,
            )
            for index, entropy in enumerate(self.entropies)
        )
        return ModelObservation(
            model_id="qwen-model",
            tokenizer_id="qwen-tokenizer",
            system_prompt_hash="sha256:system",
            system_entropies=(0.5, 1.0, 1.5),
            user_tokens=tokens,
            latency_ms=10.0,
        )


class StaticSemanticGuard:
    def __init__(self, assessment: SemanticAssessment) -> None:
        self.assessment = assessment
        self.calls = 0
        self.seen_prompt: str | None = None

    def assess(self, prompt: str) -> SemanticAssessment:
        self.calls += 1
        self.seen_prompt = prompt
        return self.assessment
```

Add the regression test:

```python
def test_workflow_sends_one_canonical_prompt_to_both_detectors() -> None:
    workflow = make_workflow([0.1, 0.2])
    request = AnalysisRequest(
        prompt="\r\n\r\nsecurity review\r\n",
        model_id="qwen-model",
    )

    workflow.analyze(request, request_id="req-normalized")

    assert workflow._test_semantic_guard.seen_prompt == "security review"
    assert workflow._test_runtime.seen_user_prompt == "security review"
```

- [ ] **Step 3: Run the focused tests and verify RED**

Run:

```powershell
$env:PYTHONPATH = 'backend;.'
.\.venv\Scripts\python.exe -m pytest -q `
  tests/unit/test_schemas.py `
  tests/integration/test_basic_workflow.py `
  -k 'canonicalizes or raw_length or one_canonical_prompt'
```

Expected: the canonicalization and downstream Prompt assertions fail because `AnalysisRequest.prompt` still contains `CRLF` padding. The raw-length assertion may already pass and continues guarding validation order.

- [ ] **Step 4: Implement minimal request-boundary normalization**

Replace the existing Prompt validator body in `backend/app/schemas.py` with:

```python
    @field_validator("prompt")
    @classmethod
    def canonicalize_prompt(cls, value: str) -> str:
        normalized = value.replace("\r\n", "\n").replace("\r", "\n").strip()
        if not normalized:
            raise ValueError("prompt must contain non-whitespace text")
        return normalized
```

Do not use a `mode="before"` validator: Pydantic must enforce the existing field `max_length` against the raw transported string before trimming.

- [ ] **Step 5: Run focused tests and verify GREEN**

Run:

```powershell
$env:PYTHONPATH = 'backend;.'
.\.venv\Scripts\python.exe -m pytest -q tests/unit/test_schemas.py tests/integration/test_basic_workflow.py
```

Expected: all tests pass, including blank and oversized Prompt rejection.

- [ ] **Step 6: Commit Task 1**

```powershell
git add backend/app/schemas.py tests/unit/test_schemas.py tests/integration/test_basic_workflow.py
git commit -m "fix: normalize prompt whitespace before detection"
```

### Task 2: Full Regression And AutoDL Acceptance

**Files:**
- Local source changes: none expected.
- Remote update: `/root/autodl-tmp/token-security-agent-platform/backend/app/schemas.py` only.

**Interfaces:**
- Consumes: the committed canonical `AnalysisRequest.prompt` behavior from Task 1 and the existing SSH tunnel at `127.0.0.1:18001`.
- Produces: a live `/analyze` route whose semantic and fusion decisions are invariant to surrounding `LF`, `CRLF`, or lone `CR` padding.

- [ ] **Step 1: Run complete local regression suites**

Run:

```powershell
$env:PYTHONPATH = 'backend;.'
.\.venv\Scripts\python.exe -m pytest -q
Set-Location frontend
npm.cmd test -- --run
npm.cmd run build
```

Expected: backend and frontend suites pass; the production build exits zero.

- [ ] **Step 2: Verify privacy and repository state**

Run:

```powershell
Set-Location ..
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/verify_lab_privacy.ps1 -BaseUrl http://127.0.0.1:18001
git diff --check
git status --short
```

Expected: privacy verification passes with zero violations, no whitespace errors exist, and only intentional tracked changes are present.

- [ ] **Step 3: Compare and deploy only the changed backend file**

Compute the local SHA-256 of `backend/app/schemas.py`, query the remote SHA-256 without printing file contents, then copy only that tracked file using the established SSH key:

```powershell
Get-FileHash backend/app/schemas.py -Algorithm SHA256
ssh -i .secrets/autodl_token_security_v2 -p 28129 root@connect.westb.seetacloud.com `
  "sha256sum /root/autodl-tmp/token-security-agent-platform/backend/app/schemas.py"
scp -i .secrets/autodl_token_security_v2 -P 28129 backend/app/schemas.py `
  root@connect.westb.seetacloud.com:/root/autodl-tmp/token-security-agent-platform/backend/app/schemas.py
```

Do not copy `.secrets`, PCAP files, event databases, models, calibration artifacts, protected datasets, or caches.

- [ ] **Step 4: Restart the existing remote API without changing its environment**

First confirm exactly one process matches the established command:

```powershell
ssh -i .secrets/autodl_token_security_v2 -p 28129 root@connect.westb.seetacloud.com `
  "ps -eo pid,ppid,comm,args | grep '[u]vicorn app.main:app'"
```

Require one listener using `.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000`. Then reuse the existing root-owned launcher, which contains the preserved runtime environment and accepts the port as its first argument:

```powershell
ssh -i .secrets/autodl_token_security_v2 -p 28129 root@connect.westb.seetacloud.com `
  'pid=$(pgrep -f "^/root/autodl-tmp/token-security-agent-platform/.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --log-level warning$"); test -n "$pid"; test $(echo "$pid" | wc -w) -eq 1; kill "$pid"; while kill -0 "$pid" 2>/dev/null; do sleep 1; done; cd /root/autodl-tmp/token-security-agent-platform; nohup bash tmp/task4-reconstructed-launch.sh 8000 > tmp/prompt-normalization-api.log 2>&1 < /dev/null &'
```

Do not print `/proc/<pid>/environ`, credentials, or protected paths. Poll `http://127.0.0.1:8000/health` until it returns `status=ok` with model, detector, semantic Guard, knowledge, evaluation, demo, Lab, and SuperAgent all ready.

- [ ] **Step 5: Run live CRLF invariance acceptance through the Web proxy**

Submit two synthetic requests through `http://127.0.0.1:5173/api/v1/analyze`: `傻逼` and the same text surrounded by Windows `CRLF` blank lines. Output only case names and the public fields `semantic_severity`, `semantic_categories`, `detector_status`, `decision`, and `fusion_reason`.

Expected: both cases have identical semantic severity, categories, decision, and fusion reason. Neither case may produce `safe + allow` solely because of surrounding `CRLF` padding.

- [ ] **Step 6: Verify unaffected live capabilities**

Require:

- `http://127.0.0.1:18001/health` returns `status=ok`.
- `/api/v1/superagent/capabilities` through port 5173 is ready.
- `/pcap-api/v1/superagent/pcap/detection/overview` remains enabled with 2318 eligible files.
- `/analyze`, `/challenge`, and `/super-agent` return HTTP 200.

- [ ] **Step 7: Review and integration**

Request code review for the Task 1 commit. Address any Critical or Important findings, rerun affected tests, merge the isolated feature branch locally into `feature/basic-platform-foundation`, rerun the focused backend tests on the merged result, and push only after explicit user confirmation.
