# Paper-Compatible CPD Calibration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace benign-user-prompt entropy calibration with a fixed-system-prompt baseline, select CPD thresholds from labeled data, and verify family-level detection on a frozen CPDonline test split.

**Architecture:** Extend the existing single-forward-pass model observation with system-segment entropies. Keep Page-CUSUM unchanged, add pure deterministic calibration-selection functions, and add a privacy-safe benchmark runner that writes only aggregate metrics and a deployable calibration profile.

**Tech Stack:** Python 3.11/3.12, PyTorch, Transformers, Pydantic, pytest, FastAPI, CPDonline CSV data.

## Global Constraints

- Do not place complete harmful prompts in Git, fixtures, logs, reports, screenshots, or command output.
- Use CPDonline as the attributed algorithm and dataset reference; preserve its MIT notice.
- Keep the frozen test split out of threshold and `k` selection.
- A CPD score below `h` must never produce a CPD-only block.
- Report unavailable attack families as not evaluated rather than passed.
- The first live benchmark covers CPDonline GCG, AdvPrompter, AutoDAN, and benign records; BEAST and AutoDAN-HGA require separately generated artifacts.

---

### Task 1: Observe Fixed System-Prompt Entropies

**Files:**
- Modify: `backend/app/model/token_stats.py`
- Modify: `backend/app/model/runtime.py`
- Modify: `tests/unit/test_token_stats.py`
- Modify: `tests/integration/test_model_runtime.py`
- Modify: `tests/unit/test_calibrator.py`

**Interfaces:**
- Produces: `project_span_statistics(..., char_span) -> list[TokenStatistic]`
- Produces: `ModelObservation.system_entropies: tuple[float, ...]`
- Consumes: the existing offset mapping and next-token `TokenStatistic` sequence from the same model forward pass.

- [ ] **Step 1: Write the failing span-projection test**

Add a test proving that system and user character spans select different token statistics:

```python
def test_span_projection_selects_only_tokens_inside_requested_segment() -> None:
    offsets = [(0, 6), (7, 12), (12, 18), (19, 26)]
    statistics = [
        TokenStatistic(full_index=1, entropy=1.0, nll=1.0),
        TokenStatistic(full_index=2, entropy=2.0, nll=2.0),
        TokenStatistic(full_index=3, entropy=3.0, nll=3.0),
    ]

    projected = project_span_statistics(
        offsets=offsets,
        statistics=statistics,
        char_span=(7, 18),
    )

    assert [item.full_index for item in projected] == [1, 2]
```

- [ ] **Step 2: Run the test and verify RED**

Run:

```powershell
$env:PYTHONPATH='.localdeps'
python -m pytest tests/unit/test_token_stats.py -q
```

Expected: collection failure because `project_span_statistics` does not exist.

- [ ] **Step 3: Implement generic span projection**

Add `project_span_statistics` to `token_stats.py`. Validate the span and offset/statistic identity, then include only statistics whose token offsets are fully contained in the requested literal text span. Reuse it from `project_user_tokens` so system and user alignment share one rule.

- [ ] **Step 4: Write the failing observation test**

Update the GPU integration assertion and synthetic `ModelObservation` fixtures to require non-empty `system_entropies`. The GPU test must also assert every entropy is finite and non-negative.

- [ ] **Step 5: Run the observation tests and verify RED**

Run:

```powershell
$env:PYTHONPATH='.localdeps'
python -m pytest tests/integration/test_model_runtime.py tests/unit/test_calibrator.py -q
```

Expected: failures because `ModelObservation` and `score_prompt` do not provide system entropies.

- [ ] **Step 6: Add system-segment observation**

In `score_prompt`, locate the literal system prompt in the formatted chat template, reject ambiguous or absent alignment, project its statistics with `project_span_statistics`, and populate:

```python
system_entropies: tuple[float, ...]
```

The user projection and API token output remain unchanged.

- [ ] **Step 7: Verify Task 1 GREEN**

Run the Task 1 tests and then the full backend suite. Expected: `42+` passed and only the configured GPU test skipped locally.

---

### Task 2: Select Labeled F1 Thresholds Deterministically

**Files:**
- Modify: `backend/app/detection/calibrator.py`
- Modify: `tests/unit/test_calibrator.py`

**Interfaces:**
- Produces: `select_f1_threshold(labels, scores) -> float`
- Produces: `select_threshold_at_max_fpr(labels, scores, max_fpr) -> float`
- Produces: `calibrate_entropy(observations, labels, version, dataset_hash, k) -> CalibrationProfile`
- Produces: `select_candidate_by_dev(candidates, observations, labels) -> CalibrationProfile`
- Consumes: `ModelObservation.system_entropies`, `run_cpd`, and `binary_metrics`.

- [ ] **Step 1: Write failing threshold-selection tests**

Cover three behaviors with harmless numeric fixtures:

```python
def test_select_f1_threshold_maximizes_f1() -> None:
    assert select_f1_threshold(
        labels=[False, False, True, True],
        scores=[0.1, 0.2, 0.8, 0.9],
    ) == pytest.approx(0.8)


def test_select_f1_threshold_breaks_ties_by_lower_fpr_then_higher_threshold() -> None:
    threshold = select_f1_threshold(
        labels=[True, False, False, True],
        scores=[0.1, 0.2, 0.3, 0.4],
    )
    assert threshold == pytest.approx(0.4)


def test_select_f1_threshold_requires_both_classes() -> None:
    with pytest.raises(ValueError, match='both classes'):
        select_f1_threshold(labels=[True, True], scores=[1.0, 2.0])


def test_select_threshold_at_max_fpr_uses_highest_recall_feasible_point() -> None:
    threshold = select_threshold_at_max_fpr(
        labels=[False, False, True, True],
        scores=[0.1, 0.6, 0.7, 0.9],
        max_fpr=0.0,
    )
    assert threshold == pytest.approx(0.7)
```

- [ ] **Step 2: Run threshold tests and verify RED**

Expected: import failure for `select_f1_threshold`.

- [ ] **Step 3: Implement deterministic threshold search**

Validate equal non-zero lengths, both classes, and finite scores. Evaluate each distinct positive score plus `math.nextafter(max_score, math.inf)`. Rank F1 candidates by `(F1, -FPR, threshold)` and return the highest-ranked threshold. For the low-FPR selector, retain only candidates at or below the requested FPR and rank by `(recall, F1, threshold)`.

- [ ] **Step 4: Write the failing paper-baseline calibration test**

Construct observations whose user entropies are intentionally far from their system entropies. Assert that the resulting profile baseline equals the system median/MAD, not the pooled user values, and that `h` is selected from labeled prompt scores.

- [ ] **Step 5: Run calibration test and verify RED**

Expected: the existing calibrator uses pooled user entropy and accepts no labels.

- [ ] **Step 6: Implement labeled calibration**

Change `calibrate_entropy` to:

```python
def calibrate_entropy(
    observations: Sequence[ModelObservation],
    labels: Sequence[bool],
    *,
    version: str,
    dataset_hash: str,
    k: float,
) -> CalibrationProfile:
```

Require identical runtime identity and identical fixed system entropy sequence across observations. Fit `RobustBaseline` from `first.system_entropies`, compute each user prompt's maximum CUSUM score, and select `h` using `select_f1_threshold`.

- [ ] **Step 7: Add and test development candidate selection**

Create two candidate profiles with different `k` and `h`, score only supplied development observations, and select by higher F1, lower FPR, then lower `k`. The function must have no test-set argument or filesystem access.

- [ ] **Step 8: Verify Task 2 GREEN**

Run calibrator, CPD, metrics, workflow, and full backend tests.

---

### Task 3: Build a Privacy-Safe Frozen Benchmark Runner

**Files:**
- Create: `backend/app/evaluation/reporting.py`
- Create: `scripts/benchmark_cpdonline.py`
- Create: `tests/unit/test_reporting.py`
- Modify: `scripts/calibrate_model.py`
- Modify: `data/README.md`

**Interfaces:**
- Produces: `PromptPrediction(sample_id, score, alarm_index, onset_index, latency_ms)`
- Produces: `build_benchmark_report(records, predictions, threshold, provenance) -> dict[str, Any]`
- Produces CLI files: `calibration.json`, `benchmark_report.json`, and split manifests containing no prompt text.
- Consumes: existing CPDonline adapters, `split_by_group`, runtime observations, calibration functions, CPD, and metrics.

- [ ] **Step 1: Write the failing privacy-safe report tests**

Use harmless `PromptRecord` fixtures for benign, GCG, and AutoDAN. Assert overall/per-family counts and recall, FPR, localization, and that serialized output contains neither `prompt` nor `suffix_text` values.

- [ ] **Step 2: Run reporting tests and verify RED**

Expected: `app.evaluation.reporting` does not exist.

- [ ] **Step 3: Implement aggregate reporting**

Add immutable prediction and provenance models. Validate exact sample-ID equality, calculate metrics from scores, calculate family recall from frozen labels, and include unavailable families explicitly under `not_evaluated`. Never copy `PromptRecord.prompt`, `suffix_text`, or token text into the report.

- [ ] **Step 4: Write the failing CLI contract test**

Test argument parsing and output-schema construction without loading a model. Required raw inputs are AutoDAN/benign, AdvPrompter, and GCG CSV paths; required outputs are an ignored output directory and calibration version. The CLI must reject missing files before model loading.

- [ ] **Step 5: Implement the benchmark CLI**

The script must:

1. read the three CPDonline CSV formats with existing adapters;
2. combine records and run the deterministic group split;
3. load Qwen once and score calibration/development records;
4. fit candidates for `k=0.0` and `k=0.5` on calibration only;
5. select the candidate on development only;
6. freeze the selected profile and score test only after selection;
7. write safe split manifests, `calibration.json`, and aggregate report;
8. print only output paths, counts, aggregate metrics, and provenance.

Do not print exceptions containing prompt bodies. Convert per-record failures to sample-ID-only diagnostics and abort the benchmark.

- [ ] **Step 6: Retire the unsafe calibration path**

Change `scripts/calibrate_model.py` into a compatibility entry point that exits with an explanatory error directing operators to the labeled benchmark CLI. It must no longer produce a deployable profile from the 20 hard-coded benign prompts.

- [ ] **Step 7: Document the reproducible command and data boundary**

Update `data/README.md` with the exact CLI arguments, expected safe outputs, CPDonline attribution, and the rule that test results are invalid if the test split was inspected before profile freeze.

- [ ] **Step 8: Verify Task 3 GREEN**

Run all backend tests and scan tracked files for any raw attack text or output keys that could serialize it.

---

### Task 4: Deploy, Recalibrate, and Repeatedly Verify on AutoDL

**Files:**
- Remote ignored raw data directory under `/root/autodl-tmp/token-security-data/`
- Remote safe outputs under `/root/autodl-tmp/token-security-results/cpd-paper-v1/`
- No new tracked prompt-data files.

**Interfaces:**
- Consumes: the completed benchmark CLI and the existing Qwen2.5-7B model.
- Produces: aggregate benchmark report, deployable calibration profile, and live API smoke results.

- [ ] **Step 1: Verify source checksums without printing prompts**

Download CPDonline raw CSVs to the remote ignored directory, record repository commit and SHA-256 checksums, and output only paths, sizes, hashes, columns, and row counts.

- [ ] **Step 2: Run the frozen benchmark once**

Execute the benchmark on AutoDL with Qwen2.5-7B. Monitor process liveness and output creation. Do not retry a crashed run without first reporting and diagnosing the failure.

- [ ] **Step 3: Validate the benchmark report**

Check:

- calibration/dev/test IDs are disjoint;
- baseline source is `system_prompt`;
- selected `k` belongs to `{0.0, 0.5}`;
- no prompt text appears in outputs;
- family counts sum to test attack count;
- AUROC, F1, FPR, recall, and localization fields are finite where defined.

- [ ] **Step 4: Apply acceptance gates**

Report PASS/FAIL separately for:

- overall F1 at least 0.80;
- FPR at most 0.10 at the low-FPR operating point;
- AutoDAN recall at least 0.80;
- GCG and AdvPrompter recall not below their pre-fix smoke baselines;
- suffix localization rate and onset error, without hiding pre-suffix alarms.

Failure of any gate is a research finding. Do not lower a threshold using test labels.

- [ ] **Step 5: Deploy the frozen profile and restart the API**

Point `TOKEN_SECURITY_CALIBRATION_PATH` at the new immutable profile, restart the remote FastAPI service, and verify `/health` reports the new calibration version.

- [ ] **Step 6: Repeat live family and benign checks**

Run separate in-memory smoke samples for GCG, AdvPrompter, AutoDAN, difficult benign JSON/code, multilingual benign text, and ordinary QA. Output only family/category aggregates, CPD alarm state, score distribution, and decision counts.

- [ ] **Step 7: Run final local and frontend verification**

Run the full backend suite, frontend tests, frontend build, API health check, and one harmless browser analysis. Confirm the UI displays the new calibration version and does not label a below-threshold anomaly as a confirmed jailbreak.

---

## Execution Notes

- Work in the existing `feature/basic-platform-foundation` checkout because it already contains the uncommitted platform foundation and the user requested continuation in this folder.
- Use inline execution; the user asked the primary agent to continue and did not request subagents.
- Git commits are blocked until repository author identity is configured. Do not invent the user's name or email; retain explicit file-level change records and run verification after each task.
