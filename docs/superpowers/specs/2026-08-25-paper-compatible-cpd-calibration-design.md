# Paper-Compatible CPD Calibration Design

## Purpose

Repair the basic-task detector so its calibration and evaluation match the
methodological claims in *Detecting Fluent Optimization-Based Adversarial
Prompts via Sequential Entropy Changes* closely enough to support a defensible
competition result.

The current detector uses entropy pooled from 20 simple benign user prompts as
its robust baseline and sets `h` above the largest benign calibration score.
That differs materially from the paper, which derives the entropy location and
scale from the fixed system prompt and selects the prompt-level threshold with
labeled benign and adversarial data. The observed 30% AutoDAN alarm rate is
therefore evidence against the current calibration, not evidence that the Web
policy layer should be made more aggressive.

## Goals

- Derive entropy median and MAD scale from the fixed system-prompt token stream.
- Select `h` from labeled calibration data by prompt-level F1, with a
  deterministic tie-break rule.
- Compare canonical `k=0` and conservative `k=0.5` without using the frozen test
  split for model selection.
- Preserve the current rule that a CPD score below `h` cannot be blocked by CPD
  alone.
- Report overall and per-family detection metrics, benign false-positive rate,
  AUROC, latency, and suffix-localization quality.
- Keep complete prompt text out of Git, fixtures, logs, reports, and screenshots.

## Non-Goals

- Lowering `h` manually until selected attacks pass.
- Claiming that CPD detects every jailbreak or harmful request.
- Claiming CPD Online or Page-CUSUM as original project contributions.
- Adding BEAST or AutoDAN-HGA labels without generated artifacts whose provenance
  can be verified.
- Adding the semantic guard, NLL fusion, counterfactual verification, PCAP, or
  advanced-agent workflow in this correction phase.

## Data Contract

CPDonline is the attributed reference source for the first reproducible
benchmark. Raw prompt data remains outside version control under `data/raw/` or
behind a read-only external path. Versioned repository artifacts contain only
sample identifiers, group identifiers, labels, source metadata, checksums, and
aggregate results.

Records use the existing `PromptRecord` contract and group-aware deterministic
split:

- calibration: 20% of groups, used to fit operating thresholds;
- development: 20% of groups, used to select `k` and the declared operating
  point;
- test: 60% of groups, read only after baseline and detector parameters freeze.

The same normalized base request and attack family must remain in one group to
prevent suffix or request variants from leaking between splits.

## Model Observation

`TransformersModelRuntime` will expose system-segment entropy statistics in
addition to the existing user-token statistics. Both segments must come from
the same chat-template forward pass and therefore share model, tokenizer,
system-prompt hash, and template identity.

System-token projection uses character offsets for the literal fixed system
prompt. Chat-template control tokens outside that literal span are excluded.
Failure to locate either the system or user text verbatim is an alignment error;
calibration must stop rather than silently use the wrong tokens.

For a fixed model and system prompt, the system entropy sequence is deterministic.
The calibration profile is fitted from that sequence once, rather than pooling
user-token entropies across benign prompts.

## Detector Calibration

The robust baseline is:

```text
mu0 = median(H_system)
sigma0 = max(1e-6, 1.4826 * median(abs(H_system - mu0)))
```

For each labeled calibration prompt and each candidate `k` in `{0.0, 0.5}`:

```text
Z_t = (H_user,t - mu0) / sigma0
W_t = max(0, W_t-1 + Z_t - k)
score(prompt) = max_t W_t
```

Candidate thresholds are the distinct finite prompt scores plus one value above
the maximum score so that the all-negative operating point is representable.
The selected threshold maximizes prompt-level F1 on the calibration split. Ties
are resolved by lower false-positive rate, then higher threshold. This makes the
selection deterministic and avoids silently preferring an unnecessarily
aggressive detector.

The development split compares the two frozen `(k, h)` candidates. Selection is
by higher development F1, then lower benign false-positive rate, then lower
`k`. After this choice, baseline, `k`, and `h` are immutable for the test run.

An additional FPR@10% operating point is reported separately. It is an analysis
point, not a replacement for the F1-selected production profile.

## Runtime Decision Flow

```text
fixed system prompt + user prompt
  -> one model forward pass
  -> system entropy baseline identity check
  -> user entropy Page-CUSUM
  -> score < h: allow or review, never CPD-only block
  -> score >= h: CPD alarm and suffix-onset estimate
  -> current policy maps alarm evidence to the configured action
```

The API continues returning the scalar score, `k`, `h`, alarm token, onset token,
token trace, and provenance. The calibration version changes so an old
benign-user-prompt profile cannot be loaded accidentally after deployment.

## Evaluation Outputs

The frozen test report contains no prompt text. It records:

- total sample counts and source/version checksums;
- overall precision, recall, F1, AUROC, and benign false-positive rate;
- per-family count, recall, score distribution, and miss count;
- onset mean absolute error and trigger-in-suffix rate;
- inference latency p50 and p95;
- results at the F1-selected and FPR@10% operating points;
- the exact model, tokenizer, system-prompt hash, baseline, `k`, `h`, and
  calibration version.

The initial engineering target is overall F1 at least 0.80, benign FPR at most
10% at the declared low-FPR operating point, AutoDAN recall at least 80%, and no
regression below the current GCG and AdvPrompter smoke-test performance. These
are project acceptance targets, not claims copied from the paper.

## Error Handling

- Reject mixed model, tokenizer, system-prompt, or chat-template identities.
- Reject empty, non-finite, or zero-scale system entropy sequences.
- Reject threshold fitting when labels contain only one class.
- Reject evaluation records with unknown sample IDs or invalid suffix spans.
- Mark unavailable attack families as not evaluated; never count them as passes.
- Abort a frozen test run if its dataset checksum differs from the split
  manifest.

## Test Strategy

Unit tests will be written before production changes and must demonstrate:

- system and user token spans are projected independently and correctly;
- system entropy, not benign user entropy, defines the robust baseline;
- F1 threshold selection and tie-breaking are deterministic;
- candidate selection uses development metrics without reading test labels;
- a below-threshold trace cannot cause a CPD-only block;
- calibration identity mismatches fail closed;
- aggregate reports contain no prompt text.

Integration tests will use synthetic harmless token streams. Live AutoDL
verification will use CPDonline raw samples only in memory and will emit
aggregate metrics without request bodies or token text.

## Innovation Boundary

This correction establishes a credible baseline; it is not the claimed
innovation. After it passes, the advanced design may evaluate project-created
extensions such as Entropy/NLL sequential fusion, semantic contradiction
checking, and minimal intervention. Each extension must be compared against the
frozen CPD-only baseline through an ablation, otherwise it is a feature claim
rather than demonstrated innovation.
