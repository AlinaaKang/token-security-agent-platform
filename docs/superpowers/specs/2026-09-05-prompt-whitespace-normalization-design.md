# Prompt Whitespace Normalization Design

## Problem

The analysis API currently validates that a Prompt contains non-whitespace text
but preserves its original line endings and surrounding whitespace. Qwen3Guard
can classify the same short unsafe or controversial text differently when it is
padded with Windows `CRLF` blank lines. This creates a formatting-based bypass:
the semantic result can become `safe`, and when Entropy-CPD also has no alarm,
the fusion policy returns `allow`.

The behavior is reproducible with `CRLF` padding and is visible in the audit
records. Plain input and `LF`-only padding do not consistently reproduce it.

## Decision

Canonicalize `AnalysisRequest.prompt` at the API model boundary before either
detector receives it:

1. Convert Windows `CRLF` and lone `CR` as line breaks and convert both to `LF`.
2. Remove leading and trailing Unicode whitespace with `strip()`.
3. Preserve all internal text and internal whitespace exactly after newline
   normalization.
4. Reject the request if the normalized Prompt is empty.

The normalized value becomes the single input for Qwen3Guard, model scoring,
Entropy-CPD alignment, knowledge enhancement, and audit hashing/counting. This
keeps semantic and Token evidence on one coordinate system and prevents direct
API clients from bypassing a frontend-only cleanup.

## Alternatives Rejected

- **Semantic-only normalization:** preserves the old Token coordinate system,
  but makes the two detectors inspect different text and produces ambiguous
  evidence offsets.
- **Frontend-only normalization:** improves the web form but leaves the API
  vulnerable to direct or alternative clients.

## Compatibility And Privacy

- No detector model, threshold, fusion rule, route, challenge, mascot, PCAP
  workflow, or AutoDL topology changes.
- Meaningful internal newlines and spaces remain part of the Prompt.
- Prompt text remains excluded from responses and persistent audit records.
- Audit hashes and character counts describe the canonical text. Existing
  records are not migrated or rewritten.
- The existing 32,768-character transport bound remains fail-closed. Oversized
  padded inputs are not made acceptable merely because trimming would shorten
  them.

## Testing

Add request-model tests proving that:

- ordinary Prompt text is unchanged;
- leading and trailing `LF` padding is removed;
- `CRLF` and lone `CR` are converted to `LF`;
- internal blank lines are preserved;
- whitespace-only input remains invalid;
- an input exceeding the existing raw character limit remains invalid.

Add a workflow-level regression test with a recording semantic guard and model
runtime to prove both detectors receive the same canonical Prompt. Existing API,
workflow, frontend, challenge, and PCAP suites provide regression coverage.
