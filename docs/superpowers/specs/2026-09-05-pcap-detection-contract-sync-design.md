# PCAP Detection Contract Synchronization

## Problem

The Docker HTTP detector emits the current localized-evidence contract, including
`web_injection`, `behavior_anomaly`, and bounded `purpose_candidates`. The Windows
PowerShell gate still validates an older subset. Evidence-bearing reports can
therefore be rejected as `invalid_report_schema` and surfaced as `tool_failed`,
while empty reports pass. A completed batch with failures can also be labelled as
if every selected file was checked successfully.

## Design

Keep the existing strict allowlist. Extend the PowerShell validator and stable
serializer only for fields and enum values already accepted by the Python public
models:

- request evidence from `http_rule`, including SQL injection, command injection,
  path traversal, and web injection;
- packet evidence from `behavior_anomaly` with the existing `none` candidate;
- bounded purpose candidates on request evidence;
- the current fixed supporting-signal vocabulary.

Unknown keys, unknown enum values, malformed packet ranges, duplicate IDs, and
unbounded arrays remain rejected. Raw request text, payloads, file names, paths,
IP addresses, ports, stderr, and private reasoning remain outside the report.

## Result States

The detection banner has three terminal conclusions:

1. Evidence exists: `发现异常候选`.
2. No evidence and no failures: `未发现可定位异常`.
3. No evidence with one or more failures: `检测不完整，存在未完成样本`.

The third state must not imply that failed files are safe. Existing per-sample
failure labels and retry guidance remain visible.

## Verification

- PowerShell launcher tests accept each current evidence shape and continue to
  reject extra fields and forbidden values.
- Frontend tests cover all three terminal conclusions.
- The two previously rejected authorized samples complete through the Docker
  gate and return only structured candidate evidence.
- Backend and frontend suites, production build, privacy checks, and live proxy
  checks remain green.

## Scope

This change does not modify Prompt analysis, Entropy-CPD, Challenge scoring,
mascots, AutoDL routing, PCAP selection, raw capture handling, or competition
platform integration.
