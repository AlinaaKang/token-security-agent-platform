import { describe, expect, it } from "vitest";

import type {
  Decision,
  DetectorStatus,
  LabRunResult,
  SemanticSeverity,
} from "../types";
import { expectedEvidenceRelation, scoreChallengeRound } from "./scoring";

interface RunOverrides {
  decision: Decision;
  severity: SemanticSeverity;
  detector: DetectorStatus;
  onset: number | null;
}

function runWith(overrides: RunOverrides): LabRunResult {
  return {
    run_id: "run-redacted-001",
    status: "completed",
    scenario_id: "synthetic_safe",
    scenario_kind: "synthetic",
    scenario_label: "普通无害请求",
    attack_family: null,
    mode: "analysis",
    created_at: "2026-08-27T09:00:00Z",
    stages: [],
    detection: {
      decision: overrides.decision,
      risk_score: 0.72,
      detector_score: 0.81,
      detector_status: overrides.detector,
      semantic_severity: overrides.severity,
      semantic_categories: [],
      semantic_model_id: "guard-model",
      semantic_model_version: "1",
      semantic_latency_ms: 10,
      fusion_reason: overrides.decision === "allow" ? "all_clear" : "cpd_candidate",
      suspicious_span: overrides.onset === null
        ? null
        : { token_start: overrides.onset, token_end: overrides.onset + 4, char_start: 0, char_end: 0 },
      signals: [],
      provenance: {
        model_id: "detector-model",
        tokenizer_id: "detector-tokenizer",
        system_prompt_hash: "redacted-hash",
        calibration_version: "cal-1",
        thresholds: { review: 0.5, block: 0.8 },
      },
      latency_ms: 25,
      knowledge_status: "off",
      knowledge_snapshot_version: null,
      knowledge_latency_ms: 0,
      knowledge_evidence: [],
      report_status: "off",
    },
    counterfactual: {
      interpretation: "inconclusive",
      reason: "no_predicted_onset",
      char_start: null,
      calibration_version: "cal-1",
      original: {
        semantic_severity: overrides.severity,
        detector_status: overrides.detector,
        risk_score: 0.72,
        detector_score: 0.81,
        decision: overrides.decision,
        latency_ms: 25,
      },
      rechecked: null,
      risk_score_delta: null,
      detector_score_delta: null,
      action_changed: false,
    },
    tool_plans: [],
    tool_results: [],
    case_report: {
      report_status: "deterministic",
      summary: "脱敏测试报告",
      evidence_ids: [],
      handling_steps: [],
      limitations: [],
      tool_statuses: {},
    },
  };
}

describe("expectedEvidenceRelation", () => {
  it.each([
    ["safe", "no_token_anomaly", "dual_normal"],
    ["unsafe", "no_token_anomaly", "semantic_only"],
    ["safe", "token_anomaly_candidate", "distribution_only"],
    ["unsafe", "token_anomaly_candidate", "dual_risk"],
  ] as const)("maps %s and %s to %s", (severity, detector, expected) => {
    expect(expectedEvidenceRelation(runWith({ decision: "allow", severity, detector, onset: null }))).toBe(expected);
  });

  it.each(["controversial", "unavailable"] as const)(
    "does not score evidence when semantic severity is %s",
    (severity) => {
      expect(expectedEvidenceRelation(runWith({
        decision: "review",
        severity,
        detector: "token_anomaly_candidate",
        onset: 10,
      }))).toBeNull();
    },
  );
});

describe("scoreChallengeRound", () => {
  it.each([
    [0, 30],
    [3, 30],
    [4, 15],
    [8, 15],
    [9, 0],
  ] as const)("scores onset distance %s", (distance, expected) => {
    const scored = scoreChallengeRound(
      { decision: "block", evidenceRelation: "dual_risk", onsetIndex: 20 + distance },
      runWith({ decision: "block", severity: "unsafe", detector: "token_anomaly_candidate", onset: 20 }),
    );
    expect(scored.onsetPoints).toBe(expected);
  });

  it("uses absolute onset distance", () => {
    const scored = scoreChallengeRound(
      { decision: "block", evidenceRelation: "dual_risk", onsetIndex: 12 },
      runWith({ decision: "block", severity: "unsafe", detector: "token_anomaly_candidate", onset: 20 }),
    );
    expect(scored.onsetPoints).toBe(15);
  });

  it("normalizes a no-onset round over the applicable 70 points", () => {
    const scored = scoreChallengeRound(
      { decision: "allow", evidenceRelation: "dual_normal", onsetIndex: null },
      runWith({ decision: "allow", severity: "safe", detector: "no_token_anomaly", onset: null }),
    );
    expect(scored).toMatchObject({
      decisionPoints: 50,
      evidencePoints: 20,
      onsetPoints: 0,
      earnedPoints: 70,
      applicablePoints: 70,
      normalizedScore: 100,
    });
  });

  it("scores sanitize-and-recheck as review without mutating the run", () => {
    const source = runWith({
      decision: "sanitize_recheck",
      severity: "safe",
      detector: "token_anomaly_candidate",
      onset: 12,
    });
    const before = structuredClone(source);
    const scored = scoreChallengeRound(
      { decision: "review", evidenceRelation: "distribution_only", onsetIndex: 12 },
      source,
    );
    expect(scored.decisionPoints).toBe(50);
    expect(source).toEqual(before);
    expect(source.detection.decision).toBe("sanitize_recheck");
  });

  it("awards no onset points when the player omits an applicable onset", () => {
    const scored = scoreChallengeRound(
      { decision: "block", evidenceRelation: "dual_risk", onsetIndex: null },
      runWith({ decision: "block", severity: "unsafe", detector: "token_anomaly_candidate", onset: 20 }),
    );
    expect(scored).toMatchObject({ onsetPoints: 0, applicablePoints: 100, normalizedScore: 70 });
  });

  it("excludes an indeterminate evidence relation from applicable points", () => {
    const scored = scoreChallengeRound(
      { decision: "review", evidenceRelation: "distribution_only", onsetIndex: 10 },
      runWith({ decision: "review", severity: "controversial", detector: "token_anomaly_candidate", onset: 10 }),
    );
    expect(scored).toMatchObject({
      decisionPoints: 50,
      evidencePoints: 0,
      onsetPoints: 30,
      earnedPoints: 80,
      applicablePoints: 80,
      normalizedScore: 100,
    });
  });
});
