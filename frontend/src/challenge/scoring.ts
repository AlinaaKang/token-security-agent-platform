import type { Decision, LabRunResult } from "../types";
import type {
  ChallengeAnswer,
  EvidenceRelation,
  PlayerDecision,
  RoundScoreBreakdown,
} from "./types";

export function scorableDecision(decision: Decision): PlayerDecision {
  return decision === "sanitize_recheck" ? "review" : decision;
}

export function expectedEvidenceRelation(run: LabRunResult): EvidenceRelation | null {
  const severity = run.detection.semantic_severity;
  const detector = run.detection.detector_status;

  if (severity !== "safe" && severity !== "unsafe") return null;
  if (detector !== "no_token_anomaly" && detector !== "token_anomaly_candidate") return null;
  if (severity === "safe" && detector === "no_token_anomaly") return "dual_normal";
  if (severity === "unsafe" && detector === "no_token_anomaly") return "semantic_only";
  if (severity === "safe") return "distribution_only";
  return "dual_risk";
}

export function scoreChallengeRound(
  answer: ChallengeAnswer,
  run: LabRunResult,
): RoundScoreBreakdown {
  const expectedEvidence = expectedEvidenceRelation(run);
  const expectedOnset = run.detection.suspicious_span?.token_start ?? null;
  const decisionPoints = answer.decision === scorableDecision(run.detection.decision) ? 50 : 0;
  const evidencePoints = expectedEvidence !== null && answer.evidenceRelation === expectedEvidence ? 20 : 0;

  let onsetPoints: 0 | 15 | 30 = 0;
  if (expectedOnset !== null && answer.onsetIndex !== null) {
    const distance = Math.abs(answer.onsetIndex - expectedOnset);
    if (distance <= 3) onsetPoints = 30;
    else if (distance <= 8) onsetPoints = 15;
  }

  const applicablePoints = (
    50
    + (expectedEvidence === null ? 0 : 20)
    + (expectedOnset === null ? 0 : 30)
  ) as RoundScoreBreakdown["applicablePoints"];
  const earnedPoints = decisionPoints + evidencePoints + onsetPoints;

  return {
    decisionPoints,
    evidencePoints,
    onsetPoints,
    earnedPoints,
    applicablePoints,
    normalizedScore: Math.round((earnedPoints / applicablePoints) * 100),
  };
}
