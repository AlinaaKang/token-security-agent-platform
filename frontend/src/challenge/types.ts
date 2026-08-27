export type PlayerDecision = "allow" | "review" | "block";

export type EvidenceRelation =
  | "dual_normal"
  | "semantic_only"
  | "distribution_only"
  | "dual_risk";

export interface ChallengeAnswer {
  decision: PlayerDecision;
  evidenceRelation: EvidenceRelation | null;
  onsetIndex: number | null;
}

export interface RoundScoreBreakdown {
  decisionPoints: 0 | 50;
  evidencePoints: 0 | 20;
  onsetPoints: 0 | 15 | 30;
  earnedPoints: number;
  applicablePoints: 50 | 70 | 80 | 100;
  normalizedScore: number;
}
