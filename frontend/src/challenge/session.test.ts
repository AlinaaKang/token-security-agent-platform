import { describe, expect, it } from "vitest";

import type { LabRunResult } from "../types";
import type { ResolvedChallengeRound } from "./definitions";
import {
  challengeSessionReducer,
  createChallengeSession,
  createChallengeSetup,
} from "./session";
import type { ChallengeAnswer, RoundScoreBreakdown } from "./types";

const rounds: ResolvedChallengeRound[] = [
  { roundId: "safe", scenarioId: "synthetic_safe", label: "普通无害", family: null, publicInput: { available: false } },
  { roundId: "autodan", scenarioId: "autodan_01", label: "AutoDAN", family: "autodan", publicInput: { available: false } },
];

const answer: ChallengeAnswer = {
  decision: "allow",
  evidenceRelation: "dual_normal",
  onsetIndex: null,
};

const perfectScore: RoundScoreBreakdown = {
  decisionPoints: 50,
  evidencePoints: 20,
  onsetPoints: 0,
  earnedPoints: 70,
  applicablePoints: 70,
  normalizedScore: 100,
};

const partialScore: RoundScoreBreakdown = {
  decisionPoints: 50,
  evidencePoints: 0,
  onsetPoints: 0,
  earnedPoints: 50,
  applicablePoints: 100,
  normalizedScore: 50,
};

const run = {
  run_id: "run-redacted-session",
  status: "completed",
  scenario_id: "synthetic_safe",
  scenario_kind: "synthetic",
  scenario_label: "普通无害",
  attack_family: null,
  mode: "analysis",
  created_at: "2026-08-27T09:00:00Z",
  stages: [],
  detection: {
    decision: "allow",
    risk_score: 0.1,
    detector_score: 0.1,
    detector_status: "no_token_anomaly",
    semantic_severity: "safe",
    semantic_categories: [],
    semantic_model_id: "guard-model",
    semantic_model_version: "1",
    semantic_latency_ms: 10,
    fusion_reason: "all_clear",
    suspicious_span: null,
    signals: [],
    provenance: {
      model_id: "detector-model",
      tokenizer_id: "detector-tokenizer",
      system_prompt_hash: "redacted-hash",
      calibration_version: "cal-1",
      thresholds: {},
    },
    latency_ms: 20,
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
      semantic_severity: "safe",
      detector_status: "no_token_anomaly",
      risk_score: 0.1,
      detector_score: 0.1,
      decision: "allow",
      latency_ms: 20,
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
} satisfies LabRunResult;

function revealRound(score: RoundScoreBreakdown = perfectScore) {
  let state = createChallengeSession(rounds);
  state = challengeSessionReducer(state, { type: "start_round" });
  state = challengeSessionReducer(state, { type: "receive_run", run });
  return challengeSessionReducer(state, { type: "submit_answer", answer, score });
}

describe("challenge session setup", () => {
  it("creates an empty setup state", () => {
    expect(createChallengeSetup()).toEqual({
      phase: "setup",
      rounds: [],
      roundIndex: 0,
      currentRun: null,
      currentAnswer: null,
      currentScore: null,
      completedScores: [],
      combo: 0,
      totalScore: 0,
      errorCode: null,
    });
  });

  it("creates a ready configured session", () => {
    const state = createChallengeSession(rounds);
    expect(state.phase).toBe("ready");
    expect(state.rounds).toEqual(rounds);
    expect(state.rounds).not.toBe(rounds);
  });
});

describe("challengeSessionReducer", () => {
  it("runs a round through investigating, guessing, reveal, and next", () => {
    let state = createChallengeSession(rounds);
    state = challengeSessionReducer(state, { type: "start_round" });
    expect(state.phase).toBe("investigating");
    state = challengeSessionReducer(state, { type: "receive_run", run });
    expect(state.phase).toBe("guessing");
    state = challengeSessionReducer(state, { type: "submit_answer", answer, score: perfectScore });
    expect(state.phase).toBe("revealed");
    state = challengeSessionReducer(state, { type: "advance" });
    expect(state.roundIndex).toBe(1);
    expect(state.phase).toBe("ready");
    expect(state.currentRun).toBeNull();
  });

  it("moves a failed request to a retryable error without adding score", () => {
    let state = challengeSessionReducer(createChallengeSession(rounds), { type: "start_round" });
    state = challengeSessionReducer(state, { type: "fail_round" });
    expect(state).toMatchObject({
      phase: "round_error",
      errorCode: "challenge_run_failed",
      completedScores: [],
      totalScore: 0,
    });
    state = challengeSessionReducer(state, { type: "retry" });
    expect(state).toMatchObject({ phase: "investigating", errorCode: null });
  });

  it("ignores answer submission before a run exists", () => {
    const state = createChallengeSession(rounds);
    expect(challengeSessionReducer(state, { type: "submit_answer", answer, score: perfectScore })).toBe(state);
  });

  it("increments combo only for a normalized 100-point round", () => {
    const first = revealRound();
    expect(first.combo).toBe(1);
    let state = challengeSessionReducer(first, { type: "advance" });
    state = challengeSessionReducer(state, { type: "start_round" });
    state = challengeSessionReducer(state, { type: "receive_run", run });
    state = challengeSessionReducer(state, { type: "submit_answer", answer, score: partialScore });
    expect(state.combo).toBe(0);
  });

  it("calculates the rounded arithmetic mean of completed normalized scores", () => {
    let state = revealRound();
    state = challengeSessionReducer(state, { type: "advance" });
    state = challengeSessionReducer(state, { type: "start_round" });
    state = challengeSessionReducer(state, { type: "receive_run", run });
    state = challengeSessionReducer(state, { type: "submit_answer", answer, score: { ...partialScore, normalizedScore: 51 } });
    expect(state.totalScore).toBe(76);
  });

  it("completes after advancing from the last reveal", () => {
    let state = revealRound();
    state = challengeSessionReducer(state, { type: "advance" });
    state = challengeSessionReducer(state, { type: "start_round" });
    state = challengeSessionReducer(state, { type: "receive_run", run });
    state = challengeSessionReducer(state, { type: "submit_answer", answer, score: partialScore });
    state = challengeSessionReducer(state, { type: "advance" });
    expect(state.phase).toBe("complete");
    expect(state.completedScores).toHaveLength(2);
  });

  it("exits to a fresh setup state and discards completed data", () => {
    const revealed = revealRound();
    expect(challengeSessionReducer(revealed, { type: "exit" })).toEqual(createChallengeSetup());
  });

  it("keeps illegal transitions referentially stable", () => {
    const state = createChallengeSetup();
    expect(challengeSessionReducer(state, { type: "advance" })).toBe(state);
    expect(challengeSessionReducer(state, { type: "receive_run", run })).toBe(state);
    expect(challengeSessionReducer(state, { type: "retry" })).toBe(state);
  });
});
