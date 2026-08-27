import type { LabRunResult } from "../types";
import type { ResolvedChallengeRound } from "./definitions";
import type { ChallengeAnswer, RoundScoreBreakdown } from "./types";

export type ChallengePhase =
  | "setup"
  | "ready"
  | "investigating"
  | "guessing"
  | "revealed"
  | "round_error"
  | "complete";

export interface ChallengeSessionState {
  phase: ChallengePhase;
  rounds: ResolvedChallengeRound[];
  roundIndex: number;
  currentRun: LabRunResult | null;
  currentAnswer: ChallengeAnswer | null;
  currentScore: RoundScoreBreakdown | null;
  completedScores: RoundScoreBreakdown[];
  combo: number;
  totalScore: number;
  errorCode: "challenge_run_failed" | null;
}

export type ChallengeSessionAction =
  | { type: "start_round" }
  | { type: "receive_run"; run: LabRunResult }
  | { type: "fail_round" }
  | { type: "retry" }
  | { type: "submit_answer"; answer: ChallengeAnswer; score: RoundScoreBreakdown }
  | { type: "advance" }
  | { type: "exit" };

export function createChallengeSetup(): ChallengeSessionState {
  return {
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
  };
}

export function createChallengeSession(
  rounds: ResolvedChallengeRound[],
): ChallengeSessionState {
  return {
    ...createChallengeSetup(),
    phase: "ready",
    rounds: [...rounds],
  };
}

function meanScore(scores: RoundScoreBreakdown[]): number {
  if (scores.length === 0) return 0;
  return Math.round(
    scores.reduce((sum, score) => sum + score.normalizedScore, 0) / scores.length,
  );
}

export function challengeSessionReducer(
  state: ChallengeSessionState,
  action: ChallengeSessionAction,
): ChallengeSessionState {
  if (action.type === "exit") return createChallengeSetup();

  if (action.type === "start_round" && state.phase === "ready") {
    return { ...state, phase: "investigating", errorCode: null };
  }

  if (action.type === "receive_run" && state.phase === "investigating") {
    return { ...state, phase: "guessing", currentRun: action.run, errorCode: null };
  }

  if (action.type === "fail_round" && state.phase === "investigating") {
    return { ...state, phase: "round_error", errorCode: "challenge_run_failed" };
  }

  if (action.type === "retry" && state.phase === "round_error") {
    return { ...state, phase: "investigating", errorCode: null };
  }

  if (action.type === "submit_answer" && state.phase === "guessing" && state.currentRun !== null) {
    const completedScores = [...state.completedScores, action.score];
    return {
      ...state,
      phase: "revealed",
      currentAnswer: action.answer,
      currentScore: action.score,
      completedScores,
      combo: action.score.normalizedScore === 100 ? state.combo + 1 : 0,
      totalScore: meanScore(completedScores),
    };
  }

  if (action.type === "advance" && state.phase === "revealed") {
    const isLastRound = state.roundIndex >= state.rounds.length - 1;
    return {
      ...state,
      phase: isLastRound ? "complete" : "ready",
      roundIndex: isLastRound ? state.roundIndex : state.roundIndex + 1,
      currentRun: null,
      currentAnswer: null,
      currentScore: null,
      errorCode: null,
    };
  }

  return state;
}
