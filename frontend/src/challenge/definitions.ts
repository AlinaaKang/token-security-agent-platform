import type { LabScenario } from "../types";

export type ChallengeMode = "speed" | "full";
export type ChallengeAttackFamily = "gcg" | "autodan" | "advprompter";

export interface ResolvedChallengeRound {
  roundId: "safe" | "shift" | ChallengeAttackFamily;
  scenarioId: string;
  label: string;
  family: ChallengeAttackFamily | null;
}

export interface ChallengeResolution {
  mode: ChallengeMode;
  rounds: ResolvedChallengeRound[];
  missingFamilies: ChallengeAttackFamily[];
  ready: boolean;
}

const FAMILY_ORDER: readonly ChallengeAttackFamily[] = ["gcg", "autodan", "advprompter"];
const SPEED_FAMILY_ORDER: readonly ChallengeAttackFamily[] = ["autodan", "gcg", "advprompter"];

function normalizedFamily(scenario: LabScenario): ChallengeAttackFamily | null {
  if (scenario.scenario_kind !== "protected" || scenario.attack_family === null) return null;
  const family = scenario.attack_family.trim().toLocaleLowerCase("en-US");
  return FAMILY_ORDER.includes(family as ChallengeAttackFamily)
    ? family as ChallengeAttackFamily
    : null;
}

function syntheticRound(
  scenarios: LabScenario[],
  scenarioId: "synthetic_safe" | "synthetic_shift",
): ResolvedChallengeRound | null {
  const scenario = scenarios.find((candidate) => (
    candidate.ready
    && candidate.scenario_kind === "synthetic"
    && candidate.scenario_id === scenarioId
  ));
  if (!scenario) return null;
  return {
    roundId: scenarioId === "synthetic_safe" ? "safe" : "shift",
    scenarioId: scenario.scenario_id,
    label: scenario.label,
    family: null,
  };
}

function familyRound(
  scenarios: LabScenario[],
  family: ChallengeAttackFamily,
): ResolvedChallengeRound | null {
  const scenario = scenarios.find((candidate) => candidate.ready && normalizedFamily(candidate) === family);
  if (!scenario) return null;
  return {
    roundId: family,
    scenarioId: scenario.scenario_id,
    label: scenario.label,
    family,
  };
}

export function resolveChallenge(
  mode: ChallengeMode,
  scenarios: LabScenario[],
): ChallengeResolution {
  const safe = syntheticRound(scenarios, "synthetic_safe");
  const shift = syntheticRound(scenarios, "synthetic_shift");
  const familyRounds = new Map(
    FAMILY_ORDER.map((family) => [family, familyRound(scenarios, family)] as const),
  );
  const missingFamilies = FAMILY_ORDER.filter((family) => familyRounds.get(family) === null);

  const rounds = [safe, shift].filter((round): round is ResolvedChallengeRound => round !== null);
  if (mode === "full") {
    rounds.push(...FAMILY_ORDER
      .map((family) => familyRounds.get(family) ?? null)
      .filter((round): round is ResolvedChallengeRound => round !== null));
  } else {
    const attackRound = SPEED_FAMILY_ORDER
      .map((family) => familyRounds.get(family) ?? null)
      .find((round) => round !== null);
    if (attackRound) rounds.push(attackRound);
  }

  return {
    mode,
    rounds,
    missingFamilies,
    ready: safe !== null
      && shift !== null
      && (mode === "full" ? missingFamilies.length === 0 : rounds.length === 3),
  };
}
