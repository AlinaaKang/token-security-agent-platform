import { describe, expect, it } from "vitest";

import type { LabScenario } from "../types";
import { resolveChallenge } from "./definitions";

const catalog: LabScenario[] = [
  { scenario_id: "synthetic_safe", label: "普通无害", scenario_kind: "synthetic", attack_family: null, ready: true },
  { scenario_id: "synthetic_shift", label: "无害格式突变", scenario_kind: "synthetic", attack_family: null, ready: true },
  { scenario_id: "gcg_01", label: "GCG", scenario_kind: "protected", attack_family: "gcg", ready: true },
  { scenario_id: "autodan_01", label: "AutoDAN", scenario_kind: "protected", attack_family: "AutoDAN", ready: true },
  { scenario_id: "adv_01", label: "AdvPrompter", scenario_kind: "protected", attack_family: "advprompter", ready: true },
];

describe("resolveChallenge", () => {
  it("resolves the three-round speed challenge with AutoDAN preference", () => {
    const result = resolveChallenge("speed", catalog);
    expect(result.ready).toBe(true);
    expect(result.rounds.map((item) => item.scenarioId)).toEqual([
      "synthetic_safe",
      "synthetic_shift",
      "autodan_01",
    ]);
  });

  it("resolves full challenge families case-insensitively in fixed order", () => {
    const result = resolveChallenge("full", catalog);
    expect(result.ready).toBe(true);
    expect(result.rounds.map((item) => item.family)).toEqual([
      null,
      null,
      "gcg",
      "autodan",
      "advprompter",
    ]);
  });

  it.each([
    [["gcg", "advprompter"], "gcg"],
    [["advprompter"], "advprompter"],
  ] as const)("falls back through the fixed speed family preference %j", (families, expected) => {
    const includedFamilies: readonly string[] = families;
    const filtered = catalog.filter((scenario) => (
      scenario.attack_family === null
      || includedFamilies.includes(scenario.attack_family.toLocaleLowerCase("en-US"))
    ));
    const result = resolveChallenge("speed", filtered);
    expect(result.rounds.at(2)?.family).toBe(expected);
  });

  it("ignores unavailable scenarios", () => {
    const result = resolveChallenge("speed", catalog.map((scenario) => (
      scenario.scenario_id === "autodan_01" ? { ...scenario, ready: false } : scenario
    )));
    expect(result.rounds.at(2)?.family).toBe("gcg");
  });

  it("reports a missing full-mode family without constructing a partial playable session", () => {
    const result = resolveChallenge(
      "full",
      catalog.filter((scenario) => scenario.attack_family?.toLocaleLowerCase("en-US") !== "gcg"),
    );
    expect(result.ready).toBe(false);
    expect(result.missingFamilies).toEqual(["gcg"]);
    expect(result.rounds.map((item) => item.family)).not.toContain("gcg");
  });

  it("requires both exact synthetic scenario IDs", () => {
    const result = resolveChallenge(
      "speed",
      catalog.filter((scenario) => scenario.scenario_id !== "synthetic_shift"),
    );
    expect(result.ready).toBe(false);
    expect(result.rounds.map((item) => item.roundId)).toEqual(["safe", "autodan"]);
  });

  it("does not infer attack families from labels or scenario IDs", () => {
    const misleading: LabScenario[] = [
      ...catalog.filter((scenario) => scenario.attack_family === null),
      { scenario_id: "autodan_in_name", label: "AutoDAN", scenario_kind: "protected", attack_family: null, ready: true },
    ];
    const result = resolveChallenge("speed", misleading);
    expect(result.ready).toBe(false);
    expect(result.rounds).toHaveLength(2);
  });

  it("returns only privacy-safe challenge metadata", () => {
    const serialized = JSON.stringify(resolveChallenge("full", catalog));
    for (const forbidden of [
      "prompt",
      "suffix",
      "token_text",
      "token_id",
      "query_text",
      "raw_output",
      "guard_raw_output",
    ]) {
      expect(serialized).not.toContain(`\"${forbidden}\"`);
    }
  });
});
