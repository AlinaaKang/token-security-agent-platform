import { describe, expect, it } from "vitest";

import type { LabScenario } from "../types";
import { resolveChallenge } from "./definitions";

const catalog: LabScenario[] = [
  {
    scenario_id: "synthetic_safe",
    label: "普通无害",
    scenario_kind: "synthetic",
    attack_family: null,
    ready: true,
    public_input: {
      disclosure: "full",
      content: "Explain why input validation is useful in a web application.",
      intent_summary: "解释 Web 应用输入校验的价值",
      redaction_notice: null,
    },
  },
  {
    scenario_id: "synthetic_shift",
    label: "无害格式突变",
    scenario_kind: "synthetic",
    attack_family: null,
    ready: true,
    public_input: {
      disclosure: "full",
      content: "Explain why input validation is useful\nin a web application.\n",
      intent_summary: "解释多行输入校验的价值",
      redaction_notice: null,
    },
  },
  {
    scenario_id: "gcg_01",
    label: "GCG",
    scenario_kind: "protected",
    attack_family: "gcg",
    ready: true,
    public_input: {
      disclosure: "redacted",
      content: "受保护的对抗攻击输入",
      intent_summary: "受保护攻击样本",
      redaction_notice: "[对抗攻击内容已隐藏]",
    },
    PRIVATE_PROTECTED_SENTINEL: "PRIVATE_PROTECTED_SENTINEL",
  },
  {
    scenario_id: "autodan_01",
    label: "AutoDAN",
    scenario_kind: "protected",
    attack_family: "AutoDAN",
    ready: true,
    public_input: {
      disclosure: "redacted",
      content: "受保护的对抗攻击输入",
      intent_summary: "受保护攻击样本",
      redaction_notice: "[对抗攻击内容已隐藏]",
    },
  },
  {
    scenario_id: "adv_01",
    label: "AdvPrompter",
    scenario_kind: "protected",
    attack_family: "advprompter",
    ready: true,
    public_input: {
      disclosure: "redacted",
      content: "受保护的对抗攻击输入",
      intent_summary: "受保护攻击样本",
      redaction_notice: "[对抗攻击内容已隐藏]",
    },
  },
] as unknown as LabScenario[];

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

  it("resolves only the approved public-input fields with original content", () => {
    const resolution = resolveChallenge("speed", catalog);
    expect(resolution.rounds[0]?.publicInput).toEqual({
      available: true,
      disclosure: "full",
      content: "Explain why input validation is useful in a web application.",
      intentSummary: "解释 Web 应用输入校验的价值",
      redactionNotice: null,
    });
    expect(resolution.rounds[1]?.publicInput).toMatchObject({
      content: "Explain why input validation is useful\nin a web application.\n",
    });
  });

  it.each([
    ["a missing public-input object", undefined],
    ["blank content", { disclosure: "full", content: " \n ", intent_summary: "summary", redaction_notice: null }],
    ["blank intent summary", { disclosure: "full", content: "content", intent_summary: "\t", redaction_notice: null }],
    ["an invalid disclosure", { disclosure: "private", content: "content", intent_summary: "summary", redaction_notice: null }],
    ["a full disclosure with a notice", { disclosure: "full", content: "content", intent_summary: "summary", redaction_notice: "[对抗攻击内容已隐藏]" }],
    ["a redacted disclosure without the fixed notice", { disclosure: "redacted", content: "content", intent_summary: "summary", redaction_notice: null }],
  ])("keeps the scenario available for %s while hiding malformed public input", (_case, public_input) => {
    const scenarios = catalog.map((scenario) => (
      scenario.scenario_id === "synthetic_safe"
        ? { ...scenario, public_input }
        : scenario
    )) as unknown as LabScenario[];
    const resolution = resolveChallenge("speed", scenarios);

    expect(resolution.rounds[0]?.scenarioId).toBe("synthetic_safe");
    expect(resolution.rounds[0]?.publicInput).toEqual({ available: false });
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
    const resolution = resolveChallenge("full", catalog);
    const serialized = JSON.stringify(resolution.rounds);
    expect(serialized).not.toContain("PRIVATE_PROTECTED_SENTINEL");
    for (const forbidden of [
      "prompt",
      "suffix",
      "token_text",
      "token_id",
      "query_text",
      "raw_output",
      "guard_raw_output",
      "hidden_reasoning",
    ]) {
      expect(serialized).not.toContain(`\"${forbidden}\"`);
    }
  });
});
