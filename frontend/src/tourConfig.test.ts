import { describe, expect, it } from "vitest";

import { TOURS } from "./tourConfig";

describe("guided tour route configuration", () => {
  it("covers all primary routes with uniquely targeted steps", () => {
    for (const route of ["/analyze", "/events", "/evaluation", "/lab", "/super-agent", "/challenge"]) {
      const steps = TOURS[route];
      expect(steps?.length).toBeGreaterThanOrEqual(2);
      expect(new Set(steps?.map((step) => step.id)).size).toBe(steps?.length);
      expect(new Set(steps?.map((step) => step.target)).size).toBe(steps?.length);
    }
  });

  it("defines reading-only steps for audit and evaluation destinations", () => {
    expect(TOURS["/events"]?.map((step) => step.target)).toEqual(["events-summary", "events-table"]);
    expect(TOURS["/evaluation"]?.map((step) => step.target)).toEqual([
      "evaluation-scope",
      "evaluation-methods",
      "evaluation-limits",
    ]);
    expect(TOURS["/events"]?.some((step) => step.advanceOnClick)).toBe(false);
    expect(TOURS["/evaluation"]?.some((step) => step.advanceOnClick)).toBe(false);
  });

  it("auto-advances only local selector steps and keeps execution steps manual", () => {
    for (const route of ["/analyze", "/lab", "/super-agent", "/challenge"]) {
      const steps = TOURS[route];
      expect(steps?.at(-1)?.advanceOnClick).not.toBe(true);
      expect(steps?.at(-1)?.id).toContain("command");
    }
  });

  it("guides the lab through input kind, active input, boundary, and manual command", () => {
    expect(TOURS["/lab"]?.map((step) => step.target)).toEqual([
      "lab-input-kind",
      "lab-active-input",
      "lab-active-boundary",
      "lab-active-command",
    ]);
  });
});
