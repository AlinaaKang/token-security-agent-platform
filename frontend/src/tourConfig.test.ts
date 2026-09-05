import { describe, expect, it } from "vitest";

import { TOURS } from "./tourConfig";

describe("guided tour route configuration", () => {
  it("covers each interactive route with four uniquely targeted steps", () => {
    for (const route of ["/analyze", "/lab", "/super-agent", "/challenge"]) {
      const steps = TOURS[route];
      expect(steps).toHaveLength(4);
      expect(new Set(steps?.map((step) => step.id)).size).toBe(4);
      expect(new Set(steps?.map((step) => step.target)).size).toBe(4);
    }
  });

  it("does not define automatic tours for read-only destinations", () => {
    expect(TOURS["/events"]).toBeUndefined();
    expect(TOURS["/evaluation"]).toBeUndefined();
  });

  it("auto-advances only local selector steps and keeps execution steps manual", () => {
    for (const steps of Object.values(TOURS)) {
      expect(steps?.at(-1)?.advanceOnClick).not.toBe(true);
      expect(steps?.at(-1)?.id).toContain("command");
    }
  });
});
