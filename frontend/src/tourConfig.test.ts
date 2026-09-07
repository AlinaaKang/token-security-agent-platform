import { describe, expect, it } from "vitest";

import { resolveTour } from "./tourConfig";

describe("PCAP professional workspace tours", () => {
  it.each(["/pcap-profile", "/pcap-evaluation"])("provides a non-empty tour for %s", (route) => {
    const tour = resolveTour(route, "");

    expect(tour?.route).toBe(route);
    expect(tour?.steps.length).toBeGreaterThanOrEqual(3);
    expect(tour?.steps.every((step) => step.target.length > 0)).toBe(true);
  });
});
