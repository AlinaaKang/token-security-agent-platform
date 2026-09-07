import { describe, expect, it } from "vitest";

import { formatAgentMessageTime } from "./messageTime";

function localIso(year: number, month: number, day: number, hour: number, minute: number) {
  return new Date(year, month - 1, day, hour, minute).toISOString();
}

describe("agent message time", () => {
  it.each([
    [localIso(2026, 9, 7, 8, 10), new Date(2026, 8, 7, 12, 0), "08:10"],
    [localIso(2026, 9, 6, 8, 10), new Date(2026, 8, 7, 12, 0), "昨天 08:10"],
    [localIso(2026, 8, 20, 8, 10), new Date(2026, 8, 7, 12, 0), "8月20日 08:10"],
    [localIso(2025, 12, 30, 23, 59), new Date(2026, 0, 1, 12, 0), "2025年12月30日 23:59"],
  ])("formats relative dates without rewriting the source instant", (value, now, expected) => {
    const result = formatAgentMessageTime(value, now);
    expect(result.short).toBe(expected);
    expect(result.dateTime).toBe(value);
    expect(result.full).toContain("202");
  });
});
