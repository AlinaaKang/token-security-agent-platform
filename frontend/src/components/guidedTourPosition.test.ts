import { beforeEach, describe, expect, it } from "vitest";

import { clampGuidePosition, guidePositionStorageKey, loadGuidePosition, saveGuidePosition } from "./guidedTourPosition";

describe("guided tour launcher position", () => {
  beforeEach(() => localStorage.clear());

  it("clamps the launcher inside a twelve pixel viewport margin", () => {
    expect(clampGuidePosition(
      { x: 2000, y: -20 },
      { width: 1280, height: 720 },
      { width: 120, height: 44 },
    )).toEqual({ x: 1148, y: 12 });
  });

  it("stores desktop and mobile positions independently", () => {
    saveGuidePosition({ x: 100, y: 80 }, false, localStorage);
    saveGuidePosition({ x: 20, y: 68 }, true, localStorage);

    expect(loadGuidePosition(false, localStorage)).toEqual({ x: 100, y: 80 });
    expect(loadGuidePosition(true, localStorage)).toEqual({ x: 20, y: 68 });
    expect(guidePositionStorageKey(false)).not.toBe(guidePositionStorageKey(true));
  });

  it("ignores malformed and non-finite stored positions", () => {
    localStorage.setItem(guidePositionStorageKey(false), "not-json");
    expect(loadGuidePosition(false, localStorage)).toBeNull();
    localStorage.setItem(guidePositionStorageKey(false), JSON.stringify({ x: "far", y: 4 }));
    expect(loadGuidePosition(false, localStorage)).toBeNull();
  });
});
