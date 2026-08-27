import { describe, expect, it } from "vitest";

import {
  canInspectRole,
  createInvestigationState,
  inspectRole,
  roleStateFor,
} from "./investigation";

describe("interactive detective investigation", () => {
  it("starts with only the semantic detective ready", () => {
    const state = createInvestigationState();
    expect(state.step).toBe("semantic");
    expect(roleStateFor(state, "guard")).toBe("ready");
    expect(roleStateFor(state, "cpd")).toBe("locked");
    expect(roleStateFor(state, "agent")).toBe("locked");
  });

  it("unlocks guard, cpd, and agent in that order", () => {
    let state = createInvestigationState();
    state = inspectRole(state, "guard");
    expect(state.step).toBe("cpd");
    expect(roleStateFor(state, "guard")).toBe("presenting");
    expect(roleStateFor(state, "cpd")).toBe("ready");

    state = inspectRole(state, "cpd");
    expect(state.step).toBe("captain");
    expect(roleStateFor(state, "agent")).toBe("ready");

    state = inspectRole(state, "agent");
    expect(state.step).toBe("complete");
    expect(state.visitedRoles).toEqual(new Set(["guard", "cpd", "agent"]));
  });

  it("ignores a locked role", () => {
    const state = createInvestigationState();
    expect(canInspectRole(state, "agent")).toBe(false);
    expect(inspectRole(state, "agent")).toBe(state);
  });

  it("allows revisiting without changing progress", () => {
    let state = inspectRole(createInvestigationState(), "guard");
    state = inspectRole(state, "cpd");
    const reviewed = inspectRole(state, "guard");
    expect(reviewed.step).toBe("captain");
    expect(reviewed.selectedRole).toBe("guard");
    expect(reviewed.selectionKind).toBe("review");
    expect(roleStateFor(reviewed, "guard")).toBe("visited");
    expect(roleStateFor(reviewed, "agent")).toBe("ready");
  });

  it("marks first visits separately from reviews", () => {
    const first = inspectRole(createInvestigationState(), "guard");
    expect(first.selectionKind).toBe("first_visit");
    const review = inspectRole(first, "guard");
    expect(review.selectionKind).toBe("review");
  });

  it("creates a fresh independent visited set on reset", () => {
    const changed = inspectRole(createInvestigationState(), "guard");
    const reset = createInvestigationState();
    expect(changed.visitedRoles.has("guard")).toBe(true);
    expect(reset.visitedRoles.size).toBe(0);
  });
});
