import { describe, expect, it } from "vitest";

import {
  canInspectRole,
  completeRolePresentation,
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

  it("unlocks guard, cpd, and agent only after each report completes", () => {
    let state = createInvestigationState();
    state = inspectRole(state, "guard");
    expect(state.step).toBe("semantic");
    expect(state.presentingRole).toBe("guard");
    expect(roleStateFor(state, "guard")).toBe("presenting");
    expect(canInspectRole(state, "cpd")).toBe(false);

    state = completeRolePresentation(state, "guard");
    expect(state.step).toBe("cpd");
    expect(state.presentingRole).toBeNull();
    expect(roleStateFor(state, "cpd")).toBe("ready");

    state = inspectRole(state, "cpd");
    expect(state.step).toBe("cpd");
    state = completeRolePresentation(state, "cpd");
    expect(state.step).toBe("captain");
    expect(roleStateFor(state, "agent")).toBe("ready");

    state = inspectRole(state, "agent");
    expect(state.step).toBe("captain");
    state = completeRolePresentation(state, "agent");
    expect(state.step).toBe("complete");
    expect(state.visitedRoles).toEqual(new Set(["guard", "cpd", "agent"]));
  });

  it("ignores every role switch while a first report is presenting", () => {
    const presenting = inspectRole(createInvestigationState(), "guard");
    expect(canInspectRole(presenting, "guard")).toBe(false);
    expect(canInspectRole(presenting, "cpd")).toBe(false);
    expect(inspectRole(presenting, "guard")).toBe(presenting);
    expect(inspectRole(presenting, "cpd")).toBe(presenting);
  });

  it("ignores a locked role", () => {
    const state = createInvestigationState();
    expect(canInspectRole(state, "agent")).toBe(false);
    expect(inspectRole(state, "agent")).toBe(state);
  });

  it("allows revisiting without changing progress", () => {
    let state = inspectRole(createInvestigationState(), "guard");
    state = completeRolePresentation(state, "guard");
    state = inspectRole(state, "cpd");
    state = completeRolePresentation(state, "cpd");
    const reviewed = inspectRole(state, "guard");
    expect(reviewed.step).toBe("captain");
    expect(reviewed.presentingRole).toBeNull();
    expect(reviewed.selectedRole).toBe("guard");
    expect(reviewed.selectionKind).toBe("review");
    expect(roleStateFor(reviewed, "guard")).toBe("visited");
    expect(roleStateFor(reviewed, "agent")).toBe("ready");
  });

  it("marks first visits separately from reviews", () => {
    const first = inspectRole(createInvestigationState(), "guard");
    expect(first.selectionKind).toBe("first_visit");
    const review = inspectRole(completeRolePresentation(first, "guard"), "guard");
    expect(review.selectionKind).toBe("review");
  });

  it("creates a fresh independent visited set on reset", () => {
    const changed = completeRolePresentation(inspectRole(createInvestigationState(), "guard"), "guard");
    const reset = createInvestigationState();
    expect(changed.visitedRoles.has("guard")).toBe(true);
    expect(reset.visitedRoles.size).toBe(0);
  });

  it("ignores stale or mismatched completion events", () => {
    const initial = createInvestigationState();
    expect(completeRolePresentation(initial, "guard")).toBe(initial);
    const presenting = inspectRole(initial, "guard");
    expect(completeRolePresentation(presenting, "cpd")).toBe(presenting);
  });
});
