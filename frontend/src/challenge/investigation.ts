export type PresentationMode = "interactive" | "auto";
export type InvestigationRole = "guard" | "cpd" | "agent";
export type InvestigationStep = "semantic" | "cpd" | "captain" | "complete";
export type InvestigationSelectionKind = "first_visit" | "review" | null;
export type InvestigationRoleState = "locked" | "ready" | "presenting" | "visited";

export interface InvestigationState {
  step: InvestigationStep;
  selectedRole: InvestigationRole | null;
  selectionKind: InvestigationSelectionKind;
  visitedRoles: ReadonlySet<InvestigationRole>;
}

const STEP_ROLE: Record<Exclude<InvestigationStep, "complete">, InvestigationRole> = {
  semantic: "guard",
  cpd: "cpd",
  captain: "agent",
};

const NEXT_STEP: Record<InvestigationRole, InvestigationStep> = {
  guard: "cpd",
  cpd: "captain",
  agent: "complete",
};

export function createInvestigationState(): InvestigationState {
  return {
    step: "semantic",
    selectedRole: null,
    selectionKind: null,
    visitedRoles: new Set<InvestigationRole>(),
  };
}

export function canInspectRole(state: InvestigationState, role: InvestigationRole): boolean {
  if (state.visitedRoles.has(role)) return true;
  return state.step !== "complete" && STEP_ROLE[state.step] === role;
}

export function inspectRole(
  state: InvestigationState,
  role: InvestigationRole,
): InvestigationState {
  if (!canInspectRole(state, role)) return state;
  const revisiting = state.visitedRoles.has(role);
  const visitedRoles = new Set(state.visitedRoles);
  visitedRoles.add(role);
  return {
    step: revisiting ? state.step : NEXT_STEP[role],
    selectedRole: role,
    selectionKind: revisiting ? "review" : "first_visit",
    visitedRoles,
  };
}

export function roleStateFor(
  state: InvestigationState,
  role: InvestigationRole,
): InvestigationRoleState {
  if (state.selectedRole === role && state.selectionKind === "first_visit") return "presenting";
  if (state.visitedRoles.has(role)) return "visited";
  if (state.step !== "complete" && STEP_ROLE[state.step] === role) return "ready";
  return "locked";
}
