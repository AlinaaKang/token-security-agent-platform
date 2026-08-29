import type { SuperAgentEventStatus, SuperAgentTraceEvent } from "../types";

export type ReasoningStageId = "observe" | "rule" | "replan" | "act" | "verify";
export type ReasoningStageState = "waiting" | SuperAgentEventStatus;

export interface ReasoningStage {
  id: ReasoningStageId;
  label: string;
  events: SuperAgentTraceEvent[];
  state: ReasoningStageState;
  latestSequence: number | null;
}

export const REASONING_STAGE_ORDER: ReadonlyArray<{ id: ReasoningStageId; label: string }> = [
  { id: "observe", label: "观察证据" },
  { id: "rule", label: "应用规则" },
  { id: "replan", label: "调整计划" },
  { id: "act", label: "执行动作" },
  { id: "verify", label: "验证结果" },
];

export function reasoningStageIdFor(event: SuperAgentTraceEvent): ReasoningStageId {
  if (event.phase === "complete") return "verify";
  if (event.phase === "replan") return "replan";
  if (event.phase === "act" && event.tool_id) return "act";
  if (event.phase === "plan") return "rule";
  if (event.phase === "observe" && event.actor === "response_operator") return "verify";
  return "observe";
}

function stateFor(events: SuperAgentTraceEvent[]): ReasoningStageState {
  if (!events.length) return "waiting";
  if (events.some((item) => item.status === "failed")) return "failed";
  return events.at(-1)?.status ?? "waiting";
}

export function buildReasoningStages(events: SuperAgentTraceEvent[]): ReasoningStage[] {
  const ordered = [...events].sort((left, right) => left.sequence - right.sequence);
  return REASONING_STAGE_ORDER.map(({ id, label }) => {
    const stageEvents = ordered.filter((item) => reasoningStageIdFor(item) === id);
    return {
      id,
      label,
      events: stageEvents,
      state: stateFor(stageEvents),
      latestSequence: stageEvents.at(-1)?.sequence ?? null,
    };
  });
}

export function partitionEvidenceCodes(codes: string[]) {
  return codes.reduce<{ observations: string[]; rules: string[] }>((result, code) => {
    const target = code.startsWith("policy:") || code.startsWith("base_action:") ? result.rules : result.observations;
    target.push(code);
    return result;
  }, { observations: [], rules: [] });
}
