import type { AgentEvent, AgentTaskSnapshot } from "./types";

export function reduceAgentEvent(
  state: AgentTaskSnapshot,
  event: AgentEvent,
): AgentTaskSnapshot {
  if (event.task_id !== state.task_id) return state;
  const latest = state.events.at(-1)?.sequence ?? 0;
  if (event.sequence <= latest) return state;

  let status = state.status;
  if (event.kind === "task_cancelled") status = "cancelled";
  else if (event.kind === "task_degraded") status = "degraded";
  else if (event.phase === "complete") status = "completed";
  else if (event.kind === "tool_started") status = "running";

  return {
    ...state,
    status,
    updated_at: event.created_at,
    events: [...state.events, event],
  };
}
