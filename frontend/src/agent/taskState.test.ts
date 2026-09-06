import { describe, expect, it } from "vitest";

import type { AgentEvent, AgentTaskSnapshot } from "./types";
import { reduceAgentEvent } from "./taskState";

function snapshot(): AgentTaskSnapshot {
  return {
    task_id: "task_01",
    version: 2,
    task_type: "pcap_dataset_investigation",
    status: "running",
    title: "PCAP 数据集调查",
    objective_summary: "调查异常候选。",
    created_at: "2026-09-07T08:00:00Z",
    updated_at: "2026-09-07T08:00:01Z",
    messages: [], plan: [], observations: [], evidence: [], hypotheses: [],
    timeline: [], conflicts: [], events: [], replan_count: 0,
    authorization_scopes: [], final_status: null, report: null, limitations: [],
  };
}

function event(overrides: Partial<AgentEvent> = {}): AgentEvent {
  return {
    task_id: "task_01",
    sequence: 8,
    phase: "observe",
    kind: "tool_observed",
    summary: "工具观察已返回。",
    created_at: "2026-09-07T08:00:02Z",
    evidence_refs: [],
    ...overrides,
  };
}

describe("agent event reduction", () => {
  it("applies only monotonic events for the active task", () => {
    const original = snapshot();
    const state = reduceAgentEvent(original, event());

    expect(reduceAgentEvent(state, event({ task_id: "task_other", sequence: 9 }))).toBe(state);
    expect(reduceAgentEvent(state, event({ sequence: 7 }))).toBe(state);
    expect(state.events.at(-1)?.sequence).toBe(8);
  });

  it("deduplicates a replayed event", () => {
    const state = reduceAgentEvent(snapshot(), event({ sequence: 3 }));

    expect(reduceAgentEvent(state, event({ sequence: 3 }))).toBe(state);
  });

  it("reflects terminal event semantics without inventing evidence", () => {
    const state = reduceAgentEvent(
      snapshot(),
      event({ sequence: 9, phase: "complete", kind: "task_cancelled" }),
    );

    expect(state.status).toBe("cancelled");
    expect(state.evidence).toEqual([]);
  });
});
