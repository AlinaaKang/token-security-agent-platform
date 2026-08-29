import { describe, expect, it } from "vitest";
import type { SuperAgentTraceEvent } from "../types";
import {
  buildReasoningStages,
  partitionEvidenceCodes,
  reasoningStageIdFor,
} from "./reasoningChain";

const event = (partial: Partial<SuperAgentTraceEvent>): SuperAgentTraceEvent => ({
  sequence: 1,
  phase: "observe",
  actor: "semantic_analyst",
  status: "succeeded",
  summary: "公开摘要",
  evidence_codes: [],
  tool_id: null,
  ...partial,
});

describe("reasoning chain mapping", () => {
  it("maps every public event to exactly one visual stage", () => {
    expect(reasoningStageIdFor(event({ phase: "plan", actor: "coordinator" }))).toBe("rule");
    expect(reasoningStageIdFor(event({ phase: "act", actor: "coordinator" }))).toBe("observe");
    expect(reasoningStageIdFor(event({ phase: "observe", actor: "token_analyst" }))).toBe("observe");
    expect(reasoningStageIdFor(event({ phase: "replan", actor: "coordinator" }))).toBe("replan");
    expect(reasoningStageIdFor(event({ phase: "act", actor: "response_operator", tool_id: "security_case" }))).toBe("act");
    expect(reasoningStageIdFor(event({ phase: "observe", actor: "response_operator" }))).toBe("verify");
    expect(reasoningStageIdFor(event({ phase: "complete", actor: "coordinator" }))).toBe("verify");
  });

  it("sorts events by sequence and keeps empty stages", () => {
    const stages = buildReasoningStages([
      event({ sequence: 3, phase: "replan" }),
      event({ sequence: 1, phase: "observe" }),
    ]);
    expect(stages.map((stage) => stage.id)).toEqual(["observe", "rule", "replan", "act", "verify"]);
    expect(stages.find((stage) => stage.id === "observe")?.events[0].sequence).toBe(1);
    expect(stages.find((stage) => stage.id === "act")?.state).toBe("waiting");
  });

  it("separates public policy codes from observed evidence", () => {
    expect(partitionEvidenceCodes(["semantic:unsafe", "policy:bounded-react-v1", "base_action:block"]))
      .toEqual({ observations: ["semantic:unsafe"], rules: ["policy:bounded-react-v1", "base_action:block"] });
  });
});
