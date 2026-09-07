import { describe, expect, it } from "vitest";

import type { AgentTaskSnapshot } from "./types";
import { agentWorkspaceUrl, resolveAgentWorkspaceMode, taskWorkspaceMode } from "./workspaceMode";

function task(taskType: string): AgentTaskSnapshot {
  return { task_id: "task_1", task_type: taskType } as AgentTaskSnapshot;
}

describe("agent workspace modes", () => {
  it("resolves an explicit PCAP mode and defaults invalid modes to Prompt", () => {
    expect(resolveAgentWorkspaceMode("?mode=pcap")).toBe("pcap");
    expect(resolveAgentWorkspaceMode("?mode=prompt")).toBe("prompt");
    expect(resolveAgentWorkspaceMode("?mode=unknown")).toBe("prompt");
  });

  it("uses the selected task when the URL does not declare a mode", () => {
    expect(resolveAgentWorkspaceMode("?task=task_1", task("pcap_dataset_investigation"))).toBe("pcap");
    expect(resolveAgentWorkspaceMode("", task("prompt_investigation"))).toBe("prompt");
  });

  it("groups dataset and capture investigations into the PCAP conversation", () => {
    expect(taskWorkspaceMode(task("pcap_dataset_investigation"))).toBe("pcap");
    expect(taskWorkspaceMode(task("pcap_capture_investigation"))).toBe("pcap");
    expect(taskWorkspaceMode(task("prompt_investigation"))).toBe("prompt");
    expect(taskWorkspaceMode(task("cross_domain_case"))).toBe("prompt");
    expect(taskWorkspaceMode(task("knowledge_question"))).toBe("prompt");
  });

  it("keeps general questions in the workspace where the conversation started", () => {
    expect(taskWorkspaceMode({ ...task("knowledge_explanation"), workspace_mode: "pcap" })).toBe("pcap");
    expect(taskWorkspaceMode({ ...task("pcap_capture_investigation"), workspace_mode: "prompt" })).toBe("prompt");
  });

  it("builds stable new and historical conversation URLs", () => {
    expect(agentWorkspaceUrl("pcap")).toBe("/super-agent?mode=pcap");
    expect(agentWorkspaceUrl("prompt", "task 1/2")).toBe("/super-agent?mode=prompt&task=task%201%2F2");
  });
});
