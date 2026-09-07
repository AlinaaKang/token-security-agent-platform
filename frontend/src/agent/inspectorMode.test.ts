import { describe, expect, it } from "vitest";

import type { AgentTaskSnapshot } from "./types";
import type { PcapDetectionMissionResult } from "../types";
import { resolveInspectorMode } from "./inspectorMode";

const task = (taskType: string) => ({ task_type: taskType } as AgentTaskSnapshot);
const mission = { objective: "detect_pcap_anomalies" } as PcapDetectionMissionResult;

describe("agent inspector mode", () => {
  it("uses the selected task type before a background PCAP mission", () => {
    expect(resolveInspectorMode(task("prompt_investigation"), mission)).toBe("prompt");
    expect(resolveInspectorMode(task("pcap_dataset_investigation"), null)).toBe("pcap");
    expect(resolveInspectorMode(task("knowledge_explanation"), null)).toBe("knowledge");
    expect(resolveInspectorMode(task("cross_domain_case"), null)).toBe("cross-domain");
  });

  it("shows the PCAP inspector for a local mission without an Agent task", () => {
    expect(resolveInspectorMode(null, mission)).toBe("pcap");
    expect(resolveInspectorMode(null, null)).toBe("cross-domain");
  });
});
