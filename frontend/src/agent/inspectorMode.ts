import type { AgentTaskSnapshot } from "./types";
import type { PcapDetectionMissionResult } from "../types";

export type AgentInspectorMode = "prompt" | "pcap" | "cross-domain" | "knowledge";

export function resolveInspectorMode(task: AgentTaskSnapshot | null, mission: PcapDetectionMissionResult | null): AgentInspectorMode {
  if (task?.task_type === "prompt_investigation") return "prompt";
  if (task?.task_type.includes("pcap")) return "pcap";
  if (task?.task_type === "knowledge_explanation") return "knowledge";
  if (task) return "cross-domain";
  return mission ? "pcap" : "cross-domain";
}
