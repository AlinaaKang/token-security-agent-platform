import type { AgentTaskSnapshot } from "./types";

export type AgentWorkspaceMode = "prompt" | "pcap";

export function taskWorkspaceMode(task: AgentTaskSnapshot): AgentWorkspaceMode {
  if (task.workspace_mode === "prompt" || task.workspace_mode === "pcap") return task.workspace_mode;
  return task.task_type === "pcap_dataset_investigation" || task.task_type === "pcap_capture_investigation"
    ? "pcap"
    : "prompt";
}

export function resolveAgentWorkspaceMode(search: string, task?: AgentTaskSnapshot | null): AgentWorkspaceMode {
  const explicit = new URLSearchParams(search).get("mode");
  if (explicit === "pcap" || explicit === "prompt") return explicit;
  return task ? taskWorkspaceMode(task) : "prompt";
}

export function agentWorkspaceUrl(mode: AgentWorkspaceMode, taskId?: string | null): string {
  const task = taskId ? `&task=${encodeURIComponent(taskId)}` : "";
  return `/super-agent?mode=${mode}${task}`;
}
