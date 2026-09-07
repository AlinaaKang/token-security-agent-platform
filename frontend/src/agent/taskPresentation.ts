import type { AgentTaskSnapshot } from "./types";

export type AgentTaskTone = "blue" | "green" | "red" | "amber";

export function presentAgentTaskStatus(task: AgentTaskSnapshot): { label: string; tone: AgentTaskTone } {
  if (task.status === "completed") {
    if (task.final_status === "risk_found") return { label: "发现风险", tone: "red" };
    if (task.final_status === "safe") return { label: "当前未命中", tone: "green" };
    if (task.final_status === "contained") return { label: "已处置", tone: "green" };
    return { label: "结论不确定", tone: "amber" };
  }
  if (task.status === "awaiting_authorization") return { label: "等待授权", tone: "amber" };
  if (task.status === "planned" || task.status === "queued") return { label: "准备执行", tone: "blue" };
  if (task.status === "running") return { label: "运行中", tone: "blue" };
  if (task.status === "paused") return { label: "已暂停", tone: "amber" };
  if (task.status === "degraded") return { label: "检测未完整", tone: "amber" };
  if (task.status === "failed") return { label: "执行失败", tone: "amber" };
  if (task.status === "cancelled") return { label: "已取消", tone: "amber" };
  return { label: "草稿", tone: "blue" };
}
