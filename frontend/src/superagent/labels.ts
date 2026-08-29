import type { LabToolId, SuperAgentActor, SuperAgentTracePhase } from "../types";

export const superAgentActorLabels: Record<SuperAgentActor, string> = {
  coordinator: "任务协调员",
  semantic_analyst: "语义分析员",
  token_analyst: "曲线分析员",
  knowledge_analyst: "知识分析员",
  response_operator: "响应执行员",
};

export const superAgentPhaseLabels: Record<SuperAgentTracePhase, string> = {
  plan: "PLAN",
  act: "ACT",
  observe: "OBSERVE",
  replan: "REPLAN",
  complete: "COMPLETE",
};

export const superAgentToolLabels: Record<LabToolId, string> = {
  gateway_enforcement: "内部网关状态",
  security_case: "脱敏安全案件",
  evidence_bundle: "证据归档包",
};

export function superAgentEvidenceLabel(code: string) {
  const prefix = "knowledge_id:";
  return code.startsWith(prefix) ? code.slice(prefix.length) : code;
}
