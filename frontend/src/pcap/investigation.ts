import type { PcapMissionResult, PcapPublicNarrative } from "../types";

export type PcapInvestigationRole = "guard" | "cpd" | "captain";
export type PcapInvestigationRoleState = "locked" | "ready" | "presenting" | "visited";
export type PcapEvidenceSection = "evidence" | "confirmed" | "candidate" | "unknown";

export interface PcapEvidenceLine {
  section: PcapEvidenceSection;
  text: string;
}

export interface PcapInvestigationState {
  selectedRole: PcapInvestigationRole | null;
  presentingRole: PcapInvestigationRole | null;
  visitedRoles: PcapInvestigationRole[];
}

const ROLE_ORDER: PcapInvestigationRole[] = ["guard", "cpd", "captain"];

const PUBLIC_NARRATIVE_LABELS: Record<PcapPublicNarrative, string> = {
  batch_triage_completed: "批次分诊已完成",
  coordinator_plan: "有界批次计划已建立",
  cpd_evidence_unavailable: "CPD 证据不可用",
  deterministic_response_ready: "确定性响应记录已就绪",
  encrypted_transport_observed: "观察到加密传输",
  evidence_level_validated: "证据级别已核验",
  insufficient_evidence: "现有证据不足",
  no_packet_payload_retained: "未保留数据包载荷",
  plaintext_application_protocol_observed: "观察到明文应用协议",
  plaintext_application_protocol_candidate_not_proven_llm_traffic: "明文应用协议候选，不证明 LLM 流量",
  retain_public_metadata: "保留公开元数据供人工复核",
  token_evidence_unavailable: "Token 证据不可用",
  tool_authorization_accepted: "执行授权已接受",
  traffic_only_evidence: "仅有网络流量证据",
};

export function initialPcapInvestigationState(): PcapInvestigationState {
  return {
    selectedRole: null,
    presentingRole: null,
    visitedRoles: [],
  };
}

export function roleStateForPcap(
  state: PcapInvestigationState,
  role: PcapInvestigationRole,
): PcapInvestigationRoleState {
  if (state.presentingRole === role) return "presenting";
  if (state.visitedRoles.includes(role)) return "visited";
  const roleIndex = ROLE_ORDER.indexOf(role);
  const priorRolesVisited = ROLE_ORDER.slice(0, roleIndex)
    .every((priorRole) => state.visitedRoles.includes(priorRole));
  return priorRolesVisited && state.presentingRole === null ? "ready" : "locked";
}

export function selectPcapRole(
  state: PcapInvestigationState,
  role: PcapInvestigationRole,
): PcapInvestigationState {
  const roleState = roleStateForPcap(state, role);
  if (roleState === "locked" || roleState === "presenting" || state.presentingRole !== null) return state;
  return {
    ...state,
    selectedRole: role,
    presentingRole: roleState === "ready" ? role : null,
  };
}

export function finishPcapRole(
  state: PcapInvestigationState,
  role: PcapInvestigationRole,
): PcapInvestigationState {
  if (state.presentingRole !== role) return state;
  return {
    selectedRole: role,
    presentingRole: null,
    visitedRoles: state.visitedRoles.includes(role)
      ? state.visitedRoles
      : [...state.visitedRoles, role],
  };
}

function reportLine(
  section: Exclude<PcapEvidenceSection, "evidence">,
  narratives: PcapPublicNarrative[],
): PcapEvidenceLine {
  return {
    section,
    text: narratives.length
      ? narratives.map((narrative) => PUBLIC_NARRATIVE_LABELS[narrative]).join("；")
      : "暂无公开结论",
  };
}

export function buildPcapRoleLines(
  mission: PcapMissionResult,
  role: PcapInvestigationRole,
): PcapEvidenceLine[] {
  const captures = mission.summary?.captures ?? [];
  const selectedCount = mission.summary?.selected_count ?? 0;

  if (role === "guard") {
    const plaintextCount = captures.filter(
      ({ visibility }) => visibility.plaintext_application_protocol_observed,
    ).length;
    const encryptedCount = captures.filter(
      ({ visibility }) => visibility.encrypted_transport_observed,
    ).length;
    return [
      { section: "evidence", text: "尚未恢复 Prompt，语义证据暂不可用" },
      { section: "evidence", text: `明文应用协议可见：${plaintextCount} / ${selectedCount} 个捕获` },
      { section: "evidence", text: `加密传输可见：${encryptedCount} / ${selectedCount} 个捕获；加密载荷内容不可见` },
    ];
  }

  if (role === "cpd") {
    const eligibleCount = captures.filter(({ capability }) => capability === "token_eligible").length;
    return [
      {
        section: "evidence",
        text: `明文应用协议候选：${eligibleCount} 个；仅表示协议可见性，不证明 LLM 流量、越狱、CPD 或 Token 异常`,
      },
      { section: "evidence", text: "模型与 Token 证据不可用" },
    ];
  }

  const summary = mission.summary;
  return [
    {
      section: "evidence",
      text: `批次计数：已选择 ${summary?.selected_count ?? 0}，成功 ${summary?.succeeded_count ?? 0}，失败 ${summary?.failed_count ?? 0}，跳过 ${summary?.skipped_count ?? 0}`,
    },
    reportLine("confirmed", mission.report.confirmed),
    reportLine("candidate", mission.report.candidates),
    reportLine("unknown", mission.report.unknowns),
  ];
}
