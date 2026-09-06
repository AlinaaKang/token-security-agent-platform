import type { PcapCaptureEvidence } from "../types";

export type PcapInvestigationRole = "parser" | "traffic" | "captain";
export type PcapInvestigationRoleState = "locked" | "ready" | "presenting" | "visited";
export type PcapEvidenceSection =
  | "evidence"
  | "confirmed"
  | "candidate"
  | "unknown"
  | "recommendation";

export interface PcapEvidenceLine {
  section: PcapEvidenceSection;
  text: string;
}

export interface PcapInvestigationState {
  selectedRole: PcapInvestigationRole | null;
  presentingRole: PcapInvestigationRole | null;
  visitedRoles: PcapInvestigationRole[];
}

const ROLE_ORDER: PcapInvestigationRole[] = ["parser", "traffic", "captain"];

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

export function buildPcapRoleLines(
  capture: PcapCaptureEvidence,
  role: PcapInvestigationRole,
): PcapEvidenceLine[] {
  if (role === "parser") return parserLines(capture);
  if (role === "traffic") return trafficLines(capture);
  return captainLines(capture);
}

function parserLines(capture: PcapCaptureEvidence): PcapEvidenceLine[] {
  if (capture.status === "succeeded") {
    return [{ section: "evidence", text: `检查成功；已验证 ${capture.packet_count} 个数据包` }];
  }
  if (capture.status === "failed") {
    return [{ section: "evidence", text: `检查失败；错误代码：${capture.error_code ?? "未提供错误代码"}` }];
  }
  return [{ section: "evidence", text: "检查跳过；未形成新的检查结果" }];
}

function trafficLines(capture: PcapCaptureEvidence): PcapEvidenceLine[] {
  const protocols = Object.entries(capture.protocol_counts)
    .filter(([, count]) => Number.isFinite(count))
    .sort(([left], [right]) => left.localeCompare(right));
  const lines: PcapEvidenceLine[] = protocols.length
    ? protocols.map(([protocol, count]) => ({ section: "evidence", text: `协议计数：${protocol.toUpperCase()} ${count}` }))
    : [{ section: "evidence", text: "协议计数：无可用协议计数" }];

  if (capture.visibility.plaintext_application_protocol_observed) {
    lines.push({ section: "evidence", text: "明文应用协议可见" });
  } else if (capture.visibility.encrypted_transport_observed) {
    lines.push({ section: "evidence", text: "加密传输可见；应用层内容不可见" });
  } else {
    lines.push({ section: "evidence", text: "应用层不可见" });
  }

  const capabilityText = capture.capability === "token_eligible"
    ? "证据能力：可继续进行应用层检测；不证明存在 LLM 流量或攻击"
    : capture.capability === "traffic_only"
      ? "证据能力：仅有网络证据可用，无法恢复应用层语义"
      : "证据能力：可观测证据不足，无法形成可靠结论";
  lines.push({ section: "evidence", text: capabilityText });
  return lines;
}

function captainLines(capture: PcapCaptureEvidence): PcapEvidenceLine[] {
  if (capture.status === "failed") {
    return [
      { section: "confirmed", text: "未形成可验证检查结果" },
      { section: "candidate", text: "暂无可复核网络证据" },
      { section: "unknown", text: `失败原因：${capture.error_code ?? "未提供错误代码"}` },
      { section: "recommendation", text: "建议重试该文件" },
    ];
  }

  if (capture.status === "skipped") {
    return [
      { section: "confirmed", text: "未形成新的检查结果" },
      { section: "candidate", text: "暂无可复核网络证据" },
      { section: "unknown", text: `跳过原因：${capture.error_code ?? "未提供跳过原因"}` },
      { section: "recommendation", text: "建议重试该文件" },
    ];
  }

  if (capture.capability === "token_eligible") {
    return [
      { section: "confirmed", text: "已形成可验证网络证据" },
      { section: "candidate", text: "明文应用协议可见" },
      { section: "unknown", text: "应用层语义结论未知" },
      { section: "recommendation", text: "建议进入异常检测继续研判" },
    ];
  }

  if (capture.capability === "traffic_only") {
    return [
      { section: "confirmed", text: "已形成可验证网络证据" },
      { section: "candidate", text: "仅有网络证据可供复核" },
      { section: "unknown", text: "应用层语义未知" },
      { section: "recommendation", text: "建议保留网络元数据供人工复核" },
    ];
  }

  return [
    { section: "confirmed", text: "检查完成但证据不足" },
    { section: "candidate", text: "暂无可复核网络证据" },
    { section: "unknown", text: "可观测证据不足" },
    { section: "recommendation", text: "建议补充可见流量后重试" },
  ];
}
