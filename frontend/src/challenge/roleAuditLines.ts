import type { LabRunResult, SemanticSeverity } from "../types";
import type { EvidenceRelation } from "./types";
import type { InvestigationRole } from "./investigation";
import { expectedEvidenceRelation } from "./scoring";

export interface RoleAuditLine {
  id: string;
  label: string;
  value: string;
}

const SEMANTIC_LABELS: Record<SemanticSeverity, string> = {
  safe: "语义安全",
  controversial: "语义争议",
  unsafe: "语义危险",
  unavailable: "语义证据不可用",
};

const RELATION_LABELS: Record<EvidenceRelation, string> = {
  dual_normal: "双路正常",
  semantic_only: "仅语义风险",
  distribution_only: "仅分布异常",
  dual_risk: "双路风险",
};

function guardLines(run: LabRunResult): RoleAuditLine[] {
  const detection = run.detection;
  return [
    { id: "semantic-status", label: "检测状态", value: "语义检测已完成" },
    { id: "semantic-severity", label: "语义等级", value: SEMANTIC_LABELS[detection.semantic_severity] },
    {
      id: "semantic-categories",
      label: "风险类别",
      value: detection.semantic_categories.length ? detection.semantic_categories.join("、") : "未命中风险类别",
    },
    {
      id: "semantic-model",
      label: "模型与耗时",
      value: `${detection.semantic_model_id} / ${detection.semantic_model_version} · ${detection.semantic_latency_ms.toFixed(1)} ms`,
    },
  ];
}

function cpdLines(run: LabRunResult): RoleAuditLine[] {
  const detection = run.detection;
  const threshold = detection.provenance.thresholds.h;
  return [
    { id: "token-status", label: "观测状态", value: "Token 观测已完成" },
    {
      id: "cpd-status",
      label: "CPD 状态",
      value: detection.detector_status === "token_anomaly_candidate" ? "发现分布异常候选" : "未发现分布异常候选",
    },
    {
      id: "cpd-score",
      label: "分数 / 阈值",
      value: `${detection.detector_score.toFixed(2)} / ${threshold === undefined ? "不可用" : threshold.toFixed(2)}`,
    },
    {
      id: "cpd-onset",
      label: "异常起点",
      value: detection.suspicious_span ? `Token ${detection.suspicious_span.token_start}` : "不适用",
    },
    {
      id: "cpd-boundary",
      label: "证据边界",
      value: "分布异常只代表候选信号，不单独证明恶意",
    },
  ];
}

function captainLines(run: LabRunResult): RoleAuditLine[] {
  const relation = expectedEvidenceRelation(run);
  return [
    { id: "captain-input", label: "证据接收", value: "已收到语义与 CPD 两路公开证据" },
    {
      id: "captain-relation",
      label: "证据关系",
      value: relation === null ? "证据不足" : RELATION_LABELS[relation],
    },
    { id: "captain-boundary", label: "展示边界", value: "提交研判前不展示系统动作" },
    { id: "captain-ready", label: "汇总状态", value: "调查证据已汇总，可以进入玩家研判" },
  ];
}

export function buildRoleAuditLines(
  run: LabRunResult,
  role: InvestigationRole,
): RoleAuditLine[] {
  if (role === "guard") return guardLines(run);
  if (role === "cpd") return cpdLines(run);
  return captainLines(run);
}
