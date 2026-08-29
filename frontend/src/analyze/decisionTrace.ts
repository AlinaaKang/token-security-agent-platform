import type {
  AnalysisResult,
  Decision,
  FusionReason,
  SemanticCategory,
  SemanticSeverity,
} from "../types";

export type AnalyzeDecisionStageId =
  | "ingest"
  | "semantic"
  | "token"
  | "cpd"
  | "fusion"
  | "decision";

export interface AnalyzeDecisionStage {
  id: AnalyzeDecisionStageId;
  label: string;
  status: "completed" | "candidate" | "unavailable";
  summary: string;
  evidence: string[];
}

const semanticLabels: Record<SemanticSeverity, string> = {
  safe: "语义安全",
  controversial: "语义争议",
  unsafe: "语义危险",
  unavailable: "语义检测不可用",
};

const categoryLabels: Record<SemanticCategory, string> = {
  violent: "暴力与武器",
  non_violent_illegal_acts: "非暴力违法行为",
  sexual_content: "性内容",
  pii: "个人敏感信息",
  suicide_self_harm: "自杀与自伤",
  unethical_acts: "不道德行为",
  politically_sensitive: "敏感政治话题",
  copyright_violation: "版权违规",
  jailbreak: "Jailbreak",
};

const fusionLabels: Record<FusionReason, string> = {
  semantic_unsafe: "语义安全策略拦截",
  semantic_controversial: "语义争议，转人工复核",
  cpd_candidate: "Token 异常策略处置",
  all_clear: "双路证据均正常",
  semantic_unavailable_cpd_candidate: "语义不可用，按 Token 异常处置",
  semantic_unavailable_gateway_fail_safe: "语义防线不可用，网关转人工复核",
  semantic_unavailable_analysis_degraded: "语义防线不可用，分析模式降级放行",
};

const decisionLabels: Record<Decision, string> = {
  allow: "放行",
  review: "人工复核",
  block: "拦截",
  sanitize_recheck: "净化后复检",
};

export function publicModelName(modelId: string): string {
  return modelId.split(/[\\/]/).filter(Boolean).at(-1) ?? "模型不可用";
}

function fusionRelation(result: AnalysisResult): string {
  if (result.semantic_severity === "unavailable") return "语义证据不可用，CPD 结果独立展示";
  if (result.semantic_severity === "controversial") return "语义争议需结合 CPD 处置";

  const semanticRisk = result.semantic_severity === "unsafe";
  const cpdCandidate = result.detector_status === "token_anomaly_candidate";
  if (semanticRisk && cpdCandidate) return "语义与 CPD 均提示风险";
  if (semanticRisk) return "语义风险证据为主";
  if (cpdCandidate) return "CPD 候选证据为主";
  return "两路公开证据均正常";
}

export function buildAnalyzeDecisionTrace(
  result: AnalysisResult,
): AnalyzeDecisionStage[] {
  const semanticUnavailable = result.semantic_severity === "unavailable";
  const threshold = result.provenance.thresholds.h;
  const detectorCandidate = result.detector_status === "token_anomaly_candidate";
  const categories = result.semantic_categories.length
    ? result.semantic_categories.map((category) => categoryLabels[category]).join("、")
    : "未标记危险类别";

  return [
    {
      id: "ingest",
      label: "脱敏接收",
      status: "completed",
      summary: "检测请求已脱敏接收并进入检测链路",
      evidence: ["未回显提交内容"],
    },
    {
      id: "semantic",
      label: "语义检测",
      status: semanticUnavailable ? "unavailable" : "completed",
      summary: semanticLabels[result.semantic_severity],
      evidence: semanticUnavailable
        ? ["语义证据不可用"]
        : [
            `风险类别 ${categories}`,
            `公开模型 ${publicModelName(result.semantic_model_id)}`,
            `服务端语义耗时 ${result.semantic_latency_ms.toFixed(1)} ms`,
          ],
    },
    {
      id: "token",
      label: "Token 观测",
      status: "completed",
      summary: `已完成 ${result.signals.length} 个数值信号观测`,
      evidence: [`公开数值信号数量 ${result.signals.length}`],
    },
    {
      id: "cpd",
      label: "CPD 判断",
      status: detectorCandidate ? "candidate" : "completed",
      summary: detectorCandidate ? "发现分布异常候选" : "未发现分布异常候选",
      evidence: [
        `检测分数 ${result.detector_score.toFixed(3)}`,
        threshold === undefined ? "阈值 h 不适用" : `阈值 h ${threshold.toFixed(3)}`,
        result.suspicious_span ? `异常起点 Token ${result.suspicious_span.token_start}` : "异常起点不适用",
      ],
    },
    {
      id: "fusion",
      label: "证据融合",
      status: "completed",
      summary: fusionLabels[result.fusion_reason],
      evidence: [fusionRelation(result), "固定融合策略"],
    },
    {
      id: "decision",
      label: "处置决策",
      status: "completed",
      summary: `最终处置：${decisionLabels[result.decision]}`,
      evidence: [
        `风险分数 ${result.risk_score.toFixed(3)}`,
        "处置来自固定策略融合",
      ],
    },
  ];
}
