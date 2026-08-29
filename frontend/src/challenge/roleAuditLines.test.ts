import { describe, expect, it } from "vitest";

import type { LabRunResult } from "../types";
import { buildRoleAuditLines } from "./roleAuditLines";

const run = {
  run_id: "run-redacted-001",
  status: "completed",
  scenario_id: "synthetic_safe",
  scenario_kind: "synthetic",
  scenario_label: "普通无害请求",
  attack_family: null,
  mode: "analysis",
  created_at: "2026-08-29T09:00:00Z",
  stages: [],
  detection: {
    decision: "review",
    risk_score: 0.72,
    detector_score: 2.4,
    detector_status: "token_anomaly_candidate",
    semantic_severity: "safe",
    semantic_categories: [],
    semantic_model_id: "guard-model",
    semantic_model_version: "1.0",
    semantic_latency_ms: 4,
    fusion_reason: "cpd_candidate",
    suspicious_span: { token_start: 2, token_end: 3, char_start: 0, char_end: 0 },
    signals: [
      { index: 0, entropy: 0.8, nll: 1.1, cpd_entropy: 0, cpd_nll: 0, risk: 0.1 },
      { index: 2, entropy: 3.8, nll: 4.4, cpd_entropy: 5.8, cpd_nll: 0, risk: 0.9 },
    ],
    provenance: {
      model_id: "qwen-model",
      tokenizer_id: "qwen-tokenizer",
      system_prompt_hash: "redacted-hash",
      calibration_version: "cal-v2",
      thresholds: { k: 0.5, h: 1.8 },
    },
    latency_ms: 28,
    knowledge_status: "off",
    knowledge_snapshot_version: null,
    knowledge_latency_ms: 0,
    knowledge_evidence: [],
    report_status: "off",
  },
  counterfactual: {
    interpretation: "inconclusive",
    reason: "no_predicted_onset",
    char_start: null,
    calibration_version: "cal-v2",
    original: {
      semantic_severity: "safe",
      detector_status: "token_anomaly_candidate",
      risk_score: 0.72,
      detector_score: 2.4,
      decision: "review",
      latency_ms: 28,
    },
    rechecked: null,
    risk_score_delta: null,
    detector_score_delta: null,
    action_changed: false,
  },
  tool_plans: [],
  tool_results: [],
  case_report: {
    report_status: "deterministic",
    summary: "脱敏测试报告",
    evidence_ids: [],
    handling_steps: [],
    limitations: [],
    tool_statuses: {},
  },
} satisfies LabRunResult;

function withDetection(overrides: Partial<LabRunResult["detection"]>): LabRunResult {
  return { ...run, detection: { ...run.detection, ...overrides } };
}

describe("challenge role audit lines", () => {
  it("builds a deterministic semantic report from public fields", () => {
    expect(buildRoleAuditLines(run, "guard").map((line) => line.value)).toEqual([
      "语义检测已完成",
      "语义安全",
      "未命中风险类别",
      "guard-model / 1.0 · 4.0 ms",
    ]);
  });

  it("builds a deterministic CPD report and preserves the candidate caveat", () => {
    expect(buildRoleAuditLines(run, "cpd").map((line) => line.value)).toEqual([
      "Token 观测已完成",
      "发现分布异常候选",
      "2.40 / 1.80",
      "Token 2",
      "分布异常只代表候选信号，不单独证明恶意",
    ]);
  });

  it("builds a captain report without revealing the system action", () => {
    const values = buildRoleAuditLines(run, "agent").map((line) => line.value);
    expect(values).toEqual([
      "已收到语义与 CPD 两路公开证据",
      "仅分布异常",
      "提交研判前不展示系统动作",
      "调查证据已汇总，可以进入玩家研判",
    ]);
    expect(values.join(" ")).not.toContain("人工复核");
  });

  it("uses explicit unavailable values without inventing evidence", () => {
    const unavailable = withDetection({
      semantic_severity: "unavailable",
      semantic_categories: [],
      semantic_latency_ms: 0,
      detector_score: 0,
      detector_status: "no_token_anomaly",
      suspicious_span: null,
      provenance: { ...run.detection.provenance, thresholds: {} },
    });
    expect(buildRoleAuditLines(unavailable, "guard").map((line) => line.value)).toContain("语义证据不可用");
    expect(buildRoleAuditLines(unavailable, "cpd").map((line) => line.value)).toEqual([
      "Token 观测已完成",
      "未发现分布异常候选",
      "0.00 / 不可用",
      "不适用",
      "分布异常只代表候选信号，不单独证明恶意",
    ]);
  });

  it("never serializes private fields or hidden reasoning claims", () => {
    const serialized = JSON.stringify([
      ...buildRoleAuditLines(run, "guard"),
      ...buildRoleAuditLines(run, "cpd"),
      ...buildRoleAuditLines(run, "agent"),
    ]).toLowerCase();
    for (const forbidden of [
      "prompt",
      "suffix",
      "token_text",
      "token_id",
      "raw_output",
      "guard_raw_output",
      "隐藏 cot 已展示",
    ]) expect(serialized).not.toContain(forbidden);
  });
});
