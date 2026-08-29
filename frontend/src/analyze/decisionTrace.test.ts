import { describe, expect, it } from "vitest";

import type { AnalysisResult } from "../types";
import { buildAnalyzeDecisionTrace, publicModelName } from "./decisionTrace";

const result = {
  request_id: "request-redacted-001",
  decision: "block",
  risk_score: 0.91,
  detector_score: 0.81234,
  detector_status: "no_token_anomaly",
  semantic_severity: "unsafe",
  semantic_categories: ["jailbreak"],
  semantic_model_id: "/root/autodl-tmp/models/Qwen3Guard-Gen-0.6B",
  semantic_model_version: "private-version",
  semantic_latency_ms: 12.4,
  semantic_verification: "performed",
  fusion_reason: "semantic_unsafe",
  audit_persisted: true,
  suspicious_span: null,
  signals: [
    {
      index: 3,
      token_id: 15001,
      token_text: "token_text private suffix",
      entropy: 1.1,
      nll: 2.2,
      cpd_entropy: 3.3,
      cpd_nll: 4.4,
      risk: 0.5,
    },
    {
      index: 4,
      token_id: 15002,
      token_text: "token_id private prompt",
      entropy: 1.2,
      nll: 2.3,
      cpd_entropy: 3.4,
      cpd_nll: 4.5,
      risk: 0.6,
    },
  ],
  evidence: [{ source: "retrieval terms", summary: "guard_raw_output raw_output" }],
  actions: ["隐藏 CoT 已展示"],
  provenance: {
    model_id: "private detector model",
    tokenizer_id: "private tokenizer",
    system_prompt_hash: "private hash",
    calibration_version: "cal-v1",
    thresholds: { h: 1.25 },
  },
  latency_ms: 34.5,
} satisfies AnalysisResult;

function withResult(overrides: Partial<AnalysisResult>): AnalysisResult {
  return { ...result, ...overrides };
}

describe("analyze decision trace", () => {
  it("maps public evidence into the six-stage decision order", () => {
    const trace = buildAnalyzeDecisionTrace(result);

    expect(trace.map((stage) => stage.id)).toEqual([
      "ingest",
      "semantic",
      "token",
      "cpd",
      "fusion",
      "decision",
    ]);
    expect(trace.map((stage) => stage.label)).toEqual([
      "脱敏接收",
      "语义检测",
      "Token 观测",
      "CPD 判断",
      "证据融合",
      "处置决策",
    ]);
    expect(trace.find((stage) => stage.id === "semantic")?.summary).toContain("语义危险");
    expect(trace.find((stage) => stage.id === "token")?.summary).toContain("2 个数值信号");
    expect(trace.find((stage) => stage.id === "cpd")?.summary).toContain("未发现分布异常候选");
    expect(trace.find((stage) => stage.id === "fusion")?.summary).toContain("语义安全策略拦截");
    expect(trace.find((stage) => stage.id === "decision")?.summary).toContain("拦截");
    expect(trace.find((stage) => stage.id === "cpd")?.evidence).toEqual([
      "检测分数 0.812",
      "阈值 h 1.250",
      "异常起点不适用",
    ]);
  });

  it("reduces model identifiers to public names", () => {
    expect(publicModelName("/root/autodl-tmp/models/Qwen3Guard-Gen-0.6B"))
      .toBe("Qwen3Guard-Gen-0.6B");
    expect(publicModelName("C:\\models\\Qwen3Guard-Gen-0.6B"))
      .toBe("Qwen3Guard-Gen-0.6B");
  });

  it("does not serialize protected input, token, model, or reasoning data", () => {
    const serialized = JSON.stringify(buildAnalyzeDecisionTrace(result)).toLowerCase();

    for (const forbidden of [
      "prompt", "suffix", "token_text", "token_id", "guard_raw_output",
      "raw_output", "/root/", "autodl-tmp", "隐藏 cot 已展示",
    ]) expect(serialized).not.toContain(forbidden);
  });

  it("uses explicit unavailable values without inventing missing evidence", () => {
    const unavailable = withResult({
      semantic_severity: "unavailable",
      semantic_categories: [],
      signals: [],
      suspicious_span: null,
      provenance: { ...result.provenance, thresholds: {} },
    });
    const trace = buildAnalyzeDecisionTrace(unavailable);

    expect(trace.find((stage) => stage.id === "semantic")).toMatchObject({
      status: "unavailable",
      summary: "语义检测不可用",
    });
    expect(trace.find((stage) => stage.id === "token")?.summary).toContain("0 个数值信号");
    expect(trace.find((stage) => stage.id === "cpd")?.evidence).toContain("阈值 h 不适用");
    expect(trace.find((stage) => stage.id === "cpd")?.evidence).toContain("异常起点不适用");
  });

  it("does not describe a semantic controversy as normal evidence", () => {
    const trace = buildAnalyzeDecisionTrace(withResult({
      semantic_severity: "controversial",
      fusion_reason: "semantic_controversial",
    }));

    expect(trace.find((stage) => stage.id === "fusion")?.evidence[0]).toBe("语义争议需结合 CPD 处置");
  });
});
