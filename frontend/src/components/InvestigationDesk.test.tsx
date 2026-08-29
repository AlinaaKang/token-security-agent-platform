import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { LabRunResult } from "../types";
import { InvestigationDesk } from "./InvestigationDesk";

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

const run = {
  run_id: "run-redacted-001",
  status: "completed",
  scenario_id: "synthetic_safe",
  scenario_kind: "synthetic",
  scenario_label: "普通无害请求",
  attack_family: null,
  mode: "analysis",
  created_at: "2026-08-27T09:00:00Z",
  stages: [],
  detection: {
    decision: "sanitize_recheck",
    risk_score: 0.72,
    detector_score: 8.4,
    detector_status: "token_anomaly_candidate",
    semantic_severity: "safe",
    semantic_categories: ["jailbreak"],
    semantic_model_id: "guard-model",
    semantic_model_version: "guard-v1",
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
      thresholds: { k: 0.5, h: 5 },
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
      detector_score: 8.4,
      decision: "sanitize_recheck",
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

describe("InvestigationDesk", () => {
  it("reveals a first semantic report before completing the role", () => {
    vi.useFakeTimers();
    const onPresentationComplete = vi.fn();
    render(
      <InvestigationDesk
        run={run}
        role="guard"
        mode="first_visit"
        playbackKey="round-1:guard"
        onPresentationComplete={onPresentationComplete}
      />,
    );
    expect(screen.getByText("语义检测已完成")).toBeInTheDocument();
    expect(screen.queryByText("语义安全")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "立即显示完整汇报" }));
    expect(screen.getByText("语义安全")).toBeInTheDocument();
    expect(screen.getByText("jailbreak")).toBeInTheDocument();
    expect(screen.getByText("guard-model / guard-v1 · 4.0 ms")).toBeInTheDocument();
    expect(onPresentationComplete).toHaveBeenCalledWith("guard");
  });

  it("shows a stable semantic unavailable report", () => {
    render(
      <InvestigationDesk
        run={withDetection({ semantic_severity: "unavailable" })}
        role="guard"
        mode="review"
        playbackKey="round-1:guard-review"
        onPresentationComplete={vi.fn()}
      />,
    );
    expect(screen.getByText("语义证据不可用")).toBeInTheDocument();
  });

  it("keeps the CPD chart hidden until the first report completes", () => {
    vi.useFakeTimers();
    const onPresentationComplete = vi.fn();
    render(
      <InvestigationDesk
        run={run}
        role="cpd"
        mode="first_visit"
        playbackKey="round-1:cpd"
        onPresentationComplete={onPresentationComplete}
      />,
    );
    expect(screen.queryByRole("img", { name: "Token 挑战信号曲线" })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "立即显示完整汇报" }));
    expect(screen.getByRole("img", { name: "Token 挑战信号曲线" })).toBeInTheDocument();
    expect(screen.getByText("发现分布异常候选")).toBeInTheDocument();
    expect(screen.getByText("8.40 / 5.00")).toBeInTheDocument();
    expect(screen.getByText("Token 2")).toBeInTheDocument();
    expect(onPresentationComplete).toHaveBeenCalledWith("cpd");
    expect(screen.queryByRole("button", { name: /选择 Token/ })).not.toBeInTheDocument();
  });

  it("shows a complete CPD review immediately without completing another visit", () => {
    vi.useFakeTimers();
    const onPresentationComplete = vi.fn();
    render(
      <InvestigationDesk
        run={withDetection({ suspicious_span: null })}
        role="cpd"
        mode="review"
        playbackKey="round-1:cpd-review"
        onPresentationComplete={onPresentationComplete}
      />,
    );
    expect(screen.getByRole("img", { name: "Token 挑战信号曲线" })).toBeInTheDocument();
    expect(screen.getByText("不适用")).toBeInTheDocument();
    expect(screen.getByText("分布异常只代表候选信号，不单独证明恶意")).toBeInTheDocument();
    expect(onPresentationComplete).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("summarizes conflicting evidence without revealing a scored category or final decision", () => {
    render(
      <InvestigationDesk
        run={withDetection({ decision: "block" })}
        role="agent"
        mode="review"
        playbackKey="round-1:agent-review"
        onPresentationComplete={vi.fn()}
      />,
    );
    const desk = screen.getByRole("region", { name: "中央证据台" });
    expect(desk).toHaveTextContent("两路证据存在分歧");
    expect(desk).not.toHaveTextContent("仅分布异常");
    expect(desk).not.toHaveTextContent("仅语义风险");
    expect(desk).not.toHaveTextContent("双路正常");
    expect(desk).not.toHaveTextContent("双路风险");
    expect(desk).not.toHaveTextContent("拦截");
    expect(desk).not.toHaveTextContent("block");
  });

  it("summarizes consistent evidence without revealing a scored category", () => {
    render(
      <InvestigationDesk
        run={withDetection({ detector_status: "no_token_anomaly" })}
        role="agent"
        mode="review"
        playbackKey="round-1:agent-consistent"
        onPresentationComplete={vi.fn()}
      />,
    );
    const desk = screen.getByRole("region", { name: "中央证据台" });
    expect(desk).toHaveTextContent("两路证据结论一致");
    expect(desk).not.toHaveTextContent("双路正常");
  });

  it("summarizes insufficient evidence without revealing a scored category", () => {
    render(
      <InvestigationDesk
        run={withDetection({ semantic_severity: "controversial" })}
        role="agent"
        mode="review"
        playbackKey="round-1:agent-insufficient"
        onPresentationComplete={vi.fn()}
      />,
    );
    const desk = screen.getByRole("region", { name: "中央证据台" });
    expect(desk).toHaveTextContent("现有证据不足以形成双路关系");
    expect(desk).not.toHaveTextContent("仅分布异常");
  });
});
