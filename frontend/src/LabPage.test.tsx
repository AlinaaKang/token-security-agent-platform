import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { App } from "./App";
import { LabSignalChart } from "./components/LabSignalChart";


const health = {
  status: "ok",
  api: { ready: true },
  model: { ready: true, model_id: "qwen-model" },
  detector: { ready: true, calibration_version: "cal-v2" },
  semantic_guard: { ready: true, model_id: "guard-model", model_version: "guard-v1" },
  knowledge: { ready: true, snapshot_version: "official-v1", card_count: 12, generator_ready: true },
  lab: { enabled: true, ready: true, reason: "ready" },
};

const scenarios = [
  { scenario_id: "synthetic_safe", label: "普通无害", scenario_kind: "synthetic", attack_family: null, ready: true },
  { scenario_id: "autodan_01", label: "AutoDAN 优化攻击", scenario_kind: "protected", attack_family: "autodan", ready: true },
];

const metrics = {
  run_count: 1,
  counterfactual_eligible_count: 1,
  counterfactual_executed_count: 1,
  counterfactual_execution_rate: 1,
  evidence_agreement_count: 1,
  evidence_conflict_count: 0,
  evidence_conflict_rate: 0,
  tool_success_count: 0,
  tool_failure_count: 0,
  tool_success_rate: 0,
  report_generated_count: 1,
  report_fallback_count: 0,
  action_invariance_count: 1,
  action_invariance_rate: 1,
  latency_ms: { p50: 30, p95: 30 },
  privacy_violation_count: 0,
};

const run = {
  run_id: "lab_123",
  status: "completed",
  scenario_id: "custom",
  scenario_kind: "custom",
  scenario_label: "自定义输入",
  attack_family: null,
  mode: "gateway",
  created_at: "2026-08-26T10:00:00Z",
  stages: [
    { stage_id: "semantic_guard", status: "succeeded", latency_ms: 4, timing_basis: "measured", summary: "语义安全等级与类别已归一化。" },
    { stage_id: "token_observation", status: "succeeded", latency_ms: 23, timing_basis: "combined", summary: "Token 观测与 CPD 使用组合耗时。" },
    { stage_id: "entropy_cpd", status: "succeeded", latency_ms: null, timing_basis: "unavailable", summary: "Entropy-CPD 产生异常候选和预测起点。" },
    { stage_id: "fixed_fusion", status: "succeeded", latency_ms: null, timing_basis: "unavailable", summary: "固定融合表生成基础动作。" },
    { stage_id: "knowledge_retrieval", status: "succeeded", latency_ms: 3, timing_basis: "measured", summary: "本地知识证据已附加，且不改变基础动作。" },
  ],
  detection: {
    decision: "block",
    risk_score: 0.9,
    detector_score: 9,
    detector_status: "token_anomaly_candidate",
    semantic_severity: "unsafe",
    semantic_categories: ["jailbreak"],
    semantic_model_id: "guard-model",
    semantic_model_version: "guard-v1",
    semantic_latency_ms: 4,
    fusion_reason: "semantic_unsafe",
    suspicious_span: { token_start: 2, token_end: 4, char_start: 12, char_end: 30 },
    signals: [
      { index: 0, entropy: 0.8, nll: 1.1, cpd_entropy: 0, cpd_nll: 0, risk: 0.1 },
      { index: 1, entropy: 1.2, nll: 1.6, cpd_entropy: 0.4, cpd_nll: 0, risk: 0.2 },
      { index: 2, entropy: 3.8, nll: 4.4, cpd_entropy: 5.8, cpd_nll: 0, risk: 0.9 },
      { index: 3, entropy: 4.1, nll: 4.8, cpd_entropy: 8.4, cpd_nll: 0, risk: 1 },
    ],
    provenance: {
      model_id: "qwen-model",
      tokenizer_id: "qwen-tokenizer",
      system_prompt_hash: "sha256:system",
      calibration_version: "cal-v2",
      thresholds: { k: 0.5, h: 5 },
    },
    latency_ms: 30,
    knowledge_status: "ready",
    knowledge_snapshot_version: "official-v1",
    knowledge_latency_ms: 3,
    knowledge_evidence: [{
      knowledge_id: "owasp-llm01-prompt-injection",
      title_zh: "提示词注入控制",
      risk_domain: "prompt_injection",
      summary: "使用分层控制限制提示词注入风险。",
      recommendations: ["保留基础检测动作。"],
      source: {
        publisher: "owasp",
        title: "OWASP GenAI Security Project",
        url: "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
        version: "2025",
        verified_at: "2026-08-26T00:00:00Z",
        usage_note: "official summary",
      },
      retrieval_score: 4,
      matched_tags: ["jailbreak"],
    }],
    report_status: "fallback",
  },
  counterfactual: {
    interpretation: "risk_reduced",
    reason: "completed",
    char_start: 12,
    calibration_version: "cal-v2",
    original: { semantic_severity: "unsafe", detector_status: "token_anomaly_candidate", risk_score: 0.9, detector_score: 9, decision: "block", latency_ms: 30 },
    rechecked: { semantic_severity: "safe", detector_status: "no_token_anomaly", risk_score: 0.2, detector_score: 1, decision: "allow", latency_ms: 22 },
    risk_score_delta: 0.7,
    detector_score_delta: 8,
    action_changed: true,
  },
  tool_plans: [
    { tool_id: "gateway_preview", title: "网关策略预览", status: "planned", effective_action: "block", artifact_summary: "预览网关执行 block。", knowledge_ids: ["owasp-llm01-prompt-injection"] },
    { tool_id: "soc_case_preview", title: "安全工单预览", status: "planned", effective_action: "block", artifact_summary: "预览脱敏安全工单。", knowledge_ids: ["owasp-llm01-prompt-injection"] },
    { tool_id: "evidence_export_preview", title: "证据清单预览", status: "planned", effective_action: "block", artifact_summary: "预览结构化证据清单。", knowledge_ids: ["owasp-llm01-prompt-injection"] },
  ],
  tool_results: [],
  case_report: {
    report_status: "deterministic",
    summary: "基础检测动作为 block；反事实敏感性结论为 risk_reduced。",
    evidence_ids: ["owasp-llm01-prompt-injection"],
    handling_steps: ["保留拦截动作，并生成脱敏调查记录。"],
    limitations: ["反事实结果仅为敏感性证据，不构成严格因果证明。", "所有处置工具均为模拟执行，不代表外部系统已变更。"],
    tool_statuses: {},
  },
};

function response(payload: unknown, ok = true, status = 200) {
  return Promise.resolve({ ok, status, json: async () => payload });
}

function installFetch(options: { legacyHealth?: boolean } = {}) {
  const requests: Array<{ url: string; init?: RequestInit }> = [];
  vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    requests.push({ url, init });
    if (url === "/health") {
      if (options.legacyHealth) {
        const { lab: _, ...legacy } = health;
        return response(legacy);
      }
      return response(health);
    }
    if (url === "/api/v1/lab/scenarios") return response(scenarios);
    if (url === "/api/v1/lab/metrics") return response(metrics);
    if (url === "/api/v1/lab/runs") return response(run, true, 201);
    if (url.includes("/tools/gateway_preview/dry-run")) {
      return response({
        ...run,
        tool_results: [{
          tool_id: "gateway_preview",
          status: "failed",
          error_code: "simulated_tool_failure",
          latency_ms: 0.1,
          effective_action: "block",
          artifact_summary: "模拟工具失败；保留基础动作或升级人工复核。",
          evidence_sha256: null,
        }],
      });
    }
    throw new Error(`Unexpected request: ${url}`);
  }));
  return requests;
}

describe("security lab workspace", () => {
  beforeEach(() => {
    window.history.pushState({}, "", "/lab");
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("adds an isolated lab route without replacing the stable pages", async () => {
    installFetch();
    render(<App />);

    expect(await screen.findByRole("main", { name: "AI 安全攻防实验舱" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "攻防实验舱" })).toHaveClass("active");
    expect(screen.getByRole("link", { name: "专业调查" })).toHaveClass("active");
    expect(screen.getByRole("link", { name: "侦探挑战" })).toHaveAttribute("href", "/challenge");
    expect(screen.getByText("普通无害")).toBeInTheDocument();
    expect(screen.getByText("AutoDAN 优化攻击")).toBeInTheDocument();
  });

  it("creates a custom investigation and renders the recorded evidence pipeline", async () => {
    const requests = installFetch();
    render(<App />);
    await screen.findByText("实验舱已就绪");
    fireEvent.change(screen.getByLabelText("自定义 Prompt"), {
      target: { value: "SAFE_CUSTOM_INPUT" },
    });
    fireEvent.click(screen.getByRole("button", { name: "开始调查" }));

    expect(await screen.findByText("证据到达顺序")).toBeInTheDocument();
    const timeline = screen.getByRole("list", { name: "证据到达顺序" });
    expect(within(timeline).getAllByRole("listitem")).toHaveLength(5);
    expect(within(timeline).getByText("语义 Guard")).toBeInTheDocument();
    expect(within(timeline).getByText("知识检索")).toBeInTheDocument();
    expect(screen.getByLabelText("Token 信号同步曲线").querySelectorAll("path").length).toBe(3);
    expect(screen.getByText("组合计时")).toBeInTheDocument();

    const createRequest = requests.find((item) => item.url === "/api/v1/lab/runs");
    expect(JSON.parse(String(createRequest?.init?.body))).toEqual({
      scenario_kind: "custom",
      custom_input: "SAFE_CUSTOM_INPUT",
      mode: "analysis",
    });
    expect(screen.queryByText("SAFE_CUSTOM_INPUT")).not.toBeInTheDocument();
  });

  it("shows counterfactual sensitivity without claiming strict causality", async () => {
    installFetch();
    render(<App />);
    await screen.findByText("实验舱已就绪");
    fireEvent.change(screen.getByLabelText("自定义 Prompt"), { target: { value: "SAFE_CUSTOM_INPUT" } });
    fireEvent.click(screen.getByRole("button", { name: "开始调查" }));
    await screen.findByText("证据到达顺序");
    fireEvent.click(screen.getByRole("tab", { name: "反事实验证" }));

    expect(screen.getByText("风险降低")).toBeInTheDocument();
    expect(screen.getByText("0.900")).toBeInTheDocument();
    expect(screen.getByText("0.200")).toBeInTheDocument();
    expect(screen.getByText(/不构成严格因果证明/)).toBeInTheDocument();
  });

  it("dry-runs a fixed tool and keeps a failed block action blocked", async () => {
    installFetch();
    render(<App />);
    await screen.findByText("实验舱已就绪");
    fireEvent.change(screen.getByLabelText("自定义 Prompt"), { target: { value: "SAFE_CUSTOM_INPUT" } });
    fireEvent.click(screen.getByRole("button", { name: "开始调查" }));
    await screen.findByText("证据到达顺序");
    fireEvent.click(screen.getByRole("tab", { name: "处置沙箱" }));
    fireEvent.click(screen.getByLabelText("模拟一次工具失败"));
    fireEvent.click(screen.getByRole("button", { name: "模拟执行网关策略预览" }));

    expect(await screen.findByText("模拟执行失败")).toBeInTheDocument();
    expect(screen.getByText("保留动作：拦截")).toBeInTheDocument();
    expect(screen.queryByText("保留动作：放行")).not.toBeInTheDocument();
  });

  it("renders legal knowledge citations and a redacted case report", async () => {
    installFetch();
    render(<App />);
    await screen.findByText("实验舱已就绪");
    fireEvent.change(screen.getByLabelText("自定义 Prompt"), { target: { value: "SAFE_CUSTOM_INPUT" } });
    fireEvent.click(screen.getByRole("button", { name: "开始调查" }));

    expect(await screen.findByText("OWASP GenAI Security Project")).toBeInTheDocument();
    expect(screen.getAllByText("owasp-llm01-prompt-injection").length).toBeGreaterThan(0);
    expect(screen.getByRole("region", { name: "脱敏案件报告" })).toBeInTheDocument();
    const page = document.body.textContent ?? "";
    for (const forbidden of ["token_text", "token_id", "raw_output", "guard_raw_output"]) {
      expect(page).not.toContain(forbidden);
    }
  });

  it("degrades clearly when a legacy health response has no lab state", async () => {
    installFetch({ legacyHealth: true });
    render(<App />);

    expect(await screen.findByText("实验舱未启用")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "开始调查" })).toBeDisabled();
  });

  it("labels aggregate lab metrics separately from frozen classification performance", async () => {
    installFetch();
    render(<App />);
    await screen.findByText("实验舱已就绪");
    fireEvent.change(screen.getByLabelText("自定义 Prompt"), { target: { value: "SAFE_CUSTOM_INPUT" } });
    fireEvent.click(screen.getByRole("button", { name: "开始调查" }));

    expect(await screen.findByRole("region", { name: "实验舱运行指标" })).toBeInTheDocument();
    expect(screen.getByText("实验舱运行指标")).toBeInTheDocument();
    expect(screen.getByText("这些是运行覆盖与稳定性数据，不是冻结分类性能。" )).toBeInTheDocument();
    expect(screen.queryByText("agent-ablation-v1")).not.toBeInTheDocument();
  });

  it("positions the shared chart cursor by observation order for sparse indexes", () => {
    render(<LabSignalChart signals={[
      { index: 10, entropy: 1, nll: 1, cpd_entropy: 0, cpd_nll: 0, risk: 0.1 },
      { index: 20, entropy: 2, nll: 2, cpd_entropy: 1, cpd_nll: 0, risk: 0.2 },
    ]} />);

    expect(document.querySelector(".lab-chart-cursor")).toHaveAttribute("x1", "878");
  });
});
