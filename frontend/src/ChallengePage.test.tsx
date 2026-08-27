import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { App } from "./App";

const health = {
  status: "ok",
  model: { ready: true, model_id: "qwen-model" },
  detector: { ready: true, calibration_version: "cal-v2" },
  lab: { enabled: true, ready: true, reason: "ready" },
};

const scenarios = [
  { scenario_id: "synthetic_safe", label: "普通无害", scenario_kind: "synthetic", attack_family: null, ready: true },
  { scenario_id: "synthetic_shift", label: "无害格式突变", scenario_kind: "synthetic", attack_family: null, ready: true },
  { scenario_id: "gcg_01", label: "GCG", scenario_kind: "protected", attack_family: "gcg", ready: true },
  { scenario_id: "autodan_01", label: "AutoDAN", scenario_kind: "protected", attack_family: "autodan", ready: true },
  { scenario_id: "adv_01", label: "AdvPrompter", scenario_kind: "protected", attack_family: "advprompter", ready: true },
];

const runResult = {
  run_id: "challenge_run_1",
  status: "completed",
  scenario_id: "synthetic_safe",
  scenario_kind: "synthetic",
  scenario_label: "挑战样本",
  attack_family: null,
  mode: "analysis",
  created_at: "2026-08-27T09:00:00Z",
  stages: [
    { stage_id: "semantic_guard", status: "succeeded", latency_ms: 4, timing_basis: "measured", summary: "语义等级已归一化。" },
    { stage_id: "token_observation", status: "succeeded", latency_ms: 21, timing_basis: "combined", summary: "Token 观测已完成。" },
    { stage_id: "entropy_cpd", status: "succeeded", latency_ms: null, timing_basis: "unavailable", summary: "CPD 候选已生成。" },
    { stage_id: "fixed_fusion", status: "succeeded", latency_ms: null, timing_basis: "unavailable", summary: "固定融合已完成。" },
    { stage_id: "knowledge_retrieval", status: "succeeded", latency_ms: 3, timing_basis: "measured", summary: "知识证据已附加。" },
  ],
  detection: {
    decision: "sanitize_recheck",
    risk_score: 0.72,
    detector_score: 8.4,
    detector_status: "token_anomaly_candidate",
    semantic_severity: "safe",
    semantic_categories: [],
    semantic_model_id: "guard-model",
    semantic_model_version: "guard-v1",
    semantic_latency_ms: 4,
    fusion_reason: "cpd_candidate",
    suspicious_span: { token_start: 2, token_end: 3, char_start: 0, char_end: 0 },
    signals: [
      { index: 0, entropy: 0.8, nll: 1.1, cpd_entropy: 0, cpd_nll: 0, risk: 0.1 },
      { index: 1, entropy: 1.2, nll: 1.6, cpd_entropy: 0.4, cpd_nll: 0, risk: 0.2 },
      { index: 2, entropy: 3.8, nll: 4.4, cpd_entropy: 5.8, cpd_nll: 0, risk: 0.9 },
    ],
    provenance: {
      model_id: "qwen-model",
      tokenizer_id: "qwen-tokenizer",
      system_prompt_hash: "sha256:system",
      calibration_version: "cal-v2",
      thresholds: { k: 0.5, h: 5 },
    },
    latency_ms: 28,
    knowledge_status: "ready",
    knowledge_snapshot_version: "official-v1",
    knowledge_latency_ms: 3,
    knowledge_evidence: [{
      knowledge_id: "owasp-llm01-prompt-injection",
      title_zh: "提示词注入控制",
      risk_domain: "prompt_injection",
      summary: "分层控制建议。",
      recommendations: ["保留基础动作。"],
      source: {
        publisher: "owasp",
        title: "OWASP GenAI Security Project",
        url: "https://genai.owasp.org/",
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
    char_start: 0,
    calibration_version: "cal-v2",
    original: { semantic_severity: "safe", detector_status: "token_anomaly_candidate", risk_score: 0.72, detector_score: 8.4, decision: "sanitize_recheck", latency_ms: 28 },
    rechecked: { semantic_severity: "safe", detector_status: "no_token_anomaly", risk_score: 0.1, detector_score: 0.2, decision: "allow", latency_ms: 20 },
    risk_score_delta: 0.62,
    detector_score_delta: 8.2,
    action_changed: true,
  },
  tool_plans: [],
  tool_results: [],
  case_report: {
    report_status: "deterministic",
    summary: "脱敏案件摘要",
    evidence_ids: ["owasp-llm01-prompt-injection"],
    handling_steps: ["保留基础动作。"],
    limitations: ["敏感性证据不构成严格因果证明。"],
    tool_statuses: {},
  },
};

function response(payload: unknown, ok = true) {
  return Promise.resolve({ ok, status: ok ? 200 : 503, json: async () => payload });
}

function installFetch(options: {
  health?: unknown;
  scenarios?: unknown;
  failRunAttempts?: number;
  run?: typeof runResult;
} = {}) {
  const requests: Array<{ url: string; init?: RequestInit }> = [];
  let runAttempts = 0;
  vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    requests.push({ url, init });
    if (url === "/health") return response(options.health ?? health);
    if (url === "/api/v1/lab/scenarios") return response(options.scenarios ?? scenarios);
    if (url === "/api/v1/lab/runs") {
      runAttempts += 1;
      if (runAttempts <= (options.failRunAttempts ?? 0)) {
        return Promise.reject(new Error("private upstream detail"));
      }
      const body = JSON.parse(String(init?.body));
      return response({
        ...(options.run ?? runResult),
        run_id: `challenge_run_${requests.length}`,
        scenario_id: body.sample_id,
        scenario_kind: body.sample_id.startsWith("synthetic_") ? "synthetic" : "protected",
        attack_family: body.sample_id.startsWith("autodan") ? "autodan" : null,
      });
    }
    throw new Error(`Unexpected request: ${url}`);
  }));
  return requests;
}

describe("token detective challenge setup", () => {
  beforeEach(() => {
    window.history.pushState({}, "", "/challenge");
  });

  afterEach(() => {
    cleanup();
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("adds an isolated challenge route with speed and full setup choices", async () => {
    const requests = installFetch();
    render(<App />);

    expect(await screen.findByRole("main", { name: "Token 侦探挑战" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "侦探挑战" })).toHaveClass("active");
    expect(screen.getByRole("link", { name: "专业调查" })).toHaveAttribute("href", "/lab");
    expect(screen.getByRole("button", { name: "三关速战" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "五关完整挑战" })).toBeEnabled();
    expect(screen.getByRole("img", { name: "Guard 语义侦探" })).toBeInTheDocument();
    expect(requests.map((item) => item.url).sort()).toEqual([
      "/api/v1/lab/scenarios",
      "/health",
    ]);
    expect(requests.every((item) => item.init?.method === undefined)).toBe(true);
  });

  it("disables setup when the lab is unavailable", async () => {
    installFetch({
      health: { ...health, lab: { enabled: false, ready: false, reason: "disabled" } },
    });
    render(<App />);

    expect(await screen.findByText("挑战模式不可用")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "三关速战" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "五关完整挑战" })).toBeDisabled();
  });

  it("keeps speed mode available and labels a missing full-mode family", async () => {
    installFetch({
      scenarios: scenarios.filter((scenario) => scenario.attack_family !== "gcg"),
    });
    render(<App />);

    expect(await screen.findByText("完整挑战缺少：GCG")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "三关速战" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "五关完整挑战" })).toBeDisabled();
  });

  it("treats a legacy health response without lab state as unavailable", async () => {
    const { lab: _, ...legacyHealth } = health;
    installFetch({ health: legacyHealth });
    render(<App />);

    expect(await screen.findByText("挑战模式不可用")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "三关速战" })).toBeDisabled();
  });

  it("plays three redacted rounds, reveals deterministic scoring, and clears on exit", async () => {
    const requests = installFetch();
    render(<App />);

    await screen.findByRole("button", { name: "三关速战" });
    fireEvent.click(screen.getByRole("button", { name: "进入挑战" }));

    fireEvent.click(await screen.findByRole("button", { name: "跳过回放" }));

    const clues = await screen.findByRole("region", { name: "本关线索" });
    expect(JSON.parse(String(requests.find((item) => item.url === "/api/v1/lab/runs")?.init?.body))).toEqual({
      scenario_kind: "frozen",
      sample_id: "synthetic_safe",
      mode: "analysis",
    });
    expect(within(clues).getByText("语义安全")).toBeInTheDocument();
    expect(within(clues).getByRole("img", { name: "Token 挑战信号曲线" })).toBeInTheDocument();
    expect(screen.queryByText("基础动作")).not.toBeInTheDocument();
    expect(screen.queryByText("cpd_candidate")).not.toBeInTheDocument();
    expect(screen.queryByText("risk_reduced")).not.toBeInTheDocument();
    expect(screen.queryByText("owasp-llm01-prompt-injection")).not.toBeInTheDocument();
    expect(screen.queryByText("本关百分制分数")).not.toBeInTheDocument();

    async function answerRound() {
      fireEvent.click(screen.getByRole("button", { name: "仅分布异常" }));
      fireEvent.click(screen.getByRole("button", { name: "人工复核" }));
      fireEvent.click(screen.getByRole("button", { name: "选择 Token 2" }));
      fireEvent.click(screen.getByRole("button", { name: "提交研判" }));
      return screen.findByRole("region", { name: "本关揭晓" });
    }

    const firstReveal = await answerRound();
    expect(within(firstReveal).getByText("净化后复检（按复核类计分）")).toBeInTheDocument();
    expect(within(firstReveal).getByText("本关百分制分数")).toBeInTheDocument();
    expect(within(firstReveal).getByText("100")).toBeInTheDocument();
    expect(screen.getByText("调查过程回放")).toBeInTheDocument();
    expect(screen.getByText("挑战得分不是检测准确率或攻击覆盖率")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "下一关" }));
    await waitFor(() => expect(requests.filter((item) => item.url === "/api/v1/lab/runs")).toHaveLength(2));
    fireEvent.click(await screen.findByRole("button", { name: "跳过回放" }));
    await screen.findByRole("region", { name: "本关线索" });
    await answerRound();

    fireEvent.click(screen.getByRole("button", { name: "下一关" }));
    await waitFor(() => expect(requests.filter((item) => item.url === "/api/v1/lab/runs")).toHaveLength(3));
    fireEvent.click(await screen.findByRole("button", { name: "跳过回放" }));
    await screen.findByRole("region", { name: "本关线索" });
    await answerRound();

    const protectedBody = String(requests.filter((item) => item.url === "/api/v1/lab/runs").at(-1)?.init?.body);
    expect(JSON.parse(protectedBody)).toEqual({
      scenario_kind: "frozen",
      sample_id: "autodan_01",
      mode: "analysis",
    });
    for (const forbidden of ["prompt", "suffix", "token_text", "token_id", "query_text", "raw_output", "guard_raw_output"]) {
      expect(protectedBody).not.toContain(`\"${forbidden}\"`);
    }

    fireEvent.click(screen.getByRole("button", { name: "查看总分" }));
    expect(screen.getByRole("region", { name: "挑战总结" })).toHaveTextContent("总分 100");
    fireEvent.click(screen.getByRole("button", { name: "退出挑战" }));
    expect(screen.getByRole("button", { name: "进入挑战" })).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "本关揭晓" })).not.toBeInTheDocument();
  });

  it("replays returned stages at a presentation interval and preserves server latency", async () => {
    vi.useFakeTimers();
    installFetch();
    render(<App />);

    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });
    fireEvent.click(screen.getByRole("button", { name: "进入挑战" }));
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });

    expect(screen.getByRole("region", { name: "调查过程回放" })).toBeInTheDocument();
    expect(screen.getByText("4 ms")).toBeInTheDocument();
    expect(screen.getByRole("img", { name: "Guard 语义侦探" }).closest("figure")).toHaveClass("active");

    await act(async () => { await vi.advanceTimersByTimeAsync(350); });
    expect(screen.getByRole("img", { name: "CPD 曲线侦探" }).closest("figure")).toHaveClass("active");
    fireEvent.click(screen.getByRole("button", { name: "跳过回放" }));
    expect(screen.getByRole("region", { name: "本关线索" })).toBeInTheDocument();
    expect(screen.getByRole("group", { name: "证据关系" })).toBeInTheDocument();
    expect(screen.getByRole("group", { name: "处置动作" })).toBeInTheDocument();
  });

  it("shows fixed failure copy and retries the same round without a score penalty", async () => {
    const requests = installFetch({ failRunAttempts: 1 });
    render(<App />);

    await screen.findByRole("button", { name: "进入挑战" });
    fireEvent.click(screen.getByRole("button", { name: "进入挑战" }));
    expect(await screen.findByText("本关调查失败")).toBeInTheDocument();
    expect(screen.queryByText("private upstream detail")).not.toBeInTheDocument();
    expect(screen.getByText("当前总分").parentElement).toHaveTextContent("0");

    fireEvent.click(screen.getByRole("button", { name: "重试本关" }));
    await waitFor(() => expect(requests.filter((item) => item.url === "/api/v1/lab/runs")).toHaveLength(2));
    fireEvent.click(await screen.findByRole("button", { name: "跳过回放" }));
    expect(screen.getByRole("region", { name: "本关线索" })).toBeInTheDocument();
  });

  it("allows scoring when the returned knowledge stage is unavailable", async () => {
    installFetch({
      run: {
        ...runResult,
        stages: runResult.stages.map((stage) => stage.stage_id === "knowledge_retrieval"
          ? { ...stage, status: "unavailable", latency_ms: null, timing_basis: "unavailable" }
          : stage),
      },
    });
    render(<App />);

    await screen.findByRole("button", { name: "进入挑战" });
    fireEvent.click(screen.getByRole("button", { name: "进入挑战" }));
    fireEvent.click(await screen.findByRole("button", { name: "跳过回放" }));
    fireEvent.click(screen.getByRole("button", { name: "仅分布异常" }));
    fireEvent.click(screen.getByRole("button", { name: "人工复核" }));
    fireEvent.click(screen.getByRole("button", { name: "选择 Token 2" }));
    fireEvent.click(screen.getByRole("button", { name: "提交研判" }));

    expect(screen.getByRole("region", { name: "本关揭晓" })).toBeInTheDocument();
  });
});
