import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { App } from "./App";
import type { LabRunResult } from "./types";

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
} satisfies LabRunResult;

function response(payload: unknown, ok = true) {
  return Promise.resolve({ ok, status: ok ? 200 : 503, json: async () => payload });
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

function installFetch(options: {
  health?: unknown;
  scenarios?: unknown;
  failRunAttempts?: number;
  run?: LabRunResult;
  pendingRun?: Promise<LabRunResult>;
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
      return (options.pendingRun ?? Promise.resolve(options.run ?? runResult)).then((run) => response({
        ...run,
        run_id: `challenge_run_${requests.length}`,
        scenario_id: body.sample_id,
        scenario_kind: body.sample_id.startsWith("synthetic_") ? "synthetic" : "protected",
        attack_family: body.sample_id.startsWith("autodan") ? "autodan" : null,
      }));
    }
    throw new Error(`Unexpected request: ${url}`);
  }));
  return requests;
}

async function beginChallengeWhenReady() {
  const beginButton = await screen.findByRole("button", { name: "进入挑战" });
  await waitFor(() => expect(beginButton).toBeEnabled());
  fireEvent.click(beginButton);
}

function selectAutomaticPresentation() {
  fireEvent.click(screen.getByRole("button", { name: "自动演示" }));
}

async function completeInteractiveRole(roleName: string, nextRoleName?: string) {
  fireEvent.click(await screen.findByRole("button", { name: roleName }));
  fireEvent.click(screen.getByRole("button", { name: "立即显示完整汇报" }));
  if (nextRoleName) {
    await waitFor(() => expect(screen.getByRole("button", { name: nextRoleName })).toBeEnabled());
  }
}

async function completeInteractiveInvestigation() {
  await completeInteractiveRole("Guard 语义侦探", "CPD 曲线侦探");
  await completeInteractiveRole("CPD 曲线侦探", "Agent 小队队长");
  await completeInteractiveRole("Agent 小队队长");
  return screen.findByRole("region", { name: "本关线索" });
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
    expect(screen.getByRole("button", { name: "Guard 语义侦探" })).toBeInTheDocument();
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

  it("defaults to interactive investigation and keeps auto mode selectable before start", async () => {
    installFetch();
    render(<App />);

    expect(await screen.findByRole("button", { name: "互动调查" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "自动演示" })).toHaveAttribute("aria-pressed", "false");
  });

  it("reveals evidence in strict detective order before showing the answer workspace", async () => {
    installFetch();
    render(<App />);
    await beginChallengeWhenReady();

    expect(await screen.findByRole("button", { name: "Guard 语义侦探" })).toBeEnabled();
    expect(screen.queryByRole("region", { name: "本关线索" })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /Guard 语义侦探/ }));
    const investigationDesk = screen.getByRole("region", { name: "中央证据台" });
    expect(investigationDesk).toBeInTheDocument();
    expect(investigationDesk).toHaveTextContent("语义侦探汇报");
    expect(screen.getByRole("region", { name: "可审计决策过程" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "CPD 曲线侦探" })).toBeDisabled();
    expect(screen.queryByRole("region", { name: "本关线索" })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "立即显示完整汇报" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "CPD 曲线侦探" })).toBeEnabled());
    fireEvent.click(screen.getByRole("button", { name: /CPD 曲线侦探/ }));
    expect(screen.getByRole("region", { name: "中央证据台" })).toHaveTextContent("曲线侦探汇报");
    expect(screen.getByRole("button", { name: "Agent 小队队长" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "立即显示完整汇报" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Agent 小队队长" })).toBeEnabled());

    fireEvent.click(screen.getByRole("button", { name: "Guard 语义侦探" }));
    expect(screen.getByRole("region", { name: "中央证据台" })).toHaveTextContent("语义侦探汇报");
    expect(screen.queryByRole("button", { name: "立即显示完整汇报" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Agent 小队队长" })).toBeEnabled();

    fireEvent.click(screen.getByRole("button", { name: /Agent 小队队长/ }));
    expect(screen.getByRole("region", { name: "中央证据台" })).toHaveTextContent("小队队长总结");
    expect(screen.queryByRole("region", { name: "本关线索" })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "立即显示完整汇报" }));
    const clues = await screen.findByRole("region", { name: "本关线索" });
    expect(screen.getAllByRole("figure")).toHaveLength(3);
    expect(investigationDesk).not.toContainElement(clues);
  });

  it("does not expose the system decision before the player answers", async () => {
    installFetch({ run: { ...runResult, detection: { ...runResult.detection, decision: "block" } } });
    render(<App />);
    await beginChallengeWhenReady();
    await completeInteractiveInvestigation();
    expect(screen.getByRole("region", { name: "中央证据台" })).not.toHaveTextContent("拦截");
  });

  it("reviews an earlier report without locking the captain again", async () => {
    installFetch();
    render(<App />);
    await beginChallengeWhenReady();
    await completeInteractiveRole("Guard 语义侦探", "CPD 曲线侦探");
    await completeInteractiveRole("CPD 曲线侦探", "Agent 小队队长");
    fireEvent.click(screen.getByRole("button", { name: /Guard 语义侦探/ }));
    expect(screen.getByRole("region", { name: "中央证据台" })).toHaveTextContent("语义侦探汇报");
    expect(screen.getByRole("button", { name: "Agent 小队队长" })).toBeEnabled();
  });

  it("keeps the answer workspace open and Guard idle after reviewing all completed reports", async () => {
    installFetch();
    render(<App />);
    await beginChallengeWhenReady();

    const workspace = await completeInteractiveInvestigation();
    const guard = screen.getByRole("button", { name: "Guard 语义侦探" });

    fireEvent.click(guard);

    expect(workspace).toBeInTheDocument();
    expect(guard.closest("figure")).toHaveAttribute("data-motion", "idle");
    expect(guard).toHaveAttribute("aria-pressed", "true");
    const statusId = guard.getAttribute("aria-describedby");
    expect(statusId).toBe("mascot-role-status-guard");
    expect(document.getElementById(statusId!)).toHaveTextContent("正在回看");
  });

  it("lets unavailable evidence complete all three investigation steps", async () => {
    installFetch({
      run: {
        ...runResult,
        detection: {
          ...runResult.detection,
          semantic_severity: "unavailable",
          semantic_categories: [],
          suspicious_span: null,
          signals: [],
        },
      },
    });
    render(<App />);
    await beginChallengeWhenReady();
    fireEvent.click(await screen.findByRole("button", { name: /Guard 语义侦探/ }));
    fireEvent.click(screen.getByRole("button", { name: "立即显示完整汇报" }));
    expect(screen.getByText("语义证据不可用")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole("button", { name: "CPD 曲线侦探" })).toBeEnabled());
    await completeInteractiveRole("CPD 曲线侦探", "Agent 小队队长");
    await completeInteractiveRole("Agent 小队队长");
    expect(await screen.findByRole("region", { name: "本关线索" })).toBeInTheDocument();
  });

  it("resets interactive progress on retry, next round, and exit", async () => {
    const requests = installFetch({ failRunAttempts: 1 });
    render(<App />);
    await beginChallengeWhenReady();

    expect(await screen.findByText("本关调查失败")).toBeInTheDocument();
    expect(screen.queryByText("可以汇报")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "重试本关" }));
    await waitFor(() => expect(requests.filter((item) => item.url === "/api/v1/lab/runs")).toHaveLength(2));
    expect(await screen.findByRole("button", { name: "Guard 语义侦探" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "CPD 曲线侦探" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Agent 小队队长" })).toBeDisabled();

    async function investigateAndAnswerRound() {
      await completeInteractiveInvestigation();
      fireEvent.click(screen.getByRole("button", { name: "仅分布异常" }));
      fireEvent.click(screen.getByRole("button", { name: "人工复核" }));
      fireEvent.click(screen.getByRole("button", { name: "选择 Token 2" }));
      fireEvent.click(screen.getByRole("button", { name: "提交研判" }));
      await screen.findByRole("region", { name: "本关揭晓" });
    }

    await investigateAndAnswerRound();
    fireEvent.click(screen.getByRole("button", { name: "下一关" }));
    await waitFor(() => expect(requests.filter((item) => item.url === "/api/v1/lab/runs")).toHaveLength(3));
    expect(await screen.findByRole("button", { name: "Guard 语义侦探" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "CPD 曲线侦探" })).toBeDisabled();
    expect(screen.queryByRole("region", { name: "中央证据台" })).not.toBeInTheDocument();

    await investigateAndAnswerRound();
    fireEvent.click(screen.getByRole("button", { name: "下一关" }));
    await waitFor(() => expect(requests.filter((item) => item.url === "/api/v1/lab/runs")).toHaveLength(4));
    expect(await screen.findByRole("button", { name: "Guard 语义侦探" })).toBeEnabled();
    await investigateAndAnswerRound();

    fireEvent.click(screen.getByRole("button", { name: "查看总分" }));
    fireEvent.click(screen.getByRole("button", { name: "退出挑战" }));
    expect(screen.getByRole("button", { name: "进入挑战" })).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "中央证据台" })).not.toBeInTheDocument();
    expect(screen.queryByText("可以汇报")).not.toBeInTheDocument();

    await beginChallengeWhenReady();
    await waitFor(() => expect(requests.filter((item) => item.url === "/api/v1/lab/runs")).toHaveLength(5));
    expect(await screen.findByRole("button", { name: "Guard 语义侦探" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "CPD 曲线侦探" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Agent 小队队长" })).toBeDisabled();
    expect(screen.queryByRole("region", { name: "中央证据台" })).not.toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "本关线索" })).not.toBeInTheDocument();
  });

  it("plays three redacted rounds, reveals deterministic scoring, and clears on exit", async () => {
    const requests = installFetch();
    render(<App />);

    await screen.findByRole("button", { name: "三关速战" });
    selectAutomaticPresentation();
    await beginChallengeWhenReady();

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
    expect(screen.getByText("检测结果回放")).toBeInTheDocument();
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
    const celebrationTeam = screen.getByRole("region", { name: "侦探学院调查小队" });
    expect(within(celebrationTeam).getAllByRole("figure")).toHaveLength(3);
    within(celebrationTeam).getAllByRole("figure").forEach((figure) => {
      expect(figure).toHaveAttribute("data-motion", "celebrate");
    });
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
    selectAutomaticPresentation();
    fireEvent.click(screen.getByRole("button", { name: "进入挑战" }));
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });

    expect(screen.getByRole("region", { name: "检测结果回放" })).toBeInTheDocument();
    const liveStage = screen.getByRole("status");
    expect(liveStage).toHaveAttribute("aria-live", "polite");
    expect(liveStage).toHaveAttribute("aria-atomic", "true");
    expect(liveStage).toHaveTextContent("检测结果回放 · 1 / 5");
    expect(liveStage).toHaveTextContent("语义等级已归一化。");
    expect(liveStage).toHaveTextContent("4 ms");
    expect(screen.getByRole("button", { name: "Guard 语义侦探" }).closest("figure"))
      .toHaveAttribute("data-motion", "hop");

    await act(async () => { await vi.advanceTimersByTimeAsync(699); });
    expect(screen.getByRole("status")).toBe(liveStage);
    expect(liveStage).toHaveTextContent("语义等级已归一化。");
    expect(screen.getByRole("button", { name: "Guard 语义侦探" }).closest("figure"))
      .toHaveAttribute("data-motion", "hop");

    await act(async () => { await vi.advanceTimersByTimeAsync(1); });
    expect(screen.getByRole("status")).toBe(liveStage);
    expect(liveStage).toHaveTextContent("Token 观测已完成。");
    expect(liveStage).toHaveTextContent("21 ms");
    expect(screen.getByRole("button", { name: "CPD 曲线侦探" }).closest("figure"))
      .toHaveAttribute("data-motion", "hop");

    const expectedStages = [
      ["CPD 候选已生成。", "服务端耗时不可用", "hop"],
      ["固定融合已完成。", "服务端耗时不可用", "hop"],
      ["知识证据已附加。", "3 ms", "hop"],
    ] as const;
    for (const [summary, latency, motion] of expectedStages) {
      await act(async () => { await vi.advanceTimersByTimeAsync(700); });
      expect(screen.getByRole("status")).toBe(liveStage);
      expect(liveStage).toHaveTextContent(summary);
      expect(liveStage).toHaveTextContent(latency);
      expect(screen.getAllByRole("figure").find((figure) => figure.dataset.motion !== "idle"))
        .toHaveAttribute("data-motion", motion);
    }

    await act(async () => { await vi.advanceTimersByTimeAsync(700); });
    expect(screen.getByRole("region", { name: "本关线索" })).toBeInTheDocument();
    expect(screen.getByRole("group", { name: "证据关系" })).toBeInTheDocument();
    expect(screen.getByRole("group", { name: "处置动作" })).toBeInTheDocument();
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("keeps every mascot idle until the run response returns", async () => {
    const pendingRun = deferred<typeof runResult>();
    installFetch({ pendingRun: pendingRun.promise });
    render(<App />);

    selectAutomaticPresentation();
    await beginChallengeWhenReady();

    expect(screen.getByText("正在等待脱敏检测结果")).toBeInTheDocument();
    const team = screen.getByRole("region", { name: "侦探学院调查小队" });
    expect(team).not.toHaveAttribute("data-stage");
    within(team).getAllByRole("figure").forEach((figure) => {
      expect(figure).toHaveAttribute("data-motion", "idle");
      expect(figure).not.toHaveClass("active");
    });

    await act(async () => {
      pendingRun.resolve(runResult);
      await pendingRun.promise;
    });
    expect(await screen.findByRole("region", { name: "检测结果回放" })).toBeInTheDocument();
    expect(team).toHaveAttribute("data-stage", "semantic_guard");
    expect(within(team).getByRole("button", { name: "Guard 语义侦探" }).closest("figure"))
      .toHaveAttribute("data-motion", "hop");
  });

  it("keeps evidence conflict hidden during replay and guessing", async () => {
    installFetch();
    render(<App />);

    selectAutomaticPresentation();
    await beginChallengeWhenReady();
    await screen.findByRole("region", { name: "检测结果回放" });
    expect(screen.queryByText("证据分歧")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Agent 小队队长" }).closest("figure"))
      .not.toHaveClass("conflict");

    fireEvent.click(screen.getByRole("button", { name: "跳过回放" }));
    expect(screen.getByRole("region", { name: "本关线索" })).toBeInTheDocument();
    expect(screen.queryByText("证据分歧")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Agent 小队队长" }).closest("figure"))
      .not.toHaveClass("conflict");

    fireEvent.click(screen.getByRole("button", { name: "仅分布异常" }));
    fireEvent.click(screen.getByRole("button", { name: "人工复核" }));
    fireEvent.click(screen.getByRole("button", { name: "选择 Token 2" }));
    fireEvent.click(screen.getByRole("button", { name: "提交研判" }));
    expect(screen.getByText("证据分歧")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Agent 小队队长" }).closest("figure"))
      .toHaveClass("conflict");
  });

  it("stops the replay timer permanently after skip", async () => {
    vi.useFakeTimers();
    installFetch();
    render(<App />);

    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });
    selectAutomaticPresentation();
    fireEvent.click(screen.getByRole("button", { name: "进入挑战" }));
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
      await Promise.resolve();
    });

    expect(screen.getByRole("region", { name: "检测结果回放" }))
      .toHaveTextContent("检测结果回放 · 1 / 5");
    expect(vi.getTimerCount()).toBe(1);
    fireEvent.click(screen.getByRole("button", { name: "跳过回放" }));
    expect(vi.getTimerCount()).toBe(0);

    await act(async () => { await vi.advanceTimersByTimeAsync(7_000); });
    expect(screen.getByRole("region", { name: "本关线索" })).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "检测结果回放" })).not.toBeInTheDocument();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("shows fixed failure copy and retries the same round without a score penalty", async () => {
    const requests = installFetch({ failRunAttempts: 1 });
    render(<App />);

    selectAutomaticPresentation();
    await beginChallengeWhenReady();
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

    selectAutomaticPresentation();
    await beginChallengeWhenReady();
    fireEvent.click(await screen.findByRole("button", { name: "跳过回放" }));
    fireEvent.click(screen.getByRole("button", { name: "仅分布异常" }));
    fireEvent.click(screen.getByRole("button", { name: "人工复核" }));
    fireEvent.click(screen.getByRole("button", { name: "选择 Token 2" }));
    fireEvent.click(screen.getByRole("button", { name: "提交研判" }));

    expect(screen.getByRole("region", { name: "本关揭晓" })).toBeInTheDocument();
  });

  it("does not require an evidence answer when the system relation is unavailable", async () => {
    installFetch({
      run: {
        ...runResult,
        detection: {
          ...runResult.detection,
          semantic_severity: "unavailable",
          detector_status: "no_token_anomaly",
        },
      },
    });
    render(<App />);

    selectAutomaticPresentation();
    await beginChallengeWhenReady();
    fireEvent.click(await screen.findByRole("button", { name: "跳过回放" }));
    expect(screen.getByText("证据关系不适用")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "放行" }));
    fireEvent.click(screen.getByRole("button", { name: "选择 Token 2" }));
    expect(screen.getByRole("button", { name: "提交研判" })).toBeEnabled();
    fireEvent.click(screen.getByRole("button", { name: "提交研判" }));
    expect(screen.getByRole("region", { name: "本关揭晓" })).toBeInTheDocument();
  });

  it("allows a zero-point onset submission when no signal position is selectable", async () => {
    installFetch({
      run: {
        ...runResult,
        detection: {
          ...runResult.detection,
          signals: [runResult.detection.signals[0]],
        },
      },
    });
    render(<App />);

    selectAutomaticPresentation();
    await beginChallengeWhenReady();
    fireEvent.click(await screen.findByRole("button", { name: "跳过回放" }));
    fireEvent.click(screen.getByRole("button", { name: "仅分布异常" }));
    fireEvent.click(screen.getByRole("button", { name: "人工复核" }));
    expect(screen.getByText("信号不足，定位按未选择计分")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "提交研判" })).toBeEnabled();
    fireEvent.click(screen.getByRole("button", { name: "提交研判" }));
    expect(screen.getByRole("region", { name: "本关揭晓" })).toBeInTheDocument();
  });
});
