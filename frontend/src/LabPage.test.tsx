import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { StrictMode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { App } from "./App";
import { LabSignalChart } from "./components/LabSignalChart";

const PRIVATE_RENDER_SENTINEL = "TASK9_FRONTEND_PRIVATE_SENTINEL_1c888ea6";

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
  confirmed_execution_count: 0,
  preserved_action_execution_count: 0,
  action_preservation_rate: null,
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
    }, {
      knowledge_id: "cac-generative-ai-interim-measures",
      title_zh: "生成式人工智能服务管理要求",
      risk_domain: "governance",
      summary: "面向公众的生成式人工智能服务应兼顾发展与安全治理。",
      recommendations: ["明确服务提供者的安全治理和事件处置责任。"],
      source: {
        publisher: "cac",
        title: "生成式人工智能服务管理暂行办法",
        url: "https://www.cac.gov.cn/2023-07/13/c_1690898327029107.htm",
        version: "2023",
        verified_at: "2026-08-28T00:00:00Z",
        usage_note: "中文摘要依据国家网信办官方发布。",
      },
      retrieval_score: 3,
      matched_tags: ["governance"],
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
    { tool_id: "gateway_enforcement", title: "网关策略预览", status: "planned", effective_action: "block", artifact_summary: "预览网关执行 block。", knowledge_ids: ["owasp-llm01-prompt-injection"] },
    { tool_id: "security_case", title: "安全工单预览", status: "planned", effective_action: "block", artifact_summary: "预览脱敏安全工单。", knowledge_ids: ["owasp-llm01-prompt-injection"] },
    { tool_id: "evidence_bundle", title: "证据清单预览", status: "planned", effective_action: "block", artifact_summary: "预览结构化证据清单。", knowledge_ids: ["owasp-llm01-prompt-injection"] },
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

const execution = {
  execution_id: "exec_00000000000000000000000000000001",
  run_id: "lab_123",
  tool_id: "gateway_enforcement",
  status: "succeeded",
  effective_action: "block",
  receipt_id: "receipt_00000000000000000000000000000001",
  artifact_id: null,
  error_code: null,
  latency_ms: 4.2,
  created_at: "2026-08-28T10:20:30Z",
  evidence_sha256: null,
  source_action: "allow",
  idempotency_key: "PRIVATE_IDEMPOTENCY_KEY",
  model_provenance_sha256: "PRIVATE_MODEL_DIGEST",
  calibration_provenance_sha256: "PRIVATE_CALIBRATION_DIGEST",
  hidden_reasoning: "PRIVATE_REASONING",
  prompt: "PRIVATE_PROMPT",
  suffix: "PRIVATE_SUFFIX",
  token_text: "PRIVATE_TOKEN_TEXT",
  token_id: "PRIVATE_TOKEN_ID",
  query_text: "PRIVATE_QUERY_TEXT",
  raw_output: "PRIVATE_RAW_OUTPUT",
  guard_raw_output: PRIVATE_RENDER_SENTINEL,
};

const evidenceExecution = {
  ...execution,
  execution_id: "exec_00000000000000000000000000000002",
  tool_id: "evidence_bundle",
  receipt_id: "receipt_00000000000000000000000000000002",
  artifact_id: "artifact_00000000000000000000000000000001",
  evidence_sha256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
};

function response(payload: unknown, ok = true, status = 200) {
  return Promise.resolve({ ok, status, json: async () => payload });
}

function installFetch(options: {
  legacyHealth?: boolean;
  history?: unknown[];
  executeResponses?: Array<{ payload: unknown; ok?: boolean; status?: number }>;
  runs?: unknown[];
  scenarioFailure?: boolean;
  metricsFailure?: boolean;
} = {}) {
  const requests: Array<{ url: string; init?: RequestInit }> = [];
  const executeResponses = [...(options.executeResponses ?? [])];
  const runs = [...(options.runs ?? [run])];
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
    if (url === "/api/v1/lab/scenarios") {
      return options.scenarioFailure
        ? response({ error: { message: "scenario unavailable" } }, false, 503)
        : response(scenarios);
    }
    if (url === "/api/v1/lab/metrics") {
      return options.metricsFailure
        ? response({ error: { message: "metrics unavailable" } }, false, 503)
        : response(metrics);
    }
    if (url === "/api/v1/lab/runs") return response(runs.shift() ?? run, true, 201);
    if (url === "/api/v1/lab/runs/lab_123") return response(run);
    if (url.endsWith("/executions")) return response(options.history ?? []);
    if (url.includes("/execute")) {
      const next = executeResponses.shift();
      return response(next?.payload ?? execution, next?.ok ?? true, next?.status ?? 201);
    }
    if (url.includes("/tools/gateway_enforcement/dry-run")) {
      return response({
        ...run,
        tool_results: [{
          tool_id: "gateway_enforcement",
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

async function startRun() {
  await screen.findByText("实验舱已就绪");
  fireEvent.change(screen.getByLabelText("自定义 Prompt"), { target: { value: "SAFE_CUSTOM_INPUT" } });
  fireEvent.click(screen.getByRole("button", { name: "开始调查" }));
  await screen.findByText("证据到达顺序");
}

describe("security lab workspace", () => {
  beforeEach(() => {
    window.history.pushState({}, "", "/lab");
    window.sessionStorage.clear();
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
      target: { value: PRIVATE_RENDER_SENTINEL },
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
      custom_input: PRIVATE_RENDER_SENTINEL,
      mode: "analysis",
    });
    expect(document.body).not.toHaveTextContent(PRIVATE_RENDER_SENTINEL);
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

  it("separates tool preview from confirmed platform-internal execution", async () => {
    const requests = installFetch();
    render(<App />);
    await startRun();
    fireEvent.click(screen.getByRole("tab", { name: "工具执行中心" }));

    const toolCenter = screen.getByRole("region", { name: "工具执行中心" });
    expect(within(toolCenter).getAllByRole("button", { name: /^预览/ })).toHaveLength(3);
    expect(within(toolCenter).getAllByRole("button", { name: /^确认执行/ })).toHaveLength(3);
    const preview = within(toolCenter).getByRole("button", { name: "预览网关策略预览" });
    expect(preview).toHaveAttribute("title", "预览网关策略预览");
    fireEvent.click(preview);
    expect(await within(toolCenter).findByText("预览失败")).toBeInTheDocument();
    expect(requests.some((item) => item.url.endsWith("/tools/gateway_enforcement/dry-run"))).toBe(true);
    expect(requests.some((item) => item.url.includes("/execute"))).toBe(false);
  });

  it("restores the last redacted run and execution history after refresh", async () => {
    const requests = installFetch({ history: [execution] });
    window.sessionStorage.setItem("token-security-lab-run-id", run.run_id);

    render(<App />);

    expect(await screen.findByText("证据到达顺序")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "工具执行中心" }));
    expect(await screen.findByText(execution.receipt_id)).toBeInTheDocument();
    expect(requests.some((item) => item.url === "/api/v1/lab/runs/lab_123")).toBe(true);
    expect(requests.some((item) => item.url === "/api/v1/lab/runs" && item.init?.method === "POST")).toBe(false);
  });

  it.each([
    ["场景", { scenarioFailure: true }],
    ["指标", { metricsFailure: true }],
  ])("辅助%s接口失败时仍恢复最后一次脱敏运行", async (_label, failure) => {
    const requests = installFetch(failure);
    window.sessionStorage.setItem("token-security-lab-run-id", run.run_id);

    render(<App />);

    expect(await screen.findByText("证据到达顺序")).toBeInTheDocument();
    expect(requests.some((item) => item.url === "/api/v1/lab/runs/lab_123")).toBe(true);
  });

  it("requires explicit confirmation, focuses cancel, and cancels without a request", async () => {
    const requests = installFetch();
    render(<App />);
    await startRun();
    fireEvent.click(screen.getByRole("tab", { name: "工具执行中心" }));
    const executeButton = screen.getByRole("button", { name: "确认执行网关策略预览" });
    fireEvent.click(executeButton);

    const dialog = screen.getByRole("dialog", { name: "确认平台内部执行" });
    expect(dialog.tagName).toBe("DIALOG");
    expect(within(dialog).getByText(/仅在本平台内部执行/)).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "取消" })).toHaveFocus();
    fireEvent.keyDown(dialog, { key: "Escape" });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(executeButton).toHaveFocus();

    fireEvent.click(screen.getByRole("button", { name: "确认执行网关策略预览" }));
    fireEvent.click(screen.getByRole("button", { name: "取消" }));
    expect(requests.some((item) => item.url.includes("/execute"))).toBe(false);
  });

  it("posts only confirmation and a UUID, then renders one verifiable receipt", async () => {
    const uuid = "00000000-0000-0000-0000-000000000099";
    vi.spyOn(globalThis.crypto, "randomUUID").mockReturnValue(uuid);
    const requests = installFetch({ history: [execution] });
    render(<App />);
    await startRun();
    fireEvent.click(screen.getByRole("tab", { name: "工具执行中心" }));
    fireEvent.click(screen.getByRole("button", { name: "确认执行网关策略预览" }));
    fireEvent.click(screen.getByRole("button", { name: "仅在平台内部执行" }));

    expect(await screen.findByText(execution.receipt_id)).toBeInTheDocument();
    const executeRequest = requests.find((item) => item.url.endsWith("/tools/gateway_enforcement/execute"));
    expect(JSON.parse(String(executeRequest?.init?.body))).toEqual({ confirmed: true, idempotency_key: uuid });
    expect(screen.getAllByText(execution.receipt_id)).toHaveLength(1);
    expect(screen.getByText("拦截")).toBeInTheDocument();
    expect(screen.getByText("2026/08/28 18:20:30")).toBeInTheDocument();
    const toolCenterText = screen.getByRole("region", { name: "工具执行中心" }).textContent ?? "";
    for (const forbidden of [
      "PRIVATE_IDEMPOTENCY_KEY", "PRIVATE_MODEL_DIGEST", "PRIVATE_CALIBRATION_DIGEST",
      "PRIVATE_REASONING", "PRIVATE_PROMPT", "PRIVATE_SUFFIX", "PRIVATE_TOKEN_TEXT", "allow",
      "PRIVATE_TOKEN_ID", "PRIVATE_QUERY_TEXT", "PRIVATE_RAW_OUTPUT", PRIVATE_RENDER_SENTINEL,
    ]) {
      expect(toolCenterText).not.toContain(forbidden);
    }
  });

  it("restores evidence receipts with SHA-256 and a download command", async () => {
    installFetch({ history: [evidenceExecution] });
    render(<App />);
    await startRun();
    fireEvent.click(screen.getByRole("tab", { name: "工具执行中心" }));

    expect(await screen.findByText(evidenceExecution.receipt_id)).toBeInTheDocument();
    expect(screen.getByText(evidenceExecution.evidence_sha256)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "下载证据包" })).toHaveAttribute(
      "href",
      `/api/v1/lab/artifacts/${evidenceExecution.artifact_id}/download`,
    );
  });

  it("keeps both row actions disabled while execution is pending", async () => {
    let resolveExecution!: (value: Awaited<ReturnType<typeof response>>) => void;
    const pendingExecution = new Promise<Awaited<ReturnType<typeof response>>>((resolve) => {
      resolveExecution = resolve;
    });
    const requests = installFetch();
    const fetchMock = vi.mocked(fetch);
    const baseFetch = fetchMock.getMockImplementation();
    fetchMock.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).includes("/execute")) {
        requests.push({ url: String(input), init });
        return pendingExecution as ReturnType<typeof fetch>;
      }
      if (baseFetch) return baseFetch(input, init) as ReturnType<typeof fetch>;
      throw new Error(`Unexpected replacement request: ${String(input)}`);
    });
    render(<App />);
    await startRun();
    fireEvent.click(screen.getByRole("tab", { name: "工具执行中心" }));
    fireEvent.click(screen.getByRole("button", { name: "确认执行网关策略预览" }));
    fireEvent.click(screen.getByRole("button", { name: "仅在平台内部执行" }));

    const row = screen.getByRole("article", { name: "网关策略预览" });
    expect(within(row).getByRole("button", { name: "预览网关策略预览" })).toBeDisabled();
    expect(within(row).getByRole("button", { name: "正在执行网关策略预览" })).toBeDisabled();
    resolveExecution(await response(execution));
    expect(await screen.findByText(execution.receipt_id)).toBeInTheDocument();
  });

  it("retries network or 503 failures with the same per-tool UUID", async () => {
    const uuid = "00000000-0000-0000-0000-000000000077";
    vi.spyOn(globalThis.crypto, "randomUUID").mockReturnValue(uuid);
    const requests = installFetch({ executeResponses: [
      { payload: { error: { code: "lab_tool_storage_unavailable", message: "PRIVATE_RAW_ERROR" } }, ok: false, status: 503 },
      { payload: execution, status: 200 },
    ] });
    render(<App />);
    await startRun();
    fireEvent.click(screen.getByRole("tab", { name: "工具执行中心" }));

    for (let attempt = 0; attempt < 2; attempt += 1) {
      fireEvent.click(screen.getByRole("button", { name: "确认执行网关策略预览" }));
      fireEvent.click(screen.getByRole("button", { name: "仅在平台内部执行" }));
      if (attempt === 0) await screen.findByText("平台内部执行暂不可用，请重试。");
    }

    expect(await screen.findByText(execution.receipt_id)).toBeInTheDocument();
    const bodies = requests
      .filter((item) => item.url.endsWith("/tools/gateway_enforcement/execute"))
      .map((item) => JSON.parse(String(item.init?.body)));
    expect(bodies).toEqual([
      { confirmed: true, idempotency_key: uuid },
      { confirmed: true, idempotency_key: uuid },
    ]);
    expect(document.body).not.toHaveTextContent("PRIVATE_RAW_ERROR");
  });

  it("ignores stale execution history after switching runs", async () => {
    const secondRun = { ...run, run_id: "lab_456", scenario_label: "第二次调查" };
    let resolveFirstHistory!: (value: Awaited<ReturnType<typeof response>>) => void;
    const firstHistory = new Promise<Awaited<ReturnType<typeof response>>>((resolve) => {
      resolveFirstHistory = resolve;
    });
    const requests: Array<{ url: string; init?: RequestInit }> = [];
    let createCount = 0;
    vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      requests.push({ url, init });
      if (url === "/health") return response(health);
      if (url === "/api/v1/lab/scenarios") return response(scenarios);
      if (url === "/api/v1/lab/metrics") return response(metrics);
      if (url === "/api/v1/lab/runs") return response(createCount++ === 0 ? run : secondRun, true, 201);
      if (url === "/api/v1/lab/runs/lab_123/executions") return firstHistory;
      if (url === "/api/v1/lab/runs/lab_456/executions") return response([]);
      throw new Error(`Unexpected request: ${url}`);
    }));
    render(<App />);
    await startRun();
    fireEvent.change(screen.getByLabelText("自定义 Prompt"), { target: { value: "SECOND_SAFE_INPUT" } });
    fireEvent.click(screen.getByRole("button", { name: "开始调查" }));
    await waitFor(() => expect(requests.some((item) => item.url === "/api/v1/lab/runs/lab_456/executions")).toBe(true));
    resolveFirstHistory(await response([execution]));
    fireEvent.click(screen.getByRole("tab", { name: "工具执行中心" }));

    expect(screen.queryByText(execution.receipt_id)).not.toBeInTheDocument();
    expect(requests.filter((item) => item.url.endsWith("/executions"))).toHaveLength(2);
  });

  it("loads execution history once per run under StrictMode effect replay", async () => {
    const requests = installFetch();
    render(<StrictMode><App /></StrictMode>);
    await startRun();

    expect(requests.filter((item) => item.url === "/api/v1/lab/runs/lab_123/executions")).toHaveLength(1);
  });

  it("retries a failed StrictMode history load on an accessible user command", async () => {
    const requests = installFetch();
    const fetchMock = vi.mocked(fetch);
    const baseFetch = fetchMock.getMockImplementation();
    let historyAttempts = 0;
    fetchMock.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/executions")) {
        requests.push({ url, init });
        historyAttempts += 1;
        return historyAttempts === 1
          ? response({ error: { code: "lab_tool_storage_unavailable", message: "PRIVATE_HISTORY_ERROR" } }, false, 503) as ReturnType<typeof fetch>
          : response([execution]) as ReturnType<typeof fetch>;
      }
      if (baseFetch) return baseFetch(input, init) as ReturnType<typeof fetch>;
      throw new Error(`Unexpected replacement request: ${url}`);
    });
    render(<StrictMode><App /></StrictMode>);
    await startRun();
    fireEvent.click(screen.getByRole("tab", { name: "工具执行中心" }));

    const retry = await screen.findByRole("button", { name: "重试执行历史" });
    expect(requests.filter((item) => item.url.endsWith("/executions"))).toHaveLength(1);
    expect(document.body).not.toHaveTextContent("PRIVATE_HISTORY_ERROR");
    fireEvent.click(retry);

    expect(await screen.findByText(execution.receipt_id)).toBeInTheDocument();
    expect(requests.filter((item) => item.url.endsWith("/executions"))).toHaveLength(2);
  });

  it("keeps newer execution receipts first when delayed history arrives", async () => {
    const oldExecution = {
      ...execution,
      execution_id: "exec_00000000000000000000000000000000",
      receipt_id: "receipt_00000000000000000000000000000000",
      created_at: "2026-08-28T09:00:00Z",
    };
    let resolveHistory!: (value: Awaited<ReturnType<typeof response>>) => void;
    const pendingHistory = new Promise<Awaited<ReturnType<typeof response>>>((resolve) => {
      resolveHistory = resolve;
    });
    installFetch();
    const fetchMock = vi.mocked(fetch);
    const baseFetch = fetchMock.getMockImplementation();
    fetchMock.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith("/executions")) return pendingHistory as ReturnType<typeof fetch>;
      if (baseFetch) return baseFetch(input, init) as ReturnType<typeof fetch>;
      throw new Error(`Unexpected replacement request: ${String(input)}`);
    });
    render(<App />);
    await startRun();
    fireEvent.click(screen.getByRole("tab", { name: "工具执行中心" }));
    fireEvent.click(screen.getByRole("button", { name: "确认执行网关策略预览" }));
    fireEvent.click(screen.getByRole("button", { name: "仅在平台内部执行" }));
    expect(await screen.findByText(execution.receipt_id)).toBeInTheDocument();

    resolveHistory(await response([oldExecution, execution]));
    expect(await screen.findByText(oldExecution.receipt_id)).toBeInTheDocument();
    const ledger = screen.getByText("回执账本").closest(".lab-receipt-ledger");
    const rows = ledger?.querySelectorAll(".lab-receipt-row") ?? [];
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveTextContent(execution.receipt_id);
    expect(rows[1]).toHaveTextContent(oldExecution.receipt_id);
    expect(screen.getAllByText(execution.receipt_id)).toHaveLength(1);
  });

  it("renders legal knowledge citations and a redacted case report", async () => {
    installFetch();
    render(<App />);
    await screen.findByText("实验舱已就绪");
    fireEvent.change(screen.getByLabelText("自定义 Prompt"), { target: { value: "SAFE_CUSTOM_INPUT" } });
    fireEvent.click(screen.getByRole("button", { name: "开始调查" }));

    expect(await screen.findByText("OWASP GenAI Security Project")).toBeInTheDocument();
    expect(screen.getByText("生成式人工智能服务管理暂行办法")).toBeInTheDocument();
    expect(screen.getByText("国家网信办")).toBeInTheDocument();
    expect(screen.getByText("治理与合规")).toBeInTheDocument();
    expect(screen.queryByText("undefined")).not.toBeInTheDocument();
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
    const metricsRegion = screen.getByRole("region", { name: "实验舱运行指标" });
    expect(within(metricsRegion).getByText("实验舱运行指标")).toBeInTheDocument();
    expect(within(metricsRegion).getByText("已验证执行动作保持率")).toBeInTheDocument();
    expect(within(metricsRegion).getByText("N/A")).toBeInTheDocument();
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
