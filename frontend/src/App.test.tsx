import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { App } from "./App";

const health = {
  status: "ok",
  api: { ready: true },
  model: { ready: true, model_id: "/models/qwen" },
  detector: { ready: true, calibration_version: "cal-v2" },
  semantic_guard: { ready: true, model_id: "/models/qwen-guard", model_version: "guard-v1" },
  audit: { ready: true, storage: "sqlite" },
  evaluation: { ready: true, report_version: 2, deployment_match: true },
  demo: { ready: true, sample_count: 3 },
  knowledge: { ready: true, snapshot_version: "official-v1", card_count: 12, generator_ready: true },
};

const analysisResult = {
  request_id: "req_safe_demo",
  decision: "block",
  risk_score: 0,
  detector_score: 0,
  detector_status: "no_token_anomaly",
  semantic_severity: "unsafe",
  semantic_categories: ["violent"],
  semantic_model_id: "/models/qwen-guard",
  semantic_model_version: "guard-v1",
  semantic_latency_ms: 7.2,
  semantic_verification: "performed",
  fusion_reason: "semantic_unsafe",
  guard_raw_output: "Safety: Unsafe\nCategories: Violent",
  audit_persisted: true,
  suspicious_span: null,
  signals: [
    { index: 0, token_id: 10, token_text: "安全", entropy: 0.9, nll: 1.2, cpd_entropy: 0, cpd_nll: 0, risk: 0.1 },
    { index: 1, token_id: 11, token_text: "测试", entropy: 1.8, nll: 2.1, cpd_entropy: 3.2, cpd_nll: 0, risk: 0.63 },
  ],
  evidence: [{ source: "entropy_cpd", summary: "CPD threshold reached" }],
  actions: ["review"],
  provenance: {
    model_id: "/models/qwen",
    tokenizer_id: "/models/qwen",
    system_prompt_hash: "sha256:system",
    calibration_version: "cal-v2",
    thresholds: { k: 0.5, h: 5 },
  },
  latency_ms: 28.4,
  knowledge_status: "ready",
  knowledge_snapshot_version: "official-v1",
  knowledge_latency_ms: 3.4,
  knowledge_retrieval_latency_ms: 0.4,
  knowledge_report_latency_ms: 3.0,
  knowledge_evidence: [{
    knowledge_id: "owasp-llm01-prompt-injection",
    title_zh: "提示词注入与越狱防护的官方控制建议长标题",
    risk_domain: "prompt_injection",
    summary: "将外部输入视为不可信数据，并在模型调用前执行分层检测。",
    recommendations: ["保留基础检测动作，并将高风险请求转入人工复核。"],
    source: {
      publisher: "owasp",
      title: "OWASP GenAI Security Project",
      url: "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
      version: "2025",
      verified_at: "2026-08-26T00:00:00Z",
      usage_note: "official summary",
    },
    retrieval_score: 4.25,
    matched_tags: ["jailbreak"],
  }],
  grounded_report: {
    summary: "基础检测动作为 block；本地知识卡支持该处置。",
    evidence_ids: ["owasp-llm01-prompt-injection"],
    handling_steps: ["保留基础检测动作，并将高风险请求转入人工复核。"],
    limitations: ["知识证据不改变基础检测动作。"],
  },
  report_status: "fallback",
};

const events = {
  total: 1,
  limit: 50,
  offset: 0,
  items: [{
    request_id: "req_safe_demo",
    created_at: "2026-08-25T10:00:00Z",
    prompt_sha256: `sha256:${"a".repeat(64)}`,
    prompt_char_count: 18,
    token_count: 9,
    detector_score: 8.125,
    k: 0.5,
    h: 5,
    onset_token: 2,
    detector_status: "token_anomaly_candidate",
    decision: "review",
    mode: "gateway",
    model_id: "/models/qwen",
    calibration_version: "cal-v2",
    latency_ms: 28.4,
    semantic_severity: "unsafe",
    semantic_categories: ["violent"],
    semantic_model_id: "/models/qwen-guard",
    semantic_model_version: "guard-v1",
    semantic_latency_ms: 7.2,
    fusion_reason: "semantic_unsafe",
    knowledge_snapshot_version: "official-v1",
    knowledge_mode: "report",
    knowledge_status: "ready",
    knowledge_card_ids: ["owasp-llm01-prompt-injection"],
    report_status: "fallback",
    knowledge_latency_ms: 3.4,
  }],
};

function method(displayName: string, f1: number, fpr: number, localization = false) {
  return {
    display_name: displayName,
    profile: { threshold: 1.5, low_fpr_threshold: 3.5, window_size: null },
    operating_points: {
      f1_selected: { threshold: 1.5, precision: 0.9, recall: 0.8, f1, auroc: 0.91, false_positive_rate: fpr },
      low_fpr_selected_on_dev: { threshold: 3.5, precision: 0.92, recall: 0.6, f1: 0.72, auroc: 0.91, false_positive_rate: 0.08 },
    },
    families: {
      gcg: {
        count: 129,
        operating_points: {
          f1_selected: { detected: 129, missed: 0, recall: 1 },
          low_fpr_selected_on_dev: { detected: 126, missed: 3, recall: 0.9767 },
        },
        score: { min: 1, median: 2, max: 3 },
      },
      autodan: {
        count: 150,
        operating_points: {
          f1_selected: { detected: 136, missed: 14, recall: 0.9067 },
          low_fpr_selected_on_dev: { detected: 56, missed: 94, recall: 0.3733 },
        },
        score: { min: 1, median: 2, max: 3 },
      },
      advprompter: {
        count: 181,
        operating_points: {
          f1_selected: { detected: 173, missed: 8, recall: 0.9558 },
          low_fpr_selected_on_dev: { detected: 31, missed: 150, recall: 0.1713 },
        },
        score: { min: 1, median: 2, max: 3 },
      },
    },
    localization: localization ? { onset_mae: 39.68, trigger_in_suffix_rate: 0.6261 } : null,
    latency_ms: { p50_ms: 22.5, p95_ms: 29.4 },
  };
}

const evaluation = {
  schema_version: 2,
  counts: { total: 663, attacks: 460, benign: 203 },
  methods: {
    global_nll: method("Global NLL", 0.96996, 0.09852),
    window_nll: method("Window NLL", 0.98158, 0.04926),
    entropy_cpd: method("Entropy-CPD", 0.8327, 0.75862, true),
  },
  not_evaluated: ["autodan-hga", "beast"],
  provenance: { calibration_version: "cal-v2", dataset_hash: `sha256:${"b".repeat(64)}` },
  deployment_match: true,
  knowledge: {
    schema_version: 1,
    case_count: 36,
    hit_at_1: 0.9444444444444444,
    hit_at_3: 0.9722222222222222,
    mrr: 0.9583333333333334,
    citation_validity: 1,
    decision_invariance: 1,
    domains: {},
    snapshot_version: "official-v1",
    snapshot_hash: `sha256:${"c".repeat(64)}`,
    fixture_hash: `sha256:${"d".repeat(64)}`,
    retrieval_weights: { tag: 2, lexical: 1 },
    latency_ms: { p50: 0.068, p95: 0.093 },
    runtime_versions: { model: "not_applicable_retrieval_only", python: "3.14.3", sqlite: "3.50.4" },
    generated_report_count: 0,
    fallback_report_count: 0,
  },
};

function jsonResponse(payload: unknown, ok = true) {
  return Promise.resolve({ ok, json: async () => payload });
}

function installFetch(options: {
  analysis?: unknown;
  health?: unknown;
  events?: unknown;
} = {}) {
  vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    if (url === "/health") return jsonResponse(options.health ?? health);
    if (url.startsWith("/api/v1/demo-samples")) {
      return jsonResponse([
        { sample_id: "sample_01", family: "gcg", split: "test", evaluated: true },
        { sample_id: "sample_02", family: "autodan", split: "test", evaluated: true },
      ]);
    }
    if (url === "/api/v1/analyze") return jsonResponse(options.analysis ?? analysisResult);
    if (url === "/api/v1/events?limit=50&offset=0") return jsonResponse(options.events ?? events);
    if (url === "/api/v1/evaluation/summary") return jsonResponse(evaluation);
    throw new Error(`Unexpected request: ${url}`);
  }));
}

function latestAnalyzeRequestBody() {
  const calls = vi.mocked(fetch).mock.calls;
  const call = [...calls].reverse().find(([input]) => String(input) === "/api/v1/analyze");
  expect(call).toBeDefined();
  return JSON.parse(String(call?.[1]?.body));
}

describe("competition security console", () => {
  beforeEach(() => {
    window.history.pushState({}, "", "/analyze");
    installFetch();
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("separates semantic blocking from a normal Token distribution", async () => {
    render(<App />);
    expect(await screen.findByText("检测服务已连接")).toBeInTheDocument();
    expect(screen.getByText("研究原型 · 基础与进阶任务")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Prompt"), { target: { value: "SAFE_TEST_INPUT" } });
    fireEvent.change(screen.getByLabelText("工作模式"), { target: { value: "gateway" } });
    fireEvent.click(screen.getByRole("button", { name: "开始检测" }));

    expect(await screen.findByText("语义危险")).toBeInTheDocument();
    expect(screen.getByText("暴力与武器")).toBeInTheDocument();
    expect(screen.getByText("未发现 Token 异常")).toBeInTheDocument();
    expect(screen.getByText("语义安全策略拦截")).toBeInTheDocument();
    expect(screen.getAllByText("拦截").length).toBeGreaterThan(0);
    expect(screen.getByText("已写入脱敏审计")).toBeInTheDocument();
    expect(screen.queryByText(/Safety: Unsafe/)).not.toBeInTheDocument();
  });

  it("sends off as the default knowledge mode", async () => {
    render(<App />);
    await screen.findByText("检测服务已连接");
    fireEvent.change(screen.getByLabelText("Prompt"), { target: { value: "SAFE_TEST_INPUT" } });
    fireEvent.click(screen.getByRole("button", { name: "开始检测" }));

    await screen.findByText("语义危险");
    expect(latestAnalyzeRequestBody().knowledge_mode).toBe("off");
  });

  it("sends evidence mode and renders official evidence without private retrieval text", async () => {
    render(<App />);
    await screen.findByText("检测服务已连接");
    const modeControl = screen.getByRole("group", { name: "知识增强模式" });
    fireEvent.click(within(modeControl).getByRole("button", { name: "仅证据" }));
    fireEvent.change(screen.getByLabelText("Prompt"), { target: { value: "SAFE_PRIVATE_QUERY" } });
    fireEvent.click(screen.getByRole("button", { name: "开始检测" }));

    expect(await screen.findByText("OWASP GenAI Security Project")).toBeInTheDocument();
    expect(latestAnalyzeRequestBody().knowledge_mode).toBe("evidence");
    expect(screen.getByText("知识证据不改变基础判定")).toBeInTheDocument();
    expect(screen.getByText("提示词注入与越狱防护的官方控制建议长标题")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /OWASP GenAI Security Project/ })).toHaveAttribute(
      "href",
      "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
    );
    expect(
      within(screen.getByRole("region", { name: "本地知识证据" })).queryByText("SAFE_PRIVATE_QUERY"),
    ).not.toBeInTheDocument();
  });

  it("sends report mode and labels deterministic fallback reports", async () => {
    render(<App />);
    await screen.findByText("检测服务已连接");
    const modeControl = screen.getByRole("group", { name: "知识增强模式" });
    fireEvent.click(within(modeControl).getByRole("button", { name: "证据与报告" }));
    fireEvent.change(screen.getByLabelText("Prompt"), { target: { value: "SAFE_REPORT_INPUT" } });
    fireEvent.click(screen.getByRole("button", { name: "开始检测" }));

    expect(await screen.findByText("模板降级报告")).toBeInTheDocument();
    expect(latestAnalyzeRequestBody().knowledge_mode).toBe("report");
    expect(screen.getByText("基础检测动作为 block；本地知识卡支持该处置。")).toBeInTheDocument();
  });

  it("labels generated reports and unavailable knowledge without changing the decision", async () => {
    installFetch({
      analysis: { ...analysisResult, report_status: "generated" },
      health: { ...health, knowledge: { ready: false, snapshot_version: null, card_count: 0, generator_ready: false } },
    });
    render(<App />);
    await screen.findByText("检测服务已连接");
    expect(screen.getByText("知识库不可用")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Prompt"), { target: { value: "SAFE_REPORT_INPUT" } });
    fireEvent.click(screen.getByRole("button", { name: "开始检测" }));

    expect(await screen.findByText("模型生成报告")).toBeInTheDocument();
    expect(screen.getAllByText("拦截").length).toBeGreaterThan(0);
  });

  it("keeps a safe semantic result separate from a CPD candidate", async () => {
    installFetch({
      analysis: {
        ...analysisResult,
        decision: "review",
        detector_score: 8.125,
        detector_status: "token_anomaly_candidate",
        semantic_severity: "safe",
        semantic_categories: [],
        fusion_reason: "cpd_candidate",
        suspicious_span: { token_start: 2, token_end: 4, char_start: 6, char_end: 12 },
      },
    });
    render(<App />);
    await screen.findByText("检测服务已连接");
    fireEvent.change(screen.getByLabelText("Prompt"), { target: { value: "SAFE_TEST_INPUT" } });
    fireEvent.change(screen.getByLabelText("工作模式"), { target: { value: "gateway" } });
    fireEvent.click(screen.getByRole("button", { name: "开始检测" }));

    expect((await screen.findAllByText("语义安全")).length).toBeGreaterThan(0);
    expect(screen.getByText("Token 异常候选")).toBeInTheDocument();
    expect(screen.getByText("Token 异常策略处置")).toBeInTheDocument();
    expect(screen.getAllByText("人工复核").length).toBeGreaterThan(0);
  });

  it("routes controversial semantic evidence to review", async () => {
    installFetch({
      analysis: {
        ...analysisResult,
        decision: "review",
        semantic_severity: "controversial",
        semantic_categories: ["politically_sensitive"],
        fusion_reason: "semantic_controversial",
      },
    });
    render(<App />);
    await screen.findByText("检测服务已连接");
    fireEvent.change(screen.getByLabelText("Prompt"), { target: { value: "SAFE_CONTEXT_INPUT" } });
    fireEvent.click(screen.getByRole("button", { name: "开始检测" }));

    expect(await screen.findByText("语义争议")).toBeInTheDocument();
    expect(screen.getByText("敏感政治话题")).toBeInTheDocument();
    expect(screen.getByText("语义争议，转人工复核")).toBeInTheDocument();
  });

  it("shows a fail-safe banner when the semantic Guard is unavailable", async () => {
    installFetch({
      health: {
        ...health,
        status: "degraded",
        semantic_guard: { ready: false, model_id: "unconfigured", model_version: "unconfigured" },
      },
      analysis: {
        ...analysisResult,
        decision: "review",
        semantic_severity: "unavailable",
        semantic_categories: [],
        semantic_model_id: "unconfigured",
        semantic_model_version: "unconfigured",
        semantic_verification: "unavailable",
        fusion_reason: "semantic_unavailable_gateway_fail_safe",
      },
    });
    render(<App />);
    await screen.findByText("检测服务已连接");
    fireEvent.change(screen.getByLabelText("Prompt"), { target: { value: "SAFE_GATEWAY_INPUT" } });
    fireEvent.change(screen.getByLabelText("工作模式"), { target: { value: "gateway" } });
    fireEvent.click(screen.getByRole("button", { name: "开始检测" }));

    expect(await screen.findByText("语义检测不可用")).toBeInTheDocument();
    expect(screen.getByText("语义防线不可用，网关转人工复核")).toBeInTheDocument();
  });

  it("offers frozen samples by ID and family without exposing source text", async () => {
    render(<App />);
    const selector = await screen.findByLabelText("冻结测试样本");
    expect(within(selector).getByText("sample_01 · GCG")).toBeInTheDocument();
    expect(within(selector).getByText("sample_02 · AutoDAN")).toBeInTheDocument();
    expect(screen.queryByText("SAFE_TEST_INPUT")).not.toBeInTheDocument();
  });

  it("loads privacy-safe events and renders a hash instead of a prompt", async () => {
    window.history.pushState({}, "", "/events");
    render(<App />);
    expect(await screen.findByText("req_safe_demo")).toBeInTheDocument();
    expect(screen.getByText("sha256:aaaaaaaaaaaa…")).toBeInTheDocument();
    expect(screen.getByText("8.125")).toBeInTheDocument();
    expect(screen.getByText("人工复核")).toBeInTheDocument();
    expect(screen.getByText("语义危险")).toBeInTheDocument();
    expect(screen.getByText("暴力与武器")).toBeInTheDocument();
    expect(screen.getByText("语义安全策略拦截")).toBeInTheDocument();
    expect(screen.getByText("official-v1")).toBeInTheDocument();
    expect(screen.getByText("模板降级")).toBeInTheDocument();
    expect(screen.queryByText("Prompt")).not.toBeInTheDocument();
  });

  it("shows all frozen benchmark methods, operating points and scope", async () => {
    window.history.pushState({}, "", "/evaluation");
    render(<App />);
    expect(await screen.findByText("663")).toBeInTheDocument();
    expect(screen.getAllByText("Global NLL").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Window NLL").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Entropy-CPD").length).toBeGreaterThan(0);
    expect(screen.getByText("F1 最优阈值")).toBeInTheDocument();
    expect(screen.getByText("低误报阈值（开发集选择）")).toBeInTheDocument();
    expect(screen.getAllByText("AutoDAN").length).toBeGreaterThan(0);
    expect(screen.getByText("BEAST · 未评测")).toBeInTheDocument();
    expect(screen.getByText("AutoDAN-HGA · 未评测")).toBeInTheDocument();
    expect(screen.getByText("Qwen3Guard 功能验收")).toBeInTheDocument();
    expect(screen.getByText("尚未进行独立冻结语义评测")).toBeInTheDocument();
    expect(screen.getByText("/models/qwen-guard")).toBeInTheDocument();
    expect(screen.getByText("知识检索冻结评测")).toBeInTheDocument();
    expect(screen.getByText("97.22%")).toBeInTheDocument();
    expect(screen.getAllByText("100.00%").length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText("仅为冻结工程检索评测")).toBeInTheDocument();
    expect(screen.getByTitle(`sha256:${"c".repeat(64)}`)).toBeInTheDocument();
  });

  it("keeps evaluation usable with a legacy health response", async () => {
    const { semantic_guard: _, ...legacyHealth } = health;
    installFetch({ health: legacyHealth });
    window.history.pushState({}, "", "/evaluation");

    render(<App />);

    expect(await screen.findByText("Qwen3Guard 功能验收")).toBeInTheDocument();
    expect(screen.getByText("模型未就绪")).toBeInTheDocument();
    expect(screen.getByText("尚未进行独立冻结语义评测")).toBeInTheDocument();
  });
});
