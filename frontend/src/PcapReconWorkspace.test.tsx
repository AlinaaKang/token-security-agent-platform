import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { SuperAgentPage as App } from "./pages/SuperAgentPage";

const reconOverview = {
  enabled: true,
  eligible_file_count: 2318,
  sample_limit: 20,
  sampling_method: "size_quartile_v1",
};

const reconMission = {
  recon_id: "recon_0123456789abcdef0123456789abcdef",
  objective: "reconnoiter_pcap_dataset",
  status: "completed",
  events: [
    { sequence: 1, actor: "coordinator", status: "succeeded", summary: "authorization_accepted" },
    { sequence: 2, actor: "coordinator", status: "succeeded", summary: "quartile_sample_selected" },
    { sequence: 3, actor: "coordinator", status: "succeeded", summary: "isolated_full_capture_scan_running" },
    { sequence: 4, actor: "coordinator", status: "succeeded", summary: "aggregate_profile_validated" },
    { sequence: 5, actor: "coordinator", status: "succeeded", summary: "method_selection_checkpoint_ready" },
  ],
  summary: {
    schema_version: 1,
    sampled_count: 20,
    succeeded_count: 18,
    failed_count: 2,
    quartile_counts: { quartile_1: 5, quartile_2: 5, quartile_3: 5, quartile_4: 5 },
    size_bucket_counts: { under_2_kib: 4, "2_kib_to_64_kib": 6, "64_kib_to_1_mib": 5, at_least_1_mib: 5 },
    packet_bucket_counts: { empty: 1, "1_to_15": 4, "16_to_63": 7, "at_least_64": 8 },
    duration_bucket_counts: { zero: 1, under_1_second: 6, "1_to_10_seconds": 8, over_10_seconds: 5 },
    protocol_presence_counts: { tcp: 14, dns: 7, tls: 9, arp: 3 },
    plaintext_sample_count: 6,
    encrypted_sample_count: 12,
    sequence_candidate_count: 11,
  },
  created_at: "2026-09-03T00:00:00Z",
};

function response(payload: unknown, ok = true, status = ok ? 200 : 500) {
  return Promise.resolve({ ok, status, json: async () => payload });
}

function installFetch(options: { reconRestoreStatus?: number } = {}) {
  vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url === "/api/v1/lab/scenarios") return response([]);
    if (url === "/api/v1/superagent/capabilities") return response({ ready: true, internal_only: true, objectives: ["investigate_and_respond"], actors: ["coordinator"], max_tool_calls: 3, max_trace_events: 12, replanning_limit: 1 });
    if (url === "/pcap-api/v1/superagent/pcap/overview") return response({ enabled: true, pending_file_count: 17, tool_id: "pcap_batch_triage", max_batch_size: 20, max_trace_events: 12, actors: ["coordinator"] });
    if (url === "/pcap-api/v1/superagent/pcap/reconnaissance/overview") return response(reconOverview);
    if (url === "/pcap-api/v1/superagent/pcap/reconnaissance/authorizations") return response({ authorization_id: "pcap_auth_0123456789abcdef0123456789abcdef", max_files: 20 }, true);
    if (url === "/pcap-api/v1/superagent/missions" && init?.method === "POST") return response(reconMission);
    if (url === "/pcap-api/v1/superagent/missions/recon_0123456789abcdef0123456789abcdef") return options.reconRestoreStatus ? response({ error: { message: "private" } }, false, options.reconRestoreStatus) : response(reconMission);
    throw new Error(`Unexpected request: ${url}`);
  }));
}

describe("PCAP reconnaissance workspace", () => {
  beforeEach(() => { window.history.pushState({}, "", "/super-agent"); installFetch(); });
  afterEach(() => { cleanup(); vi.unstubAllGlobals(); window.sessionStorage.clear(); });

  it("keeps Prompt mode free of PCAP requests and opens PCAP in batch triage", async () => {
    render(<App />);
    await screen.findByLabelText("任务场景");
    expect(vi.mocked(fetch).mock.calls.map(([url]) => String(url)).some((url) => url.includes("/pcap/"))).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "PCAP 证据分诊" }));
    expect(await screen.findByRole("button", { name: "批量分诊" })).toHaveAttribute("aria-pressed", "true");
  });

  it("fetches only the aggregate recon overview, then requires two confirmation clicks", async () => {
    render(<App />);
    await screen.findByLabelText("任务场景");
    fireEvent.click(screen.getByRole("button", { name: "PCAP 证据分诊" }));
    fireEvent.click(await screen.findByRole("button", { name: "数据勘察" }));
    expect(await screen.findByText("按文件大小四分位抽取 20 个代表样本")).toBeVisible();
    expect(vi.mocked(fetch).mock.calls.filter(([url]) => String(url).endsWith("/reconnaissance/authorizations")).length).toBe(0);
    fireEvent.click(screen.getByRole("button", { name: "准备开始勘察" }));
    expect(screen.getByRole("region", { name: "PCAP 勘察授权确认" })).toBeVisible();
    expect(vi.mocked(fetch).mock.calls.filter(([url]) => String(url).endsWith("/reconnaissance/authorizations")).length).toBe(0);
    expect(screen.getByText("本次将在无网络只读容器中完整扫描 20 个分层样本，仅返回聚合画像，不检测攻击，不展示文件身份或载荷。")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "确认并开始勘察" }));
    await waitFor(() => expect(vi.mocked(fetch).mock.calls.filter(([url]) => String(url).endsWith("/reconnaissance/authorizations")).length).toBe(1));
    const body = JSON.parse(String(vi.mocked(fetch).mock.calls.find(([url]) => String(url).endsWith("/reconnaissance/authorizations"))?.[1]?.body));
    expect(body).toEqual({ confirmed: true, sample_limit: 20 });
  });

  it("renders only aggregate profile fields and the phase gate", async () => {
    window.sessionStorage.setItem("token-security-superagent-pcap-recon-mission-id", reconMission.recon_id);
    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "PCAP 证据分诊" }));
    fireEvent.click(await screen.findByRole("button", { name: "数据勘察" }));
    expect(await screen.findByText("四分位覆盖")).toBeVisible();
    expect(screen.getByText("数据包数量分布")).toBeVisible();
    expect(screen.getByText("持续时间分布")).toBeVisible();
    expect(screen.getByText("协议出现样本数")).toBeVisible();
    expect(screen.getByText("arp")).toBeVisible();
    expect(screen.getByText("明文样本 6")).toBeVisible();
    expect(screen.getByText("加密样本 12")).toBeVisible();
    expect(screen.getByText("序列候选 11")).toBeVisible();
    expect(screen.getByText("当前阶段：认识数据")).toBeVisible();
    expect(screen.getByText("下一阶段：根据真实画像选择规则、Request 定位、行为异常或可选 CPD")).toBeVisible();
    expect(screen.getByRole("region", { name: "PCAP 数据勘察工作区" }).textContent).not.toMatch(/filename|path|IP|port|Payload|Prompt|攻击类型|异常 Packet|CPD 结果|Token 结果/i);
  });

  it("keeps the overview usable and clears stale 404 mission storage", async () => {
    window.sessionStorage.setItem("token-security-superagent-pcap-recon-mission-id", reconMission.recon_id);
    cleanup(); vi.unstubAllGlobals(); installFetch({ reconRestoreStatus: 404 }); render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "PCAP 证据分诊" }));
    fireEvent.click(await screen.findByRole("button", { name: "数据勘察" }));
    expect(await screen.findByText("按文件大小四分位抽取 20 个代表样本")).toBeVisible();
    expect(screen.getByRole("button", { name: "准备开始勘察" })).toBeEnabled();
    expect(window.sessionStorage.getItem("token-security-superagent-pcap-recon-mission-id")).toBeNull();
  });

  it("drops unknown trace summaries instead of rendering backend text", async () => {
    const missionWithUnknown = { ...reconMission, events: [...reconMission.events, { sequence: 6, actor: "coordinator", status: "succeeded", summary: "PRIVATE_UNKNOWN_TRACE" }] };
    window.sessionStorage.setItem("token-security-superagent-pcap-recon-mission-id", reconMission.recon_id);
    cleanup(); vi.unstubAllGlobals();
    vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/pcap/reconnaissance/overview")) return response(reconOverview);
      if (url.endsWith(`/missions/${reconMission.recon_id}`)) return response(missionWithUnknown);
      if (url === "/api/v1/lab/scenarios") return response([]);
      if (url === "/api/v1/superagent/capabilities") return response({ ready: true, internal_only: true, objectives: ["investigate_and_respond"], actors: ["coordinator"], max_tool_calls: 3, max_trace_events: 12, replanning_limit: 1 });
      if (url === "/pcap-api/v1/superagent/pcap/overview") return response({ enabled: true, pending_file_count: 17, tool_id: "pcap_batch_triage", max_batch_size: 20, max_trace_events: 12, actors: ["coordinator"] });
      throw new Error(`Unexpected request: ${url}`);
    }));
    render(<App />); fireEvent.click(await screen.findByRole("button", { name: "PCAP 证据分诊" })); fireEvent.click(await screen.findByRole("button", { name: "数据勘察" }));
    await screen.findByText("四分位覆盖");
    expect(screen.getByRole("region", { name: "PCAP 数据勘察工作区" }).textContent).not.toContain("PRIVATE_UNKNOWN_TRACE");
  });

  it("shows a deterministic retry action for a degraded reconnaissance mission", async () => {
    const degraded = { ...reconMission, status: "degraded", summary: null };
    window.sessionStorage.setItem("token-security-superagent-pcap-recon-mission-id", reconMission.recon_id);
    cleanup(); vi.unstubAllGlobals();
    vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/pcap/reconnaissance/overview")) return response(reconOverview);
      if (url.endsWith(`/missions/${reconMission.recon_id}`)) return response(degraded);
      if (url.endsWith("/pcap/reconnaissance/authorizations")) return response({ authorization_id: "pcap_auth_0123456789abcdef0123456789abcdef", max_files: 20 });
      if (url === "/pcap-api/v1/superagent/missions" && init?.method === "POST") return response(reconMission);
      if (url === "/api/v1/lab/scenarios") return response([]);
      if (url === "/api/v1/superagent/capabilities") return response({ ready: true, internal_only: true, objectives: ["investigate_and_respond"], actors: ["coordinator"], max_tool_calls: 3, max_trace_events: 12, replanning_limit: 1 });
      if (url === "/pcap-api/v1/superagent/pcap/overview") return response({ enabled: true, pending_file_count: 17, tool_id: "pcap_batch_triage", max_batch_size: 20, max_trace_events: 12, actors: ["coordinator"] });
      throw new Error(`Unexpected request: ${url}`);
    }));
    render(<App />); fireEvent.click(await screen.findByRole("button", { name: "PCAP 证据分诊" })); fireEvent.click(await screen.findByRole("button", { name: "数据勘察" }));
    expect(await screen.findByText("勘察未完成，可重新授权重试")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "重新授权勘察" }));
    await waitFor(() => expect(vi.mocked(fetch).mock.calls.filter(([url]) => String(url).endsWith("/reconnaissance/authorizations")).length).toBe(1));
  });
});
