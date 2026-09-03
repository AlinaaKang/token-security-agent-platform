import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { App } from "./App";

const PRIVATE_SENTINEL = "PRIVATE_PCAP_PATH_PAYLOAD_SHA256";
const missionId = "mission_0123456789abcdef0123456789abcdef";

const overview = {
  enabled: true,
  pending_file_count: 17,
  tool_id: "pcap_batch_triage",
  max_batch_size: 20,
  max_trace_events: 12,
  actors: ["coordinator", "network_evidence_analyst", "knowledge_analyst", "response_operator"],
};

const runningMission = {
  mission_id: missionId,
  objective: "triage_pcap_evidence",
  status: "running",
  batch_id: "batch_0123456789abcdef0123456789abcdef",
  events: [
    { sequence: 1, actor: "coordinator", status: "succeeded", summary: "tool_authorization_accepted", tool_id: null },
    { sequence: 2, actor: "network_evidence_analyst", status: "running", summary: "traffic_only_evidence", tool_id: "pcap_batch_triage" },
  ],
  summary: null,
  report: {
    confirmed: ["traffic_only_evidence"],
    candidates: ["plaintext_application_protocol_candidate_not_proven_llm_traffic"],
    unknowns: ["cpd_evidence_unavailable", "token_evidence_unavailable"],
    recommended_action: ["retain_public_metadata"],
  },
  limitations: ["no_packet_payload_retained", "token_evidence_unavailable"],
  created_at: "2026-09-01T02:00:00Z",
};

const completedMission = {
  ...runningMission,
  status: "completed",
  events: [
    ...runningMission.events,
    { sequence: 3, actor: "coordinator", status: "succeeded", summary: "batch_triage_completed", tool_id: null },
  ],
  summary: {
    schema_version: 1,
    batch_id: runningMission.batch_id,
    selected_count: 2,
    succeeded_count: 1,
    failed_count: 1,
    skipped_count: 0,
    captures: [
      {
        capture_id: "capture_0123456789abcdef0123456789abcdef",
        status: "succeeded",
        packet_count: 48,
        protocol_counts: { tcp: 32, tls: 16 },
        visibility: {
          plaintext_application_protocol_observed: false,
          encrypted_transport_observed: true,
          tls_observed: true,
          quic_observed: false,
        },
        capability: "traffic_only",
        error_code: null,
      },
      {
        capture_id: "capture_fedcba9876543210fedcba9876543210",
        status: "failed",
        packet_count: 0,
        protocol_counts: {},
        visibility: {
          plaintext_application_protocol_observed: false,
          encrypted_transport_observed: false,
          tls_observed: false,
          quic_observed: false,
        },
        capability: null,
        error_code: "inspection_failed",
      },
    ],
  },
};

function response(payload: unknown, ok = true, status = 200) {
  return Promise.resolve({ ok, status, json: async () => payload });
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((resolvePromise) => { resolve = resolvePromise; });
  return { promise, resolve };
}

function requestUrls() {
  return vi.mocked(fetch).mock.calls.map(([input]) => String(input));
}

function requestBodies(path: string) {
  return vi.mocked(fetch).mock.calls
    .filter(([input]) => String(input).endsWith(path))
    .map(([, init]) => JSON.parse(String(init?.body)));
}

function installFetch(options: {
  overview?: typeof overview;
  overviewResponse?: Promise<typeof overview>;
  missionSequence?: Array<unknown | Error | Promise<unknown>>;
  cancelResponse?: Promise<unknown>;
  failPath?: string;
} = {}) {
  const missions = [...(options.missionSequence ?? [runningMission, completedMission])];
  vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    if (options.failPath && url.endsWith(options.failPath)) {
      return response({ error: { message: PRIVATE_SENTINEL } }, false, 500);
    }
    if (url === "/api/v1/lab/scenarios") return response([]);
    if (url === "/api/v1/superagent/capabilities") {
      return response({
        ready: true,
        internal_only: true,
        objectives: ["investigate_and_respond"],
        actors: ["coordinator", "semantic_analyst", "token_analyst", "knowledge_analyst", "response_operator"],
        max_tool_calls: 3,
        max_trace_events: 12,
        replanning_limit: 1,
      });
    }
    if (url === "/api/v1/superagent/pcap/overview") {
      return options.overviewResponse
        ? options.overviewResponse.then((payload) => response(payload))
        : response(options.overview ?? overview);
    }
    if (url === "/api/v1/superagent/pcap/authorizations") {
      return response({ authorization_id: "pcap_auth_0123456789abcdef0123456789abcdef", max_files: 20 }, true, 201);
    }
    if (url === "/api/v1/superagent/missions") return response(runningMission, true, 201);
    if (url === `/api/v1/superagent/missions/${missionId}/cancel`) {
      return options.cancelResponse
        ? options.cancelResponse.then((payload) => response(payload))
        : response(runningMission);
    }
    if (url === `/api/v1/superagent/missions/${missionId}`) {
      const next = missions.shift() ?? completedMission;
      if (next instanceof Error) {
        return response({ error: { message: next.message } }, false, 500);
      }
      if (next instanceof Promise) return next.then((payload) => response(payload));
      return response(next);
    }
    throw new Error(`Unexpected request: ${url}`);
  }));
}

async function openPcapMode() {
  fireEvent.click(await screen.findByRole("button", { name: "PCAP 证据分诊" }));
  await screen.findByText("待处理文件 17");
}

describe("PCAP SuperAgent evidence workspace", () => {
  beforeEach(() => {
    window.history.pushState({}, "", "/super-agent");
    installFetch();
  });

  afterEach(() => {
    cleanup();
    window.sessionStorage.clear();
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("requires overview and a separate second confirmation before authorization starts", async () => {
    render(<App />);
    await openPcapMode();

    expect(requestBodies("/pcap/authorizations")).toHaveLength(0);
    fireEvent.click(screen.getByRole("button", { name: "准备开始" }));
    expect(requestBodies("/pcap/authorizations")).toHaveLength(0);
    expect(screen.getByRole("region", { name: "PCAP 执行授权确认" })).toBeVisible();

    fireEvent.click(screen.getByRole("button", { name: "确认并开始" }));

    await waitFor(() => expect(requestBodies("/pcap/authorizations")).toEqual([
      { confirmed: true, max_files: 20 },
    ]));
    expect(requestBodies("/superagent/missions")).toContainEqual({
      objective: "triage_pcap_evidence",
      authorization_id: "pcap_auth_0123456789abcdef0123456789abcdef",
    });
    expect(window.sessionStorage.getItem("token-security-superagent-pcap-mission-id")).toBe(missionId);
    expect(document.body.textContent).not.toContain(PRIVATE_SENTINEL);
  });

  it("disables preparation when PCAP capability is unavailable", async () => {
    cleanup();
    vi.unstubAllGlobals();
    installFetch({ overview: { ...overview, enabled: false } });
    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "PCAP 证据分诊" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("PCAP 证据分诊暂不可用");
    expect(screen.queryByText(/待处理文件/)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "准备开始" })).toBeDisabled();
    expect(requestBodies("/pcap/authorizations")).toHaveLength(0);
  });

  it("shows no pending count until the dynamic overview resolves", async () => {
    cleanup();
    vi.unstubAllGlobals();
    const pendingOverview = deferred<typeof overview>();
    installFetch({ overviewResponse: pendingOverview.promise });
    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "PCAP 证据分诊" }));

    expect(screen.queryByText(/待处理文件/)).not.toBeInTheDocument();
    expect(screen.getByText("正在读取证据目录")).toBeVisible();

    pendingOverview.resolve(overview);
    expect(await screen.findByText("待处理文件 17")).toBeVisible();
  });

  it("enforces the public max-files range before showing consent", async () => {
    render(<App />);
    await openPcapMode();
    const maxFiles = screen.getByRole("spinbutton", { name: "本次最多处理文件数" });

    fireEvent.change(maxFiles, { target: { value: "0" } });
    expect(screen.getByText("请输入 1 至 20 之间的整数")).toBeVisible();
    expect(screen.getByRole("button", { name: "准备开始" })).toBeDisabled();

    fireEvent.change(maxFiles, { target: { value: "21" } });
    expect(screen.getByRole("button", { name: "准备开始" })).toBeDisabled();

    fireEvent.change(maxFiles, { target: { value: "7" } });
    expect(screen.getByRole("button", { name: "准备开始" })).toBeEnabled();
  });

  it("polls a running mission until terminal evidence and never claims unavailable detection", async () => {
    vi.useFakeTimers();
    render(<App />);
    await act(async () => { await vi.runOnlyPendingTimersAsync(); });
    fireEvent.click(screen.getByRole("button", { name: "PCAP 证据分诊" }));
    await act(async () => { await vi.runOnlyPendingTimersAsync(); });
    fireEvent.click(screen.getByRole("button", { name: "准备开始" }));
    fireEvent.click(screen.getByRole("button", { name: "确认并开始" }));
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });

    expect(screen.getByText("任务运行中")).toBeVisible();
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });

    expect(screen.getByText("任务已完成")).toBeVisible();
    expect(screen.getByText("已选择 2")).toBeVisible();
    expect(screen.getByText("capture_0123456789abcdef0123456789abcdef")).toBeVisible();
    expect(screen.getAllByText("CPD 证据不可用")[0]).toBeVisible();
    expect(screen.getAllByText("Token 证据不可用")[0]).toBeVisible();
    expect(document.body.textContent).not.toMatch(/LLM 检测|越狱检测|CPD 检测|Token 检测/);
  });

  it("offers an accessible retry after polling fails and resumes to terminal", async () => {
    vi.useFakeTimers();
    cleanup();
    vi.unstubAllGlobals();
    installFetch({ missionSequence: [new Error(PRIVATE_SENTINEL), completedMission] });
    render(<App />);
    await act(async () => { await vi.runOnlyPendingTimersAsync(); });
    fireEvent.click(screen.getByRole("button", { name: "PCAP 证据分诊" }));
    await act(async () => { await vi.runOnlyPendingTimersAsync(); });
    fireEvent.click(screen.getByRole("button", { name: "准备开始" }));
    fireEvent.click(screen.getByRole("button", { name: "确认并开始" }));
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });

    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
    expect(screen.getByRole("alert")).toHaveTextContent("无法刷新 PCAP 任务状态，请重试。");
    expect(screen.getByRole("button", { name: "重试刷新" })).toBeEnabled();
    expect(document.body.textContent).not.toContain(PRIVATE_SENTINEL);

    fireEvent.click(screen.getByRole("button", { name: "重试刷新" }));
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
    expect(screen.getByText("任务已完成")).toBeVisible();
  });

  it("restores only from the PCAP key and resumes polling without authorizing", async () => {
    window.sessionStorage.setItem("token-security-superagent-mission-id", "mission_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    window.sessionStorage.setItem("token-security-superagent-pcap-mission-id", missionId);
    installFetch({ missionSequence: [completedMission] });
    render(<App />);
    await screen.findByLabelText("任务场景");

    expect(requestUrls()).not.toContain(`/api/v1/superagent/missions/${missionId}`);
    fireEvent.click(screen.getByRole("button", { name: "PCAP 证据分诊" }));

    expect(await screen.findByText("任务已完成")).toBeVisible();
    expect(requestUrls()).toContain(`/api/v1/superagent/missions/${missionId}`);
    expect(requestBodies("/pcap/authorizations")).toHaveLength(0);
  });

  it("keeps polling after cancel acknowledgement until cleanup publishes cancelled", async () => {
    window.sessionStorage.setItem("token-security-superagent-pcap-mission-id", missionId);
    installFetch({
      missionSequence: [runningMission, { ...runningMission, status: "cancelled" }],
    });
    render(<App />);
    await screen.findByLabelText("任务场景");
    window.sessionStorage.setItem("token-security-superagent-mission-id", "mission_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    fireEvent.click(screen.getByRole("button", { name: "PCAP 证据分诊" }));
    expect(await screen.findByText("任务运行中")).toBeVisible();

    fireEvent.click(screen.getByRole("button", { name: "取消任务" }));
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });

    expect(screen.getByText("任务运行中")).toBeVisible();
    expect(window.sessionStorage.getItem("token-security-superagent-pcap-mission-id")).toBe(missionId);

    expect(await screen.findByText("任务已取消", {}, { timeout: 2000 })).toBeVisible();
    expect(window.sessionStorage.getItem("token-security-superagent-pcap-mission-id")).toBeNull();
    expect(window.sessionStorage.getItem("token-security-superagent-mission-id")).toBe("mission_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  });

  it("keeps a mission cancelled when an earlier poll resolves late", async () => {
    vi.useFakeTimers();
    cleanup();
    vi.unstubAllGlobals();
    const stalePoll = deferred<unknown>();
    const cancelResult = deferred<unknown>();
    installFetch({
      missionSequence: [stalePoll.promise],
      cancelResponse: cancelResult.promise,
    });
    render(<App />);
    await act(async () => { await vi.runOnlyPendingTimersAsync(); });
    fireEvent.click(screen.getByRole("button", { name: "PCAP 证据分诊" }));
    await act(async () => { await vi.runOnlyPendingTimersAsync(); });
    fireEvent.click(screen.getByRole("button", { name: "准备开始" }));
    fireEvent.click(screen.getByRole("button", { name: "确认并开始" }));
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    act(() => { vi.advanceTimersByTime(1000); });

    fireEvent.click(screen.getByRole("button", { name: "取消任务" }));
    await act(async () => {
      cancelResult.resolve({ ...runningMission, status: "cancelled" });
      await Promise.resolve();
      stalePoll.resolve(runningMission);
      await Promise.resolve();
    });

    expect(screen.getByText("任务已取消")).toBeVisible();
    expect(screen.queryByText("任务运行中")).not.toBeInTheDocument();
  });

  it("uses fixed public error copy and does not render backend details", async () => {
    cleanup();
    vi.unstubAllGlobals();
    installFetch({ failPath: "/pcap/overview" });
    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "PCAP 证据分诊" }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("PCAP 证据分诊暂不可用");
    expect(alert).not.toHaveTextContent(PRIVATE_SENTINEL);
    expect(screen.queryByText(/待处理文件/)).not.toBeInTheDocument();
  });

  it("shows complete public evidence status without exposing private capture fields", async () => {
    window.sessionStorage.setItem("token-security-superagent-pcap-mission-id", missionId);
    installFetch({ missionSequence: [{ ...completedMission, private: { path: PRIVATE_SENTINEL } }] });
    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "PCAP 证据分诊" }));
    await screen.findByText("任务已完成");

    const evidence = screen.getByRole("region", { name: "PCAP 批次证据" });
    expect(within(evidence).getByText("成功 1")).toBeVisible();
    expect(within(evidence).getByText("失败 1")).toBeVisible();
    const failedCapture = within(evidence)
      .getByText("capture_fedcba9876543210fedcba9876543210")
      .closest("article");
    expect(failedCapture).not.toBeNull();
    expect(within(failedCapture!).getByText("检查失败")).toBeVisible();
    expect(within(failedCapture!).getByText("inspection_failed")).toBeVisible();
    expect(within(failedCapture!).queryByText("证据不足")).not.toBeInTheDocument();
    expect(screen.getByRole("region", { name: "PCAP 侦探证据回放" })).toBeVisible();
    expect(document.body.textContent).not.toContain(PRIVATE_SENTINEL);
  });

  it("does not mount mascot evidence playback before the PCAP mission is terminal", async () => {
    window.sessionStorage.setItem("token-security-superagent-pcap-mission-id", missionId);
    installFetch({ missionSequence: [runningMission] });
    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "PCAP 证据分诊" }));
    await screen.findByText("任务运行中");

    expect(screen.queryByRole("region", { name: "PCAP 侦探证据回放" })).not.toBeInTheDocument();
  });

  it("opens PCAP on the batch triage segment by default", async () => {
    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "PCAP 证据分诊" }));
    expect(await screen.findByRole("button", { name: "批量分诊" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "数据勘察" })).toHaveAttribute("aria-pressed", "false");
  });

  it("stops triage mission polling after switching to reconnaissance", async () => {
    vi.useFakeTimers();
    render(<App />);
    await act(async () => { await vi.runOnlyPendingTimersAsync(); });
    fireEvent.click(screen.getByRole("button", { name: "PCAP 证据分诊" }));
    await act(async () => { await vi.runOnlyPendingTimersAsync(); });
    fireEvent.click(screen.getByRole("button", { name: "准备开始" }));
    fireEvent.click(screen.getByRole("button", { name: "确认并开始" }));
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    const before = requestUrls().filter((url) => url.includes("/missions/")).length;
    fireEvent.click(screen.getByRole("button", { name: "数据勘察" }));
    await act(async () => { await vi.advanceTimersByTimeAsync(3000); });
    expect(requestUrls().filter((url) => url.includes("/missions/")).length).toBe(before);
  });
});
