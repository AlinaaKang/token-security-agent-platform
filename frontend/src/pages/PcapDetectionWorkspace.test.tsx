import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { PcapDetectionWorkspace } from "./PcapDetectionWorkspace";

const evidence = {
  evidence_id: "evidence_0123456789abcdef0123456789abcdef",
  granularity: "request",
  verified_packet_count: 3,
  start_packet: 2,
  end_packet: 2,
  start_offset_ms: 100,
  end_offset_ms: 100,
  attack_candidate: "sql_injection",
  detector: "http_rule",
  confidence: 0.95,
  supporting_signals: ["sql_syntax_pattern", "request_boundary"],
};

const detectionMissionKey = "token-security-superagent-pcap-detection-id";

function detectionResult(
  status: "completed" | "queued" | "running" = "completed",
  detectionId = "detection_0123456789abcdef0123456789abcdef",
) {
  return {
    detection_id: detectionId,
    objective: "detect_pcap_anomalies",
    status,
    events: [],
    summary: { schema_version: 1, analyzed_count: 1, succeeded_count: 1, failed_count: 0, evidence: [evidence], processed_samples: [{ sample_index: 1, status: "succeeded", evidence_count: 1, failure_code: null }] },
    report: { confirmed_evidence_ids: [evidence.evidence_id], candidate_evidence_ids: [evidence.evidence_id], unknowns: [], recommended_actions: ["review_localized_requests"] },
    failure_code: null,
    created_at: "2026-09-04T00:00:00Z",
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((resolvePromise) => { resolve = resolvePromise; });
  return { promise, resolve };
}

describe("PcapDetectionWorkspace", () => {
  afterEach(() => {
    cleanup();
    window.sessionStorage.clear();
    vi.useRealTimers();
  });
  beforeEach(() => {
    vi.restoreAllMocks();
    window.sessionStorage.clear();
    vi.stubGlobal("fetch", vi.fn((url: string, init?: RequestInit) => {
      if (url.includes("/overview")) return Promise.resolve(new Response(JSON.stringify({ enabled: true, eligible_file_count: 3, max_files: 20, localization: "request_or_packet" }), { status: 200 }));
      if (init?.method === "POST" && url.includes("authorizations")) return Promise.resolve(new Response(JSON.stringify({ authorization_id: "pcap_auth_0123456789abcdef0123456789abcdef", max_files: 1 }), { status: 201 }));
      if (init?.method === "POST") return Promise.resolve(new Response(JSON.stringify(detectionResult("completed")), { status: 201 }));
      return Promise.resolve(new Response(JSON.stringify(detectionResult()), { status: 200 }));
    }));
  });

  it("requires an explicit authorization confirmation before starting", async () => {
    render(<PcapDetectionWorkspace />);
    expect(await screen.findByRole("button", { name: /准备异常检测/ })).toBeEnabled();
    expect(screen.queryByText("确认并开始")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /准备异常检测/ }));
    expect(screen.getByText("仅在确认后进入 Docker 隔离检测")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /确认并开始/ })).toBeEnabled();
  });

  it("renders localized evidence, timeline, and mascot roles after detection", async () => {
    render(<PcapDetectionWorkspace />);
    fireEvent.click(await screen.findByRole("button", { name: /准备异常检测/ }));
    fireEvent.click(screen.getByRole("button", { name: /确认并开始/ }));
    expect((await screen.findAllByText("SQL 注入候选")).length).toBeGreaterThan(0);
    expect(screen.getByText("Packet 2-2")).toBeInTheDocument();
    expect(screen.getByText("短请求无需调用 CPD")).toBeInTheDocument();
    expect(screen.getByText("规则侦探")).toBeInTheDocument();
    expect(screen.getByText("小队队长")).toBeInTheDocument();
    expect(screen.getByText("样本 01 · 完成 · 证据 1")).toHaveClass("is-alert");
  });

  it("polls a queued mission until the backend publishes the completed result", async () => {
    let reads = 0;
    vi.stubGlobal("fetch", vi.fn((url: string, init?: RequestInit) => {
      if (url.includes("/overview")) return Promise.resolve(new Response(JSON.stringify({ enabled: true, eligible_file_count: 3, max_files: 20, localization: "request_or_packet" }), { status: 200 }));
      if (init?.method === "POST" && url.includes("authorizations")) return Promise.resolve(new Response(JSON.stringify({ authorization_id: "pcap_auth_0123456789abcdef0123456789abcdef", max_files: 1 }), { status: 201 }));
      if (init?.method === "POST") return Promise.resolve(new Response(JSON.stringify(detectionResult("queued")), { status: 201 }));
      reads += 1;
      return Promise.resolve(new Response(JSON.stringify(detectionResult(reads > 0 ? "completed" : "queued")), { status: 200 }));
    }));
    render(<PcapDetectionWorkspace />);
    fireEvent.click(await screen.findByRole("button", { name: /准备异常检测/ }));
    fireEvent.click(screen.getByRole("button", { name: /确认并开始/ }));
    expect(await screen.findByText("检测完成")).toBeInTheDocument();
  });

  it("restores a saved running mission and polls until it completes", async () => {
    window.sessionStorage.setItem(detectionMissionKey, "detection_saved_running");
    let missionReads = 0;
    vi.stubGlobal("fetch", vi.fn((url: string) => {
      if (url.includes("/overview")) return Promise.resolve(new Response(JSON.stringify({ enabled: true, eligible_file_count: 3, max_files: 20, localization: "request_or_packet" }), { status: 200 }));
      missionReads += 1;
      return Promise.resolve(new Response(JSON.stringify(detectionResult(missionReads === 1 ? "running" : "completed", "detection_saved_running")), { status: 200 }));
    }));

    render(<PcapDetectionWorkspace />);

    expect(await screen.findByText("检测运行中")).toBeInTheDocument();
    expect(await screen.findByText("检测完成")).toBeInTheDocument();
    expect(window.sessionStorage.getItem(detectionMissionKey)).toBe("detection_saved_running");
    expect(missionReads).toBe(2);
  });

  it("restores a saved terminal mission without removing its saved ID", async () => {
    window.sessionStorage.setItem(detectionMissionKey, "detection_saved_terminal");
    vi.stubGlobal("fetch", vi.fn((url: string) => {
      if (url.includes("/overview")) return Promise.resolve(new Response(JSON.stringify({ enabled: true, eligible_file_count: 3, max_files: 20, localization: "request_or_packet" }), { status: 200 }));
      return Promise.resolve(new Response(JSON.stringify(detectionResult("completed", "detection_saved_terminal")), { status: 200 }));
    }));

    render(<PcapDetectionWorkspace />);

    expect(await screen.findByText("检测完成")).toBeInTheDocument();
    expect(window.sessionStorage.getItem(detectionMissionKey)).toBe("detection_saved_terminal");
  });

  it.each([404, 410])("clears a missing saved mission after a %s restore response without authorizing", async (status) => {
    window.sessionStorage.setItem(detectionMissionKey, "detection_missing");
    let authorizationCalls = 0;
    vi.stubGlobal("fetch", vi.fn((url: string, init?: RequestInit) => {
      if (url.includes("/overview")) return Promise.resolve(new Response(JSON.stringify({ enabled: true, eligible_file_count: 3, max_files: 20, localization: "request_or_packet" }), { status: 200 }));
      if (init?.method === "POST") authorizationCalls += 1;
      return Promise.resolve(new Response(JSON.stringify({ detail: "missing" }), { status }));
    }));

    render(<PcapDetectionWorkspace />);

    expect(await screen.findByRole("alert")).toHaveTextContent("已保存的异常检测任务已失效或无效，请开始新任务");
    expect(screen.getByRole("button", { name: /准备异常检测/ })).toBeEnabled();
    expect(window.sessionStorage.getItem(detectionMissionKey)).toBeNull();
    expect(authorizationCalls).toBe(0);
  });

  it.each([
    ["null", null],
    ["incomplete", { objective: "detect_pcap_anomalies" }],
    ["wrong objective", { ...detectionResult("completed", "detection_saved_invalid"), objective: "reconnoiter_pcap_dataset" }],
    ["wrong ID", detectionResult("completed", "detection_different")],
    ["unusable structure", { ...detectionResult("completed", "detection_saved_invalid"), report: null }],
  ])("clears a saved mission with a %s restore payload without rendering or polling it", async (_case, payload) => {
    window.sessionStorage.setItem(detectionMissionKey, "detection_saved_invalid");
    const missionUrls: string[] = [];
    vi.stubGlobal("fetch", vi.fn((url: string) => {
      if (url.includes("/overview")) return Promise.resolve(new Response(JSON.stringify({ enabled: true, eligible_file_count: 3, max_files: 20, localization: "request_or_packet" }), { status: 200 }));
      missionUrls.push(url);
      return Promise.resolve(new Response(JSON.stringify(payload), { status: 200 }));
    }));

    render(<PcapDetectionWorkspace />);

    expect(await screen.findByRole("alert")).toHaveTextContent("已保存的异常检测任务已失效或无效，请开始新任务");
    expect(screen.getByRole("button", { name: /准备异常检测/ })).toBeEnabled();
    expect(screen.queryByText("检测完成")).not.toBeInTheDocument();
    expect(window.sessionStorage.getItem(detectionMissionKey)).toBeNull();
    expect(missionUrls).toHaveLength(1);
    expect(missionUrls[0]).toContain("detection_saved_invalid");
    expect(missionUrls[0]).not.toContain("undefined");
  });

  it("marks the workspace busy and names the task while restoring", async () => {
    window.sessionStorage.setItem(detectionMissionKey, "detection_pending_restore");
    const pendingRestore = deferred<Response>();
    vi.stubGlobal("fetch", vi.fn((url: string) => {
      if (url.includes("/overview")) return Promise.resolve(new Response(JSON.stringify({ enabled: true, eligible_file_count: 3, max_files: 20, localization: "request_or_packet" }), { status: 200 }));
      return pendingRestore.promise;
    }));

    render(<PcapDetectionWorkspace />);

    expect(await screen.findByText("正在恢复异常检测任务")).toBeVisible();
    expect(screen.getByRole("region", { name: "PCAP 异常检测工作区" })).toHaveAttribute("aria-busy", "true");

    pendingRestore.resolve(new Response(JSON.stringify(detectionResult("completed", "detection_pending_restore")), { status: 200 }));
    expect(await screen.findByText("检测完成")).toBeInTheDocument();
  });

  it("retains a saved mission after a transient restore failure and retries the same ID", async () => {
    window.sessionStorage.setItem(detectionMissionKey, "detection_retryable");
    const missionUrls: string[] = [];
    let missionReads = 0;
    let authorizationCalls = 0;
    vi.stubGlobal("fetch", vi.fn((url: string, init?: RequestInit) => {
      if (url.includes("/overview")) return Promise.resolve(new Response(JSON.stringify({ enabled: true, eligible_file_count: 3, max_files: 20, localization: "request_or_packet" }), { status: 200 }));
      if (init?.method === "POST") authorizationCalls += 1;
      missionUrls.push(url);
      missionReads += 1;
      if (missionReads === 1) return Promise.resolve(new Response(JSON.stringify({ detail: "temporary failure" }), { status: 503 }));
      return Promise.resolve(new Response(JSON.stringify(detectionResult("completed", "detection_retryable")), { status: 200 }));
    }));

    render(<PcapDetectionWorkspace />);

    expect(await screen.findByRole("alert")).toHaveTextContent("无法恢复异常检测任务，请重试");
    expect(window.sessionStorage.getItem(detectionMissionKey)).toBe("detection_retryable");
    fireEvent.click(screen.getByRole("button", { name: "重试恢复" }));
    expect(await screen.findByText("检测完成")).toBeInTheDocument();
    expect(missionUrls).toEqual([
      expect.stringContaining("detection_retryable"),
      expect.stringContaining("detection_retryable"),
    ]);
    expect(authorizationCalls).toBe(0);
  });

  it("continues starting a detection when session storage refuses to persist the mission ID", async () => {
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new Error("storage unavailable"); });

    render(<PcapDetectionWorkspace />);
    fireEvent.click(await screen.findByRole("button", { name: /准备异常检测/ }));
    fireEvent.click(screen.getByRole("button", { name: /确认并开始/ }));

    expect(await screen.findByText("检测完成")).toBeInTheDocument();
    expect(screen.queryByText("无法启动异常检测，请重试")).not.toBeInTheDocument();
  });

  it("continues loading the workspace when session storage refuses to read a mission ID", async () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => { throw new Error("storage unavailable"); });

    render(<PcapDetectionWorkspace />);

    expect(await screen.findByRole("button", { name: /准备异常检测/ })).toBeEnabled();
    expect(vi.mocked(fetch).mock.calls.filter(([input]) => String(input).includes("/missions/"))).toHaveLength(0);
  });

  it("keeps an invalid restore usable when session storage refuses to remove the stale ID", async () => {
    window.sessionStorage.setItem(detectionMissionKey, "detection_unremovable");
    vi.spyOn(Storage.prototype, "removeItem").mockImplementation(() => { throw new Error("storage unavailable"); });
    vi.stubGlobal("fetch", vi.fn((url: string) => {
      if (url.includes("/overview")) return Promise.resolve(new Response(JSON.stringify({ enabled: true, eligible_file_count: 3, max_files: 20, localization: "request_or_packet" }), { status: 200 }));
      return Promise.resolve(new Response(JSON.stringify({ objective: "detect_pcap_anomalies" }), { status: 200 }));
    }));

    render(<PcapDetectionWorkspace />);

    expect(await screen.findByRole("alert")).toHaveTextContent("已保存的异常检测任务已失效或无效，请开始新任务");
    expect(screen.getByRole("button", { name: /准备异常检测/ })).toBeEnabled();
    await waitFor(() => expect(vi.mocked(fetch).mock.calls.filter(([input]) => String(input).includes("/missions/"))).toHaveLength(1));
  });

  it("states explicitly when a completed scan found no localized anomaly", async () => {
    vi.stubGlobal("fetch", vi.fn((url: string, init?: RequestInit) => {
      if (url.includes("/overview")) return Promise.resolve(new Response(JSON.stringify({ enabled: true, eligible_file_count: 1, max_files: 20, localization: "request_or_packet" }), { status: 200 }));
      if (init?.method === "POST" && url.includes("authorizations")) return Promise.resolve(new Response(JSON.stringify({ authorization_id: "pcap_auth_0123456789abcdef0123456789abcdef", max_files: 1 }), { status: 201 }));
      return Promise.resolve(new Response(JSON.stringify({ ...detectionResult("completed"), summary: { schema_version: 1, analyzed_count: 1, succeeded_count: 1, failed_count: 0, evidence: [] }, report: { confirmed_evidence_ids: [], candidate_evidence_ids: [], unknowns: ["no_localized_attack_evidence"], recommended_actions: ["allow_no_rule_evidence"] } }), { status: init?.method === "POST" ? 201 : 200 }));
    }));
    render(<PcapDetectionWorkspace />);
    fireEvent.click(await screen.findByRole("button", { name: /准备异常检测/ }));
    fireEvent.click(screen.getByRole("button", { name: /确认并开始/ }));
    expect(await screen.findByText("未发现可定位异常")).toBeInTheDocument();
    expect(screen.getByLabelText("检测统计")).toHaveTextContent("成功 1");
    expect(screen.getByLabelText("检测统计")).toHaveTextContent("失败 0");
    expect(screen.getByLabelText("检测统计")).toHaveTextContent("证据 0");
  });

  it("does not present an incomplete scan as an all-clear result", async () => {
    vi.stubGlobal("fetch", vi.fn((url: string, init?: RequestInit) => {
      if (url.includes("/overview")) return Promise.resolve(new Response(JSON.stringify({ enabled: true, eligible_file_count: 2, max_files: 20, localization: "request_or_packet" }), { status: 200 }));
      if (init?.method === "POST" && url.includes("authorizations")) return Promise.resolve(new Response(JSON.stringify({ authorization_id: "pcap_auth_0123456789abcdef0123456789abcdef", max_files: 2 }), { status: 201 }));
      return Promise.resolve(new Response(JSON.stringify({
        ...detectionResult("completed"),
        summary: {
          schema_version: 1,
          analyzed_count: 2,
          succeeded_count: 1,
          failed_count: 1,
          evidence: [],
          processed_samples: [
            { sample_index: 1, status: "succeeded", evidence_count: 0, failure_code: null },
            { sample_index: 2, status: "failed", evidence_count: 0, failure_code: "tool_failed" },
          ],
        },
        report: {
          confirmed_evidence_ids: [],
          candidate_evidence_ids: [],
          unknowns: ["no_localized_attack_evidence", "partial_file_failure"],
          recommended_actions: ["allow_no_rule_evidence", "retry_failed_files"],
        },
      }), { status: init?.method === "POST" ? 201 : 200 }));
    }));

    render(<PcapDetectionWorkspace />);
    fireEvent.click(await screen.findByRole("button", { name: /准备异常检测/ }));
    fireEvent.click(screen.getByRole("button", { name: /确认并开始/ }));

    expect(await screen.findByText("检测不完整，存在未完成样本")).toBeInTheDocument();
    expect(screen.queryByText("未发现可定位异常")).not.toBeInTheDocument();
    expect(screen.queryByText("证据不足，保持允许。")).not.toBeInTheDocument();
    expect(screen.queryByText("当前样本保留为允许结果。")).not.toBeInTheDocument();
    expect(screen.getAllByText("部分样本未完成，请重试失败样本。")).not.toHaveLength(0);
  });
});
