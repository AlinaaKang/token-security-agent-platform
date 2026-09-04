import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
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

function detectionResult(status: "completed" | "queued" = "completed") {
  return {
    detection_id: "detection_0123456789abcdef0123456789abcdef",
    objective: "detect_pcap_anomalies",
    status,
    events: [],
    summary: { schema_version: 1, analyzed_count: 1, succeeded_count: 1, failed_count: 0, evidence: [evidence] },
    report: { confirmed_evidence_ids: [evidence.evidence_id], candidate_evidence_ids: [evidence.evidence_id], unknowns: [], recommended_actions: ["review_localized_requests"] },
    failure_code: null,
    created_at: "2026-09-04T00:00:00Z",
  };
}

describe("PcapDetectionWorkspace", () => {
  afterEach(() => cleanup());
  beforeEach(() => {
    vi.restoreAllMocks();
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
  });
});
