import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { PcapMissionResult } from "../types";
import { PcapEvidenceDesk } from "./PcapEvidenceDesk";

const mission: PcapMissionResult = {
  mission_id: "mission_public",
  objective: "triage_pcap_evidence",
  status: "completed",
  batch_id: "batch_public",
  events: [],
  summary: {
    schema_version: 1,
    batch_id: "batch_public",
    selected_count: 2,
    succeeded_count: 2,
    failed_count: 0,
    skipped_count: 0,
    captures: [
      {
        capture_id: "capture_plaintext",
        status: "succeeded",
        packet_count: 12,
        protocol_counts: { http: 12 },
        visibility: {
          plaintext_application_protocol_observed: true,
          encrypted_transport_observed: false,
          tls_observed: false,
          quic_observed: false,
        },
        capability: "token_eligible",
        error_code: null,
      },
      {
        capture_id: "capture_encrypted",
        status: "succeeded",
        packet_count: 12,
        protocol_counts: { tls: 12 },
        visibility: {
          plaintext_application_protocol_observed: false,
          encrypted_transport_observed: true,
          tls_observed: true,
          quic_observed: false,
        },
        capability: "traffic_only",
        error_code: null,
      },
    ],
  },
  report: {
    confirmed: ["traffic_only_evidence"],
    candidates: ["plaintext_application_protocol_candidate_not_proven_llm_traffic"],
    unknowns: ["cpd_evidence_unavailable", "token_evidence_unavailable"],
    recommended_action: ["retain_public_metadata"],
  },
  limitations: ["no_packet_payload_retained", "token_evidence_unavailable"],
  created_at: "2026-09-01T02:00:00Z",
};

beforeEach(() => {
  vi.useFakeTimers();
  vi.stubGlobal("matchMedia", vi.fn().mockReturnValue({ matches: false }));
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("PcapEvidenceDesk", () => {
  it("reveals first-visit evidence one safe line every 420 ms", async () => {
    const onComplete = vi.fn();
    render(<PcapEvidenceDesk mission={mission} role="guard" replay={false} onComplete={onComplete} />);

    expect(screen.getByText("尚未恢复 Prompt，语义证据暂不可用")).toBeVisible();
    expect(screen.queryByText("明文应用协议可见：1 / 2 个捕获")).not.toBeInTheDocument();

    await act(async () => { await vi.advanceTimersByTimeAsync(420); });
    expect(screen.getByText("明文应用协议可见：1 / 2 个捕获")).toBeVisible();
    expect(screen.queryByText(/加密传输可见/)).not.toBeInTheDocument();

    await act(async () => { await vi.advanceTimersByTimeAsync(420); });
    expect(screen.getByText("加密传输可见：1 / 2 个捕获；加密载荷内容不可见")).toBeVisible();
    expect(onComplete).toHaveBeenCalledTimes(1);
  });

  it("renders every line immediately when replaying a visited role", () => {
    render(<PcapEvidenceDesk mission={mission} role="guard" replay onComplete={vi.fn()} />);
    expect(screen.getAllByRole("listitem")).toHaveLength(3);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("uses no reveal timer when reduced motion is requested", () => {
    vi.stubGlobal("matchMedia", vi.fn().mockReturnValue({ matches: true }));
    const onComplete = vi.fn();
    render(<PcapEvidenceDesk mission={mission} role="guard" replay={false} onComplete={onComplete} />);

    expect(screen.getAllByRole("listitem")).toHaveLength(3);
    expect(onComplete).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("renders Captain findings as distinct confirmed, candidate, and unknown sections", () => {
    render(<PcapEvidenceDesk mission={mission} role="captain" replay onComplete={vi.fn()} />);
    expect(screen.getByRole("region", { name: "已证实" })).toHaveTextContent("仅有网络流量证据");
    expect(screen.getByRole("region", { name: "候选" })).toHaveTextContent("明文应用协议候选，不证明 LLM 流量");
    expect(screen.getByRole("region", { name: "未知" })).toHaveTextContent("CPD 证据不可用；Token 证据不可用");
  });
});
