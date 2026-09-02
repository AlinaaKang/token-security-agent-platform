import { act, cleanup, render, screen } from "@testing-library/react";
import { useLayoutEffect, useRef } from "react";
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

function installMotionPreference(initialMatches = false) {
  let matches = initialMatches;
  const listeners = new Set<(event: MediaQueryListEvent) => void>();
  const mediaQuery = {
    get matches() { return matches; },
    media: "(prefers-reduced-motion: reduce)",
    onchange: null,
    addEventListener: vi.fn((_type: string, listener: (event: MediaQueryListEvent) => void) => {
      listeners.add(listener);
    }),
    removeEventListener: vi.fn((_type: string, listener: (event: MediaQueryListEvent) => void) => {
      listeners.delete(listener);
    }),
    addListener: vi.fn(),
    removeListener: vi.fn(),
    dispatchEvent: vi.fn(),
  };
  vi.stubGlobal("matchMedia", vi.fn().mockReturnValue(mediaQuery));
  return {
    mediaQuery,
    listenerCount: () => listeners.size,
    setReduced(nextMatches: boolean) {
      matches = nextMatches;
      listeners.forEach((listener) => listener({ matches } as MediaQueryListEvent));
    },
  };
}

function CommitProbe({
  role,
  replay,
  onCommit,
}: {
  role: "guard" | "cpd" | "captain";
  replay: boolean;
  onCommit: (text: string) => void;
}) {
  const rootRef = useRef<HTMLDivElement>(null);
  useLayoutEffect(() => {
    onCommit(rootRef.current?.textContent ?? "");
  }, [onCommit, replay, role]);
  return (
    <div ref={rootRef}>
      <PcapEvidenceDesk mission={mission} role={role} replay={replay} onComplete={vi.fn()} />
    </div>
  );
}

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

  it("renders every line immediately when replaying a completed role", () => {
    render(<PcapEvidenceDesk mission={mission} role="guard" replay onComplete={vi.fn()} />);
    expect(screen.getAllByRole("listitem")).toHaveLength(3);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("commits only the first CPD line immediately after Guard replay", () => {
    const commits: string[] = [];
    const onCommit = (text: string) => commits.push(text);
    const { rerender } = render(<CommitProbe role="guard" replay onCommit={onCommit} />);
    commits.length = 0;

    rerender(<CommitProbe role="cpd" replay={false} onCommit={onCommit} />);

    expect(commits[0]).toContain("明文应用协议候选：1 个");
    expect(commits[0]).not.toContain("模型与 Token 证据不可用");
  });

  it("commits only Captain counts immediately after CPD replay", () => {
    const commits: string[] = [];
    const onCommit = (text: string) => commits.push(text);
    const { rerender } = render(<CommitProbe role="cpd" replay onCommit={onCommit} />);
    commits.length = 0;

    rerender(<CommitProbe role="captain" replay={false} onCommit={onCommit} />);

    expect(commits[0]).toContain("批次计数：已选择 2，成功 2，失败 0，跳过 0");
    expect(commits[0]).not.toContain("仅有网络流量证据");
    expect(commits[0]).not.toContain("明文应用协议候选，不证明 LLM 流量");
  });

  it("uses no reveal timer when reduced motion is requested", () => {
    vi.stubGlobal("matchMedia", vi.fn().mockReturnValue({ matches: true }));
    const onComplete = vi.fn();
    render(<PcapEvidenceDesk mission={mission} role="guard" replay={false} onComplete={onComplete} />);

    expect(screen.getAllByRole("listitem")).toHaveLength(3);
    expect(onComplete).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("finishes active playback when reduced motion changes and removes its listener", () => {
    const preference = installMotionPreference();
    const onComplete = vi.fn();
    const { unmount } = render(
      <PcapEvidenceDesk mission={mission} role="guard" replay={false} onComplete={onComplete} />,
    );
    expect(screen.getAllByRole("listitem")).toHaveLength(1);
    expect(vi.getTimerCount()).toBe(1);
    expect(preference.listenerCount()).toBe(1);

    act(() => preference.setReduced(true));
    expect(screen.getAllByRole("listitem")).toHaveLength(3);
    expect(onComplete).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);

    act(() => preference.setReduced(false));
    expect(screen.getAllByRole("listitem")).toHaveLength(3);
    expect(onComplete).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);

    unmount();
    expect(preference.mediaQuery.removeEventListener).toHaveBeenCalledTimes(1);
    expect(preference.listenerCount()).toBe(0);
  });

  it("renders Captain findings as distinct confirmed, candidate, and unknown sections", () => {
    render(<PcapEvidenceDesk mission={mission} role="captain" replay onComplete={vi.fn()} />);
    expect(screen.getByRole("region", { name: "已证实" })).toHaveTextContent("仅有网络流量证据");
    expect(screen.getByRole("region", { name: "候选" })).toHaveTextContent("明文应用协议候选，不证明 LLM 流量");
    expect(screen.getByRole("region", { name: "未知" })).toHaveTextContent("CPD 证据不可用；Token 证据不可用");
  });
});
