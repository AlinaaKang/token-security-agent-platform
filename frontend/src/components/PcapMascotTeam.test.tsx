import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { PcapMissionResult } from "../types";
import { PcapMascotTeam } from "./PcapMascotTeam";

const networkOnlyMission: PcapMissionResult = {
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

describe("PcapMascotTeam", () => {
  it("uses the three original mascot assets and never invents Token evidence", () => {
    render(<PcapMascotTeam mission={networkOnlyMission} />);
    expect(screen.getByRole("img", { name: "Guard 语义侦探" })).toHaveAttribute("src", "/mascots/guard-detective.webp");
    expect(screen.getByRole("img", { name: "CPD 曲线侦探" })).toHaveAttribute("src", "/mascots/cpd-detective.webp");
    expect(screen.getByRole("img", { name: "Agent 小队队长" })).toHaveAttribute("src", "/mascots/agent-captain.webp");
    fireEvent.click(screen.getByRole("button", { name: "Guard 语义侦探" }));
    expect(screen.getByText("尚未恢复 Prompt，语义证据暂不可用")).toBeVisible();
    expect(screen.queryByText(/异常 Token 起点/)).not.toBeInTheDocument();
  });

  it("starts with one in-place Guard hop, a next-role cue, and locked later controls", () => {
    render(<PcapMascotTeam mission={networkOnlyMission} />);
    const guard = screen.getByRole("button", { name: "Guard 语义侦探" });
    expect(guard).toBeEnabled();
    expect(screen.getByRole("button", { name: "CPD 曲线侦探" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Agent 小队队长" })).toBeDisabled();
    expect(screen.getByText("下一步：点击语义侦探")).toBeVisible();
    expect(guard.closest("figure")).toHaveAttribute("data-motion", "hop");
    expect(screen.getAllByRole("figure").filter((figure) => figure.dataset.motion === "hop")).toHaveLength(1);
    expect(screen.queryByTestId("pcap-mascot-center-stage")).not.toBeInTheDocument();
  });

  it("unlocks roles in order and keeps completed roles available for immediate replay", async () => {
    render(<PcapMascotTeam mission={networkOnlyMission} />);
    fireEvent.click(screen.getByRole("button", { name: "Guard 语义侦探" }));
    await act(async () => { await vi.advanceTimersByTimeAsync(840); });

    const guard = screen.getByRole("button", { name: "Guard 语义侦探" });
    const cpd = screen.getByRole("button", { name: "CPD 曲线侦探" });
    expect(guard).toBeEnabled();
    expect(cpd).toBeEnabled();
    expect(screen.getByText("下一步：点击曲线侦探")).toBeVisible();
    expect(cpd.closest("figure")).toHaveAttribute("data-motion", "hop");

    fireEvent.click(guard);
    expect(screen.getAllByRole("listitem")).toHaveLength(3);
    expect(guard).toHaveAttribute("aria-pressed", "true");
    expect(cpd).toBeEnabled();
    expect(vi.getTimerCount()).toBe(0);

    fireEvent.click(cpd);
    await act(async () => { await vi.advanceTimersByTimeAsync(420); });
    const captain = screen.getByRole("button", { name: "Agent 小队队长" });
    expect(captain).toBeEnabled();
    fireEvent.click(captain);
    await act(async () => { await vi.advanceTimersByTimeAsync(1_260); });
    expect(screen.getByRole("region", { name: "已证实" })).toBeVisible();
  });

  it("disables every role while a first-visit report is presenting", () => {
    render(<PcapMascotTeam mission={networkOnlyMission} />);
    fireEvent.click(screen.getByRole("button", { name: "Guard 语义侦探" }));
    screen.getAllByRole("button").forEach((button) => expect(button).toBeDisabled());
    expect(screen.getByRole("button", { name: "Guard 语义侦探" }).closest("figure"))
      .toHaveAttribute("data-motion", "hop");
  });

  it("removes hop motion and reveal timers when reduced motion is requested", () => {
    vi.stubGlobal("matchMedia", vi.fn().mockReturnValue({ matches: true }));
    render(<PcapMascotTeam mission={networkOnlyMission} />);
    screen.getAllByRole("figure").forEach((figure) => expect(figure).toHaveAttribute("data-motion", "none"));
    fireEvent.click(screen.getByRole("button", { name: "Guard 语义侦探" }));
    expect(screen.getAllByRole("listitem")).toHaveLength(3);
    expect(vi.getTimerCount()).toBe(0);
  });
});
