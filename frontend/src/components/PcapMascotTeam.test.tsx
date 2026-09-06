import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { PcapMissionResult } from "../types";
import { PcapMascotTeam } from "./PcapMascotTeam";

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
        packet_count: 18,
        protocol_counts: { tls: 18 },
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
  report: { confirmed: [], candidates: [], unknowns: [], recommended_action: [] },
  limitations: [],
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
  it("shows the batch replay, default capture, role order, and original assets", () => {
    render(<PcapMascotTeam mission={mission} />);
    expect(screen.getByRole("region", { name: "批量分诊互动复盘" })).toBeVisible();
    expect(screen.getByText("逐份解释当前批次的公开 PCAP 证据")).toBeVisible();
    expect(screen.getByRole("button", { name: "回放捕获 1" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "回放捕获 2" })).toHaveAttribute("aria-pressed", "false");
    expect(screen.getByRole("button", { name: "文件解析员" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "流量分析员" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "分诊队长" })).toBeDisabled();
    expect(screen.getByRole("img", { name: "文件解析员" })).toHaveAttribute("src", "/mascots/guard-detective.webp");
    expect(screen.getByRole("img", { name: "流量分析员" })).toHaveAttribute("src", "/mascots/cpd-detective.webp");
    expect(screen.getByRole("img", { name: "分诊队长" })).toHaveAttribute("src", "/mascots/agent-captain.webp");
  });

  it("replays roles sequentially and keeps completed roles available", async () => {
    render(<PcapMascotTeam mission={mission} />);
    fireEvent.click(screen.getByRole("button", { name: "文件解析员" }));
    expect(screen.getByText("检查成功；已验证 12 个数据包")).toBeVisible();
    const traffic = screen.getByRole("button", { name: "流量分析员" });
    expect(traffic).toBeEnabled();
    fireEvent.click(traffic);
    expect(screen.getByText("协议计数：HTTP 12")).toBeVisible();
    expect(screen.getByRole("button", { name: "分诊队长" })).toBeDisabled();
    await act(async () => { await vi.advanceTimersByTimeAsync(840); });
    expect(screen.getByRole("button", { name: "分诊队长" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "文件解析员" })).toBeEnabled();
  });

  it("switches capture and resets roles without leaking prior evidence", () => {
    render(<PcapMascotTeam mission={mission} />);
    fireEvent.click(screen.getByRole("button", { name: "文件解析员" }));
    expect(screen.getByText("检查成功；已验证 12 个数据包")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "回放捕获 2" }));
    expect(screen.getByRole("button", { name: "回放捕获 2" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "回放捕获 1" })).toHaveAttribute("aria-pressed", "false");
    expect(screen.getByRole("button", { name: "文件解析员" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "流量分析员" })).toBeDisabled();
    expect(screen.queryByText("检查成功；已验证 12 个数据包")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "文件解析员" }));
    expect(screen.getByText("检查成功；已验证 18 个数据包")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "流量分析员" }));
    expect(screen.getByText("协议计数：TLS 18")).toBeVisible();
    expect(screen.queryByText("协议计数：HTTP 12")).not.toBeInTheDocument();
  });

  it("shows an empty batch without mascot controls", () => {
    const emptyMission = { ...mission, summary: { ...mission.summary!, captures: [] } };
    render(<PcapMascotTeam mission={emptyMission} />);
    expect(screen.getByText("本批次没有可回放文件")).toBeVisible();
    expect(screen.queryByRole("button", { name: "文件解析员" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "流量分析员" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "分诊队长" })).not.toBeInTheDocument();
  });
});
