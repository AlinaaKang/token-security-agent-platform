import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { PcapCaptureEvidence } from "../types";
import { PcapEvidenceDesk } from "./PcapEvidenceDesk";

const plaintextCapture: PcapCaptureEvidence = {
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
};

const encryptedCapture: PcapCaptureEvidence = {
  ...plaintextCapture,
  capture_id: "capture_encrypted",
  protocol_counts: { tls: 12 },
  visibility: {
    plaintext_application_protocol_observed: false,
    encrypted_transport_observed: true,
    tls_observed: true,
    quic_observed: false,
  },
  capability: "traffic_only",
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
  it("reveals parser evidence one safe line every 420 ms", async () => {
    const onComplete = vi.fn();
    render(
      <PcapEvidenceDesk
        missionId="mission_public"
        capture={plaintextCapture}
        role="parser"
        replay={false}
        onComplete={onComplete}
      />,
    );

    expect(screen.getByText("检查成功；已验证 12 个数据包")).toBeVisible();
    await act(async () => { await vi.advanceTimersByTimeAsync(420); });
    expect(onComplete).toHaveBeenCalledTimes(1);
  });

  it("renders all traffic lines immediately when replaying a completed role", () => {
    render(
      <PcapEvidenceDesk
        missionId="mission_public"
        capture={encryptedCapture}
        role="traffic"
        replay
        onComplete={vi.fn()}
      />,
    );
    expect(screen.getByText("协议计数：TLS 12")).toBeVisible();
    expect(screen.getByText("加密传输可见；加密载荷内容不可见")).toBeVisible();
    expect(screen.getByText("证据能力：仅有网络证据可用，无法恢复应用层语义")).toBeVisible();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("renders Captain findings with a recommendation section", () => {
    render(
      <PcapEvidenceDesk
        missionId="mission_public"
        capture={plaintextCapture}
        role="captain"
        replay
        onComplete={vi.fn()}
      />,
    );
    expect(screen.getByRole("region", { name: "已证实" })).toBeVisible();
    expect(screen.getByRole("region", { name: "候选" })).toBeVisible();
    expect(screen.getByRole("region", { name: "未知" })).toBeVisible();
    expect(screen.getByRole("region", { name: "建议动作" })).toHaveTextContent("建议进入异常检测继续研判");
  });

  it("uses no reveal timer when reduced motion is requested", () => {
    vi.stubGlobal("matchMedia", vi.fn().mockReturnValue({ matches: true }));
    const onComplete = vi.fn();
    render(
      <PcapEvidenceDesk
        missionId="mission_public"
        capture={plaintextCapture}
        role="traffic"
        replay={false}
        onComplete={onComplete}
      />,
    );
    expect(screen.getAllByRole("listitem")).toHaveLength(3);
    expect(onComplete).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("cleans up the reveal timer when the desk unmounts", () => {
    const onComplete = vi.fn();
    const { unmount } = render(
      <PcapEvidenceDesk
        missionId="mission_public"
        capture={plaintextCapture}
        role="traffic"
        replay={false}
        onComplete={onComplete}
      />,
    );
    expect(vi.getTimerCount()).toBe(1);
    unmount();
    expect(vi.getTimerCount()).toBe(0);
    expect(onComplete).not.toHaveBeenCalled();
  });
});
