import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { PcapDetectionMissionResult } from "../types";
import { PcapDetectionResult } from "./PcapDetectionResult";

const evidence = {
  evidence_id: "evidence_0123456789abcdef0123456789abcdef",
  granularity: "request" as const,
  verified_packet_count: 3,
  start_packet: 4,
  end_packet: 4,
  start_offset_ms: 125,
  end_offset_ms: 125,
  attack_candidate: "sql_injection" as const,
  detector: "http_rule" as const,
  confidence: 0.93,
  supporting_signals: ["sql_syntax_pattern" as const, "request_boundary" as const],
  purpose_candidates: ["auth_bypass" as const, "data_extraction" as const],
};

function mission(
  overrides: Partial<PcapDetectionMissionResult> = {},
): PcapDetectionMissionResult {
  return {
    detection_id: "detection_0123456789abcdef0123456789abcdef",
    objective: "detect_pcap_anomalies",
    status: "completed",
    events: [],
    summary: {
      schema_version: 1,
      analyzed_count: 1,
      succeeded_count: 1,
      failed_count: 0,
      evidence: [evidence],
      processed_samples: [
        { sample_index: 1, status: "succeeded", evidence_count: 1, failure_code: null },
      ],
    },
    report: {
      confirmed_evidence_ids: [evidence.evidence_id],
      candidate_evidence_ids: [evidence.evidence_id],
      unknowns: [],
      recommended_actions: ["review_localized_requests"],
    },
    failure_code: null,
    created_at: "2026-09-06T00:00:00Z",
    ...overrides,
  };
}

describe("PcapDetectionResult", () => {
  afterEach(cleanup);

  it("renders localized evidence, purpose candidates, timeline, and mascots", () => {
    render(
      <PcapDetectionResult
        mission={mission()}
        sampleLabel={() => "上传样本"}
        busy={false}
      />,
    );

    expect(screen.getByText("发现异常候选")).toBeInTheDocument();
    expect(screen.getByText("上传样本 · 完成 · 证据 1")).toHaveClass("is-alert");
    expect(screen.getByText("目的候选：认证绕过、数据提取")).toBeInTheDocument();
    expect(screen.getByText("Packet 4-4")).toBeInTheDocument();
    expect(screen.getByText("短请求无需调用 CPD")).toBeInTheDocument();
    expect(screen.getByText("小队队长")).toBeInTheDocument();
  });

  it("separates no-hit and incomplete conclusions with colored counts", () => {
    const noHit = mission({
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
    });
    const { rerender } = render(
      <PcapDetectionResult mission={noHit} sampleLabel={(index) => `样本 ${index}`} busy={false} />,
    );

    expect(screen.getByText("检测不完整，存在未完成样本")).toBeInTheDocument();
    expect(screen.queryByText("未发现可定位异常")).not.toBeInTheDocument();
    expect(screen.getByText("成功 1")).toHaveClass("is-success");
    expect(screen.getByText("失败 1")).toHaveClass("is-failed");
    expect(screen.getByText("证据 0")).toHaveClass("is-evidence");

    rerender(
      <PcapDetectionResult
        mission={mission({
          summary: { ...noHit.summary!, failed_count: 0, analyzed_count: 1, processed_samples: [noHit.summary!.processed_samples[0]] },
        })}
        sampleLabel={(index) => `样本 ${index}`}
        busy={false}
      />,
    );
    expect(screen.getByText("未发现可定位异常")).toBeInTheDocument();
  });

  it("supports cancellation without rendering protected raw fields", () => {
    const onCancel = vi.fn();
    const running = {
      ...mission({ status: "running" }),
      filename: "PRIVATE_CAPTURE.pcap",
      payload: "PRIVATE_PAYLOAD",
    } as PcapDetectionMissionResult;
    render(
      <PcapDetectionResult
        mission={running}
        sampleLabel={() => "上传样本"}
        onCancel={onCancel}
        busy={false}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "取消" }));
    expect(onCancel).toHaveBeenCalledOnce();
    expect(screen.queryByText("PRIVATE_CAPTURE.pcap")).not.toBeInTheDocument();
    expect(screen.queryByText("PRIVATE_PAYLOAD")).not.toBeInTheDocument();
  });
});
