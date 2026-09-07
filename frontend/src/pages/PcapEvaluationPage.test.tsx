import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { api } from "../api";
import { PcapEvaluationPage } from "./PcapEvaluationPage";

const metrics = {
  sample_count: 8,
  true_positive: 3,
  false_positive: 2,
  false_negative: 1,
  true_negative: 2,
  precision: 0.6,
  recall: 0.75,
  f1: 2 / 3,
  false_positive_rate: 0.5,
  localization_hit_rate: 0.5,
};

describe("PcapEvaluationPage", () => {
  afterEach(() => { cleanup(); vi.restoreAllMocks(); });

  it("shows versioned aggregate metrics, ablations, and the synthetic boundary", async () => {
    vi.spyOn(api, "pcapEvaluation").mockResolvedValue({
      schema_version: 1,
      benchmark_version: "pcap-detection-regression-v1",
      dataset_kind: "synthetic_sanitized_regression",
      generated_at: "2026-09-07T08:00:00Z",
      ...metrics,
      ablations: { rule_only: metrics, behavior_only: metrics, fused: metrics },
    });

    render(<PcapEvaluationPage />);

    expect(screen.getByRole("heading", { name: "PCAP 评测中心" })).toBeVisible();
    const summary = await screen.findByRole("region", { name: "PCAP 回归指标" });
    expect(within(summary).getByText("60.00%")).toBeVisible();
    expect(within(summary).getByText("75.00%")).toBeVisible();
    expect(within(summary).getByText("66.67%")).toBeVisible();
    expect(within(summary).getAllByText("50.00%")).toHaveLength(2);
    expect(screen.getByText("仅规则检测")).toBeVisible();
    expect(screen.getByText("仅行为检测")).toBeVisible();
    expect(screen.getByText("融合检测")).toBeVisible();
    expect(screen.getByText(/不代表真实生产网络的总体准确率/)).toBeVisible();
    expect(screen.getByText("pcap-detection-regression-v1")).toBeVisible();
  });

  it("shows an unavailable result without fabricated zero metrics", async () => {
    vi.spyOn(api, "pcapEvaluation").mockRejectedValue(new Error("service unavailable"));

    render(<PcapEvaluationPage />);

    expect(await screen.findByRole("alert")).toHaveTextContent("PCAP 评测报告暂不可用");
    expect(screen.queryByText("0.00%")).not.toBeInTheDocument();
  });
});
