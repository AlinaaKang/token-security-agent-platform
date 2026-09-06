import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { AgentReportInspector } from "./AgentReportInspector";

afterEach(cleanup);

describe("AgentReportInspector", () => {
  it("offers a ready cited Markdown report", () => {
    render(<AgentReportInspector report={{ report_id: "report_01", title: "PCAP 调查报告", format: "markdown", status: "ready", artifact_ref: "artifact_public_01", evidence_refs: ["ev_01", "ev_02"], generated_at: "2026-09-07T08:00:00Z" }} />);
    expect(screen.getByRole("link", { name: "打开 Markdown 报告" })).toHaveAttribute("href", "/api/v1/agent/reports/report_01");
    expect(screen.getByText("引用 2 条证据")).toBeVisible();
  });

  it("explains why an unavailable report cannot be opened", () => {
    render(<AgentReportInspector report={{ report_id: "report_02", title: "调查报告", format: "markdown", status: "unavailable", artifact_ref: null, evidence_refs: [], generated_at: "2026-09-07T08:00:00Z" }} />);
    expect(screen.queryByRole("link", { name: "打开 Markdown 报告" })).not.toBeInTheDocument();
    expect(screen.getByText("报告暂不可用，请先完成至少一项可引用的调查证据。")) .toBeVisible();
  });
});
