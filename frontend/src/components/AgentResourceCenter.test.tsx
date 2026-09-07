import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { AgentResourceCenter } from "./AgentResourceCenter";

afterEach(cleanup);

describe("AgentResourceCenter", () => {
  it("labels real simulated degraded and unavailable connectors", () => {
    render(<AgentResourceCenter resource="connectors" loading={false} error={null} playbooks={[]} knowledge={null} reports={[]} connectors={[
      { connector_id: "pcap_docker", title: "PCAP 隔离 Docker", state: "available", authenticity: "real" },
      { connector_id: "endpoint_demo", title: "端点遥测演示", state: "simulated", authenticity: "simulated" },
      { connector_id: "autodl_guard", title: "AutoDL 语义 Guard", state: "degraded", authenticity: "derived" },
      { connector_id: "external_edr", title: "外部 EDR", state: "unavailable", authenticity: "derived" },
    ]} />);
    expect(screen.getByText("真实可用")).toBeVisible();
    expect(screen.getByText("内置仿真")).toBeVisible();
    expect(screen.getByText("降级")).toBeVisible();
    expect(screen.getByText("未接入")).toBeVisible();
    expect(screen.queryByRole("textbox", { name: /连接器 URL/ })).not.toBeInTheDocument();
  });

  it("shows versioned playbooks without arbitrary code nodes", () => {
    render(<AgentResourceCenter resource="skills" loading={false} error={null} connectors={[]} knowledge={null} reports={[]} playbooks={[{
      playbook_id: "pcap_dataset_v1", title: "PCAP 数据集调查", task_type: "pcap_dataset_investigation", description: "分批检查异常候选。", version: "1.0.0", step_count: 4,
    }]} />);
    expect(screen.getByText("PCAP 数据集调查")).toBeVisible();
    expect(screen.getByText("v1.0.0 · 4 个受控步骤")).toBeVisible();
    expect(screen.queryByRole("button", { name: /添加.*代码/ })).not.toBeInTheDocument();
  });

  it("shows the versioned knowledge catalog instead of a static placeholder", () => {
    render(<AgentResourceCenter resource="knowledge" loading={false} error={null} connectors={[]} playbooks={[]} reports={[]} knowledge={{
      snapshot_version: "official-v2", card_count: 18,
      items: [{ knowledge_id: "owasp-llm01", title: "提示词注入风险", publisher: "owasp", version: "2025", risk_domain: "prompt_injection" }],
    }} />);
    expect(screen.getByText("official-v2 · 18 条知识卡片")).toBeVisible();
    expect(screen.getByText("提示词注入风险")).toBeVisible();
    expect(screen.getByText("OWASP · 2025")).toBeVisible();
  });

  it("shows report downloads and actionable loading empty and error states", () => {
    const { rerender } = render(<AgentResourceCenter resource="reports" loading={true} error={null} connectors={[]} playbooks={[]} knowledge={null} reports={[]} />);
    expect(screen.getByText("正在读取调查报告")).toBeVisible();
    rerender(<AgentResourceCenter resource="reports" loading={false} error={null} connectors={[]} playbooks={[]} knowledge={null} reports={[]} />);
    expect(screen.getByText(/完成一次 Prompt 或 PCAP 调查后/)).toBeVisible();
    rerender(<AgentResourceCenter resource="reports" loading={false} error="报告接口不可用" connectors={[]} playbooks={[]} knowledge={null} reports={[]} />);
    expect(screen.getByRole("alert")).toHaveTextContent("报告接口不可用");
    rerender(<AgentResourceCenter resource="reports" loading={false} error={null} connectors={[]} playbooks={[]} knowledge={null} reports={[{
      task_id: "task_01", task_title: "Prompt 安全调查", final_status: "risk_found", report_id: "report_01", title: "Prompt 安全调查报告", status: "ready", generated_at: "2026-09-07T08:00:00Z", download_url: "/api/v1/agent/reports/report_01",
    }]} />);
    expect(screen.getByRole("link", { name: /查看 Prompt 安全调查报告/ })).toHaveAttribute("href", "/api/v1/agent/reports/report_01");
  });
});
