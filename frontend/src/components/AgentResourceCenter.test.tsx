import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { AgentResourceCenter } from "./AgentResourceCenter";

afterEach(cleanup);

describe("AgentResourceCenter", () => {
  it("labels real simulated degraded and unavailable connectors", () => {
    render(<AgentResourceCenter resource="connectors" capabilities={{
      planner_mode: "deterministic_fallback", tool_ids: [],
      connector_states: { pcap_docker: "available", endpoint_demo: "simulated", autodl_guard: "degraded", external_edr: "unavailable" },
      max_plan_steps: 12, max_concurrent_tools: 3, max_replans: 2, max_active_hypotheses: 5, pcap_batch_size: 20,
    }} playbooks={[]} />);
    expect(screen.getByText("真实可用")).toBeVisible();
    expect(screen.getByText("内置仿真")).toBeVisible();
    expect(screen.getByText("降级")).toBeVisible();
    expect(screen.getByText("未接入")).toBeVisible();
    expect(screen.queryByRole("textbox", { name: /连接器 URL/ })).not.toBeInTheDocument();
  });

  it("shows versioned playbooks without arbitrary code nodes", () => {
    render(<AgentResourceCenter resource="skills" capabilities={null} playbooks={[{
      playbook_id: "pcap_dataset_v1", title: "PCAP 数据集调查", task_type: "pcap_dataset_investigation", description: "分批检查异常候选。", version: "1.0.0", step_count: 4,
    }]} />);
    expect(screen.getByText("PCAP 数据集调查")).toBeVisible();
    expect(screen.getByText("v1.0.0 · 4 个受控步骤")).toBeVisible();
    expect(screen.queryByRole("button", { name: /添加.*代码/ })).not.toBeInTheDocument();
  });
});
