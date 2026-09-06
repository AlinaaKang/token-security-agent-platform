import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "./api";
import type { AgentTaskSnapshot } from "./agent/types";
import { AgentWorkspacePage } from "./pages/AgentWorkspacePage";

const timestamp = "2026-09-07T08:00:00Z";

function task(overrides: Partial<AgentTaskSnapshot> = {}): AgentTaskSnapshot {
  return {
    task_id: "task_01",
    version: 1,
    task_type: "pcap_dataset_investigation",
    status: "awaiting_authorization",
    title: "PCAP 数据集调查",
    objective_summary: "检测这批 PCAP 并生成报告。",
    created_at: timestamp,
    updated_at: timestamp,
    messages: [
      { message_id: "msg_01", role: "user", kind: "message", content: "[用户已提交安全任务，原始内容未保存]", created_at: timestamp, evidence_scope: "none", evidence_refs: [] },
      { message_id: "msg_02", role: "agent", kind: "status", content: "已理解目标，等待你授权读取所选 PCAP。", created_at: timestamp, evidence_scope: "none", evidence_refs: [] },
    ],
    plan: [
      { step_id: "step_01", tool_id: "inspect_pcap_dataset", status: "waiting", requires_authorization: true, summary: "检查数据集可解析性", depends_on: [], attempt: 0 },
      { step_id: "step_02", tool_id: "detect_pcap_batch", status: "waiting", requires_authorization: true, summary: "分批检测异常候选", depends_on: ["step_01"], attempt: 0 },
      { step_id: "step_03", tool_id: "generate_case_report", status: "waiting", requires_authorization: false, summary: "生成引用证据的报告", depends_on: ["step_02"], attempt: 0 },
    ],
    observations: [], evidence: [], hypotheses: [], timeline: [], conflicts: [], events: [],
    replan_count: 0, authorization_scopes: [], final_status: null, report: null,
    limitations: ["检测未命中不等于全部安全。"],
    ...overrides,
  };
}

class FakeEventSource {
  onmessage: ((event: MessageEvent<string>) => void) | null = null;
  onerror: (() => void) | null = null;
  close = vi.fn();
}

describe("AgentWorkspacePage", () => {
  beforeEach(() => {
    vi.stubGlobal("EventSource", FakeEventSource);
    sessionStorage.clear();
    vi.spyOn(api, "agentCapabilities").mockResolvedValue({
      planner_mode: "deterministic_fallback",
      tool_ids: ["inspect_pcap_dataset", "detect_pcap_batch", "generate_case_report"],
      connector_states: { pcap_docker: "available", endpoint_demo: "simulated" },
      max_plan_steps: 12,
      max_concurrent_tools: 3,
      max_replans: 2,
      max_active_hypotheses: 5,
      pcap_batch_size: 20,
    });
    vi.spyOn(api, "listAgentTasks").mockResolvedValue({ items: [], limit: 20, offset: 0 });
    vi.spyOn(api, "getAgentTask").mockImplementation(async () => task());
    vi.spyOn(api, "createAgentTask").mockImplementation(async (message) => {
      if (message.includes("名字")) {
        return task({
          task_type: "knowledge_explanation",
          status: "completed",
          title: "身份说明",
          objective_summary: "说明智能体身份。",
          messages: [{ message_id: "msg_identity", role: "agent", kind: "result", content: "我是 Token Security 安全智能体，专注于大模型应用安全调查。", created_at: timestamp, evidence_scope: "general", evidence_refs: [] }],
          plan: [], limitations: [], final_status: "safe",
        });
      }
      return task();
    });
    vi.spyOn(api, "authorizeAgentTask").mockResolvedValue(task({ status: "queued", authorization_scopes: ["pcap:read"] }));
    vi.spyOn(api, "messageAgentTask").mockResolvedValue(task());
    vi.spyOn(api, "cancelAgentTask").mockResolvedValue(task({ status: "cancelled" }));
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("answers identity without requesting authorization", async () => {
    render(<AgentWorkspacePage />);

    fireEvent.change(screen.getByRole("textbox", { name: "安全任务" }), { target: { value: "你叫什么名字" } });
    fireEvent.click(screen.getByRole("button", { name: "发送" }));

    expect(await screen.findByText(/我是 Token Security 安全智能体/)).toBeVisible();
    expect(api.authorizeAgentTask).not.toHaveBeenCalled();
  });

  it("shows the public plan before requesting bounded PCAP authorization", async () => {
    render(<AgentWorkspacePage />);

    fireEvent.change(screen.getByRole("textbox", { name: "安全任务" }), { target: { value: "检测这批 PCAP 并生成报告" } });
    fireEvent.click(screen.getByRole("button", { name: "发送" }));

    const plan = await screen.findByRole("region", { name: "执行计划" });
    expect(within(plan).getByText("检查数据集可解析性")).toBeVisible();
    expect(screen.getByRole("dialog", { name: "授权 PCAP 调查" })).toBeVisible();
    expect(screen.getByText("最多每批 20 个文件")).toBeVisible();
    expect(api.authorizeAgentTask).not.toHaveBeenCalled();
  });

  it("authorizes only the scope displayed in the confirmation dialog", async () => {
    render(<AgentWorkspacePage />);
    fireEvent.change(screen.getByRole("textbox", { name: "安全任务" }), { target: { value: "检测这批 PCAP" } });
    fireEvent.click(screen.getByRole("button", { name: "发送" }));

    const dialog = await screen.findByRole("dialog", { name: "授权 PCAP 调查" });
    expect(within(dialog).getByRole("button", { name: "暂不授权" })).toHaveFocus();
    fireEvent.click(within(dialog).getByRole("button", { name: "授权并开始" }));

    expect(api.authorizeAgentTask).toHaveBeenCalledWith("task_01", ["pcap:read"]);
  });

  it("does not execute example prompts until the user sends them", async () => {
    render(<AgentWorkspacePage />);
    await screen.findByText("可以这样开始");

    fireEvent.click(screen.getByRole("button", { name: "解释 packet 4-4" }));

    expect(screen.getByRole("textbox", { name: "安全任务" })).toHaveValue("packet 4-4 是什么？");
    expect(api.createAgentTask).not.toHaveBeenCalled();
  });

  it("cancels only after an explicit cancel command", async () => {
    vi.spyOn(api, "listAgentTasks").mockResolvedValue({ items: [task({ status: "running" })], limit: 20, offset: 0 });
    vi.spyOn(api, "getAgentTask").mockResolvedValue(task({ status: "running" }));
    sessionStorage.setItem("token-security:last-agent-task", "task_01");
    render(<AgentWorkspacePage />);
    await screen.findByRole("heading", { name: "PCAP 数据集调查" });

    fireEvent.change(screen.getByRole("textbox", { name: "安全任务" }), { target: { value: "取消当前任务" } });
    fireEvent.click(screen.getByRole("button", { name: "发送" }));

    await waitFor(() => expect(api.cancelAgentTask).toHaveBeenCalledWith("task_01"));
  });
});
