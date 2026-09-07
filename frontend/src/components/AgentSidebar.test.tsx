import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AgentSidebar } from "./AgentSidebar";
import type { AgentTaskSnapshot } from "../agent/types";

function task(index: number, taskType = "prompt_investigation"): AgentTaskSnapshot {
  return {
    task_id: `task_${index}`,
    title: `安全任务 ${index}`,
    task_type: taskType,
    status: index === 1 ? "completed" : "running",
    final_status: index === 1 ? "risk_found" : null,
    updated_at: new Date(Date.UTC(2026, 8, 7, 0, index)).toISOString(),
  } as AgentTaskSnapshot;
}

beforeEach(() => window.localStorage.clear());
afterEach(cleanup);

describe("AgentSidebar", () => {
  it("separates security conversations, Prompt tools, PCAP tools, and resources", () => {
    render(<MemoryRouter initialEntries={["/super-agent?mode=prompt"]}><AgentSidebar /></MemoryRouter>);

    const navigation = screen.getByRole("navigation", { name: "主导航" });
    const groups = within(navigation).getAllByRole("group");
    expect(groups.map((group) => group.getAttribute("aria-label"))).toEqual([
      "安全对话", "Prompt 专业工作区", "PCAP 专业工作区", "智能体资源",
    ]);
    expect(screen.getByRole("link", { name: "Prompt 安全调查" })).toHaveAttribute("href", "/super-agent?mode=prompt");
    expect(screen.getByRole("link", { name: "Prompt 安全调查" })).toHaveClass("agent-conversation-link");
    expect(screen.getByRole("link", { name: "PCAP 数据调查" })).toHaveAttribute("href", "/super-agent?mode=pcap");
    expect(screen.getByRole("link", { name: "PCAP 数据调查" })).toHaveClass("agent-conversation-link");
    expect(screen.getByRole("link", { name: "新建 Prompt 对话" })).toHaveAttribute("href", "/super-agent?mode=prompt");
    expect(screen.getByRole("link", { name: "新建 PCAP 对话" })).toHaveAttribute("href", "/super-agent?mode=pcap");
    expect(screen.getByRole("link", { name: "Prompt 攻防实验" })).toHaveAttribute("href", "/lab?surface=prompt");
    expect(screen.queryByRole("link", { name: "PCAP 上传检测" })).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "PCAP 流量画像" })).toHaveAttribute("href", "/pcap-profile");
    expect(screen.getByRole("link", { name: "PCAP 攻防实验" })).toHaveAttribute("href", "/lab?surface=pcap");
    expect(screen.getByRole("link", { name: "PCAP 评测中心" })).toHaveAttribute("href", "/pcap-evaluation");
    expect(screen.getByRole("link", { name: "PCAP 侦探挑战" })).toHaveAttribute("href", "/pcap-challenge");
    expect(screen.getByRole("link", { name: "Token 侦探挑战" })).toHaveAttribute("href", "/challenge");
    expect(screen.getByRole("link", { name: "Prompt 安全调查" })).toHaveAttribute("aria-current", "page");
    expect(screen.queryByRole("link", { name: "检测技能" })).not.toBeInTheDocument();
  });

  it("uses semantic headings above navigation items", () => {
    render(<MemoryRouter><AgentSidebar /></MemoryRouter>);

    expect(screen.getAllByRole("heading", { level: 2 }).map((item) => item.textContent)).toEqual([
      "安全对话", "Prompt 专业工作区", "PCAP 专业工作区", "智能体资源",
    ]);
  });

  it("separates Prompt and PCAP task history and marks the active task", () => {
    const tasks = [task(1), task(2, "pcap_dataset_investigation"), task(3, "cross_domain_case")];
    render(
      <MemoryRouter initialEntries={["/super-agent?mode=pcap&task=task_2"]}>
        <AgentSidebar recentTasks={tasks} activeTaskId="task_2" />
      </MemoryRouter>,
    );

    const promptRecent = screen.getByRole("list", { name: "Prompt 最近任务" });
    const pcapRecent = screen.getByRole("list", { name: "PCAP 最近任务" });
    expect(within(promptRecent).getByRole("link", { name: /安全任务 1/ })).toBeVisible();
    expect(within(promptRecent).getByRole("link", { name: /安全任务 3/ })).toBeVisible();
    expect(within(promptRecent).queryByRole("link", { name: /安全任务 2/ })).not.toBeInTheDocument();
    const active = within(pcapRecent).getByRole("link", { name: /安全任务 2/ });
    expect(active).toHaveAttribute("href", "/super-agent?mode=pcap&task=task_2");
    expect(active).toHaveAttribute("aria-current", "page");
  });

  it("collapses each recent task group independently and restores that choice", () => {
    const tasks = [task(1), task(2, "pcap_dataset_investigation"), task(3, "cross_domain_case")];
    const view = render(
      <MemoryRouter initialEntries={["/super-agent?mode=prompt"]}>
        <AgentSidebar recentTasks={tasks} />
      </MemoryRouter>,
    );

    const promptToggle = screen.getByRole("button", { name: "收起 Prompt 最近任务" });
    expect(promptToggle).toHaveAttribute("aria-expanded", "true");
    fireEvent.click(promptToggle);

    expect(screen.queryByRole("list", { name: "Prompt 最近任务" })).not.toBeInTheDocument();
    expect(screen.getByRole("list", { name: "PCAP 最近任务" })).toBeVisible();
    expect(screen.getByRole("link", { name: "新建 Prompt 对话" })).toBeVisible();
    expect(screen.getByRole("link", { name: "新建 PCAP 对话" })).toBeVisible();

    view.unmount();
    render(
      <MemoryRouter initialEntries={["/super-agent?mode=prompt"]}>
        <AgentSidebar recentTasks={tasks} />
      </MemoryRouter>,
    );

    const restoredToggle = screen.getByRole("button", { name: "展开 Prompt 最近任务" });
    expect(restoredToggle).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByRole("list", { name: "Prompt 最近任务" })).not.toBeInTheDocument();
    expect(screen.getByRole("list", { name: "PCAP 最近任务" })).toBeVisible();
  });

  it("omits the recent task region when there is no history", () => {
    render(<MemoryRouter><AgentSidebar recentTasks={[]} /></MemoryRouter>);
    expect(screen.queryByRole("list", { name: "Prompt 最近任务" })).not.toBeInTheDocument();
    expect(screen.queryByRole("list", { name: "PCAP 最近任务" })).not.toBeInTheDocument();
  });

  it("marks the selected agent resource instead of the conversation entry", () => {
    render(<MemoryRouter initialEntries={["/super-agent?resource=knowledge"]}><AgentSidebar /></MemoryRouter>);

    expect(screen.getByRole("link", { name: "安全知识库" })).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("link", { name: "Prompt 安全调查" })).not.toHaveAttribute("aria-current");
    expect(screen.getByRole("link", { name: "PCAP 数据调查" })).not.toHaveAttribute("aria-current");
  });

  it("confirms deletion of one recent task without opening it", () => {
    const onDeleteTask = vi.fn();
    render(
      <MemoryRouter initialEntries={["/super-agent?mode=prompt"]}>
        <AgentSidebar recentTasks={[task(1)]} onDeleteTask={onDeleteTask} />
      </MemoryRouter>,
    );

    fireEvent.click(screen.getByRole("button", { name: "删除 安全任务 1" }));
    expect(screen.getByText("删除后无法恢复")).toBeVisible();
    expect(screen.queryByRole("link", { name: /安全任务 1/ })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "确认删除 安全任务 1" }));

    expect(onDeleteTask).toHaveBeenCalledWith("task_1", "prompt");
  });
});
