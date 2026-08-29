import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { AnalyzeDecisionStage } from "../analyze/decisionTrace";
import { AnalyzeDecisionTrace } from "./AnalyzeDecisionTrace";

const stages: AnalyzeDecisionStage[] = [
  { id: "ingest", label: "脱敏接收", status: "completed", summary: "请求已脱敏接收", evidence: ["未回显提交内容"] },
  { id: "semantic", label: "语义检测", status: "completed", summary: "语义安全", evidence: ["风险类别未标记"] },
  { id: "token", label: "Token 观测", status: "completed", summary: "已完成数值信号观测", evidence: ["公开数值信号数量 3"] },
  { id: "cpd", label: "CPD 判断", status: "candidate", summary: "发现分布异常候选", evidence: ["检测分数 0.820"] },
  { id: "fusion", label: "证据融合", status: "completed", summary: "CPD 候选证据为主", evidence: ["固定融合策略"] },
  { id: "decision", label: "处置决策", status: "completed", summary: "最终处置：人工复核", evidence: ["风险分数 0.820"] },
];

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("AnalyzeDecisionTrace", () => {
  it("replays one stage at a time and resumes following after the viewer inspects an earlier stage", async () => {
    vi.useFakeTimers();
    render(<AnalyzeDecisionTrace stages={stages} playbackKey="request-1" intervalMs={20} />);

    const region = screen.getByRole("region", { name: "可审计决策轨迹" });
    expect(screen.getByRole("button", { name: "脱敏接收" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.queryByRole("button", { name: "语义检测" })).not.toBeInTheDocument();
    expect(region).toHaveTextContent("结构化决策轨迹，不包含隐藏思维链；播放间隔不代表模型耗时。");

    await act(async () => { await vi.advanceTimersByTimeAsync(19); });
    expect(screen.queryByRole("button", { name: "语义检测" })).not.toBeInTheDocument();
    await act(async () => { await vi.advanceTimersByTimeAsync(1); });
    expect(screen.getByRole("button", { name: "语义检测" })).toHaveAttribute("aria-pressed", "true");

    fireEvent.click(screen.getByRole("button", { name: "脱敏接收" }));
    expect(screen.getByRole("button", { name: "脱敏接收" })).toHaveAttribute("aria-pressed", "true");
    expect(region).toHaveTextContent("请求已脱敏接收");
    expect(screen.queryByRole("button", { name: "Token 观测" })).not.toBeInTheDocument();

    await act(async () => { await vi.advanceTimersByTimeAsync(20); });
    expect(screen.getByRole("button", { name: "Token 观测" })).toHaveAttribute("aria-pressed", "true");
    expect(region).toHaveTextContent("已完成数值信号观测");
    expect(region).toHaveTextContent("公开数值信号数量 3");
    expect(region).not.toHaveTextContent("请求已脱敏接收");
  });

  it("preserves a pending interval when equivalent stages rerender with the same playback key", async () => {
    vi.useFakeTimers();
    const { rerender } = render(
      <AnalyzeDecisionTrace stages={stages} playbackKey="request-1" intervalMs={20} />,
    );
    await act(async () => { await vi.advanceTimersByTimeAsync(10); });

    rerender(
      <AnalyzeDecisionTrace
        stages={stages.map((stage) => ({ ...stage }))}
        playbackKey="request-1"
        intervalMs={20}
      />,
    );
    expect(screen.queryByRole("button", { name: "语义检测" })).not.toBeInTheDocument();
    expect(vi.getTimerCount()).toBe(1);

    await act(async () => { await vi.advanceTimersByTimeAsync(9); });
    expect(screen.queryByRole("button", { name: "语义检测" })).not.toBeInTheDocument();
    await act(async () => { await vi.advanceTimersByTimeAsync(1); });
    expect(screen.getByRole("button", { name: "语义检测" })).toHaveAttribute("aria-pressed", "true");
  });

  it("restarts from the first stage and replaces the pending timer when the playback key changes", async () => {
    vi.useFakeTimers();
    const { rerender } = render(
      <AnalyzeDecisionTrace stages={stages} playbackKey="request-1" intervalMs={20} />,
    );
    await act(async () => { await vi.advanceTimersByTimeAsync(10); });

    rerender(<AnalyzeDecisionTrace stages={stages} playbackKey="request-2" intervalMs={20} />);
    expect(screen.getByRole("button", { name: "脱敏接收" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.queryByRole("button", { name: "语义检测" })).not.toBeInTheDocument();
    expect(vi.getTimerCount()).toBe(1);

    await act(async () => { await vi.advanceTimersByTimeAsync(10); });
    expect(screen.queryByRole("button", { name: "语义检测" })).not.toBeInTheDocument();
    await act(async () => { await vi.advanceTimersByTimeAsync(10); });
    expect(screen.getByRole("button", { name: "语义检测" })).toBeInTheDocument();
  });

  it("clears the pending timer when unmounted", () => {
    vi.useFakeTimers();
    const { unmount } = render(
      <AnalyzeDecisionTrace stages={stages} playbackKey="request-1" intervalMs={20} />,
    );
    expect(vi.getTimerCount()).toBe(1);
    unmount();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("shows every stage without creating a timer when reduced motion is preferred", () => {
    vi.useFakeTimers();
    vi.stubGlobal("matchMedia", vi.fn().mockReturnValue({ matches: true }));
    render(<AnalyzeDecisionTrace stages={stages} playbackKey="request-1" intervalMs={20} />);

    const region = screen.getByRole("region", { name: "可审计决策轨迹" });
    expect(screen.getByRole("button", { name: "处置决策" })).toHaveAttribute("aria-pressed", "true");
    expect(region).toHaveTextContent("最终处置：人工复核");
    expect(region).toHaveTextContent("风险分数 0.820");
    expect(vi.getTimerCount()).toBe(0);
  });

  it("renders an empty-state message without creating a timer for empty stages", () => {
    vi.useFakeTimers();
    render(<AnalyzeDecisionTrace stages={[]} playbackKey="request-1" intervalMs={20} />);

    expect(screen.getByText("暂无可审计阶段")).toBeInTheDocument();
    expect(vi.getTimerCount()).toBe(0);
  });
});
