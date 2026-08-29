import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { RoleAuditLine } from "../challenge/roleAuditLines";
import { RoleAuditPlayback } from "./RoleAuditPlayback";

const lines: RoleAuditLine[] = [
  { id: "one", label: "第一步", value: "第一条证据" },
  { id: "two", label: "第二步", value: "第二条证据" },
  { id: "three", label: "第三步", value: "第三条证据" },
];

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("RoleAuditPlayback", () => {
  it("reveals returned evidence one complete line per interval", async () => {
    vi.useFakeTimers();
    const onComplete = vi.fn();
    render(
      <RoleAuditPlayback
        lines={lines}
        playbackKey="round-1:guard"
        animate
        intervalMs={20}
        onComplete={onComplete}
      />,
    );

    expect(screen.getByText("第一条证据")).toBeInTheDocument();
    expect(screen.queryByText("第二条证据")).not.toBeInTheDocument();
    await act(async () => { await vi.advanceTimersByTimeAsync(19); });
    expect(screen.queryByText("第二条证据")).not.toBeInTheDocument();
    await act(async () => { await vi.advanceTimersByTimeAsync(1); });
    expect(screen.getByText("第二条证据")).toBeInTheDocument();
    expect(onComplete).not.toHaveBeenCalled();

    await act(async () => { await vi.advanceTimersByTimeAsync(20); });
    expect(screen.getByText("第三条证据")).toBeInTheDocument();
    expect(onComplete).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("shows the complete report immediately and clears the timer when skipped", () => {
    vi.useFakeTimers();
    const onComplete = vi.fn();
    render(
      <RoleAuditPlayback
        lines={lines}
        playbackKey="round-1:cpd"
        animate
        intervalMs={20}
        onComplete={onComplete}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "立即显示完整汇报" }));
    expect(screen.getByText("第三条证据")).toBeInTheDocument();
    expect(onComplete).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("restarts from the first line when the playback key changes", async () => {
    vi.useFakeTimers();
    const { rerender } = render(
      <RoleAuditPlayback lines={lines} playbackKey="round-1:guard" animate intervalMs={20} />,
    );
    await act(async () => { await vi.advanceTimersByTimeAsync(10); });

    rerender(
      <RoleAuditPlayback
        lines={[{ id: "new-one", label: "新任务", value: "新第一条" }, { id: "new-two", label: "新任务", value: "新第二条" }]}
        playbackKey="round-2:guard"
        animate
        intervalMs={20}
      />,
    );
    expect(screen.getByText("新第一条")).toBeInTheDocument();
    await act(async () => { await vi.advanceTimersByTimeAsync(10); });
    expect(screen.queryByText("新第二条")).not.toBeInTheDocument();
    await act(async () => { await vi.advanceTimersByTimeAsync(10); });
    expect(screen.getByText("新第二条")).toBeInTheDocument();
  });

  it("shows review evidence immediately without completing a first visit", () => {
    vi.useFakeTimers();
    const onComplete = vi.fn();
    render(
      <RoleAuditPlayback
        lines={lines}
        playbackKey="round-1:guard-review"
        animate={false}
        intervalMs={20}
        onComplete={onComplete}
      />,
    );
    expect(screen.getByText("第三条证据")).toBeInTheDocument();
    expect(onComplete).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("completes immediately when reduced motion is preferred", () => {
    vi.useFakeTimers();
    vi.stubGlobal("matchMedia", vi.fn().mockReturnValue({ matches: true }));
    const onComplete = vi.fn();
    render(
      <RoleAuditPlayback
        lines={lines}
        playbackKey="round-1:guard-reduced"
        animate
        intervalMs={20}
        onComplete={onComplete}
      />,
    );
    expect(screen.getByText("第三条证据")).toBeInTheDocument();
    expect(onComplete).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("cancels pending work when unmounted", () => {
    vi.useFakeTimers();
    const { unmount } = render(
      <RoleAuditPlayback lines={lines} playbackKey="round-1:agent" animate intervalMs={20} />,
    );
    expect(vi.getTimerCount()).toBe(1);
    unmount();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("states the audit boundary without claiming hidden reasoning", () => {
    render(<RoleAuditPlayback lines={lines} playbackKey="boundary" animate={false} />);
    const region = screen.getByRole("region", { name: "可审计决策过程" });
    expect(region).toHaveTextContent("已返回检测结果的逐行回放");
    expect(region).toHaveTextContent("不代表模型正在实时推理");
    expect(region).toHaveTextContent("不包含隐藏思维链");
    expect(region).not.toHaveTextContent("隐藏 CoT 已展示");
  });
});
