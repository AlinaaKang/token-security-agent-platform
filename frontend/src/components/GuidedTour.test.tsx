import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { GuidedTour, type GuidedTourStep } from "./GuidedTour";

const steps: GuidedTourStep[] = [
  { id: "input", target: "input", title: "输入区域", description: "在这里准备内容。", advanceOnClick: true },
  { id: "command", target: "command", title: "执行入口", description: "由你决定是否执行。" },
];

function Harness({ storage }: { storage?: Storage } = {}) {
  return (
    <>
      <button type="button" data-tour="input">选择模式</button>
      <button type="button" data-tour="command">开始执行</button>
      <GuidedTour route="/analyze" steps={steps} storage={storage} />
    </>
  );
}

describe("GuidedTour", () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("opens once on the first route visit and stores the exact versioned route key", () => {
    const first = render(<Harness />);
    expect(screen.getByRole("dialog", { name: "输入区域" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "打开本页使用引导" })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "跳过引导" }));
    expect(window.localStorage.getItem("token-sentinel-tour:/analyze:v1")).toBe("seen");
    first.unmount();

    render(<Harness />);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    const launcher = screen.getByRole("button", { name: "打开本页使用引导" });
    expect(launcher).toBeInTheDocument();
    expect(launcher).toHaveTextContent("本页引导");
  });

  it("moves forward and backward without clicking the highlighted command", () => {
    const command = vi.fn();
    render(
      <>
        <button type="button" data-tour="input">选择模式</button>
        <button type="button" data-tour="command" onClick={command}>开始执行</button>
        <GuidedTour route="/analyze" steps={steps} />
      </>,
    );

    fireEvent.click(screen.getByRole("button", { name: "下一步" }));
    expect(screen.getByRole("dialog", { name: "执行入口" })).toBeInTheDocument();
    expect(command).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "上一步" }));
    expect(screen.getByRole("dialog", { name: "输入区域" })).toBeInTheDocument();
  });

  it("advances only after the user really clicks a target configured for automatic progression", () => {
    const localAction = vi.fn();
    render(
      <>
        <button type="button" data-tour="input" onClick={localAction}>选择模式</button>
        <button type="button" data-tour="command">开始执行</button>
        <GuidedTour route="/analyze" steps={steps} />
      </>,
    );

    expect(localAction).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "选择模式" }));
    expect(localAction).toHaveBeenCalledOnce();
    expect(screen.getByRole("dialog", { name: "执行入口" })).toBeInTheDocument();
  });

  it("finishes, replays from help, and restores focus to the launcher", () => {
    render(<Harness />);
    fireEvent.click(screen.getByRole("button", { name: "下一步" }));
    fireEvent.click(screen.getByRole("button", { name: "完成" }));

    const launcher = screen.getByRole("button", { name: "打开本页使用引导" });
    fireEvent.click(launcher);
    expect(screen.getByRole("dialog", { name: "输入区域" })).toBeInTheDocument();
    fireEvent.keyDown(document, { key: "Escape" });

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "打开本页使用引导" })).toHaveFocus();
  });

  it("skips absent targets and closes harmlessly when none remain", () => {
    render(
      <>
        <button type="button" data-tour="command">开始执行</button>
        <GuidedTour route="/analyze" steps={steps} />
      </>,
    );

    expect(screen.getByRole("dialog", { name: "执行入口" })).toBeInTheDocument();
  });

  it("remains usable when browser storage throws", () => {
    const brokenStorage = {
      getItem: () => { throw new Error("blocked"); },
      setItem: () => { throw new Error("blocked"); },
      removeItem: () => undefined,
      clear: () => undefined,
      key: () => null,
      length: 0,
    } satisfies Storage;

    render(<Harness storage={brokenStorage} />);
    expect(screen.getByRole("dialog", { name: "输入区域" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "跳过引导" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("keeps keyboard focus inside the open panel when tabbing", () => {
    render(<Harness />);
    const skip = screen.getByRole("button", { name: "跳过引导" });
    const next = screen.getByRole("button", { name: "下一步" });

    next.focus();
    fireEvent.keyDown(document, { key: "Tab" });
    expect(skip).toHaveFocus();

    skip.focus();
    fireEvent.keyDown(document, { key: "Tab", shiftKey: true });
    expect(next).toHaveFocus();
  });

  it("exposes non-interactive spotlight and bounded panel placement semantics", () => {
    render(<Harness />);

    expect(document.querySelector(".guided-tour-spotlight")).toHaveAttribute("aria-hidden", "true");
    expect(screen.getByRole("dialog", { name: "输入区域" })).toHaveAttribute("data-placement", "below");
    expect(screen.getByText("步骤 1 / 2")).toBeInTheDocument();
  });
});
