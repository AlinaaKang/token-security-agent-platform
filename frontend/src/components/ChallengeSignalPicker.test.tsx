import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ChallengeSignalPicker } from "./ChallengeSignalPicker";

afterEach(cleanup);

const signals = [
  { index: 10, entropy: 1, nll: 1, cpd_entropy: 0, cpd_nll: 0, risk: 0.1 },
  { index: 20, entropy: 2, nll: 2, cpd_entropy: 2, cpd_nll: 0, risk: 0.8 },
  { index: 35, entropy: 1.5, nll: 2.4, cpd_entropy: 4, cpd_nll: 0, risk: 0.9 },
];

describe("ChallengeSignalPicker", () => {
  it("emits the real sparse Token index", () => {
    const onSelect = vi.fn();
    render(<ChallengeSignalPicker signals={signals.slice(0, 2)} selectedIndex={null} onSelect={onSelect} />);
    fireEvent.click(screen.getByRole("button", { name: "选择 Token 20" }));
    expect(onSelect).toHaveBeenCalledWith(20);
  });

  it("moves by observation order with arrows and confirms the focused Token", () => {
    const onSelect = vi.fn();
    render(<ChallengeSignalPicker signals={signals} selectedIndex={10} onSelect={onSelect} />);
    const first = screen.getByRole("button", { name: "选择 Token 10" });
    first.focus();
    fireEvent.keyDown(first, { key: "ArrowRight" });
    expect(screen.getByRole("button", { name: "选择 Token 20" })).toHaveFocus();
    expect(onSelect).toHaveBeenLastCalledWith(20);
    fireEvent.keyDown(screen.getByRole("button", { name: "选择 Token 20" }), { key: "Enter" });
    expect(onSelect).toHaveBeenLastCalledWith(20);
    fireEvent.keyDown(screen.getByRole("button", { name: "选择 Token 20" }), { key: "ArrowLeft" });
    expect(first).toHaveFocus();
  });

  it("renders three nonblank signal paths", () => {
    const { container } = render(
      <ChallengeSignalPicker signals={signals} selectedIndex={null} onSelect={() => undefined} />,
    );
    const paths = container.querySelectorAll(".challenge-signal-line");
    expect(paths).toHaveLength(3);
    paths.forEach((path) => expect(path.getAttribute("d")).toMatch(/^M\d/));
  });

  it("renders a stable fallback with fewer than two signals", () => {
    render(<ChallengeSignalPicker signals={signals.slice(0, 1)} selectedIndex={null} onSelect={() => undefined} />);
    expect(screen.getByText("信号不足，至少需要两个 Token 观测点")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /选择 Token/ })).not.toBeInTheDocument();
  });

  it("reserves at least 44 pixels per Token on dense traces", () => {
    const denseSignals = Array.from({ length: 20 }, (_, position) => ({
      ...signals[0],
      index: position * 2,
      entropy: position + 1,
    }));
    const { container } = render(
      <ChallengeSignalPicker signals={denseSignals} selectedIndex={null} onSelect={() => undefined} />,
    );
    expect(container.querySelector(".challenge-signal-canvas")).toHaveStyle({ minWidth: "920px" });
  });
});
