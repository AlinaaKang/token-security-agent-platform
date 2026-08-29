import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { ChallengeInputCard } from "./ChallengeInputCard";

describe("ChallengeInputCard", () => {
  afterEach(cleanup);

  it("shows reviewed safe input in full", () => {
    render(<ChallengeInputCard publicInput={{
      available: true,
      disclosure: "full",
      content: "Line one\nLine two",
      intentSummary: "测试多行安全输入",
      redactionNotice: null,
    }} />);

    expect(screen.getByRole("region", { name: "本关待检输入" })).toHaveTextContent("公开安全样本");
    expect(screen.getByText(/Line one/)).toHaveTextContent("Line one Line two");
    expect(screen.queryByText("[对抗攻击内容已隐藏]")).not.toBeInTheDocument();
  });

  it("shows the reviewed protected summary without an attack payload", () => {
    render(<ChallengeInputCard publicInput={{
      available: true,
      disclosure: "redacted",
      content: "这是经过审核的攻击家族级说明。",
      intentSummary: "受保护攻击样本",
      redactionNotice: "[对抗攻击内容已隐藏]",
    }} />);

    const card = screen.getByRole("region", { name: "本关待检输入" });
    expect(card).toHaveTextContent("受保护样本");
    expect(card).toHaveTextContent("这是经过审核的攻击家族级说明。");
    expect(card).toHaveTextContent("[对抗攻击内容已隐藏]");
  });

  it("uses the fixed protected notice when the input notice is null", () => {
    render(<ChallengeInputCard publicInput={{
      available: true,
      disclosure: "redacted",
      content: "这是经过审核的攻击家族级说明。",
      intentSummary: "受保护攻击样本",
      redactionNotice: null,
    }} />);

    expect(screen.getByRole("region", { name: "本关待检输入" }))
      .toHaveTextContent("[对抗攻击内容已隐藏]");
  });

  it("shows no fields when reviewed input is unavailable", () => {
    render(<ChallengeInputCard publicInput={{ available: false }} />);

    const card = screen.getByRole("region", { name: "本关待检输入" });
    expect(card).toHaveTextContent("公开材料暂不可用");
    expect(card).not.toHaveTextContent("任务意图");
    expect(card).not.toHaveTextContent("输入材料");
    expect(screen.queryByText("公开安全样本")).not.toBeInTheDocument();
    expect(screen.queryByText("受保护样本")).not.toBeInTheDocument();
  });
});
