import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AgentNextSteps } from "./AgentNextSteps";

describe("AgentNextSteps", () => {
  afterEach(cleanup);

  it("separates explanatory questions from executable actions", () => {
    const ask = vi.fn();
    const act = vi.fn();
    render(<AgentNextSteps
      questions={[{ question_id: "why_risky", label: "为什么判断为高风险？", message: "为什么判断为高风险？" }]}
      actions={[{ action_id: "generate_report", label: "生成调查报告", action_kind: "read_only", requires_authorization: false, enabled: true, disabled_reason: null }]}
      busy={false}
      onQuestion={ask}
      onAction={act}
    />);

    expect(screen.getByRole("group", { name: "推荐追问" })).toBeVisible();
    expect(screen.getByRole("group", { name: "建议动作" })).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "为什么判断为高风险？" }));
    fireEvent.click(screen.getByRole("button", { name: "生成调查报告" }));
    expect(ask).toHaveBeenCalledWith("为什么判断为高风险？");
    expect(act).toHaveBeenCalledWith("generate_report");
  });

  it("explains unavailable actions and prevents execution", () => {
    const act = vi.fn();
    render(<AgentNextSteps
      questions={[]}
      actions={[{ action_id: "analyze_attack_chain", label: "分析攻击链", action_kind: "read_only", requires_authorization: false, enabled: false, disabled_reason: "当前运行环境未注册所需工具。" }]}
      busy={false}
      onQuestion={vi.fn()}
      onAction={act}
    />);

    expect(screen.getByRole("button", { name: "分析攻击链" })).toBeDisabled();
    expect(screen.getByText("当前运行环境未注册所需工具。")).toBeVisible();
    expect(act).not.toHaveBeenCalled();
  });
});
