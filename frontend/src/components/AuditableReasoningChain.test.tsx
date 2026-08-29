import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { SuperAgentTraceEvent } from "../types";
import { AuditableReasoningChain } from "./AuditableReasoningChain";

const events: SuperAgentTraceEvent[] = [
  { sequence: 1, phase: "plan", actor: "coordinator", status: "succeeded", summary: "建立有界计划。", evidence_codes: ["policy:bounded-react-v1"], tool_id: null },
  { sequence: 2, phase: "observe", actor: "semantic_analyst", status: "succeeded", summary: "语义证据为 unsafe。", evidence_codes: ["semantic:unsafe"], tool_id: null },
  { sequence: 3, phase: "replan", actor: "coordinator", status: "succeeded", summary: "保持基础阻断动作。", evidence_codes: ["base_action:block"], tool_id: null },
  { sequence: 4, phase: "act", actor: "response_operator", status: "succeeded", summary: "内部网关执行成功。", evidence_codes: ["tool:gateway_enforcement"], tool_id: "gateway_enforcement" },
  { sequence: 5, phase: "complete", actor: "coordinator", status: "succeeded", summary: "任务闭环。", evidence_codes: ["final_status:contained"], tool_id: null },
];

afterEach(() => { cleanup(); vi.useRealTimers(); });

describe("AuditableReasoningChain", () => {
  it("automatically follows returned events and then supports manual review", async () => {
    vi.useFakeTimers();
    render(<AuditableReasoningChain events={events} playbackIntervalMs={10} />);
    expect(screen.getByRole("region", { name: "可审计推理链" })).toBeInTheDocument();
    await act(async () => { await vi.runAllTimersAsync(); });
    expect(screen.getByText("任务闭环。")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /观察证据/ }));
    expect(screen.getByText("语义证据为 unsafe。")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "跟随最新进度" })).toBeEnabled();
    fireEvent.click(screen.getByRole("button", { name: "跟随最新进度" }));
    expect(screen.getByText("任务闭环。")).toBeInTheDocument();
  });

  it("does not invent an action for a zero-tool safe trace", () => {
    render(<AuditableReasoningChain events={events.filter((item) => item.tool_id === null)} playbackIntervalMs={0} />);
    const chain = screen.getByRole("region", { name: "可审计推理链" });
    expect(within(chain).getByRole("button", { name: /执行动作.*等待证据/ })).toBeDisabled();
    expect(within(chain).queryByText("gateway_enforcement")).not.toBeInTheDocument();
  });

  it("shows failed evidence without rendering a successful closure", () => {
    const failed = events.map((item) => item.sequence === 4
      ? { ...item, status: "failed" as const, summary: "内部网关执行失败。" }
      : item).filter((item) => item.phase !== "complete");
    render(<AuditableReasoningChain events={failed} playbackIntervalMs={0} />);
    expect(screen.getByRole("button", { name: /执行动作.*失败/ })).toBeInTheDocument();
    expect(screen.getByText("内部网关执行失败。")).toBeInTheDocument();
    expect(screen.queryByText("任务闭环。")).not.toBeInTheDocument();
  });
});
