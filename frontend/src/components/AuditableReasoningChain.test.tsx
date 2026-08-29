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

const safeEvents: SuperAgentTraceEvent[] = [
  { sequence: 1, phase: "plan", actor: "coordinator", status: "succeeded", summary: "建立安全检查计划。", evidence_codes: ["policy:bounded-react-v1"], tool_id: null },
  { sequence: 2, phase: "observe", actor: "semantic_analyst", status: "succeeded", summary: "语义证据为 safe。", evidence_codes: ["semantic:safe"], tool_id: null },
  { sequence: 3, phase: "complete", actor: "coordinator", status: "succeeded", summary: "安全检查完成。", evidence_codes: ["final_status:closed_safe"], tool_id: null },
];

const replacementEvents: SuperAgentTraceEvent[] = [
  { sequence: 1, phase: "plan", actor: "coordinator", status: "succeeded", summary: "新任务开始。", evidence_codes: ["policy:bounded-react-v1"], tool_id: null },
  { sequence: 2, phase: "observe", actor: "token_analyst", status: "succeeded", summary: "新任务第二条证据。", evidence_codes: ["detector:no_token_anomaly"], tool_id: null },
  { sequence: 3, phase: "observe", actor: "knowledge_analyst", status: "succeeded", summary: "新任务第三条证据。", evidence_codes: ["knowledge_id:owasp-llm01"], tool_id: null },
  { sequence: 4, phase: "replan", actor: "coordinator", status: "succeeded", summary: "新任务调整计划。", evidence_codes: ["base_action:review"], tool_id: null },
  { sequence: 5, phase: "complete", actor: "coordinator", status: "succeeded", summary: "新任务完成。", evidence_codes: ["final_status:review_required"], tool_id: null },
];

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

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
    render(<AuditableReasoningChain events={safeEvents} playbackIntervalMs={0} />);
    const chain = screen.getByRole("region", { name: "可审计推理链" });
    expect(within(chain).getByRole("button", { name: /执行动作.*等待证据/ })).toBeDisabled();
    expect(within(chain).queryByText("内部网关状态")).not.toBeInTheDocument();
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

  it("restarts a full playback interval when events are replaced by the same number of events", async () => {
    vi.useFakeTimers();
    const { rerender } = render(<AuditableReasoningChain events={events} playbackIntervalMs={10} />);
    await act(async () => { await vi.advanceTimersByTimeAsync(5); });

    rerender(<AuditableReasoningChain events={replacementEvents} playbackIntervalMs={10} />);
    expect(screen.getByText("新任务开始。")).toBeInTheDocument();
    await act(async () => { await vi.advanceTimersByTimeAsync(5); });
    expect(screen.queryByText("新任务第二条证据。")).not.toBeInTheDocument();

    await act(async () => { await vi.advanceTimersByTimeAsync(5); });
    expect(screen.getByText("新任务第二条证据。")).toBeInTheDocument();
  });

  it("restarts playback when events are replaced by a different number of events", async () => {
    vi.useFakeTimers();
    const { rerender } = render(<AuditableReasoningChain events={events} playbackIntervalMs={10} />);
    await act(async () => { await vi.advanceTimersByTimeAsync(5); });

    rerender(<AuditableReasoningChain events={replacementEvents.slice(0, 2)} playbackIntervalMs={10} />);
    await act(async () => { await vi.advanceTimersByTimeAsync(5); });
    expect(screen.queryByText("新任务第二条证据。")).not.toBeInTheDocument();

    await act(async () => { await vi.advanceTimersByTimeAsync(5); });
    expect(screen.getByText("新任务第二条证据。")).toBeInTheDocument();
  });

  it("clears visible evidence and pending playback when events are replaced by an empty array", async () => {
    vi.useFakeTimers();
    const { rerender } = render(<AuditableReasoningChain events={events} playbackIntervalMs={10} />);
    await act(async () => { await vi.advanceTimersByTimeAsync(5); });

    rerender(<AuditableReasoningChain events={[]} playbackIntervalMs={10} />);
    expect(screen.queryByText("建立有界计划。")).not.toBeInTheDocument();
    expect(vi.getTimerCount()).toBe(0);
    expect(screen.getAllByText("暂无可公开证据")).toHaveLength(4);
  });

  it("cleans up pending playback timers when unmounted", () => {
    vi.useFakeTimers();
    const { unmount } = render(<AuditableReasoningChain events={events} playbackIntervalMs={10} />);
    expect(vi.getTimerCount()).toBeGreaterThan(0);

    unmount();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("shows all returned events immediately when reduced motion is preferred", () => {
    vi.useFakeTimers();
    vi.stubGlobal("matchMedia", vi.fn().mockReturnValue({ matches: true }));

    render(<AuditableReasoningChain events={events} playbackIntervalMs={10} />);
    expect(screen.getByText("任务闭环。")).toBeInTheDocument();
    expect(vi.getTimerCount()).toBe(0);
  });
});
