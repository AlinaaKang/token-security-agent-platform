import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { AgentMessage } from "../agent/types";
import { AgentConversation } from "./AgentConversation";

afterEach(cleanup);

const messages: AgentMessage[] = [
  { message_id: "u1", role: "user", kind: "message", content: "检查这个 Prompt", created_at: new Date(2026, 8, 7, 8, 10).toISOString(), evidence_scope: "none", evidence_refs: [] },
  { message_id: "a1", role: "agent", kind: "result", content: "已完成检查", created_at: new Date(2026, 8, 7, 8, 11).toISOString(), evidence_scope: "current_case", evidence_refs: [] },
];

describe("AgentConversation", () => {
  it("renders semantic timestamps beside both speaker names", () => {
    render(<AgentConversation messages={messages} now={new Date(2026, 8, 7, 12, 0)} />);

    const conversation = screen.getByRole("region", { name: "任务对话" });
    const times = Array.from(conversation.querySelectorAll("time"));
    expect(times.map((time) => time.textContent)).toEqual(["08:10", "08:11"]);
    expect(times[0]).toHaveAttribute("datetime", messages[0].created_at);
    expect(times[0]).toHaveAttribute("title", expect.stringContaining("2026年9月7日"));
  });

  it("explains and clears browser-local original text without deleting the task", () => {
    const clear = vi.fn();
    render(<AgentConversation messages={messages} localContentAvailable onClearLocalConversation={clear} />);

    expect(screen.getByText("原文已保存到当前案件，审计记录仍保持脱敏")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "清除浏览器副本" }));
    expect(clear).toHaveBeenCalledOnce();
  });

  it("places the user body before its right-side avatar and the agent avatar before its output", () => {
    render(<AgentConversation messages={messages} />);

    const rows = screen.getByRole("region", { name: "任务对话" }).querySelectorAll("article");
    expect(rows[0]).toHaveClass("is-user");
    expect(rows[0].firstElementChild).toHaveClass("agent-message-body");
    expect(rows[0].lastElementChild).toHaveClass("agent-message-avatar");
    expect(rows[1].firstElementChild).toHaveClass("agent-message-avatar");
    expect(rows[1].lastElementChild).toHaveClass("agent-message-body");
  });
});
