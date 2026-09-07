import { beforeEach, describe, expect, it } from "vitest";

import type { AgentTaskSnapshot } from "./types";
import {
  clearLocalConversation,
  hasLocalConversation,
  mergeLocalConversation,
  rememberLocalUserMessage,
} from "./localConversation";

function serverSnapshot(taskId = "task_1"): AgentTaskSnapshot {
  return {
    task_id: taskId,
    version: 1,
    task_type: "prompt_investigation",
    status: "completed",
    title: "Prompt 安全调查",
    objective_summary: "检测已提交内容。",
    created_at: "2026-09-07T00:10:00.000Z",
    updated_at: "2026-09-07T00:10:02.000Z",
    messages: [
      {
        message_id: "server_user",
        role: "user",
        kind: "message",
        content: "[用户已提交安全任务，原始内容未保存]",
        created_at: "2026-09-07T00:10:00.000Z",
        evidence_scope: "none",
        evidence_refs: [],
      },
      {
        message_id: "server_agent",
        role: "agent",
        kind: "result",
        content: "检测完成。",
        created_at: "2026-09-07T00:10:02.000Z",
        evidence_scope: "current_case",
        evidence_refs: [],
      },
    ],
    plan: [], observations: [], evidence: [], hypotheses: [], timeline: [], conflicts: [], events: [],
    replan_count: 0, authorization_scopes: [], final_status: "safe", report: null, limitations: [],
  };
}

describe("browser-local agent conversation", () => {
  beforeEach(() => localStorage.clear());

  it("restores original user text and its first timestamp over the server placeholder", () => {
    rememberLocalUserMessage("task_1", "原始 Prompt", "2026-09-07T00:10:00.000Z", localStorage);

    const merged = mergeLocalConversation(serverSnapshot(), localStorage);

    expect(merged.messages).toHaveLength(2);
    expect(merged.messages[0]).toMatchObject({
      role: "user",
      content: "原始 Prompt",
      created_at: "2026-09-07T00:10:00.000Z",
    });
    expect(merged.messages[1].content).toBe("检测完成。");
    expect(hasLocalConversation("task_1", localStorage)).toBe(true);
  });

  it("inserts a browser-only user message when the server returns only the agent answer", () => {
    rememberLocalUserMessage("task_1", "你叫什么名字", "2026-09-07T00:09:59.000Z", localStorage);
    const snapshot = serverSnapshot();
    snapshot.messages = [snapshot.messages[1]];

    const merged = mergeLocalConversation(snapshot, localStorage);

    expect(merged.messages.map((message) => message.content)).toEqual(["你叫什么名字", "检测完成。"]);
  });

  it("keeps the server turn order when the browser clock places the user message after the reply", () => {
    rememberLocalUserMessage("task_1", "你好？", "2026-09-07T00:10:03.000Z", localStorage);

    const merged = mergeLocalConversation(serverSnapshot(), localStorage);

    expect(merged.messages.map((message) => message.content)).toEqual(["你好？", "检测完成。"]);
    expect(merged.messages[0].created_at).toBe("2026-09-07T00:10:03.000Z");
  });

  it("clears only the selected task without changing the server snapshot", () => {
    rememberLocalUserMessage("task_1", "第一条", "2026-09-07T00:00:00.000Z", localStorage);
    rememberLocalUserMessage("task_2", "第二条", "2026-09-07T00:01:00.000Z", localStorage);

    clearLocalConversation("task_1", localStorage);

    expect(hasLocalConversation("task_1", localStorage)).toBe(false);
    expect(hasLocalConversation("task_2", localStorage)).toBe(true);
    expect(serverSnapshot().messages[0].content).toContain("原始内容未保存");
  });

  it("retains only the newest twenty task conversations", () => {
    for (let index = 0; index < 21; index += 1) {
      rememberLocalUserMessage(
        `task_${index}`,
        `Prompt ${index}`,
        new Date(Date.UTC(2026, 8, 7, 0, index)).toISOString(),
        localStorage,
      );
    }

    expect(hasLocalConversation("task_0", localStorage)).toBe(false);
    expect(hasLocalConversation("task_20", localStorage)).toBe(true);
  });

  it("ignores malformed or unavailable storage instead of hiding server messages", () => {
    localStorage.setItem("token-security:local-agent-conversations:v1", "not-json");
    expect(mergeLocalConversation(serverSnapshot(), localStorage)).toEqual(serverSnapshot());

    const blocked = {
      getItem: () => { throw new Error("blocked"); },
      setItem: () => { throw new Error("blocked"); },
      removeItem: () => undefined,
      clear: () => undefined,
      key: () => null,
      length: 0,
    } satisfies Storage;
    expect(() => rememberLocalUserMessage("task_1", "Prompt", "2026-09-07T00:00:00Z", blocked)).not.toThrow();
    expect(mergeLocalConversation(serverSnapshot(), blocked)).toEqual(serverSnapshot());
  });
});
