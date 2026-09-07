import { describe, expect, it } from "vitest";

import type { AgentTaskSnapshot } from "./types";
import { presentAgentTaskStatus } from "./taskPresentation";

function task(
  status: AgentTaskSnapshot["status"],
  finalStatus: AgentTaskSnapshot["final_status"] = null,
): AgentTaskSnapshot {
  return { status, final_status: finalStatus } as AgentTaskSnapshot;
}

describe("agent task status presentation", () => {
  it.each([
    [task("awaiting_authorization"), "等待授权", "amber"],
    [task("planned"), "准备执行", "blue"],
    [task("queued"), "准备执行", "blue"],
    [task("running"), "运行中", "blue"],
    [task("paused"), "已暂停", "amber"],
    [task("completed", "risk_found"), "发现风险", "red"],
    [task("completed", "safe"), "当前未命中", "green"],
    [task("completed", "contained"), "已处置", "green"],
    [task("completed", "inconclusive"), "结论不确定", "amber"],
    [task("degraded"), "检测未完整", "amber"],
    [task("failed"), "执行失败", "amber"],
    [task("cancelled"), "已取消", "amber"],
  ] as const)("maps task state to an unambiguous label and tone", (input, label, tone) => {
    expect(presentAgentTaskStatus(input)).toEqual({ label, tone });
  });
});
