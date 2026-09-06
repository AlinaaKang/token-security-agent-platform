import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "../api";
import type { AgentTaskSnapshot } from "./types";
import { useAgentTask } from "./useAgentTask";

const task: AgentTaskSnapshot = {
  task_id: "task_01", version: 1, task_type: "pcap_dataset_investigation",
  status: "running", title: "PCAP 调查", objective_summary: "调查异常。",
  created_at: "2026-09-07T08:00:00Z", updated_at: "2026-09-07T08:00:00Z",
  messages: [], plan: [], observations: [], evidence: [], hypotheses: [], timeline: [],
  conflicts: [], events: [], replan_count: 0, authorization_scopes: [],
  final_status: null, report: null, limitations: [],
};

class FakeEventSource {
  static instances: FakeEventSource[] = [];
  onmessage: ((event: MessageEvent<string>) => void) | null = null;
  onerror: (() => void) | null = null;
  close = vi.fn();
  constructor(public url: string) { FakeEventSource.instances.push(this); }
}

describe("useAgentTask", () => {
  beforeEach(() => {
    FakeEventSource.instances = [];
    vi.stubGlobal("EventSource", FakeEventSource);
    vi.spyOn(api, "getAgentTask").mockResolvedValue(task);
    vi.spyOn(api, "cancelAgentTask").mockResolvedValue({ ...task, status: "cancelled" });
    sessionStorage.clear();
  });

  afterEach(() => vi.restoreAllMocks());

  it("loads the task and opens an event stream from its latest sequence", async () => {
    renderHook(() => useAgentTask("task_01"));

    await waitFor(() => expect(api.getAgentTask).toHaveBeenCalledWith("task_01"));
    expect(FakeEventSource.instances[0].url).toContain("/api/v1/agent/tasks/task_01/events");
    expect(sessionStorage.getItem("token-security:last-agent-task")).toBe("task_01");
  });

  it("falls back to bounded polling after repeated SSE failures", async () => {
    renderHook(() => useAgentTask("task_01"));
    await waitFor(() => expect(FakeEventSource.instances).toHaveLength(1));

    act(() => {
      FakeEventSource.instances[0].onerror?.();
      FakeEventSource.instances[0].onerror?.();
      FakeEventSource.instances[0].onerror?.();
    });

    await waitFor(() => expect(api.getAgentTask).toHaveBeenCalledTimes(2));
    expect(FakeEventSource.instances[0].close).toHaveBeenCalled();
  });

  it("cleans up without cancelling when unmounted", async () => {
    const view = renderHook(() => useAgentTask("task_01"));
    await waitFor(() => expect(FakeEventSource.instances).toHaveLength(1));

    view.unmount();

    expect(FakeEventSource.instances[0].close).toHaveBeenCalled();
    expect(api.cancelAgentTask).not.toHaveBeenCalled();
  });

  it("drops a removed task after a 404 restoration failure", async () => {
    vi.mocked(api.getAgentTask).mockRejectedValue(Object.assign(new Error("missing"), { status: 404 }));

    const { result } = renderHook(() => useAgentTask("task_missing"));

    await waitFor(() => expect(result.current.removed).toBe(true));
    expect(result.current.task).toBeNull();
  });
});
