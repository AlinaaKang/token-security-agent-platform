import { useCallback, useEffect, useRef, useState } from "react";

import { api } from "../api";
import { reduceAgentEvent } from "./taskState";
import type { AgentEvent, AgentTaskSnapshot } from "./types";

const LAST_TASK_KEY = "token-security:last-agent-task";
const MAX_POLL_ATTEMPTS = 20;
const POLL_INTERVAL_MS = 1500;

type AgentTaskController = {
  task: AgentTaskSnapshot | null;
  loading: boolean;
  error: string | null;
  removed: boolean;
  transport: "sse" | "polling" | "idle";
  refresh: () => Promise<void>;
};

export function useAgentTask(taskId: string | null): AgentTaskController {
  const [task, setTask] = useState<AgentTaskSnapshot | null>(null);
  const [loading, setLoading] = useState(Boolean(taskId));
  const [error, setError] = useState<string | null>(null);
  const [removed, setRemoved] = useState(false);
  const [transport, setTransport] = useState<"sse" | "polling" | "idle">("idle");
  const activeRef = useRef(true);

  const refresh = useCallback(async () => {
    if (!taskId) return;
    try {
      const restored = await api.getAgentTask(taskId);
      if (!activeRef.current) return;
      setTask(restored);
      setError(null);
      setRemoved(false);
    } catch (failure) {
      if (!activeRef.current) return;
      const status = (failure as Error & { status?: number }).status;
      if (status === 404 || status === 410) {
        setTask(null);
        setRemoved(true);
        sessionStorage.removeItem(LAST_TASK_KEY);
      } else {
        setError(failure instanceof Error ? failure.message : "任务恢复失败");
      }
    } finally {
      if (activeRef.current) setLoading(false);
    }
  }, [taskId]);

  useEffect(() => {
    activeRef.current = true;
    setTask(null);
    setRemoved(false);
    setError(null);
    setLoading(Boolean(taskId));
    if (!taskId) {
      setTransport("idle");
      return () => { activeRef.current = false; };
    }
    sessionStorage.setItem(LAST_TASK_KEY, taskId);
    void refresh();

    let pollTimer: ReturnType<typeof setInterval> | undefined;
    let pollAttempts = 0;
    let streamFailures = 0;
    const source = new EventSource(api.agentEventStreamUrl(taskId));
    setTransport("sse");
    source.onmessage = (message) => {
      try {
        const event = JSON.parse(message.data) as AgentEvent;
        setTask((current) => current ? reduceAgentEvent(current, event) : current);
      } catch {
        setError("收到无法解析的任务事件，正在恢复最新状态");
        void refresh();
      }
    };
    source.onerror = () => {
      streamFailures += 1;
      if (streamFailures < 3 || pollTimer) return;
      source.close();
      setTransport("polling");
      void refresh();
      pollTimer = setInterval(() => {
        pollAttempts += 1;
        void refresh();
        if (pollAttempts >= MAX_POLL_ATTEMPTS && pollTimer) {
          clearInterval(pollTimer);
          pollTimer = undefined;
        }
      }, POLL_INTERVAL_MS);
    };

    return () => {
      activeRef.current = false;
      source.close();
      if (pollTimer) clearInterval(pollTimer);
    };
  }, [refresh, taskId]);

  return { task, loading, error, removed, transport, refresh };
}

export function lastSelectedAgentTaskId(): string | null {
  return sessionStorage.getItem(LAST_TASK_KEY);
}
