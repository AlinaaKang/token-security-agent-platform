import { useEffect, useMemo, useState } from "react";

import {
  buildReasoningStages,
  partitionEvidenceCodes,
  reasoningStageIdFor,
  type ReasoningStageId,
  type ReasoningStageState,
} from "../superagent/reasoningChain";
import {
  superAgentActorLabels,
  superAgentEvidenceLabel,
  superAgentPhaseLabels,
  superAgentToolLabels,
} from "../superagent/labels";
import type { SuperAgentTraceEvent } from "../types";

interface AuditableReasoningChainProps {
  events: SuperAgentTraceEvent[];
  playbackIntervalMs?: number;
}

const stageStateLabels: Record<ReasoningStageState, string> = {
  waiting: "等待证据",
  planned: "已计划",
  succeeded: "已完成",
  failed: "失败",
  skipped: "已跳过",
};

export function AuditableReasoningChain({ events, playbackIntervalMs = 220 }: AuditableReasoningChainProps) {
  const orderedEvents = useMemo(
    () => [...events].sort((left, right) => left.sequence - right.sequence),
    [events],
  );
  const prefersReducedMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
  const effectiveIntervalMs = prefersReducedMotion ? 0 : playbackIntervalMs;
  const [visibleCount, setVisibleCount] = useState(effectiveIntervalMs === 0 ? orderedEvents.length : 1);
  const [following, setFollowing] = useState(true);
  const [selectedStageId, setSelectedStageId] = useState<ReasoningStageId>(
    orderedEvents[0] ? reasoningStageIdFor(orderedEvents[0]) : "observe",
  );

  useEffect(() => {
    setFollowing(true);
    setVisibleCount(effectiveIntervalMs === 0 ? orderedEvents.length : Math.min(1, orderedEvents.length));
  }, [effectiveIntervalMs, orderedEvents]);

  useEffect(() => {
    if (effectiveIntervalMs === 0 || visibleCount >= orderedEvents.length) return;
    const timers = Array.from(
      { length: orderedEvents.length - visibleCount },
      (_, offset) => window.setTimeout(
        () => setVisibleCount((count) => Math.max(count, visibleCount + offset + 1)),
        effectiveIntervalMs * (offset + 1),
      ),
    );
    return () => timers.forEach((timer) => window.clearTimeout(timer));
  }, [effectiveIntervalMs, orderedEvents, visibleCount]);

  const visibleEvents = orderedEvents.slice(0, visibleCount);
  const stages = buildReasoningStages(visibleEvents);
  const latestStageId = visibleEvents.length
    ? reasoningStageIdFor(visibleEvents.at(-1)!)
    : "observe";
  const activeStageId = following ? latestStageId : selectedStageId;
  const activeStage = stages.find((stage) => stage.id === activeStageId) ?? stages[0];
  const activeEvents = activeStage?.events ?? [];
  const evidence = partitionEvidenceCodes(activeEvents.flatMap((event) => event.evidence_codes));
  const tools = activeEvents.flatMap((event) => event.tool_id ? [event.tool_id] : []);

  return (
    <section className="superagent-reasoning-chain" aria-label="可审计推理链" aria-live="polite">
      <header className="superagent-reasoning-header">
        <strong>可审计推理链</strong>
        <span>结构化审计轨迹，不包含隐藏思维链</span>
        <button type="button" disabled={following} onClick={() => setFollowing(true)}>
          跟随最新进度
        </button>
      </header>

      <ol className="superagent-reasoning-overview">
        {stages.map((stage) => (
          <li key={stage.id}>
            <button
              type="button"
              className={`superagent-reasoning-node is-${stage.state}${stage.id === "replan" && (stage.state === "planned" || stage.state === "succeeded") ? " is-replan" : ""}${activeStageId === stage.id ? " is-selected" : ""}`}
              disabled={stage.state === "waiting"}
              aria-pressed={activeStageId === stage.id}
              onClick={() => {
                setFollowing(false);
                setSelectedStageId(stage.id);
              }}
            >
              <span>{stage.label}</span>
              <span>{stageStateLabels[stage.state]}</span>
            </button>
          </li>
        ))}
      </ol>

      <div className="superagent-reasoning-detail">
        <div className="superagent-reasoning-detail-grid">
          <section>
            <h3>执行角色</h3>
            {activeEvents.length ? (
              <ul>{activeEvents.map((event) => <li key={event.sequence}>{superAgentActorLabels[event.actor]}</li>)}</ul>
            ) : <p>暂无可公开证据</p>}
          </section>
          <section>
            <h3>观察证据</h3>
            {evidence.observations.length ? (
              <ul>{evidence.observations.map((code, index) => <li key={`${code}-${index}`}>{superAgentEvidenceLabel(code)}</li>)}</ul>
            ) : <p>暂无可公开证据</p>}
          </section>
          <section>
            <h3>适用规则</h3>
            {evidence.rules.length ? (
              <ul>{evidence.rules.map((code, index) => <li key={`${code}-${index}`}>{superAgentEvidenceLabel(code)}</li>)}</ul>
            ) : <p>暂无可公开证据</p>}
          </section>
          <section>
            <h3>结论或动作</h3>
            {activeEvents.length ? (
              <ul>{activeEvents.map((event) => (
                <li key={event.sequence}>
                  <span>{superAgentPhaseLabels[event.phase]}</span>
                  <span>{event.summary}</span>
                </li>
              ))}</ul>
            ) : <p>暂无可公开证据</p>}
          </section>
          <section>
            <h3>工具与回执</h3>
            {tools.length ? (
              <ul>{tools.map((tool, index) => <li key={`${tool}-${index}`}>{superAgentToolLabels[tool]}</li>)}</ul>
            ) : <p>无工具调用</p>}
          </section>
        </div>
      </div>
    </section>
  );
}
