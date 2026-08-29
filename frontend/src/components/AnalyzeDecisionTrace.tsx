import { CircleAlert, CircleCheck, CircleDashed } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import type { AnalyzeDecisionStage } from "../analyze/decisionTrace";

interface AnalyzeDecisionTraceProps {
  stages: AnalyzeDecisionStage[];
  playbackKey: string;
  intervalMs?: number;
}

interface PlaybackState {
  key: string;
  visibleCount: number;
  selectedStageId: AnalyzeDecisionStage["id"] | null;
}

function StageStatusIcon({ status }: Pick<AnalyzeDecisionStage, "status">) {
  if (status === "candidate") return <CircleAlert aria-hidden="true" />;
  if (status === "unavailable") return <CircleDashed aria-hidden="true" />;
  return <CircleCheck aria-hidden="true" />;
}

export function AnalyzeDecisionTrace({
  stages,
  playbackKey,
  intervalMs = 240,
}: AnalyzeDecisionTraceProps) {
  const prefersReducedMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
  const shouldAnimate = !prefersReducedMotion && intervalMs > 0 && stages.length > 0;
  const initialVisibleCount = shouldAnimate ? 1 : stages.length;
  const [playback, setPlayback] = useState<PlaybackState>(() => ({
    key: playbackKey,
    visibleCount: initialVisibleCount,
    selectedStageId: stages[0]?.id ?? null,
  }));

  const isCurrentPlayback = playback.key === playbackKey;
  const visibleCount = isCurrentPlayback
    ? Math.min(playback.visibleCount, stages.length)
    : initialVisibleCount;
  const visibleStages = useMemo(() => stages.slice(0, visibleCount), [stages, visibleCount]);
  const latestStage = visibleStages.at(-1);
  const activeStageId = isCurrentPlayback ? playback.selectedStageId : latestStage?.id ?? null;
  const activeStage = visibleStages.find((stage) => stage.id === activeStageId) ?? latestStage;

  useEffect(() => {
    setPlayback({
      key: playbackKey,
      visibleCount: initialVisibleCount,
      selectedStageId: stages[0]?.id ?? null,
    });
  }, [initialVisibleCount, playbackKey]);

  useEffect(() => {
    if (!isCurrentPlayback || !shouldAnimate || visibleCount >= stages.length) return;

    const timer = window.setTimeout(() => {
      setPlayback((current) => {
        if (current.key !== playbackKey) return current;

        const nextVisibleCount = Math.min(current.visibleCount + 1, stages.length);
        return {
          ...current,
          visibleCount: nextVisibleCount,
          selectedStageId: stages[nextVisibleCount - 1]?.id ?? current.selectedStageId,
        };
      });
    }, intervalMs);

    return () => window.clearTimeout(timer);
  }, [intervalMs, isCurrentPlayback, playbackKey, shouldAnimate, stages, visibleCount]);

  return (
    <section aria-label="可审计决策轨迹">
      <header>
        <strong>可审计决策轨迹</strong>
        <span>结构化决策轨迹，不包含隐藏思维链</span>
      </header>
      {stages.length === 0 ? <p>暂无可审计阶段</p> : (
        <ol>
          {visibleStages.map((stage) => (
            <li key={stage.id}>
              <button
                type="button"
                aria-pressed={activeStageId === stage.id}
                onClick={() => setPlayback((current) => ({
                  ...current,
                  selectedStageId: stage.id,
                }))}
              >
                <StageStatusIcon status={stage.status} />
                <span>{stage.label}</span>
              </button>
            </li>
          ))}
        </ol>
      )}
      <div aria-live="polite">
        {activeStage ? (
          <>
            <strong>{activeStage.summary}</strong>
            <ul>{activeStage.evidence.map((item, index) => <li key={`${activeStage.id}-${index}`}>{item}</li>)}</ul>
          </>
        ) : null}
      </div>
      <p>结构化决策轨迹，不包含隐藏思维链；播放间隔不代表模型耗时。</p>
    </section>
  );
}
