import { useEffect, useMemo, useRef, useState } from "react";

import type { RoleAuditLine } from "../challenge/roleAuditLines";

interface RoleAuditPlaybackProps {
  lines: RoleAuditLine[];
  playbackKey: string;
  animate: boolean;
  intervalMs?: number;
  onComplete?: () => void;
}

interface PlaybackState {
  key: string;
  visibleCount: number;
}

export function RoleAuditPlayback({
  lines,
  playbackKey,
  animate,
  intervalMs = 420,
  onComplete,
}: RoleAuditPlaybackProps) {
  const prefersReducedMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
  const shouldAnimate = animate && !prefersReducedMotion && intervalMs > 0 && lines.length > 0;
  const initialVisibleCount = shouldAnimate ? Math.min(1, lines.length) : lines.length;
  const [playback, setPlayback] = useState<PlaybackState>({
    key: playbackKey,
    visibleCount: initialVisibleCount,
  });
  const completedKeyRef = useRef<string | null>(null);
  const visibleCount = playback.key === playbackKey
    ? Math.min(playback.visibleCount, lines.length)
    : initialVisibleCount;

  useEffect(() => {
    setPlayback({ key: playbackKey, visibleCount: initialVisibleCount });
  }, [initialVisibleCount, playbackKey]);

  useEffect(() => {
    if (!shouldAnimate || visibleCount >= lines.length) return;
    const timer = window.setTimeout(() => {
      setPlayback((current) => current.key === playbackKey
        ? { ...current, visibleCount: Math.min(current.visibleCount + 1, lines.length) }
        : current);
    }, intervalMs);
    return () => window.clearTimeout(timer);
  }, [intervalMs, lines.length, playbackKey, shouldAnimate, visibleCount]);

  useEffect(() => {
    if (!animate || lines.length === 0 || visibleCount < lines.length) return;
    if (completedKeyRef.current === playbackKey) return;
    completedKeyRef.current = playbackKey;
    onComplete?.();
  }, [animate, lines.length, onComplete, playbackKey, visibleCount]);

  const visibleLines = useMemo(() => lines.slice(0, visibleCount), [lines, visibleCount]);

  return (
    <section className="challenge-role-audit" aria-label="可审计决策过程">
      <header>
        <div>
          <span>角色证据回放</span>
          <strong>可审计决策过程</strong>
        </div>
        <span>{visibleCount} / {lines.length}</span>
      </header>
      <ol aria-live="polite">
        {visibleLines.map((line) => (
          <li key={line.id}>
            <span>{line.label}</span>
            <strong>{line.value}</strong>
          </li>
        ))}
      </ol>
      {shouldAnimate && visibleCount < lines.length ? (
        <button type="button" onClick={() => setPlayback({ key: playbackKey, visibleCount: lines.length })}>
          立即显示完整汇报
        </button>
      ) : null}
      <p>这是已返回检测结果的逐行回放，不代表模型正在实时推理，也不包含隐藏思维链。</p>
    </section>
  );
}
