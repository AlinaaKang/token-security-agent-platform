import { Flag } from "lucide-react";
import { useId, useRef } from "react";
import type { KeyboardEvent } from "react";

import type { LabPublicSignal } from "../types";
import {
  SIGNAL_CHART_HEIGHT,
  SIGNAL_CHART_PAD_X,
  SIGNAL_CHART_PAD_Y,
  SIGNAL_CHART_WIDTH,
  signalSeriesPath,
  xAtPosition,
} from "./signalGeometry";
import type { SignalSeriesKey } from "./signalGeometry";

interface ChallengeSignalPickerProps {
  signals: LabPublicSignal[];
  selectedIndex: number | null;
  onSelect: (index: number) => void;
  readOnly?: boolean;
}

const SERIES: Array<{ key: SignalSeriesKey; className: string; label: string }> = [
  { key: "entropy", className: "entropy", label: "Entropy" },
  { key: "nll", className: "nll", label: "NLL" },
  { key: "cpd_entropy", className: "cpd", label: "CPD 累积值" },
];

export function ChallengeSignalPicker({
  signals,
  selectedIndex,
  onSelect,
  readOnly = false,
}: ChallengeSignalPickerProps) {
  const buttonRefs = useRef<Array<HTMLButtonElement | null>>([]);
  const tooltipPrefix = useId();

  if (signals.length < 2) {
    return <div className="challenge-signal-empty">信号不足，至少需要两个 Token 观测点</div>;
  }

  const selectedPosition = signals.findIndex((signal) => signal.index === selectedIndex);
  const plotWidth = SIGNAL_CHART_WIDTH - SIGNAL_CHART_PAD_X * 2;
  const minimumTargetWidth = Math.ceil(
    Math.max(0, signals.length - 1) * 44 * (SIGNAL_CHART_WIDTH / plotWidth),
  );
  const canvasMinWidth = Math.max(620, minimumTargetWidth);

  function handleKeyDown(event: KeyboardEvent<HTMLButtonElement>, position: number) {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onSelect(signals[position].index);
      return;
    }
    if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
    event.preventDefault();
    const direction = event.key === "ArrowLeft" ? -1 : 1;
    const nextPosition = Math.max(0, Math.min(signals.length - 1, position + direction));
    buttonRefs.current[nextPosition]?.focus();
    onSelect(signals[nextPosition].index);
  }

  return (
    <div className="challenge-signal-picker">
      <div className="challenge-signal-legend" aria-hidden="true">
        {SERIES.map((item) => <span className={item.className} key={item.key}>{item.label}</span>)}
      </div>
      <div className="challenge-signal-canvas" style={{ minWidth: canvasMinWidth }}>
        <svg
          viewBox={`0 0 ${SIGNAL_CHART_WIDTH} ${SIGNAL_CHART_HEIGHT}`}
          role="img"
          aria-label="Token 挑战信号曲线"
        >
          <title>{readOnly ? "Token 分布信号曲线" : "Entropy、NLL 与 CPD 累积值；选择预测异常起点"}</title>
          <line
            className="challenge-signal-axis"
            x1={SIGNAL_CHART_PAD_X}
            y1={SIGNAL_CHART_HEIGHT - SIGNAL_CHART_PAD_Y}
            x2={SIGNAL_CHART_WIDTH - SIGNAL_CHART_PAD_X}
            y2={SIGNAL_CHART_HEIGHT - SIGNAL_CHART_PAD_Y}
          />
          {SERIES.map((item) => (
            <path
              className={`challenge-signal-line ${item.className}`}
              d={signalSeriesPath(signals, item.key)}
              key={item.key}
            />
          ))}
          {selectedPosition >= 0 ? (
            <line
              className="challenge-signal-selection"
              x1={xAtPosition(selectedPosition, signals.length)}
              y1={SIGNAL_CHART_PAD_Y}
              x2={xAtPosition(selectedPosition, signals.length)}
              y2={SIGNAL_CHART_HEIGHT - SIGNAL_CHART_PAD_Y}
            />
          ) : null}
        </svg>
        {!readOnly ? (
          <div className="challenge-signal-targets">
            {signals.map((signal, position) => {
              const selected = signal.index === selectedIndex;
              const tooltipId = `${tooltipPrefix}-token-${signal.index}`;

              return (
                <button
                  type="button"
                  className={selected ? "selected" : ""}
                  style={{ left: `${(xAtPosition(position, signals.length) / SIGNAL_CHART_WIDTH) * 100}%` }}
                  aria-label={`选择 Token ${signal.index}`}
                  aria-describedby={selected ? tooltipId : undefined}
                  key={signal.index}
                  ref={(node) => { buttonRefs.current[position] = node; }}
                  onClick={() => onSelect(signal.index)}
                  onKeyDown={(event) => handleKeyDown(event, position)}
                >
                  <Flag size={13} aria-hidden="true" />
                  {selected ? (
                    <span className="challenge-signal-token-tooltip" id={tooltipId} role="tooltip">
                      Token #{signal.index}
                    </span>
                  ) : null}
                </button>
              );
            })}
          </div>
        ) : null}
      </div>
    </div>
  );
}
