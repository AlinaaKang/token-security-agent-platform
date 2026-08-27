import { memo, useState } from "react";

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

const series: Array<{ key: SignalSeriesKey; label: string; className: string }> = [
  { key: "entropy", label: "Entropy", className: "entropy" },
  { key: "nll", label: "NLL", className: "nll" },
  { key: "cpd_entropy", label: "CPD 累积值", className: "cpd" },
];

export const LabSignalChart = memo(function LabSignalChart({
  signals,
}: {
  signals: LabPublicSignal[];
}) {
  const [activeIndex, setActiveIndex] = useState(
    Math.max(signals.length - 1, 0),
  );
  if (signals.length < 2) {
    return <div className="lab-chart-empty">信号不足，至少需要两个 Token 观测点</div>;
  }
  const active = signals[Math.min(activeIndex, signals.length - 1)];
  const cursorX = xAtPosition(Math.min(activeIndex, signals.length - 1), signals.length);
  return (
    <div className="lab-chart-shell">
      <div className="lab-chart-legend" aria-hidden="true">
        {series.map((item) => <span className={item.className} key={item.key}>{item.label}</span>)}
      </div>
      <svg
        className="lab-signal-chart"
        viewBox={`0 0 ${SIGNAL_CHART_WIDTH} ${SIGNAL_CHART_HEIGHT}`}
        role="img"
        aria-label="Token 信号同步曲线"
      >
        <title>Entropy、NLL 与 Entropy-CPD 累积值同步曲线</title>
        <line className="lab-chart-axis" x1={SIGNAL_CHART_PAD_X} y1={SIGNAL_CHART_HEIGHT - SIGNAL_CHART_PAD_Y} x2={SIGNAL_CHART_WIDTH - SIGNAL_CHART_PAD_X} y2={SIGNAL_CHART_HEIGHT - SIGNAL_CHART_PAD_Y} />
        {series.map((item) => (
          <path
            className={`lab-chart-line ${item.className}`}
            d={signalSeriesPath(signals, item.key)}
            key={item.key}
          />
        ))}
        <line className="lab-chart-cursor" x1={cursorX} y1={SIGNAL_CHART_PAD_Y} x2={cursorX} y2={SIGNAL_CHART_HEIGHT - SIGNAL_CHART_PAD_Y} />
        {signals.map((signal, index) => {
          const x = xAtPosition(index, signals.length);
          return (
            <rect
              className="lab-chart-hit"
              key={signal.index}
              x={x - 10}
              y={SIGNAL_CHART_PAD_Y}
              width={20}
              height={SIGNAL_CHART_HEIGHT - SIGNAL_CHART_PAD_Y * 2}
              tabIndex={0}
              aria-label={`Token ${signal.index}`}
              onFocus={() => setActiveIndex(index)}
              onMouseEnter={() => setActiveIndex(index)}
            />
          );
        })}
      </svg>
      <dl className="lab-chart-readout" aria-live="polite">
        <div><dt>Token</dt><dd>T{active.index}</dd></div>
        <div><dt>Entropy</dt><dd>{active.entropy.toFixed(3)}</dd></div>
        <div><dt>NLL</dt><dd>{active.nll.toFixed(3)}</dd></div>
        <div><dt>CPD</dt><dd>{active.cpd_entropy.toFixed(3)}</dd></div>
      </dl>
    </div>
  );
});
