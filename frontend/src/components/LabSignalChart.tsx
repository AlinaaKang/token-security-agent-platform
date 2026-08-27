import { memo, useState } from "react";

import type { LabPublicSignal } from "../types";


const WIDTH = 920;
const HEIGHT = 236;
const PAD_X = 42;
const PAD_Y = 24;

type SeriesKey = "entropy" | "nll" | "cpd_entropy";

const series: Array<{ key: SeriesKey; label: string; className: string }> = [
  { key: "entropy", label: "Entropy", className: "entropy" },
  { key: "nll", label: "NLL", className: "nll" },
  { key: "cpd_entropy", label: "CPD 累积值", className: "cpd" },
];

function xAt(index: number, count: number) {
  if (count <= 1) return WIDTH / 2;
  return PAD_X + (index / (count - 1)) * (WIDTH - PAD_X * 2);
}

function seriesPath(signals: LabPublicSignal[], key: SeriesKey) {
  const values = signals.map((signal) => signal[key]);
  const maximum = Math.max(...values, 1e-6);
  return values.map((value, index) => {
    const x = xAt(index, values.length);
    const y = HEIGHT - PAD_Y - (value / maximum) * (HEIGHT - PAD_Y * 2);
    return `${index === 0 ? "M" : "L"}${x.toFixed(2)},${y.toFixed(2)}`;
  }).join(" ");
}

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
  const cursorX = xAt(active.index, signals.length);
  return (
    <div className="lab-chart-shell">
      <div className="lab-chart-legend" aria-hidden="true">
        {series.map((item) => <span className={item.className} key={item.key}>{item.label}</span>)}
      </div>
      <svg
        className="lab-signal-chart"
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        role="img"
        aria-label="Token 信号同步曲线"
      >
        <title>Entropy、NLL 与 Entropy-CPD 累积值同步曲线</title>
        <line className="lab-chart-axis" x1={PAD_X} y1={HEIGHT - PAD_Y} x2={WIDTH - PAD_X} y2={HEIGHT - PAD_Y} />
        {series.map((item) => (
          <path
            className={`lab-chart-line ${item.className}`}
            d={seriesPath(signals, item.key)}
            key={item.key}
          />
        ))}
        <line className="lab-chart-cursor" x1={cursorX} y1={PAD_Y} x2={cursorX} y2={HEIGHT - PAD_Y} />
        {signals.map((signal, index) => {
          const x = xAt(index, signals.length);
          return (
            <rect
              className="lab-chart-hit"
              key={signal.index}
              x={x - 10}
              y={PAD_Y}
              width={20}
              height={HEIGHT - PAD_Y * 2}
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
