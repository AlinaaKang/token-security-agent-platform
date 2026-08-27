import type { LabPublicSignal } from "../types";

export const SIGNAL_CHART_WIDTH = 920;
export const SIGNAL_CHART_HEIGHT = 236;
export const SIGNAL_CHART_PAD_X = 42;
export const SIGNAL_CHART_PAD_Y = 24;

export type SignalSeriesKey = "entropy" | "nll" | "cpd_entropy";

export function xAtPosition(position: number, count: number): number {
  if (count <= 1) return SIGNAL_CHART_WIDTH / 2;
  return SIGNAL_CHART_PAD_X
    + (position / (count - 1)) * (SIGNAL_CHART_WIDTH - SIGNAL_CHART_PAD_X * 2);
}

export function signalSeriesPath(
  signals: LabPublicSignal[],
  key: SignalSeriesKey,
): string {
  const values = signals.map((signal) => signal[key]);
  const maximum = Math.max(...values, 1e-6);
  return values.map((value, position) => {
    const x = xAtPosition(position, values.length);
    const y = SIGNAL_CHART_HEIGHT - SIGNAL_CHART_PAD_Y
      - (value / maximum) * (SIGNAL_CHART_HEIGHT - SIGNAL_CHART_PAD_Y * 2);
    return `${position === 0 ? "M" : "L"}${x.toFixed(2)},${y.toFixed(2)}`;
  }).join(" ");
}
