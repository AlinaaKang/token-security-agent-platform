export type GuidePosition = { x: number; y: number };
export type GuideSize = { width: number; height: number };

const EDGE_GAP = 12;

export function guidePositionStorageKey(mobile: boolean) {
  return `token-sentinel-tour-launcher:${mobile ? "mobile" : "desktop"}:v1`;
}

export function clampGuidePosition(position: GuidePosition, viewport: GuideSize, launcher: GuideSize): GuidePosition {
  return {
    x: Math.min(Math.max(EDGE_GAP, position.x), Math.max(EDGE_GAP, viewport.width - launcher.width - EDGE_GAP)),
    y: Math.min(Math.max(EDGE_GAP, position.y), Math.max(EDGE_GAP, viewport.height - launcher.height - EDGE_GAP)),
  };
}

export function loadGuidePosition(mobile: boolean, storage?: Storage): GuidePosition | null {
  try {
    const value = storage?.getItem(guidePositionStorageKey(mobile));
    if (!value) return null;
    const parsed: unknown = JSON.parse(value);
    if (!parsed || typeof parsed !== "object") return null;
    const candidate = parsed as Partial<GuidePosition>;
    if (typeof candidate.x !== "number" || !Number.isFinite(candidate.x)) return null;
    if (typeof candidate.y !== "number" || !Number.isFinite(candidate.y)) return null;
    return { x: candidate.x, y: candidate.y };
  } catch {
    return null;
  }
}

export function saveGuidePosition(position: GuidePosition, mobile: boolean, storage?: Storage) {
  try {
    storage?.setItem(guidePositionStorageKey(mobile), JSON.stringify(position));
  } catch {
    // The launcher remains movable for this visit when storage is unavailable.
  }
}
