import { CircleHelp, X } from "lucide-react";
import { useEffect, useLayoutEffect, useRef, useState } from "react";
import type { CSSProperties, KeyboardEvent as ReactKeyboardEvent, PointerEvent as ReactPointerEvent } from "react";
import { clampGuidePosition, loadGuidePosition, saveGuidePosition, type GuidePosition } from "./guidedTourPosition";

export type GuidedTourStep = {
  id: string;
  target: string;
  title: string;
  description: string;
  advanceOnClick?: boolean;
};

type GuidedTourProps = {
  route: string;
  steps: GuidedTourStep[];
  storage?: Storage;
};

type TargetBox = {
  top: number;
  left: number;
  width: number;
  height: number;
};

const EDGE_GAP = 12;
const PANEL_WIDTH = 340;
const PANEL_HEIGHT_ESTIMATE = 230;
const DRAG_THRESHOLD = 6;
const MOBILE_BREAKPOINT = 760;

function findAvailableStep(steps: GuidedTourStep[], from: number, direction = 1) {
  for (let index = from; index >= 0 && index < steps.length; index += direction) {
    if (document.querySelector(`[data-tour="${steps[index].target}"]`)) return index;
  }
  return -1;
}

function canReadSeen(storage: Storage | undefined, key: string) {
  try {
    return storage?.getItem(key) === "seen";
  } catch {
    return false;
  }
}

function browserStorage() {
  try {
    return window.localStorage;
  } catch {
    return undefined;
  }
}

export function GuidedTour({ route, steps, storage: providedStorage }: GuidedTourProps) {
  const storage = providedStorage ?? browserStorage();
  const storageKey = `token-sentinel-tour:${route}:v1`;
  const [open, setOpen] = useState(() => !canReadSeen(storage, storageKey));
  const [stepIndex, setStepIndex] = useState(0);
  const [targetBox, setTargetBox] = useState<TargetBox | null>(null);
  const [launcherPosition, setLauncherPosition] = useState<GuidePosition | null>(() => loadGuidePosition(window.innerWidth <= MOBILE_BREAKPOINT, storage));
  const panelRef = useRef<HTMLDivElement>(null);
  const launcherRef = useRef<HTMLButtonElement>(null);
  const restoreFocusRef = useRef<HTMLElement | null>(null);
  const pointerRef = useRef<{ id: number; x: number; y: number; origin: GuidePosition; dragged: boolean; latest: GuidePosition } | null>(null);
  const suppressClickRef = useRef(false);

  const boundedPosition = (position: GuidePosition, rect: Pick<DOMRect, "width" | "height">) => clampGuidePosition(
    position,
    { width: window.innerWidth, height: window.innerHeight },
    { width: rect.width, height: rect.height },
  );

  const persistLauncherPosition = (position: GuidePosition) => {
    setLauncherPosition(position);
    saveGuidePosition(position, window.innerWidth <= MOBILE_BREAKPOINT, storage);
  };

  const markSeen = () => {
    try {
      storage?.setItem(storageKey, "seen");
    } catch {
      // Storage may be unavailable in hardened or private browser contexts.
    }
  };

  const close = () => {
    markSeen();
    setOpen(false);
    setTargetBox(null);
  };

  const move = (direction: 1 | -1) => {
    const next = findAvailableStep(steps, stepIndex + direction, direction);
    if (next >= 0) setStepIndex(next);
    else if (direction === 1) close();
  };

  const replay = () => {
    const first = findAvailableStep(steps, 0);
    if (first < 0) return;
    restoreFocusRef.current = launcherRef.current;
    setStepIndex(first);
    setOpen(true);
  };

  const onLauncherPointerDown = (event: ReactPointerEvent<HTMLButtonElement>) => {
    if (!Number.isFinite(event.clientX) || !Number.isFinite(event.clientY)) return;
    const rect = event.currentTarget.getBoundingClientRect();
    const origin = launcherPosition ?? { x: rect.left, y: rect.top };
    pointerRef.current = { id: event.pointerId, x: event.clientX, y: event.clientY, origin, dragged: false, latest: origin };
    event.currentTarget.setPointerCapture?.(event.pointerId);
  };

  const onLauncherPointerMove = (event: ReactPointerEvent<HTMLButtonElement>) => {
    const pointer = pointerRef.current;
    if (!pointer || pointer.id !== event.pointerId || !Number.isFinite(event.clientX) || !Number.isFinite(event.clientY)) return;
    const dx = event.clientX - pointer.x;
    const dy = event.clientY - pointer.y;
    if (!pointer.dragged && Math.hypot(dx, dy) <= DRAG_THRESHOLD) return;
    pointer.dragged = true;
    const rect = event.currentTarget.getBoundingClientRect();
    pointer.latest = boundedPosition({ x: pointer.origin.x + dx, y: pointer.origin.y + dy }, rect);
    setLauncherPosition(pointer.latest);
  };

  const onLauncherPointerUp = (event: ReactPointerEvent<HTMLButtonElement>) => {
    const pointer = pointerRef.current;
    if (!pointer || pointer.id !== event.pointerId) return;
    if (pointer.dragged) {
      suppressClickRef.current = true;
      persistLauncherPosition(pointer.latest);
    }
    pointerRef.current = null;
    event.currentTarget.releasePointerCapture?.(event.pointerId);
  };

  const onLauncherKeyDown = (event: ReactKeyboardEvent<HTMLButtonElement>) => {
    const directions: Record<string, GuidePosition> = {
      ArrowLeft: { x: -1, y: 0 }, ArrowRight: { x: 1, y: 0 },
      ArrowUp: { x: 0, y: -1 }, ArrowDown: { x: 0, y: 1 },
    };
    const direction = directions[event.key];
    if (!direction) return;
    event.preventDefault();
    const rect = event.currentTarget.getBoundingClientRect();
    const origin = launcherPosition ?? { x: rect.left, y: rect.top };
    const distance = event.shiftKey ? 32 : 12;
    persistLauncherPosition(boundedPosition({ x: origin.x + direction.x * distance, y: origin.y + direction.y * distance }, rect));
  };

  useLayoutEffect(() => {
    if (open || !launcherPosition || !launcherRef.current) return;
    const next = boundedPosition(launcherPosition, launcherRef.current.getBoundingClientRect());
    if (next.x !== launcherPosition.x || next.y !== launcherPosition.y) setLauncherPosition(next);
  }, [open, launcherPosition]);

  useEffect(() => {
    const clampOnResize = () => {
      if (!launcherRef.current) return;
      setLauncherPosition((current) => current ? boundedPosition(current, launcherRef.current!.getBoundingClientRect()) : current);
    };
    window.addEventListener("resize", clampOnResize);
    return () => window.removeEventListener("resize", clampOnResize);
  }, []);

  useLayoutEffect(() => {
    if (!open || steps.length === 0) return;
    const step = steps[stepIndex];
    const target = step ? document.querySelector<HTMLElement>(`[data-tour="${step.target}"]`) : null;
    if (!target) {
      const next = findAvailableStep(steps, stepIndex + 1);
      if (next >= 0) setStepIndex(next);
      else setOpen(false);
      return;
    }

    const measure = () => {
      const rect = target.getBoundingClientRect();
      setTargetBox({ top: rect.top, left: rect.left, width: rect.width, height: rect.height });
    };
    measure();
    window.addEventListener("resize", measure);
    document.addEventListener("scroll", measure, true);
    return () => {
      window.removeEventListener("resize", measure);
      document.removeEventListener("scroll", measure, true);
    };
  }, [open, stepIndex, steps]);

  useEffect(() => {
    if (!open) return;
    if (!restoreFocusRef.current) restoreFocusRef.current = document.activeElement as HTMLElement | null;
    panelRef.current?.focus();
  }, [open, stepIndex]);

  useEffect(() => {
    if (open || !restoreFocusRef.current) return;
    const destination = restoreFocusRef.current.isConnected
      ? restoreFocusRef.current
      : launcherRef.current;
    destination?.focus();
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const step = steps[stepIndex];
    if (!step?.advanceOnClick) return;
    const target = document.querySelector<HTMLElement>(`[data-tour="${step.target}"]`);
    if (!target) return;
    const advance = () => move(1);
    target.addEventListener("click", advance);
    return () => target.removeEventListener("click", advance);
  });

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        close();
        return;
      }
      if (event.key !== "Tab" || !panelRef.current) return;
      const controls = Array.from(panelRef.current.querySelectorAll<HTMLElement>("button:not(:disabled)"));
      if (controls.length === 0) return;
      const first = controls[0];
      const last = controls[controls.length - 1];
      if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      } else if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  });

  const step = steps[stepIndex];
  const isLast = findAvailableStep(steps, stepIndex + 1) < 0;
  const hasPrevious = findAvailableStep(steps, stepIndex - 1, -1) >= 0;
  const placement = targetBox && targetBox.top + targetBox.height + 12 + PANEL_HEIGHT_ESTIMATE <= window.innerHeight
    ? "below"
    : "above";
  const panelTop = targetBox
    ? placement === "below"
      ? targetBox.top + targetBox.height + 12
      : Math.max(EDGE_GAP, targetBox.top - PANEL_HEIGHT_ESTIMATE - 12)
    : EDGE_GAP;
  const panelLeft = targetBox
    ? Math.min(Math.max(EDGE_GAP, targetBox.left), Math.max(EDGE_GAP, window.innerWidth - PANEL_WIDTH - EDGE_GAP))
    : EDGE_GAP;

  return (
    <>
      {!open ? <button
        ref={launcherRef}
        type="button"
        className="guided-tour-launcher"
        aria-label="打开本页使用引导"
        title="打开本页使用引导"
        style={launcherPosition ? { left: launcherPosition.x, top: launcherPosition.y, right: "auto", bottom: "auto" } as CSSProperties : undefined}
        onPointerDown={onLauncherPointerDown}
        onPointerMove={onLauncherPointerMove}
        onPointerUp={onLauncherPointerUp}
        onPointerCancel={() => { pointerRef.current = null; }}
        onKeyDown={onLauncherKeyDown}
        onClick={(event) => {
          if (suppressClickRef.current) {
            suppressClickRef.current = false;
            event.preventDefault();
            return;
          }
          replay();
        }}
      >
        <CircleHelp size={20} aria-hidden="true" />
        <span>本页引导</span>
      </button> : null}
      {open && step && targetBox ? (
        <div className="guided-tour-layer">
          <div
            className="guided-tour-spotlight"
            aria-hidden="true"
            style={{ top: targetBox.top - 5, left: targetBox.left - 5, width: targetBox.width + 10, height: targetBox.height + 10 }}
          />
          <div
            ref={panelRef}
            className="guided-tour-panel"
            role="dialog"
            aria-modal="false"
            aria-labelledby={`guided-tour-title-${step.id}`}
            data-placement={placement}
            tabIndex={-1}
            style={{ top: panelTop, left: panelLeft }}
          >
            <div className="guided-tour-heading">
              <span>步骤 {stepIndex + 1} / {steps.length}</span>
              <button type="button" aria-label="跳过引导" title="跳过引导" onClick={close}><X size={17} aria-hidden="true" /></button>
            </div>
            <h2 id={`guided-tour-title-${step.id}`}>{step.title}</h2>
            <p>{step.description}</p>
            <div className="guided-tour-actions">
              {hasPrevious ? <button type="button" onClick={() => move(-1)}>上一步</button> : <span />}
              <button type="button" onClick={() => isLast ? close() : move(1)}>{isLast ? "完成" : "下一步"}</button>
            </div>
          </div>
        </div>
      ) : null}
    </>
  );
}
