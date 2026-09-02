import { useEffect, useState } from "react";

const REDUCED_MOTION_QUERY = "(prefers-reduced-motion: reduce)";

function readReducedMotionPreference(): boolean {
  return typeof window.matchMedia === "function"
    && window.matchMedia(REDUCED_MOTION_QUERY).matches;
}

export function usePrefersReducedMotion(): boolean {
  const [reducedMotion, setReducedMotion] = useState(readReducedMotionPreference);

  useEffect(() => {
    if (typeof window.matchMedia !== "function") return;
    const mediaQuery = window.matchMedia(REDUCED_MOTION_QUERY);
    const handleChange = (event: MediaQueryListEvent) => setReducedMotion(event.matches);
    setReducedMotion(mediaQuery.matches);

    if (typeof mediaQuery.addEventListener === "function") {
      mediaQuery.addEventListener("change", handleChange);
      return () => mediaQuery.removeEventListener("change", handleChange);
    }
    if (typeof mediaQuery.addListener === "function") {
      mediaQuery.addListener(handleChange);
      return () => mediaQuery.removeListener(handleChange);
    }
  }, []);

  return reducedMotion;
}
