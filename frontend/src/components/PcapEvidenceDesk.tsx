import { useEffect, useMemo, useState } from "react";

import {
  buildPcapRoleLines,
  type PcapEvidenceSection,
  type PcapInvestigationRole,
} from "../pcap/investigation";
import type { PcapMissionResult } from "../types";

const LINE_REVEAL_INTERVAL_MS = 420;

const roleLabels: Record<PcapInvestigationRole, string> = {
  guard: "Guard 语义侦探",
  cpd: "CPD 曲线侦探",
  captain: "Agent 小队队长",
};

const sectionLabels: Record<Exclude<PcapEvidenceSection, "evidence">, string> = {
  confirmed: "已证实",
  candidate: "候选",
  unknown: "未知",
};

interface PcapEvidenceDeskProps {
  mission: PcapMissionResult;
  role: PcapInvestigationRole;
  replay: boolean;
  onComplete: () => void;
}

function prefersReducedMotion(): boolean {
  return typeof window.matchMedia === "function"
    && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

export function PcapEvidenceDesk({ mission, role, replay, onComplete }: PcapEvidenceDeskProps) {
  const reducedMotion = prefersReducedMotion();
  const lines = useMemo(() => buildPcapRoleLines(mission, role), [mission, role]);
  const immediate = replay || reducedMotion;
  const [visibleCount, setVisibleCount] = useState(() => immediate ? lines.length : Math.min(1, lines.length));

  useEffect(() => {
    if (immediate) {
      setVisibleCount(lines.length);
      if (!replay) onComplete();
      return;
    }

    setVisibleCount(Math.min(1, lines.length));
    if (lines.length <= 1) {
      onComplete();
      return;
    }

    let nextCount = 1;
    const timer = window.setInterval(() => {
      nextCount += 1;
      setVisibleCount(nextCount);
      if (nextCount >= lines.length) {
        window.clearInterval(timer);
        onComplete();
      }
    }, LINE_REVEAL_INTERVAL_MS);
    return () => window.clearInterval(timer);
  }, [immediate, lines, onComplete, replay]);

  const visibleLines = lines.slice(0, visibleCount);
  const evidenceLines = visibleLines.filter(({ section }) => section === "evidence");

  return (
    <section className="pcap-mascot-evidence-desk" aria-label={`${roleLabels[role]} 证据汇报`} aria-live="polite">
      <header>
        <strong>{roleLabels[role]}</strong>
        <span>{replay ? "即时回看" : reducedMotion ? "完整汇报" : "逐行汇报"}</span>
      </header>
      {evidenceLines.length ? (
        <ul className="pcap-mascot-evidence-lines">
          {evidenceLines.map(({ text }) => <li key={text}>{text}</li>)}
        </ul>
      ) : null}
      {role === "captain" ? (
        <div className="pcap-mascot-finding-grid">
          {(Object.keys(sectionLabels) as Array<Exclude<PcapEvidenceSection, "evidence">>).map((section) => {
            const sectionLines = visibleLines.filter((line) => line.section === section);
            return (
              <section key={section} aria-label={sectionLabels[section]}>
                <h3>{sectionLabels[section]}</h3>
                {sectionLines.map(({ text }) => <p key={text}>{text}</p>)}
              </section>
            );
          })}
        </div>
      ) : null}
    </section>
  );
}
