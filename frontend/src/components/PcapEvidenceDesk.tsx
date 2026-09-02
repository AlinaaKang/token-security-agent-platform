import { useEffect, useMemo, useRef, useState } from "react";

import {
  buildPcapRoleLines,
  type PcapEvidenceSection,
  type PcapInvestigationRole,
} from "../pcap/investigation";
import { usePrefersReducedMotion } from "../pcap/usePrefersReducedMotion";
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

export function PcapEvidenceDesk({ mission, role, replay, onComplete }: PcapEvidenceDeskProps) {
  const reducedMotion = usePrefersReducedMotion();
  const lines = useMemo(() => buildPcapRoleLines(mission, role), [mission, role]);
  const immediate = replay || reducedMotion;
  const playbackId = `${mission.mission_id}:${role}:${replay ? "replay" : "first"}`;
  const firstVisibleCount = immediate ? lines.length : Math.min(1, lines.length);
  const completedPlaybackIds = useRef(new Set<string>());
  const [reveal, setReveal] = useState(() => ({ playbackId, visibleCount: firstVisibleCount }));
  const visibleCount = immediate
    ? lines.length
    : reveal.playbackId === playbackId ? reveal.visibleCount : firstVisibleCount;

  useEffect(() => {
    if (replay || completedPlaybackIds.current.has(playbackId)) {
      setReveal({ playbackId, visibleCount: lines.length });
      return;
    }

    if (reducedMotion) {
      completedPlaybackIds.current.add(playbackId);
      setReveal({ playbackId, visibleCount: lines.length });
      onComplete();
      return;
    }

    setReveal({ playbackId, visibleCount: Math.min(1, lines.length) });
    if (lines.length <= 1) {
      completedPlaybackIds.current.add(playbackId);
      onComplete();
      return;
    }

    let nextCount = 1;
    const timer = window.setInterval(() => {
      nextCount += 1;
      setReveal({ playbackId, visibleCount: nextCount });
      if (nextCount >= lines.length) {
        window.clearInterval(timer);
        completedPlaybackIds.current.add(playbackId);
        onComplete();
      }
    }, LINE_REVEAL_INTERVAL_MS);
    return () => window.clearInterval(timer);
  }, [lines, onComplete, playbackId, reducedMotion, replay]);

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
