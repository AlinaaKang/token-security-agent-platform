import { Activity, BadgeCheck, ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";

import type { InvestigationRole } from "../challenge/investigation";
import { buildRoleAuditLines } from "../challenge/roleAuditLines";
import type { LabRunResult } from "../types";
import { ChallengeSignalPicker } from "./ChallengeSignalPicker";
import { RoleAuditPlayback } from "./RoleAuditPlayback";

interface InvestigationDeskProps {
  run: LabRunResult;
  role: InvestigationRole;
  mode: "first_visit" | "review";
  playbackKey: string;
  onPresentationComplete: (role: InvestigationRole) => void;
}

const ROLE_HEADERS = {
  guard: { label: "语义侦探汇报", Icon: ShieldCheck },
  cpd: { label: "曲线侦探汇报", Icon: Activity },
  agent: { label: "小队队长总结", Icon: BadgeCheck },
} as const;

export function InvestigationDesk({
  run,
  role,
  mode,
  playbackKey,
  onPresentationComplete,
}: InvestigationDeskProps) {
  const [reportComplete, setReportComplete] = useState(mode === "review");
  const { label, Icon } = ROLE_HEADERS[role];
  const lines = buildRoleAuditLines(run, role);

  useEffect(() => {
    setReportComplete(mode === "review");
  }, [mode, playbackKey]);

  function completePresentation() {
    setReportComplete(true);
    onPresentationComplete(role);
  }

  return (
    <section className="challenge-investigation-desk" aria-label="中央证据台">
      <header><Icon aria-hidden="true" /><strong>{label}</strong></header>
      <RoleAuditPlayback
        lines={lines}
        playbackKey={playbackKey}
        animate={mode === "first_visit"}
        onComplete={mode === "first_visit" ? completePresentation : undefined}
      />
      {role === "cpd" && reportComplete ? (
        <ChallengeSignalPicker
          signals={run.detection.signals}
          selectedIndex={null}
          onSelect={() => undefined}
          readOnly
        />
      ) : null}
    </section>
  );
}
