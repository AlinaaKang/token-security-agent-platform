import { Activity, BadgeCheck, ShieldCheck } from "lucide-react";

import type { LabStage } from "../types";
import type { ChallengePhase } from "../challenge/session";

interface MascotTeamProps {
  phase: ChallengePhase;
  replayStageId: LabStage["stage_id"] | null;
  evidenceConflict: boolean;
}

type MascotRole = "guard" | "cpd" | "agent";

const MASCOTS = [
  {
    role: "guard" as const,
    name: "Guard 语义侦探",
    shortName: "语义侦探",
    image: "/mascots/guard-detective.webp",
    Icon: ShieldCheck,
  },
  {
    role: "cpd" as const,
    name: "CPD 曲线侦探",
    shortName: "曲线侦探",
    image: "/mascots/cpd-detective.webp",
    Icon: Activity,
  },
  {
    role: "agent" as const,
    name: "Agent 小队队长",
    shortName: "小队队长",
    image: "/mascots/agent-captain.webp",
    Icon: BadgeCheck,
  },
] as const;

function activeRole(stageId: LabStage["stage_id"] | null): MascotRole | null {
  if (stageId === "semantic_guard") return "guard";
  if (stageId === "token_observation" || stageId === "entropy_cpd") return "cpd";
  if (stageId === "fixed_fusion" || stageId === "knowledge_retrieval") return "agent";
  return null;
}

export function MascotTeam({ phase, replayStageId, evidenceConflict }: MascotTeamProps) {
  const active = activeRole(replayStageId);

  return (
    <section className="challenge-mascot-team" aria-label="侦探学院调查小队">
      <div className="challenge-mascot-status" aria-live="polite">
        {evidenceConflict ? "证据分歧" : phase === "complete" ? "调查完成" : "调查小队"}
      </div>
      <div className="challenge-mascot-lineup">
        {MASCOTS.map(({ role, name, shortName, image, Icon }) => {
          const classNames = [
            "challenge-mascot",
            `challenge-mascot-${role}`,
            active === role ? "active" : "",
            evidenceConflict && role === "agent" ? "conflict" : "",
            phase === "revealed" ? "evidence" : "",
            phase === "complete" ? "celebration" : "",
          ].filter(Boolean).join(" ");

          return (
            <figure className={classNames} key={role}>
              <div className="challenge-mascot-image-wrap">
                <img src={image} alt={name} width="512" height="512" />
                <Icon data-mascot-status-icon aria-hidden="true" size={18} strokeWidth={2.2} />
              </div>
              <figcaption>{shortName}</figcaption>
            </figure>
          );
        })}
      </div>
    </section>
  );
}
