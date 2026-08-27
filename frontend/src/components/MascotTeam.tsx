import { Activity, BadgeCheck, ScanSearch, ShieldCheck } from "lucide-react";

import {
  canInspectRole,
  roleStateFor,
  type InvestigationRole,
  type InvestigationRoleState,
  type InvestigationState,
} from "../challenge/investigation";
import type { LabStage } from "../types";
import type { ChallengePhase } from "../challenge/session";

interface MascotInteraction {
  state: InvestigationState;
  onSelect: (role: InvestigationRole) => void;
}

interface MascotTeamProps {
  phase: ChallengePhase;
  replayStageId: LabStage["stage_id"] | null;
  evidenceConflict: boolean;
  interaction?: MascotInteraction;
}

type MascotRole = InvestigationRole;
type MascotMotion = "idle" | "approach" | "inspect" | "conclude" | "conflict" | "celebrate";

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

function motionFor(
  role: MascotRole,
  phase: ChallengePhase,
  stageId: LabStage["stage_id"] | null,
  evidenceConflict: boolean,
): MascotMotion {
  if (phase === "complete") return "celebrate";
  if (phase === "revealed" && evidenceConflict && role === "agent") return "conflict";
  if (phase !== "investigating" || activeRole(stageId) !== role) return "idle";
  if (stageId === "entropy_cpd") return "inspect";
  if (stageId === "knowledge_retrieval") return "conclude";
  return "approach";
}

function interactionMotion(
  role: InvestigationRole,
  roleState: InvestigationRoleState,
): MascotMotion {
  if (roleState !== "presenting") return "idle";
  if (role === "cpd") return "inspect";
  if (role === "agent") return "conclude";
  return "approach";
}

function roleStatusLabel(role: InvestigationRole, state: InvestigationRoleState): string {
  if (state === "ready") return "可以汇报";
  if (state === "presenting") return "正在汇报";
  if (state === "visited") return "回看汇报";
  if (role === "cpd") return "等待语义侦探";
  if (role === "agent") return "等待曲线侦探";
  return "等待调查开始";
}

export function MascotTeam({ phase, replayStageId, evidenceConflict, interaction }: MascotTeamProps) {
  const active = activeRole(replayStageId);
  const revealEvidenceConflict = phase === "revealed" && evidenceConflict;

  return (
    <section
      className="challenge-mascot-team"
      aria-label="侦探学院调查小队"
      data-phase={phase}
      data-stage={replayStageId ?? undefined}
    >
      <div className="challenge-mascot-status" aria-live="polite">
        {revealEvidenceConflict ? "证据分歧" : phase === "complete" ? "调查完成" : "调查小队"}
      </div>
      <div className="challenge-evidence-desk" data-evidence-desk aria-hidden="true">
        <ScanSearch size={22} strokeWidth={2} />
      </div>
      <div className="challenge-mascot-lineup">
        {MASCOTS.map(({ role, name, shortName, image, Icon }) => {
          const roleState = interaction ? roleStateFor(interaction.state, role) : null;
          const selected = interaction?.state.selectedRole === role;
          const motion = interaction
            ? interactionMotion(role, roleState!)
            : motionFor(role, phase, replayStageId, revealEvidenceConflict);
          const canInspect = interaction ? canInspectRole(interaction.state, role) : false;
          const classNames = [
            "challenge-mascot",
            `challenge-mascot-${role}`,
            phase === "investigating" && active === role ? "active" : "",
            revealEvidenceConflict && role === "agent" ? "conflict" : "",
            phase === "revealed" ? "evidence" : "",
            phase === "complete" ? "celebration" : "",
          ].filter(Boolean).join(" ");

          return (
            <figure
              className={classNames}
              data-motion={motion}
              data-role={role}
              data-role-state={roleState ?? undefined}
              key={role}
            >
              <button
                type="button"
                className="challenge-mascot-control"
                disabled={!canInspect}
                aria-pressed={interaction ? selected : undefined}
                aria-label={interaction ? `${name}，${roleStatusLabel(role, roleState!)}` : name}
                onClick={() => interaction?.onSelect(role)}
              >
                <div className="challenge-mascot-image-wrap">
                  <img src={image} alt="" width="512" height="512" />
                  <Icon data-mascot-status-icon aria-hidden="true" size={18} strokeWidth={2.2} />
                </div>
              </button>
              <figcaption>{shortName}</figcaption>
            </figure>
          );
        })}
      </div>
    </section>
  );
}
