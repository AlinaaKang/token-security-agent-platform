import { Activity, ArrowDown, BadgeCheck, ShieldCheck } from "lucide-react";
import { useCallback, useState } from "react";

import {
  finishPcapRole,
  initialPcapInvestigationState,
  roleStateForPcap,
  selectPcapRole,
  type PcapInvestigationRole,
  type PcapInvestigationRoleState,
} from "../pcap/investigation";
import { usePrefersReducedMotion } from "../pcap/usePrefersReducedMotion";
import type { PcapMissionResult } from "../types";
import { PcapEvidenceDesk } from "./PcapEvidenceDesk";

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
    role: "captain" as const,
    name: "Agent 小队队长",
    shortName: "小队队长",
    image: "/mascots/agent-captain.webp",
    Icon: BadgeCheck,
  },
] as const;

const roleStatusLabels: Record<PcapInvestigationRoleState, string> = {
  locked: "等待前一角色汇报",
  ready: "等待点击",
  presenting: "正在逐行汇报",
  visited: "已汇报，可回看",
};

function roleStatusId(role: PcapInvestigationRole): string {
  return `pcap-mascot-role-status-${role}`;
}

export function PcapMascotTeam({ mission }: { mission: PcapMissionResult }) {
  const [state, setState] = useState(initialPcapInvestigationState);
  const reducedMotion = usePrefersReducedMotion();
  const presentationActive = state.presentingRole !== null;

  const completePresentation = useCallback(() => {
    setState((current) => current.presentingRole
      ? finishPcapRole(current, current.presentingRole)
      : current);
  }, []);

  function selectRole(role: PcapInvestigationRole) {
    setState((current) => selectPcapRole(current, role));
  }

  return (
    <section className="pcap-mascot-team" aria-label="PCAP 侦探证据回放">
      <div className="pcap-mascot-heading">
        <strong>侦探证据回放</strong>
        <span>按角色顺序复核公开证据</span>
      </div>
      <div className="pcap-mascot-lineup">
        {MASCOTS.map(({ role, name, shortName, image, Icon }) => {
          const roleState = roleStateForPcap(state, role);
          const selected = state.selectedRole === role;
          const motion = reducedMotion
            ? "none"
            : roleState === "ready" || roleState === "presenting" ? "hop" : "idle";
          return (
            <figure
              className={`pcap-mascot pcap-mascot-${role}`}
              data-motion={motion}
              data-role={role}
              data-role-state={roleState}
              key={role}
            >
              <div className="pcap-mascot-next-cue" aria-hidden={roleState === "ready" ? undefined : "true"}>
                {roleState === "ready" ? (
                  <><ArrowDown aria-hidden="true" size={13} /><span>{`下一步：点击${shortName}`}</span></>
                ) : null}
              </div>
              <button
                type="button"
                className="pcap-mascot-control"
                aria-label={name}
                aria-describedby={roleStatusId(role)}
                aria-pressed={selected}
                disabled={roleState === "locked" || presentationActive}
                onClick={() => selectRole(role)}
              >
                <div className="pcap-mascot-image-wrap">
                  <img src={image} alt={name} width="512" height="512" />
                  <Icon aria-hidden="true" size={17} />
                </div>
              </button>
              <figcaption>
                <strong>{shortName}</strong>
                <span id={roleStatusId(role)}>{selected && roleState === "visited" ? "正在回看" : roleStatusLabels[roleState]}</span>
              </figcaption>
            </figure>
          );
        })}
      </div>
      {state.selectedRole ? (
        <PcapEvidenceDesk
          mission={mission}
          role={state.selectedRole}
          replay={state.presentingRole !== state.selectedRole}
          onComplete={completePresentation}
        />
      ) : null}
    </section>
  );
}
