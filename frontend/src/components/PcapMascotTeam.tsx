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
    role: "parser" as const,
    name: "文件解析员",
    shortName: "文件解析员",
    image: "/mascots/guard-detective.webp",
    Icon: ShieldCheck,
  },
  {
    role: "traffic" as const,
    name: "流量分析员",
    shortName: "流量分析员",
    image: "/mascots/cpd-detective.webp",
    Icon: Activity,
  },
  {
    role: "captain" as const,
    name: "分诊队长",
    shortName: "分诊队长",
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
  const captures = mission.summary?.captures ?? [];
  const [selectedCaptureIndex, setSelectedCaptureIndex] = useState(0);
  const reducedMotion = usePrefersReducedMotion();
  const presentationActive = state.presentingRole !== null;
  const activeCaptureIndex = captures.length ? Math.min(selectedCaptureIndex, captures.length - 1) : 0;
  const selectedCapture = captures[activeCaptureIndex] ?? null;

  const completePresentation = useCallback(() => {
    setState((current) => current.presentingRole
      ? finishPcapRole(current, current.presentingRole)
      : current);
  }, []);

  function selectRole(role: PcapInvestigationRole) {
    setState((current) => selectPcapRole(current, role));
  }

  function selectCapture(index: number) {
    setSelectedCaptureIndex(index);
    setState(initialPcapInvestigationState());
  }

  return (
    <section className="pcap-mascot-team" aria-label="批量分诊互动复盘">
      <div className="pcap-mascot-heading">
        <strong>批量分诊互动复盘</strong>
        <span>逐份解释当前批次的公开 PCAP 证据</span>
      </div>
      {captures.length === 0 ? <p className="pcap-mascot-empty">本批次没有可回放文件</p> : null}
      {captures.length > 0 ? (
        <div className="pcap-capture-selector" role="group" aria-label="当前批次捕获回放">
          {captures.map((capture, index) => (
            <button
              type="button"
              key={capture.capture_id}
              className="pcap-capture-selector-button"
              aria-label={`回放捕获 ${index + 1}`}
              aria-pressed={activeCaptureIndex === index}
              onClick={() => selectCapture(index)}
            >
              {`捕获 ${String(index + 1).padStart(2, "0")}`}
            </button>
          ))}
        </div>
      ) : null}
      {selectedCapture ? <div className="pcap-mascot-lineup">
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
      </div> : null}
      {state.selectedRole && selectedCapture ? (
        <PcapEvidenceDesk
          missionId={mission.mission_id}
          capture={selectedCapture}
          role={state.selectedRole}
          replay={state.presentingRole !== state.selectedRole}
          onComplete={completePresentation}
        />
      ) : null}
    </section>
  );
}
