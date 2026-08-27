import { Activity, CircleAlert, Gamepad2, Play, ShieldCheck } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { api } from "../api";
import type { ChallengeMode } from "../challenge/definitions";
import { resolveChallenge } from "../challenge/definitions";
import { createChallengeSession, createChallengeSetup } from "../challenge/session";
import { LabModeSwitch } from "../components/LabModeSwitch";
import { MascotTeam } from "../components/MascotTeam";
import type { HealthResponse, LabScenario } from "../types";

const FAMILY_LABELS = {
  gcg: "GCG",
  autodan: "AutoDAN",
  advprompter: "AdvPrompter",
} as const;

export function ChallengePage() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [scenarios, setScenarios] = useState<LabScenario[]>([]);
  const [selectedMode, setSelectedMode] = useState<ChallengeMode>("speed");
  const [session, setSession] = useState(createChallengeSetup);
  const [loadFailed, setLoadFailed] = useState(false);

  useEffect(() => {
    let active = true;
    Promise.all([api.health(), api.labScenarios()])
      .then(([healthResult, scenarioResult]) => {
        if (!active) return;
        setHealth(healthResult);
        setScenarios(scenarioResult);
      })
      .catch(() => {
        if (active) setLoadFailed(true);
      });
    return () => { active = false; };
  }, []);

  const speed = useMemo(() => resolveChallenge("speed", scenarios), [scenarios]);
  const full = useMemo(() => resolveChallenge("full", scenarios), [scenarios]);
  const selected = selectedMode === "speed" ? speed : full;
  const loading = health === null && !loadFailed;
  const labReady = Boolean(health?.lab?.ready) && !loadFailed;
  const canBegin = labReady && selected.ready && session.phase === "setup";
  const missingFull = full.missingFamilies.map((family) => FAMILY_LABELS[family]).join("、");

  function beginChallenge() {
    if (!canBegin) return;
    setSession(createChallengeSession(selected.rounds));
  }

  return (
    <main className="page challenge-page" aria-label="Token 侦探挑战">
      <header className="challenge-header">
        <div>
          <LabModeSwitch />
          <h1>Token 侦探挑战</h1>
          <p>侦探学院已集合。选择关卡组，用真实脱敏检测结果完成研判。</p>
        </div>
        <span className={`readiness ${labReady ? "ready" : ""}`}>
          <Activity size={15} aria-hidden="true" />
          {loading ? "正在连接" : labReady ? "挑战目录已就绪" : "实验舱未就绪"}
        </span>
      </header>

      <section className="challenge-setup-layout" aria-label="挑战设置">
        <div className="challenge-setup-panel">
          <div className="challenge-section-title">
            <Gamepad2 size={18} aria-hidden="true" />
            <div>
              <strong>选择挑战</strong>
              <span>分数表示与当前系统结果的一致程度</span>
            </div>
          </div>

          <div className="challenge-mode-options" role="group" aria-label="挑战关卡组">
            <button
              type="button"
              aria-label="三关速战"
              className={selectedMode === "speed" ? "active" : ""}
              aria-pressed={selectedMode === "speed"}
              disabled={!labReady || !speed.ready}
              onClick={() => setSelectedMode("speed")}
            >
              <strong>三关速战</strong>
              <span>无害、格式突变、优化型攻击</span>
            </button>
            <button
              type="button"
              aria-label="五关完整挑战"
              className={selectedMode === "full" ? "active" : ""}
              aria-pressed={selectedMode === "full"}
              disabled={!labReady || !full.ready}
              onClick={() => setSelectedMode("full")}
            >
              <strong>五关完整挑战</strong>
              <span>增加 GCG、AutoDAN、AdvPrompter</span>
            </button>
          </div>

          {!labReady && !loading ? (
            <div className="challenge-availability unavailable">
              <CircleAlert size={17} aria-hidden="true" />
              挑战模式不可用
            </div>
          ) : null}
          {labReady && !full.ready && missingFull ? (
            <div className="challenge-availability">
              <CircleAlert size={17} aria-hidden="true" />
              完整挑战缺少：{missingFull}
            </div>
          ) : null}

          {session.phase === "setup" ? (
            <button className="challenge-begin-button" type="button" disabled={!canBegin} onClick={beginChallenge}>
              <Play size={17} aria-hidden="true" />
              进入挑战
            </button>
          ) : (
            <div className="challenge-ready-state" role="status">
              <ShieldCheck size={18} aria-hidden="true" />
              {session.rounds.length} 关调查已装载
            </div>
          )}
        </div>

        <MascotTeam phase={session.phase} replayStageId={null} evidenceConflict={false} />
      </section>
    </main>
  );
}
