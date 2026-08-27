import {
  Activity,
  ArrowRight,
  CheckCircle2,
  CircleAlert,
  Gamepad2,
  Play,
  RotateCcw,
  ShieldCheck,
  Trophy,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { api } from "../api";
import type { ChallengeMode } from "../challenge/definitions";
import { resolveChallenge } from "../challenge/definitions";
import {
  expectedEvidenceRelation,
  scoreChallengeRound,
} from "../challenge/scoring";
import {
  challengeSessionReducer,
  createChallengeSession,
  createChallengeSetup,
} from "../challenge/session";
import type { ChallengeSessionState } from "../challenge/session";
import type {
  EvidenceRelation,
  PlayerDecision,
} from "../challenge/types";
import { ChallengeSignalPicker } from "../components/ChallengeSignalPicker";
import { LabModeSwitch } from "../components/LabModeSwitch";
import { MascotTeam } from "../components/MascotTeam";
import type { Decision, HealthResponse, LabScenario, SemanticSeverity } from "../types";

const FAMILY_LABELS = {
  gcg: "GCG",
  autodan: "AutoDAN",
  advprompter: "AdvPrompter",
} as const;

const EVIDENCE_OPTIONS: Array<{ value: EvidenceRelation; label: string }> = [
  { value: "dual_normal", label: "双路正常" },
  { value: "semantic_only", label: "仅语义风险" },
  { value: "distribution_only", label: "仅分布异常" },
  { value: "dual_risk", label: "双路风险" },
];

const ACTION_OPTIONS: Array<{ value: PlayerDecision; label: string }> = [
  { value: "allow", label: "放行" },
  { value: "review", label: "人工复核" },
  { value: "block", label: "拦截" },
];

const DECISION_LABELS: Record<Decision, string> = {
  allow: "放行",
  review: "人工复核",
  block: "拦截",
  sanitize_recheck: "净化后复检（按复核类计分）",
};

const EVIDENCE_LABELS: Record<EvidenceRelation, string> = {
  dual_normal: "双路正常",
  semantic_only: "仅语义风险",
  distribution_only: "仅分布异常",
  dual_risk: "双路风险",
};

const SEMANTIC_LABELS: Record<SemanticSeverity, string> = {
  safe: "语义安全",
  controversial: "语义争议",
  unsafe: "语义危险",
  unavailable: "语义不可用",
};

const REPLAY_PRESENTATION_MS = 700;

interface DraftAnswer {
  decision: PlayerDecision | null;
  evidenceRelation: EvidenceRelation | null;
  onsetIndex: number | null;
}

const EMPTY_DRAFT: DraftAnswer = {
  decision: null,
  evidenceRelation: null,
  onsetIndex: null,
};

export function ChallengePage() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [scenarios, setScenarios] = useState<LabScenario[]>([]);
  const [selectedMode, setSelectedMode] = useState<ChallengeMode>("speed");
  const [session, setSession] = useState<ChallengeSessionState>(createChallengeSetup);
  const [draft, setDraft] = useState<DraftAnswer>(EMPTY_DRAFT);
  const [replayStageIndex, setReplayStageIndex] = useState<number | null>(null);
  const [replayComplete, setReplayComplete] = useState(false);
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

  useEffect(() => {
    if (session.phase !== "guessing" || replayComplete || replayStageIndex === null) return;
    const stages = session.currentRun?.stages ?? [];
    if (stages.length === 0) {
      setReplayComplete(true);
      setReplayStageIndex(null);
      return;
    }
    const timer = window.setTimeout(() => {
      if (replayStageIndex >= stages.length - 1) {
        setReplayComplete(true);
        setReplayStageIndex(null);
      } else {
        setReplayStageIndex(replayStageIndex + 1);
      }
    }, REPLAY_PRESENTATION_MS);
    return () => window.clearTimeout(timer);
  }, [replayComplete, replayStageIndex, session.currentRun, session.phase]);

  const speed = useMemo(() => resolveChallenge("speed", scenarios), [scenarios]);
  const full = useMemo(() => resolveChallenge("full", scenarios), [scenarios]);
  const selected = selectedMode === "speed" ? speed : full;
  const loading = health === null && !loadFailed;
  const labReady = Boolean(health?.lab?.ready) && !loadFailed;
  const canBegin = labReady && selected.ready && session.phase === "setup";
  const missingFull = full.missingFamilies.map((family) => FAMILY_LABELS[family]).join("、");

  async function executeRound(baseState: ChallengeSessionState) {
    if (baseState.phase !== "ready") return;
    const round = baseState.rounds[baseState.roundIndex];
    if (!round) return;
    setDraft(EMPTY_DRAFT);
    setReplayStageIndex(null);
    setReplayComplete(false);
    setSession(challengeSessionReducer(baseState, { type: "start_round" }));
    try {
      const run = await api.createLabRun({
        scenario_kind: "frozen",
        sample_id: round.scenarioId,
        mode: "analysis",
      });
      setSession((current) => challengeSessionReducer(current, { type: "receive_run", run }));
      setReplayStageIndex(run.stages.length > 0 ? 0 : null);
      setReplayComplete(run.stages.length === 0);
    } catch {
      setReplayStageIndex(null);
      setSession((current) => challengeSessionReducer(current, { type: "fail_round" }));
    }
  }

  function beginChallenge() {
    if (!canBegin) return;
    const configured = createChallengeSession(selected.rounds);
    setSession(configured);
    void executeRound(configured);
  }

  function submitAnswer() {
    const run = session.currentRun;
    if (!run || draft.decision === null) return;
    const evidenceRequired = expectedEvidenceRelation(run) !== null;
    const onsetSelectable = run.detection.signals.length >= 2;
    if (evidenceRequired && draft.evidenceRelation === null) return;
    if (run.detection.suspicious_span !== null && onsetSelectable && draft.onsetIndex === null) return;
    const answer = {
      decision: draft.decision,
      evidenceRelation: draft.evidenceRelation,
      onsetIndex: draft.onsetIndex,
    };
    const score = scoreChallengeRound(answer, run);
    setSession(challengeSessionReducer(session, { type: "submit_answer", answer, score }));
  }

  function advanceRound() {
    const advanced = challengeSessionReducer(session, { type: "advance" });
    setSession(advanced);
    if (advanced.phase === "ready") void executeRound(advanced);
  }

  function retryRound() {
    const retrying = challengeSessionReducer(session, { type: "retry" });
    setSession(retrying);
    if (retrying.phase === "investigating") {
      const readyState: ChallengeSessionState = { ...retrying, phase: "ready" };
      void executeRound(readyState);
    }
  }

  function exitChallenge() {
    setSession(challengeSessionReducer(session, { type: "exit" }));
    setDraft(EMPTY_DRAFT);
    setReplayStageIndex(null);
    setReplayComplete(false);
  }

  function skipReplay() {
    setReplayComplete(true);
    setReplayStageIndex(null);
  }

  const run = session.currentRun;
  const replaying = session.phase === "guessing" && run !== null && !replayComplete;
  const activeReplayStage = replayStageIndex === null ? null : run?.stages[replayStageIndex] ?? null;
  const evidenceRequired = run ? expectedEvidenceRelation(run) !== null : false;
  const onsetRequired = Boolean(run?.detection.suspicious_span);
  const onsetSelectable = (run?.detection.signals.length ?? 0) >= 2;
  const canSubmit = session.phase === "guessing"
    && draft.decision !== null
    && (!evidenceRequired || draft.evidenceRelation !== null)
    && (!onsetRequired || !onsetSelectable || draft.onsetIndex !== null);

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

      {session.phase === "setup" ? (
        <section className="challenge-setup-layout" aria-label="挑战设置">
          <div className="challenge-setup-panel">
            <div className="challenge-section-title">
              <Gamepad2 size={18} aria-hidden="true" />
              <div><strong>选择挑战</strong><span>分数表示与当前系统结果的一致程度</span></div>
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
                <strong>三关速战</strong><span>无害、格式突变、优化型攻击</span>
              </button>
              <button
                type="button"
                aria-label="五关完整挑战"
                className={selectedMode === "full" ? "active" : ""}
                aria-pressed={selectedMode === "full"}
                disabled={!labReady || !full.ready}
                onClick={() => setSelectedMode("full")}
              >
                <strong>五关完整挑战</strong><span>增加 GCG、AutoDAN、AdvPrompter</span>
              </button>
            </div>
            {!labReady && !loading ? (
              <div className="challenge-availability unavailable"><CircleAlert size={17} aria-hidden="true" />挑战模式不可用</div>
            ) : null}
            {labReady && !full.ready && missingFull ? (
              <div className="challenge-availability"><CircleAlert size={17} aria-hidden="true" />完整挑战缺少：{missingFull}</div>
            ) : null}
            <button className="challenge-begin-button" type="button" disabled={!canBegin} onClick={beginChallenge}>
              <Play size={17} aria-hidden="true" />进入挑战
            </button>
          </div>
          <MascotTeam phase="setup" replayStageId={null} evidenceConflict={false} />
        </section>
      ) : null}

      {session.phase !== "setup" && session.phase !== "complete" ? (
        <>
          <section className="challenge-progress" aria-label="挑战进度">
            <div><span>当前关卡</span><strong>{session.roundIndex + 1} / {session.rounds.length}</strong></div>
            <div><span>场景</span><strong>{session.rounds[session.roundIndex]?.label}</strong></div>
            <div><span>连击</span><strong>{session.combo}</strong></div>
            <div><span>当前总分</span><strong>{session.totalScore}</strong></div>
          </section>
          <MascotTeam
            phase={replaying ? "investigating" : session.phase}
            replayStageId={activeReplayStage?.stage_id ?? (session.phase === "revealed" ? "fixed_fusion" : session.phase === "guessing" ? "entropy_cpd" : "semantic_guard")}
            evidenceConflict={Boolean(run && run.detection.semantic_severity === "safe" && run.detection.detector_status === "token_anomaly_candidate")}
          />
        </>
      ) : null}

      {session.phase === "investigating" ? (
        <section className="challenge-investigating" aria-live="polite">
          <Activity size={22} aria-hidden="true" />
          <strong>调查运行中</strong>
          <span>正在等待脱敏检测结果</span>
        </section>
      ) : null}

      {session.phase === "round_error" ? (
        <section className="challenge-round-error" role="alert">
          <CircleAlert size={20} aria-hidden="true" />
          <div><strong>本关调查失败</strong><span>未记录答案或分数</span></div>
          <button type="button" onClick={retryRound}><RotateCcw size={16} aria-hidden="true" />重试本关</button>
        </section>
      ) : null}

      {replaying && activeReplayStage ? (
        <section className="challenge-stage-replay" aria-label="检测结果回放">
          <div>
            <span>检测结果回放 · {replayStageIndex! + 1} / {run!.stages.length}</span>
            <strong>{activeReplayStage.summary}</strong>
            <small>{activeReplayStage.latency_ms === null ? "服务端耗时不可用" : `${activeReplayStage.latency_ms} ms`}</small>
          </div>
          <button type="button" onClick={skipReplay}>跳过回放</button>
          <p>这是已返回检测结果的界面回放，不代表模型正在实时推理。</p>
        </section>
      ) : null}

      {session.phase === "guessing" && run && replayComplete ? (
        <section className="challenge-round-workspace" aria-label="本关线索">
          <div className="challenge-clue-heading">
            <div><span>Guard 线索</span><strong>{SEMANTIC_LABELS[run.detection.semantic_severity]}</strong></div>
            <div><span>CPD 观测</span><strong>{run.detection.detector_status === "token_anomaly_candidate" ? "发现分布候选" : "未发现分布候选"}</strong></div>
          </div>
          <ChallengeSignalPicker
            signals={run.detection.signals}
            selectedIndex={draft.onsetIndex}
            onSelect={(onsetIndex) => setDraft((current) => ({ ...current, onsetIndex }))}
          />
          <div className="challenge-answer-grid">
            {evidenceRequired ? (
              <fieldset>
                <legend>证据关系</legend>
                <div className="challenge-answer-options">
                  {EVIDENCE_OPTIONS.map((option) => (
                    <button
                      type="button"
                      aria-pressed={draft.evidenceRelation === option.value}
                      className={draft.evidenceRelation === option.value ? "active" : ""}
                      onClick={() => setDraft((current) => ({ ...current, evidenceRelation: option.value }))}
                      key={option.value}
                    >{option.label}</button>
                  ))}
                </div>
              </fieldset>
            ) : (
              <div className="challenge-answer-na">
                <strong>证据关系不适用</strong>
                <span>本关按其余适用项归一化计分</span>
              </div>
            )}
            <fieldset>
              <legend>处置动作</legend>
              <div className="challenge-answer-options challenge-action-options">
                {ACTION_OPTIONS.map((option) => (
                  <button
                    type="button"
                    aria-pressed={draft.decision === option.value}
                    className={draft.decision === option.value ? "active" : ""}
                    onClick={() => setDraft((current) => ({ ...current, decision: option.value }))}
                    key={option.value}
                  >{option.label}</button>
                ))}
              </div>
            </fieldset>
          </div>
          <div className="challenge-onset-status">
            <span>预测起点</span>
            <strong>{onsetRequired
              ? !onsetSelectable
                ? "信号不足，定位按未选择计分"
                : draft.onsetIndex === null ? "请选择曲线位置" : `T${draft.onsetIndex}`
              : "不适用"}</strong>
          </div>
          <button className="challenge-submit-button" type="button" disabled={!canSubmit} onClick={submitAnswer}>
            <ShieldCheck size={17} aria-hidden="true" />提交研判
          </button>
        </section>
      ) : null}

      {session.phase === "revealed" && run && session.currentAnswer && session.currentScore ? (
        <section className="challenge-reveal" aria-label="本关揭晓">
          <div className="challenge-reveal-heading">
            <div><CheckCircle2 size={20} aria-hidden="true" /><strong>研判揭晓</strong></div>
            <div><span>本关百分制分数</span><strong>{session.currentScore.normalizedScore}</strong></div>
          </div>
          <div className="challenge-score-table">
            <div><span>玩家动作</span><strong>{ACTION_OPTIONS.find((item) => item.value === session.currentAnswer?.decision)?.label}</strong></div>
            <div><span>系统原始动作</span><strong>{DECISION_LABELS[run.detection.decision]}</strong></div>
            <div><span>动作得分</span><strong>{session.currentScore.decisionPoints} / 50</strong></div>
            <div><span>玩家证据关系</span><strong>{session.currentAnswer.evidenceRelation ? EVIDENCE_LABELS[session.currentAnswer.evidenceRelation] : "未选择"}</strong></div>
            <div><span>系统证据关系</span><strong>{expectedEvidenceRelation(run) ? EVIDENCE_LABELS[expectedEvidenceRelation(run)!] : "不适用"}</strong></div>
            <div><span>证据得分</span><strong>{expectedEvidenceRelation(run) ? `${session.currentScore.evidencePoints} / 20` : "不适用"}</strong></div>
            <div><span>玩家起点</span><strong>{session.currentAnswer.onsetIndex === null ? "不适用" : `T${session.currentAnswer.onsetIndex}`}</strong></div>
            <div><span>CPD 起点</span><strong>{run.detection.suspicious_span ? `T${run.detection.suspicious_span.token_start}` : "不适用"}</strong></div>
            <div><span>定位得分</span><strong>{run.detection.suspicious_span ? `${session.currentScore.onsetPoints} / 30` : "不适用"}</strong></div>
          </div>
          <div className="challenge-replay-summary">
            <strong>检测结果回放</strong>
            <ol>{run.stages.map((stage) => <li key={stage.stage_id}>{stage.summary}</li>)}</ol>
          </div>
          <div className="challenge-sensitivity">
            <span>反事实敏感性证据</span>
            <strong>{run.counterfactual.interpretation === "risk_reduced" ? "移除预测片段后风险降低" : "结果未显示明确降低"}</strong>
            <small>敏感性结果不构成严格因果证明</small>
          </div>
          <p className="challenge-score-limitation">挑战得分不是检测准确率或攻击覆盖率</p>
          <button className="challenge-next-button" type="button" onClick={advanceRound}>
            {session.roundIndex >= session.rounds.length - 1 ? <Trophy size={17} aria-hidden="true" /> : <ArrowRight size={17} aria-hidden="true" />}
            {session.roundIndex >= session.rounds.length - 1 ? "查看总分" : "下一关"}
          </button>
        </section>
      ) : null}

      {session.phase === "complete" ? (
        <>
          <MascotTeam phase="complete" replayStageId={null} evidenceConflict={false} />
          <section className="challenge-summary" aria-label="挑战总结">
            <Trophy size={34} aria-hidden="true" />
            <span>挑战完成</span>
            <strong>总分 {session.totalScore}</strong>
            <p>共完成 {session.completedScores.length} 关；分数为各关百分制结果的算术平均值。</p>
            <button type="button" onClick={exitChallenge}>退出挑战</button>
          </section>
        </>
      ) : null}
    </main>
  );
}
