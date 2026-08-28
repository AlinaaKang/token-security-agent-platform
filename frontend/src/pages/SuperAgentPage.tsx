import {
  Activity,
  BrainCircuit,
  CheckCircle2,
  CircleAlert,
  FileCheck2,
  Play,
  Radar,
  RotateCw,
  ShieldCheck,
  UserRoundCog,
  Workflow,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { FormEvent } from "react";

import { api } from "../api";
import type {
  Decision,
  LabScenario,
  LabToolId,
  Mode,
  SuperAgentActor,
  SuperAgentCapabilities,
  SuperAgentFinalStatus,
  SuperAgentMissionResult,
  SuperAgentTraceEvent,
  SuperAgentTracePhase,
} from "../types";

const actorLabels: Record<SuperAgentActor, string> = {
  coordinator: "任务协调员",
  semantic_analyst: "语义分析员",
  token_analyst: "曲线分析员",
  knowledge_analyst: "知识分析员",
  response_operator: "响应执行员",
};

const actorIcons = {
  coordinator: Workflow,
  semantic_analyst: BrainCircuit,
  token_analyst: Radar,
  knowledge_analyst: FileCheck2,
  response_operator: UserRoundCog,
} as const;

const phaseLabels: Record<SuperAgentTracePhase, string> = {
  plan: "PLAN",
  act: "ACT",
  observe: "OBSERVE",
  replan: "REPLAN",
  complete: "COMPLETE",
};

const statusLabels: Record<SuperAgentFinalStatus, string> = {
  closed_safe: "安全闭环",
  contained: "已完成内部遏制",
  review_required: "等待人工复核",
  degraded: "降级收口",
};

const actionLabels: Record<Decision, string> = {
  allow: "放行",
  review: "人工复核",
  block: "拦截",
  sanitize_recheck: "净化后复检",
};

const toolLabels: Record<LabToolId, string> = {
  gateway_enforcement: "内部网关状态",
  security_case: "脱敏安全案件",
  evidence_bundle: "证据归档包",
};

function evidenceLabel(code: string) {
  const knowledgePrefix = "knowledge_id:";
  if (code.startsWith(knowledgePrefix)) return code.slice(knowledgePrefix.length);
  return code;
}

function latestEventFor(actor: SuperAgentActor, events: SuperAgentTraceEvent[]) {
  return [...events].reverse().find((event) => event.actor === actor);
}

function RoleBoard({ mission, capabilities }: { mission: SuperAgentMissionResult | null; capabilities: SuperAgentCapabilities }) {
  return (
    <section className="superagent-role-board" aria-label="智能体角色状态">
      <div className="superagent-section-heading">
        <div><UserRoundCog size={17} /><strong>协作角色</strong></div>
        <span>固定职责 · 最小权限</span>
      </div>
      <div className="superagent-role-list">
        {capabilities.actors.map((actor) => {
          const Icon = actorIcons[actor];
          const event = mission ? latestEventFor(actor, mission.events) : undefined;
          return (
            <article key={actor} className={event ? `is-${event.status}` : "is-waiting"}>
              <span className="superagent-role-icon"><Icon size={18} /></span>
              <div>
                <strong>{actorLabels[actor]}</strong>
                <small>{event ? `最近回报 · ${phaseLabels[event.phase]}` : "等待任务"}</small>
              </div>
              <span className="superagent-role-state">{event ? "已回报" : "待命"}</span>
            </article>
          );
        })}
      </div>
    </section>
  );
}

function MissionTrace({ mission }: { mission: SuperAgentMissionResult }) {
  return (
    <section className="superagent-trace" aria-label="自主任务轨迹">
      <div className="superagent-section-heading">
        <div><Activity size={17} /><strong>命令轨道</strong></div>
        <span>{mission.events.length} / 12 条公开审计事件</span>
      </div>
      <ol>
        {mission.events.map((event) => (
          <li key={event.sequence} className={`phase-${event.phase} status-${event.status}`}>
            <div className="superagent-track-marker"><span>{event.sequence}</span></div>
            <div className="superagent-event-body">
              <div className="superagent-event-meta">
                <strong>{phaseLabels[event.phase]}</strong>
                <span>{actorLabels[event.actor]}</span>
              </div>
              <p>{event.summary}</p>
              {event.evidence_codes.length ? (
                <div className="superagent-evidence-codes">
                  {event.evidence_codes.map((code) => <code key={code}>{evidenceLabel(code)}</code>)}
                </div>
              ) : null}
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}

function ClosurePanel({ mission }: { mission: SuperAgentMissionResult }) {
  const safe = mission.final_status === "closed_safe";
  return (
    <section className={`superagent-closure is-${mission.final_status}`} aria-label="任务收口">
      <div className="superagent-section-heading">
        <div>{safe ? <ShieldCheck size={17} /> : <CheckCircle2 size={17} />}<strong>闭环结果</strong></div>
        <span>{statusLabels[mission.final_status]}</span>
      </div>
      <div className="superagent-closure-summary">
        <div><span>基础动作</span><strong>{actionLabels[mission.base_action]}</strong></div>
        <div><span>最终状态</span><strong>{statusLabels[mission.final_status]}</strong></div>
        <div><span>任务 ID</span><code>{mission.mission_id}</code></div>
      </div>
      <div className="superagent-receipts">
        <div className="superagent-receipt-heading">
          <strong>内部工具回执</strong>
          <span>{mission.executions.length} / 3 次调用</span>
        </div>
        {mission.executions.length ? mission.executions.map((execution) => (
          <article key={execution.execution_id} className={`is-${execution.status}`}>
            {execution.status === "succeeded" ? <CheckCircle2 size={17} /> : <CircleAlert size={17} />}
            <div><strong>{toolLabels[execution.tool_id]}</strong><small>{actionLabels[execution.effective_action]} · {execution.status === "succeeded" ? "执行成功" : "执行失败"}</small></div>
            <code>{execution.receipt_id ?? execution.execution_id}</code>
          </article>
        )) : <p className="superagent-no-tools">无需执行处置工具</p>}
      </div>
      <div className="superagent-limitations">
        {mission.limitations.map((item) => <span key={item}>{item}</span>)}
      </div>
    </section>
  );
}

export function SuperAgentPage() {
  const [capabilities, setCapabilities] = useState<SuperAgentCapabilities | null>(null);
  const [scenarios, setScenarios] = useState<LabScenario[]>([]);
  const [selectedScenario, setSelectedScenario] = useState("");
  const [mode, setMode] = useState<Mode>("analysis");
  const [mission, setMission] = useState<SuperAgentMissionResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    Promise.allSettled([api.labScenarios(), api.superAgentCapabilities()]).then(([scenarioResult, capabilityResult]) => {
      if (!active) return;
      if (scenarioResult.status === "fulfilled") {
        const readyScenarios = scenarioResult.value.filter((item) => item.ready);
        setScenarios(readyScenarios);
        setSelectedScenario(readyScenarios[0]?.scenario_id ?? "");
      } else setError("任务场景加载失败");
      if (capabilityResult.status === "fulfilled") setCapabilities(capabilityResult.value);
      else setError("SuperAgent 服务不可用");
    });
    return () => { active = false; };
  }, []);

  const canStart = Boolean(capabilities?.ready && selectedScenario && !loading);
  const selected = useMemo(
    () => scenarios.find((item) => item.scenario_id === selectedScenario),
    [scenarios, selectedScenario],
  );

  async function startMission(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canStart) return;
    setLoading(true);
    setError(null);
    setMission(null);
    try {
      const result = await api.createSuperAgentMission({
        objective: "investigate_and_respond",
        scenario_kind: "frozen",
        sample_id: selectedScenario,
        mode,
      });
      setMission(result);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "自主任务执行失败");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="page superagent-page" aria-label="SuperAgent 自主处置工作台">
      <header className="page-header">
        <div>
          <span className="superagent-kicker"><Workflow size={15} /> 平台内部仿真闭环</span>
          <h1>SuperAgent 自主处置工作台</h1>
          <p>按固定权限完成证据观察、一次重规划与内部处置，并输出可审计的结构化轨迹。</p>
        </div>
        <span className={`readiness ${capabilities?.ready ? "ready" : ""}`}>
          <Activity size={15} /> {capabilities ? "自主链路已就绪" : "正在连接"}
        </span>
      </header>

      <form className="superagent-control-band" onSubmit={startMission}>
        <label><span>任务场景</span><select value={selectedScenario} onChange={(event) => setSelectedScenario(event.target.value)} disabled={loading}>
          {scenarios.map((item) => <option key={item.scenario_id} value={item.scenario_id}>{item.label}</option>)}
        </select></label>
        <label><span>工作模式</span><select value={mode} onChange={(event) => setMode(event.target.value as Mode)} disabled={loading}>
          <option value="analysis">安全分析</option><option value="gateway">在线防护</option>
        </select></label>
        <div className="superagent-bounds" aria-label="任务边界">
          <span>最多 {capabilities?.max_tool_calls ?? 3} 次工具调用</span>
          <span>最多 1 次重规划</span>
          <span>{selected?.scenario_kind === "protected" ? "受保护冻结样本" : "合成安全样本"}</span>
        </div>
        <button type="submit" disabled={!canStart} className="superagent-start-button">
          {loading ? <RotateCw className="superagent-spinner" size={17} /> : <Play size={17} />}
          {loading ? "任务执行中" : "启动自主任务"}
        </button>
      </form>

      {error ? <div className="superagent-error" role="alert"><CircleAlert size={16} />{error}</div> : null}

      {capabilities ? (
        <div className="superagent-workspace">
          <RoleBoard mission={mission} capabilities={capabilities} />
          {mission ? <MissionTrace mission={mission} /> : (
            <section className="superagent-empty">
              <Workflow size={30} />
              <strong>命令轨道等待任务</strong>
              <span>选择冻结场景后启动，系统将展示公开审计事件，不展示隐藏思维链。</span>
            </section>
          )}
        </div>
      ) : null}
      {mission ? <ClosurePanel mission={mission} /> : null}
    </main>
  );
}
