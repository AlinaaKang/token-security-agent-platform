import {
  Activity,
  ArrowRight,
  BookOpenCheck,
  CheckCircle2,
  CircleAlert,
  FileLock2,
  FlaskConical,
  Play,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  Wrench,
} from "lucide-react";
import { useEffect, useState } from "react";
import type { FormEvent } from "react";

import { api } from "../api";
import { LabSignalChart } from "../components/LabSignalChart";
import type {
  Decision,
  HealthResponse,
  LabCounterfactualInterpretation,
  LabRunResult,
  LabScenario,
  LabToolId,
  Mode,
} from "../types";


const decisionLabels: Record<Decision, string> = {
  allow: "放行",
  review: "人工复核",
  block: "拦截",
  sanitize_recheck: "净化后复检",
};

const stageLabels = {
  semantic_guard: "语义 Guard",
  token_observation: "Token 观测",
  entropy_cpd: "Entropy-CPD",
  fixed_fusion: "固定融合",
  knowledge_retrieval: "知识检索",
} as const;

const interpretationLabels: Record<LabCounterfactualInterpretation, string> = {
  risk_reduced: "风险降低",
  unchanged: "未见变化",
  inconclusive: "证据不足",
};

const publisherLabels = { owasp: "OWASP", mitre: "MITRE", nist: "NIST" } as const;

type LabTab = "evidence" | "counterfactual" | "tools";

function EvidenceTimeline({ run }: { run: LabRunResult }) {
  return (
    <section className="lab-band lab-evidence-arrival">
      <div className="lab-section-heading">
        <div><Activity size={17} /><strong>证据到达顺序</strong></div>
        <span>按真实调用顺序回放</span>
      </div>
      <ol className="lab-timeline" aria-label="证据到达顺序">
        {run.stages.map((stage, index) => (
          <li className={stage.status === "succeeded" ? "complete" : "unavailable"} key={stage.stage_id}>
            <span className="lab-stage-index">{index + 1}</span>
            <div>
              <strong>{stageLabels[stage.stage_id]}</strong>
              <small>{stage.summary}</small>
            </div>
            <span className="lab-stage-time">
              {stage.latency_ms === null ? "未独立计时" : `${stage.latency_ms.toFixed(1)} ms`}
              {stage.timing_basis === "combined" ? <em>组合计时</em> : null}
            </span>
          </li>
        ))}
      </ol>
    </section>
  );
}

function EvidenceProfile({ run }: { run: LabRunResult }) {
  const detection = run.detection;
  const agreement = detection.semantic_severity === "unsafe" && detection.detector_status === "token_anomaly_candidate";
  const conflict = detection.semantic_severity === "safe" && detection.detector_status === "token_anomaly_candidate";
  return (
    <div className="lab-profile">
      <div className="lab-verdict-strip">
        <div><span>基础动作</span><strong className={`lab-decision-${detection.decision}`}>{decisionLabels[detection.decision]}</strong></div>
        <div><span>语义等级</span><strong>{detection.semantic_severity}</strong></div>
        <div><span>CPD 状态</span><strong>{detection.detector_status === "token_anomaly_candidate" ? "异常候选" : "未告警"}</strong></div>
        <div><span>证据关系</span><strong>{agreement ? "双路一致" : conflict ? "证据冲突" : "双路正常"}</strong></div>
        <div><span>预测起点</span><strong>{detection.suspicious_span ? `T${detection.suspicious_span.token_start}` : "--"}</strong></div>
      </div>
      <div className="lab-chart-band">
        <div className="lab-section-heading">
          <div><ScanSearch size={17} /><strong>Token 证据剖面</strong></div>
          <span>CPD 用于异常定位，不判断语义意图</span>
        </div>
        <LabSignalChart signals={detection.signals} />
      </div>
    </div>
  );
}

function CounterfactualPanel({ run }: { run: LabRunResult }) {
  const result = run.counterfactual;
  return (
    <section className="lab-counterfactual-panel">
      <div className="lab-counterfactual-status">
        {result.interpretation === "risk_reduced" ? <CheckCircle2 size={22} /> : <CircleAlert size={22} />}
        <div>
          <strong>{interpretationLabels[result.interpretation]}</strong>
          <span>预测字符起点 {result.char_start ?? "--"} · {result.calibration_version}</span>
        </div>
      </div>
      <div className="lab-comparison">
        <article>
          <span>原始检测</span>
          <strong>{result.original.risk_score.toFixed(3)}</strong>
          <small>CPD {result.original.detector_score.toFixed(3)} · {decisionLabels[result.original.decision]}</small>
        </article>
        <ArrowRight size={20} aria-hidden="true" />
        <article>
          <span>截断后重检</span>
          <strong>{result.rechecked ? result.rechecked.risk_score.toFixed(3) : "--"}</strong>
          <small>{result.rechecked ? `CPD ${result.rechecked.detector_score.toFixed(3)} · ${decisionLabels[result.rechecked.decision]}` : "未执行有效重检"}</small>
        </article>
      </div>
      <p className="lab-method-note">该结果只表示敏感性，且不会改写基础动作。</p>
    </section>
  );
}

function ToolSandbox({
  run,
  busyTool,
  injectFailure,
  onInjectFailure,
  onRun,
}: {
  run: LabRunResult;
  busyTool: LabToolId | null;
  injectFailure: boolean;
  onInjectFailure: (value: boolean) => void;
  onRun: (toolId: LabToolId) => void;
}) {
  return (
    <section className="lab-tool-panel">
      <div className="lab-tool-toolbar">
        <div><Wrench size={17} /><strong>确定性处置工具</strong></div>
        <label><input type="checkbox" checked={injectFailure} onChange={(event) => onInjectFailure(event.target.checked)} /> 模拟一次工具失败</label>
      </div>
      <div className="lab-tool-list">
        {run.tool_plans.map((plan) => {
          const result = run.tool_results.find((item) => item.tool_id === plan.tool_id);
          return (
            <article key={plan.tool_id}>
              <div>
                <strong>{plan.title}</strong>
                <p>{result?.artifact_summary ?? plan.artifact_summary}</p>
                {result ? (
                  <span className={`lab-tool-result ${result.status}`}>
                    <strong>{result.status === "failed" ? "模拟执行失败" : "模拟执行成功"}</strong>
                    <span>保留动作：{decisionLabels[result.effective_action]}</span>
                  </span>
                ) : <span className="lab-tool-result planned">等待模拟执行</span>}
              </div>
              <button type="button" onClick={() => onRun(plan.tool_id)} disabled={busyTool !== null}>
                <Play size={15} /> {busyTool === plan.tool_id ? "模拟执行中" : `模拟执行${plan.title}`}
              </button>
            </article>
          );
        })}
      </div>
      <p className="lab-method-note">模拟执行不会连接网关、工单系统、文件系统或其他外部服务。</p>
    </section>
  );
}

function KnowledgeAndReport({ run }: { run: LabRunResult }) {
  return (
    <>
      <section className="lab-band lab-knowledge-band" aria-label="知识处置依据">
        <div className="lab-section-heading">
          <div><BookOpenCheck size={17} /><strong>知识处置依据</strong></div>
          <span>{run.detection.knowledge_snapshot_version ?? "知识快照不可用"}</span>
        </div>
        {run.detection.knowledge_evidence.length ? run.detection.knowledge_evidence.map((item) => (
          <div className="lab-knowledge-relation" key={item.knowledge_id}>
            <span>{publisherLabels[item.source.publisher]}</span>
            <a href={item.source.url} target="_blank" rel="noreferrer">{item.source.title}</a>
            <ArrowRight size={14} />
            <span>{item.risk_domain}</span>
            <ArrowRight size={14} />
            <strong>{item.recommendations[0]}</strong>
            <ArrowRight size={14} />
            <span>dry-run</span>
            <code>{item.knowledge_id}</code>
          </div>
        )) : <div className="lab-empty-inline">知识证据不可用，基础检测结果仍然有效。</div>}
      </section>
      <section className="lab-band lab-report-band" aria-label="脱敏案件报告">
        <div className="lab-section-heading">
          <div><FileLock2 size={17} /><strong>脱敏案件报告</strong></div>
          <span>{run.case_report.report_status === "fallback" ? "模板回退" : "确定性报告"}</span>
        </div>
        <p>{run.case_report.summary}</p>
        <dl>
          <div><dt>引用 ID</dt><dd>{run.case_report.evidence_ids.join("、") || "无"}</dd></div>
          <div><dt>处置步骤</dt><dd>{run.case_report.handling_steps.join("；")}</dd></div>
          <div><dt>限制</dt><dd>{run.case_report.limitations.join("；")}</dd></div>
        </dl>
        <div className="lab-simulation-notice"><ShieldAlert size={15} /> 模拟处置，不代表真实外部系统已执行</div>
      </section>
    </>
  );
}

export function LabPage() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [scenarios, setScenarios] = useState<LabScenario[]>([]);
  const [selectedScenario, setSelectedScenario] = useState("custom");
  const [customInput, setCustomInput] = useState("");
  const [mode, setMode] = useState<Mode>("analysis");
  const [run, setRun] = useState<LabRunResult | null>(null);
  const [activeTab, setActiveTab] = useState<LabTab>("evidence");
  const [loading, setLoading] = useState(false);
  const [busyTool, setBusyTool] = useState<LabToolId | null>(null);
  const [injectFailure, setInjectFailure] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    api.health().then(async (state) => {
      if (!active) return;
      setHealth(state);
      if (!state.lab?.ready) return;
      try {
        const items = await api.labScenarios();
        if (active) setScenarios(items);
      } catch (caught) {
        if (active) setError(caught instanceof Error ? caught.message : "实验场景加载失败");
      }
    }).catch(() => {
      if (active) setError("无法连接检测服务");
    });
    return () => { active = false; };
  }, []);

  const labReady = Boolean(health?.lab?.ready);
  const canSubmit = labReady && !loading && (
    selectedScenario === "custom" ? Boolean(customInput.trim()) : Boolean(selectedScenario)
  );

  async function createRun(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canSubmit) return;
    setLoading(true);
    setError(null);
    setRun(null);
    setActiveTab("evidence");
    try {
      const payload = selectedScenario === "custom"
        ? { scenario_kind: "custom" as const, custom_input: customInput, mode }
        : { scenario_kind: "frozen" as const, sample_id: selectedScenario, mode };
      const createdRun = await api.createLabRun(payload);
      setRun(createdRun);
      if (selectedScenario === "custom") setCustomInput("");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "调查运行失败");
    } finally {
      setLoading(false);
    }
  }

  async function runTool(toolId: LabToolId) {
    if (!run || busyTool) return;
    setBusyTool(toolId);
    setError(null);
    try {
      setRun(await api.dryRunLabTool(run.run_id, toolId, injectFailure));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "模拟工具执行失败");
    } finally {
      setBusyTool(null);
    }
  }

  return (
    <main className="page lab-page" aria-label="AI 安全攻防实验舱">
      <header className="page-header">
        <div>
          <h1>AI 安全攻防实验舱</h1>
          <p>按证据顺序调查异常，验证反事实敏感性，并在无外部副作用的沙箱中预演处置。</p>
        </div>
        <span className={`readiness ${labReady ? "ready" : ""}`}>
          <Activity size={15} /> {health === null ? "正在连接" : labReady ? "实验舱已就绪" : "实验舱未启用"}
        </span>
      </header>

      <form className="lab-control-band" onSubmit={createRun}>
        <div className="lab-field lab-scenario-field">
          <label htmlFor="lab-scenario">实验场景</label>
          <select id="lab-scenario" value={selectedScenario} onChange={(event) => setSelectedScenario(event.target.value)} disabled={!labReady}>
            <option value="custom">自定义输入</option>
            {scenarios.map((scenario) => <option value={scenario.scenario_id} key={scenario.scenario_id}>{scenario.label}</option>)}
          </select>
        </div>
        <div className="lab-field lab-input-field">
          <label htmlFor="lab-custom-input">自定义 Prompt</label>
          <textarea
            id="lab-custom-input"
            value={customInput}
            onChange={(event) => setCustomInput(event.target.value)}
            disabled={!labReady || selectedScenario !== "custom"}
            placeholder={selectedScenario === "custom" ? "输入待调查内容" : "受保护场景只发送样本 ID"}
            maxLength={32768}
          />
        </div>
        <div className="lab-mode-field">
          <span>工作模式</span>
          <div className="lab-segmented" role="group" aria-label="实验舱工作模式">
            {(["analysis", "gateway"] as Mode[]).map((item) => (
              <button type="button" key={item} aria-pressed={mode === item} className={mode === item ? "active" : ""} onClick={() => setMode(item)}>
                {item === "analysis" ? "安全分析" : "在线防护"}
              </button>
            ))}
          </div>
        </div>
        <button className="lab-run-button" type="submit" disabled={!canSubmit}>
          <FlaskConical size={17} /> {loading ? "调查运行中" : "开始调查"}
        </button>
      </form>

      {error ? <div className="lab-error"><CircleAlert size={17} />{error}</div> : null}
      {!run ? (
        <section className="lab-empty-state">
          <ShieldCheck size={30} />
          <strong>{labReady ? "选择场景并开始调查" : "实验舱未启用"}</strong>
          <span>{labReady ? "结果不会进入正式事件库" : "基础检测、事件和评测页面不受影响"}</span>
        </section>
      ) : (
        <>
          <EvidenceTimeline run={run} />
          <section className="lab-investigation" aria-label="调查证据工作区">
            <div className="lab-tabs" role="tablist" aria-label="调查视图">
              {([
                ["evidence", "证据剖面"],
                ["counterfactual", "反事实验证"],
                ["tools", "处置沙箱"],
              ] as Array<[LabTab, string]>).map(([id, label]) => (
                <button type="button" role="tab" aria-selected={activeTab === id} className={activeTab === id ? "active" : ""} onClick={() => setActiveTab(id)} key={id}>{label}</button>
              ))}
            </div>
            <div className="lab-tab-panel" role="tabpanel">
              {activeTab === "evidence" ? <EvidenceProfile run={run} /> : null}
              {activeTab === "counterfactual" ? <CounterfactualPanel run={run} /> : null}
              {activeTab === "tools" ? (
                <ToolSandbox
                  run={run}
                  busyTool={busyTool}
                  injectFailure={injectFailure}
                  onInjectFailure={setInjectFailure}
                  onRun={runTool}
                />
              ) : null}
            </div>
          </section>
          <KnowledgeAndReport run={run} />
        </>
      )}
    </main>
  );
}
