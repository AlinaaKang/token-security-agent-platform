import {
  Activity,
  ArrowRight,
  BookOpenCheck,
  CheckCircle2,
  CircleAlert,
  FileLock2,
  FlaskConical,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { useEffect, useState } from "react";
import type { FormEvent } from "react";

import { api } from "../api";
import { LabModeSwitch } from "../components/LabModeSwitch";
import { LabSignalChart } from "../components/LabSignalChart";
import { LabToolCenter } from "../components/LabToolCenter";
import type {
  Decision,
  HealthResponse,
  LabCounterfactualInterpretation,
  LabMetrics,
  LabRunResult,
  LabScenario,
  KnowledgePublisher,
  Mode,
  RiskDomain,
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

const publisherLabels: Record<KnowledgePublisher, string> = {
  owasp: "OWASP",
  mitre: "MITRE",
  nist: "NIST",
  cac: "国家网信办",
};

const riskDomainLabels: Record<RiskDomain, string> = {
  prompt_injection: "提示词注入",
  jailbreak: "越狱攻击",
  sensitive_information: "敏感信息",
  excessive_agency: "过度代理权限",
  supply_chain: "供应链",
  data_model_poisoning: "数据与模型投毒",
  unbounded_resource_consumption: "无界资源消耗",
  governance: "治理与合规",
  incident_response: "事件响应",
};

function publisherLabel(value: string) {
  return publisherLabels[value as KnowledgePublisher] ?? "官方来源";
}

function riskDomainLabel(value: string) {
  return riskDomainLabels[value as RiskDomain] ?? "其他风险";
}

type LabTab = "evidence" | "counterfactual" | "tools";

const lastRunStorageKey = "token-security-lab-run-id";

function readLastRunId(): string | null {
  try {
    return window.sessionStorage.getItem(lastRunStorageKey);
  } catch {
    return null;
  }
}

function rememberLastRunId(runId: string | null) {
  try {
    if (runId) window.sessionStorage.setItem(lastRunStorageKey, runId);
    else window.sessionStorage.removeItem(lastRunStorageKey);
  } catch {
    // Session storage is optional; the live run remains usable without it.
  }
}

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
            <span>{publisherLabel(item.source.publisher)}</span>
            <a href={item.source.url} target="_blank" rel="noreferrer">{item.source.title}</a>
            <ArrowRight size={14} />
            <span>{riskDomainLabel(item.risk_domain)}</span>
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
        <div className="lab-simulation-notice"><ShieldAlert size={15} /> 案件报告为脱敏记录，不代表平台外部状态</div>
      </section>
    </>
  );
}

function MetricsPanel({ metrics }: { metrics: LabMetrics }) {
  const percent = (value: number) => `${(value * 100).toFixed(0)}%`;
  return (
    <section className="lab-band lab-metrics-band" aria-label="实验舱运行指标">
      <div className="lab-section-heading">
        <div><Activity size={17} /><strong>实验舱运行指标</strong></div>
        <span>最近 {metrics.run_count} 次脱敏运行</span>
      </div>
      <div className="lab-metrics-grid">
        <div><span>反事实执行覆盖</span><strong>{percent(metrics.counterfactual_execution_rate)}</strong></div>
        <div><span>证据冲突率</span><strong>{percent(metrics.evidence_conflict_rate)}</strong></div>
        <div><span>工具预览成功率</span><strong>{percent(metrics.tool_success_rate)}</strong></div>
        <div>
          <span>已验证执行动作保持率</span>
          <strong>{metrics.action_preservation_rate === null ? "N/A" : percent(metrics.action_preservation_rate)}</strong>
        </div>
        <div><span>运行延迟 P50</span><strong>{metrics.latency_ms.p50.toFixed(1)} ms</strong></div>
        <div><span>运行延迟 P95</span><strong>{metrics.latency_ms.p95.toFixed(1)} ms</strong></div>
      </div>
      <div className="lab-metrics-note">
        <span>这些是运行覆盖与稳定性数据，不是冻结分类性能。</span>
        <span>隐私边界拦截计数：{metrics.privacy_violation_count}</span>
      </div>
    </section>
  );
}

export function LabPage() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [scenarios, setScenarios] = useState<LabScenario[]>([]);
  const [selectedScenario, setSelectedScenario] = useState("custom");
  const [customInput, setCustomInput] = useState("");
  const [mode, setMode] = useState<Mode>("analysis");
  const [run, setRun] = useState<LabRunResult | null>(null);
  const [metrics, setMetrics] = useState<LabMetrics | null>(null);
  const [activeTab, setActiveTab] = useState<LabTab>("evidence");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    api.health().then(async (state) => {
      if (!active) return;
      setHealth(state);
      if (!state.lab?.ready) return;
      const loadScenarios = async () => {
        try {
          const items = await api.labScenarios();
          if (active) setScenarios(items);
        } catch {
          if (active) setError("实验场景加载失败");
        }
      };
      const loadMetrics = async () => {
        try {
          const aggregate = await api.labMetrics();
          if (active) setMetrics(aggregate);
        } catch {
          if (active) setError("实验指标加载失败");
        }
      };
      const restoreLastRun = async () => {
        const lastRunId = readLastRunId();
        if (!lastRunId) return;
        try {
          const restoredRun = await api.getLabRun(lastRunId);
          if (active) {
            setRun(restoredRun);
            setMode(restoredRun.mode);
          }
        } catch {
          rememberLastRunId(null);
        }
      };
      await Promise.all([loadScenarios(), loadMetrics(), restoreLastRun()]);
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
      rememberLastRunId(createdRun.run_id);
      if (selectedScenario === "custom") setCustomInput("");
      api.labMetrics().then(setMetrics).catch(() => undefined);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "调查运行失败");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="page lab-page" aria-label="AI 安全攻防实验舱">
      <header className="page-header">
        <div>
          <LabModeSwitch />
          <h1>AI 安全攻防实验舱</h1>
          <p>按证据顺序调查异常，验证反事实敏感性，并对固定处置工具进行预览与平台内部执行。</p>
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
                ["tools", "工具执行中心"],
              ] as Array<[LabTab, string]>).map(([id, label]) => (
                <button type="button" role="tab" aria-selected={activeTab === id} className={activeTab === id ? "active" : ""} onClick={() => setActiveTab(id)} key={id}>{label}</button>
              ))}
            </div>
            <div className="lab-tab-panel" role="tabpanel">
              {activeTab === "evidence" ? <EvidenceProfile run={run} /> : null}
              {activeTab === "counterfactual" ? <CounterfactualPanel run={run} /> : null}
              <LabToolCenter key={run.run_id} run={run} hidden={activeTab !== "tools"} />
            </div>
          </section>
          <KnowledgeAndReport run={run} />
          {metrics ? <MetricsPanel metrics={metrics} /> : null}
        </>
      )}
    </main>
  );
}
