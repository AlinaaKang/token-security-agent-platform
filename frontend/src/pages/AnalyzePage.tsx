import {
  Activity,
  BookOpenCheck,
  Database,
  ExternalLink,
  FileText,
  FlaskConical,
  Radar,
  ShieldAlert,
  ShieldCheck,
  GitMerge,
  ScanSearch,
} from "lucide-react";
import { useEffect, useState } from "react";
import type { FormEvent } from "react";

import { api } from "../api";
import type {
  AnalysisResult,
  DemoSample,
  HealthResponse,
  KnowledgeMode,
  KnowledgePublisher,
  Mode,
  SemanticCategory,
  TokenSignal,
} from "../types";

const decisionLabels = {
  allow: "放行",
  review: "人工复核",
  block: "拦截",
  sanitize_recheck: "净化后复检",
} as const;

const semanticLabels = {
  safe: "语义安全",
  controversial: "语义争议",
  unsafe: "语义危险",
  unavailable: "语义检测不可用",
} as const;

const categoryLabels: Record<SemanticCategory, string> = {
  violent: "暴力与武器",
  non_violent_illegal_acts: "非暴力违法行为",
  sexual_content: "性内容",
  pii: "个人敏感信息",
  suicide_self_harm: "自杀与自伤",
  unethical_acts: "不道德行为",
  politically_sensitive: "敏感政治话题",
  copyright_violation: "版权违规",
  jailbreak: "Jailbreak",
};

const fusionLabels = {
  semantic_unsafe: "语义安全策略拦截",
  semantic_controversial: "语义争议，转人工复核",
  cpd_candidate: "Token 异常策略处置",
  all_clear: "双路证据均正常",
  semantic_unavailable_cpd_candidate: "语义不可用，按 Token 异常处置",
  semantic_unavailable_gateway_fail_safe: "语义防线不可用，网关转人工复核",
  semantic_unavailable_analysis_degraded: "语义防线不可用，分析模式降级放行",
} as const;

const detectorLabels = {
  no_token_anomaly: "未发现 Token 异常",
  token_anomaly_candidate: "Token 异常候选",
} as const;

const publisherLabels: Record<KnowledgePublisher, string> = {
  owasp: "OWASP",
  mitre: "MITRE",
  nist: "NIST",
  cac: "国家网信办",
};

function publisherLabel(value: string) {
  return publisherLabels[value as KnowledgePublisher] ?? "官方来源";
}

function KnowledgeModeControl({
  value,
  onChange,
}: {
  value: KnowledgeMode;
  onChange: (mode: KnowledgeMode) => void;
}) {
  const options: Array<{ value: KnowledgeMode; label: string }> = [
    { value: "off", label: "关闭" },
    { value: "evidence", label: "仅证据" },
    { value: "report", label: "证据与报告" },
  ];
  return (
    <div className="knowledge-mode-row">
      <span>知识增强模式</span>
      <div className="segmented-control" role="group" aria-label="知识增强模式">
        {options.map((option) => (
          <button
            type="button"
            key={option.value}
            className={value === option.value ? "active" : ""}
            aria-pressed={value === option.value}
            onClick={() => onChange(option.value)}
          >
            {option.label}
          </button>
        ))}
      </div>
    </div>
  );
}

function KnowledgeBand({ result }: { result: AnalysisResult | null }) {
  const evidence = result?.knowledge_evidence ?? [];
  const report = result?.grounded_report;
  const status = result?.knowledge_status ?? "off";
  const reportLabel = result?.report_status === "generated"
    ? "模型生成报告"
    : result?.report_status === "fallback"
      ? "模板降级报告"
      : result?.report_status === "unavailable"
        ? "报告不可用"
        : null;

  return (
    <section className="knowledge-band" aria-label="本地知识证据">
      <div className="knowledge-band-heading">
        <div>
          <strong><BookOpenCheck size={16} /> 本地知识证据</strong>
          <span>知识证据不改变基础判定</span>
        </div>
        <span>{result?.knowledge_snapshot_version ?? "未加载快照"}</span>
      </div>
      {!result ? (
        <div className="knowledge-empty">完成检测后显示官方知识依据</div>
      ) : status === "unavailable" ? (
        <div className="knowledge-empty error-state">知识库不可用，基础检测结果仍然有效</div>
      ) : status === "degraded" && !evidence.length ? (
        <div className="knowledge-empty">知识增强已降级，基础检测结果未改变</div>
      ) : !evidence.length ? (
        <div className="knowledge-empty">本次检测未启用知识增强</div>
      ) : (
        <>
          <div className="knowledge-list">
            {evidence.map((item) => (
              <article className="knowledge-row" key={item.knowledge_id}>
                <div className="knowledge-source">
                  <span>{publisherLabel(item.source.publisher)}</span>
                  <strong>{item.title_zh}</strong>
                  <a
                    href={item.source.url}
                    target="_blank"
                    rel="noreferrer"
                    aria-label={item.source.title + "（打开官方来源）"}
                  >
                    {item.source.title} <ExternalLink size={13} />
                  </a>
                </div>
                <div className="knowledge-guidance">
                  <p>{item.summary}</p>
                  <ul>
                    {item.recommendations.map((recommendation) => (
                      <li key={recommendation}>{recommendation}</li>
                    ))}
                  </ul>
                </div>
              </article>
            ))}
          </div>
          {report && reportLabel ? (
            <div className="grounded-report">
              <div className="report-title"><FileText size={15} /><strong>{reportLabel}</strong></div>
              <p>{report.summary}</p>
              <dl>
                <div><dt>处置步骤</dt><dd>{report.handling_steps.join("；")}</dd></div>
                <div><dt>引用 ID</dt><dd>{report.evidence_ids.join("、")}</dd></div>
                <div><dt>限制</dt><dd>{report.limitations.join("；")}</dd></div>
              </dl>
            </div>
          ) : null}
        </>
      )}
    </section>
  );
}

function familyLabel(family: string) {
  const labels: Record<string, string> = {
    gcg: "GCG",
    autodan: "AutoDAN",
    advprompter: "AdvPrompter",
  };
  return labels[family.toLowerCase()] ?? family;
}

function tokenRiskClass(risk: number) {
  if (risk >= 0.8) return "token-high";
  if (risk >= 0.5) return "token-review";
  return "token-low";
}

function TokenTrack({
  signals,
  redacted,
}: {
  signals: TokenSignal[];
  redacted: boolean;
}) {
  return (
    <section className="evidence-band" aria-label="Token 风险轨道">
      <div className="pane-heading">
        <span>Token 风险轨道</span>
        <span>Entropy / NLL / CPD</span>
      </div>
      {signals.length ? (
        <div className="token-signals">
          {signals.map((signal) => (
            <span
              className={"token-signal " + tokenRiskClass(signal.risk)}
              key={signal.index}
              title={
                "Token " + signal.index +
                " · Entropy " + signal.entropy.toFixed(3) +
                " · NLL " + signal.nll.toFixed(3) +
                " · CPD " + signal.cpd_entropy.toFixed(3)
              }
            >
              {redacted ? "T" + signal.index : signal.token_text || "T" + signal.index}
            </span>
          ))}
        </div>
      ) : (
        <div className="track-placeholder">提交内容后生成 Token 级证据</div>
      )}
    </section>
  );
}

function ResultPanel({
  result,
  loading,
  error,
}: {
  result: AnalysisResult | null;
  loading: boolean;
  error: string | null;
}) {
  return (
    <section className="decision-pane" aria-live="polite">
      <div className="pane-heading">
        <span>检测结论</span>
        <span className={"status-badge " + (result ? "status-" + result.decision : "")}>
          {loading ? "正在计算" : result ? decisionLabels[result.decision] : "等待检测"}
        </span>
      </div>
      {!result ? (
        <div className={"empty-state " + (error ? "error-state" : "")}>
          {error ? <ShieldAlert size={34} strokeWidth={1.5} /> : <ShieldCheck size={34} strokeWidth={1.5} />}
          <strong>{error ?? (loading ? "正在分析 Token 信号" : "暂无分析结果")}</strong>
        </div>
      ) : (
        <>
          <div className="evidence-chain" aria-label="双检测器融合证据">
            <article className={"evidence-node semantic-" + result.semantic_severity}>
              <h3><ShieldCheck size={15} /> 语义安全</h3>
              <strong>{semanticLabels[result.semantic_severity]}</strong>
              <div className="category-list">
                {result.semantic_categories.length
                  ? result.semantic_categories.map((category) => (
                      <span key={category}>{categoryLabels[category]}</span>
                    ))
                  : <span>未标记危险类别</span>}
              </div>
              <small>{result.semantic_model_version}</small>
            </article>
            <article className="evidence-node">
              <h3><ScanSearch size={15} /> Token 分布</h3>
              <strong>{detectorLabels[result.detector_status]}</strong>
              <span>CPD {result.detector_score.toFixed(3)}</span>
              <small>{result.suspicious_span ? "异常起点 Token " + result.suspicious_span.token_start : "无异常起点"}</small>
            </article>
            <article className={"evidence-node fusion-node status-text-" + result.decision}>
              <h3><GitMerge size={15} /> 融合处置</h3>
              <strong>{decisionLabels[result.decision]}</strong>
              <span>{fusionLabels[result.fusion_reason]}</span>
              <small>固定策略 · 可审计</small>
            </article>
          </div>
          <dl className="result-grid">
            <div><dt>处置动作</dt><dd>{decisionLabels[result.decision]}</dd></div>
            <div><dt>原始检测分数</dt><dd>{result.detector_score.toFixed(3)}</dd></div>
            <div><dt>语义模型</dt><dd>{result.semantic_model_id}</dd></div>
            <div><dt>语义延迟</dt><dd>{result.semantic_latency_ms.toFixed(1)} ms</dd></div>
            <div><dt>异常起点</dt><dd>{result.suspicious_span ? "Token " + result.suspicious_span.token_start : "--"}</dd></div>
            <div><dt>脱敏审计</dt><dd>{result.audit_persisted ? "已写入脱敏审计" : "未写入"}</dd></div>
            <div><dt>检测延迟</dt><dd>{result.latency_ms.toFixed(1)} ms</dd></div>
            <div><dt>校准版本</dt><dd>{result.provenance.calibration_version}</dd></div>
            <div><dt>阈值 k / h</dt><dd>{result.provenance.thresholds.k ?? "--"} / {result.provenance.thresholds.h ?? "--"}</dd></div>
          </dl>
        </>
      )}
    </section>
  );
}

export function AnalyzePage() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [samples, setSamples] = useState<DemoSample[]>([]);
  const [selectedSample, setSelectedSample] = useState("");
  const [prompt, setPrompt] = useState("");
  const [mode, setMode] = useState<Mode>("analysis");
  const [knowledgeMode, setKnowledgeMode] = useState<KnowledgeMode>("off");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [demoResult, setDemoResult] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    Promise.allSettled([api.health(), api.demoSamples()]).then(([healthState, sampleState]) => {
      if (!active) return;
      if (healthState.status === "fulfilled") {
        setHealth(healthState.value);
      } else {
        setError("无法连接检测服务");
      }
      if (sampleState.status === "fulfilled") {
        setSamples(sampleState.value);
        setSelectedSample(sampleState.value[0]?.sample_id ?? "");
      }
    });
    return () => { active = false; };
  }, []);

  const serviceReady = Boolean(health?.model.ready && health.detector.ready);

  async function submitAnalysis(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!serviceReady || !health?.model.model_id || !prompt.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      setResult(await api.analyze(prompt, health.model.model_id, mode, knowledgeMode));
      setDemoResult(false);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "检测请求失败");
    } finally {
      setLoading(false);
    }
  }

  async function runDemo() {
    if (!serviceReady || !selectedSample) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const payload = await api.analyzeDemo(selectedSample);
      setResult(payload.result);
      setDemoResult(true);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "冻结样本检测失败");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="page">
      <header className="page-header">
        <div>
          <h1>安全分析</h1>
          <p>联合语义安全与 Token 分布变化，输出可审计的检测证据和处置动作。</p>
        </div>
        <span className={"readiness " + (serviceReady ? "ready" : "")}>
          <Activity size={15} /> {serviceReady ? "检测服务已连接" : "检测服务待连接"}
        </span>
      </header>

      <div className="workspace-tabs" role="group" aria-label="检测输入来源">
        <span><Radar size={16} /> 自定义输入</span>
        <span><FlaskConical size={16} /> 冻结测试样本</span>
      </div>

      <div className="knowledge-service-state">
        <span className={health?.knowledge?.ready ? "ready" : ""}>
          {health?.knowledge
            ? health.knowledge.ready
              ? `知识库已就绪 · ${health.knowledge.card_count} 条`
              : "知识库不可用"
            : "知识库状态未知"}
        </span>
      </div>

      <section className="analysis-grid" aria-label="安全分析工作区">
        <div className="input-column">
          <form className="prompt-pane" onSubmit={submitAnalysis}>
            <div className="pane-heading">
              <label htmlFor="prompt">Prompt</label>
              <span>{prompt.length.toLocaleString()} / 32,768</span>
            </div>
            <textarea
              id="prompt"
              name="prompt"
              maxLength={32768}
              placeholder="输入待检测内容"
              value={prompt}
              onChange={(event) => setPrompt(event.target.value)}
            />
            <KnowledgeModeControl value={knowledgeMode} onChange={setKnowledgeMode} />
            <div className="form-actions">
              <select aria-label="工作模式" value={mode} onChange={(event) => setMode(event.target.value as Mode)}>
                <option value="analysis">安全分析</option>
                <option value="gateway">在线防护</option>
              </select>
              <button type="submit" disabled={!serviceReady || !prompt.trim() || loading}>
                <Radar size={17} /> {loading ? "检测中" : "开始检测"}
              </button>
            </div>
          </form>

          <div className="demo-control">
            <div>
              <label htmlFor="demo-sample"><Database size={15} /> 冻结测试样本</label>
              <p>仅传递样本 ID，原文不会进入浏览器或审计库。</p>
            </div>
            <div className="demo-actions">
              <select
                id="demo-sample"
                aria-label="冻结测试样本"
                value={selectedSample}
                onChange={(event) => setSelectedSample(event.target.value)}
                disabled={!samples.length}
              >
                {!samples.length && <option value="">样本服务未就绪</option>}
                {samples.map((sample) => (
                  <option value={sample.sample_id} key={sample.sample_id}>
                    {sample.sample_id} · {familyLabel(sample.family)}
                  </option>
                ))}
              </select>
              <button type="button" className="secondary-button" onClick={runDemo} disabled={!serviceReady || !selectedSample || loading}>
                <FlaskConical size={16} /> 检测样本
              </button>
            </div>
          </div>
        </div>

        <ResultPanel result={result} loading={loading} error={error} />
      </section>

      <TokenTrack signals={result?.signals ?? []} redacted={demoResult} />
      <KnowledgeBand result={result} />
    </main>
  );
}
