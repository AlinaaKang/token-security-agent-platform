import { BarChart3, BookOpenCheck, CheckCircle2, CircleSlash2, GitCompareArrows, ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";

import { api } from "../api";
import type {
  AblationMethod,
  AblationMethodReport,
  AblationOperatingPoint,
  AgentAblationReport,
  EvaluationSummary,
  HealthResponse,
  MethodSummary,
  OperatingPoint,
  SourceCoverageStatus,
} from "../types";

const methodOrder = ["global_nll", "window_nll", "entropy_cpd"] as const;
const familyOrder = ["gcg", "autodan", "advprompter"] as const;
const ablationMethodOrder: AblationMethod[] = ["semantic_only", "cpd_only", "fusion"];
const ablationPointOrder: AblationOperatingPoint[] = ["production", "fpr_10", "fpr_05"];

const ablationMethodLabels: Record<AblationMethod, string> = {
  semantic_only: "仅语义模型",
  cpd_only: "仅 Entropy-CPD",
  fusion: "融合智能体",
};

const ablationPointLabels: Record<AblationOperatingPoint, string> = {
  production: "生产策略",
  fpr_10: "FPR ≤ 10%",
  fpr_05: "FPR ≤ 5%",
};

function familyLabel(value: string) {
  const labels: Record<string, string> = {
    gcg: "GCG",
    autodan: "AutoDAN",
    advprompter: "AdvPrompter",
    "autodan-hga": "AutoDAN-HGA",
    beast: "BEAST",
  };
  return labels[value.toLowerCase()] ?? value;
}

function percent(value: number) {
  return (value * 100).toFixed(2) + "%";
}

function optionalPercent(value: number | null) {
  return value === null ? "--" : percent(value);
}

function coverageStatusLabel(status: SourceCoverageStatus) {
  if (status === "source_unavailable") return "来源缺口";
  if (status === "unverified") return "待核验";
  return "已核验";
}

function MetricCells({ point }: { point: OperatingPoint }) {
  return (
    <>
      <td className="mono">{point.f1.toFixed(4)}</td>
      <td className="mono">{point.auroc.toFixed(4)}</td>
      <td className="mono">{percent(point.false_positive_rate)}</td>
      <td className="mono">{point.threshold.toFixed(4)}</td>
    </>
  );
}

function FamilyRecall({ method }: { method: MethodSummary }) {
  return (
    <>
      {familyOrder.map((family) => {
        const summary = method.families[family];
        return (
          <td className="mono" key={family}>
            {summary ? percent(summary.operating_points.f1_selected.recall) : "--"}
          </td>
        );
      })}
    </>
  );
}

function AblationRow({ report }: { report: AblationMethodReport }) {
  return (
    <tr>
      <td><strong>{ablationMethodLabels[report.method]}</strong></td>
      <td className="mono">{percent(report.metrics.recall)}</td>
      <td className="mono">{optionalPercent(report.domain_metrics.semantic_unsafe?.recall ?? null)}</td>
      <td className="mono">{optionalPercent(report.domain_metrics.optimized_suffix?.recall ?? null)}</td>
      <td className="mono">{optionalPercent(report.domain_metrics.benign_shift?.false_positive_rate ?? null)}</td>
      <td className="mono">{report.metrics.f1.toFixed(4)}</td>
      <td className="mono">{report.latency.p95_ms.toFixed(1)} ms</td>
      <td className="mono ablation-actions">
        {report.action_counts.allow} / {report.action_counts.review} / {report.action_counts.block}
      </td>
      <td>
        {report.operating_point === "production" ? (
          <span className="constraint-state">不适用</span>
        ) : report.constraint_satisfied ? (
          <span className="constraint-state satisfied">满足</span>
        ) : (
          <span className="constraint-state unsatisfied">约束未满足</span>
        )}
      </td>
    </tr>
  );
}

function AgentAblationSection({ report }: { report: AgentAblationReport }) {
  return (
    <section className="data-section spaced-section ablation-section" aria-labelledby="agent-ablation-title">
      <div className="table-toolbar ablation-toolbar">
        <div>
          <strong id="agent-ablation-title"><GitCompareArrows size={16} /> 智能体冻结消融</strong>
          <small>冻结 test 聚合结果；知识增强不参与判定</small>
        </div>
        <span>{report.benchmark_version} · 完成 {report.completed_count}/{report.requested_count}</span>
      </div>
      <div className="table-scroll ablation-table-scroll">
        <table className="ablation-table">
          <thead>
            <tr>
              <th>检测方法</th>
              <th>总体召回</th>
              <th>语义危险召回</th>
              <th>优化后缀召回</th>
              <th>无害突变 FPR</th>
              <th>F1</th>
              <th>P95 延迟</th>
              <th>放行 / 复核 / 拦截</th>
              <th>Dev 约束状态</th>
            </tr>
          </thead>
          {ablationPointOrder.map((point) => (
            <tbody key={point}>
              <tr className="operating-point-row">
                <th colSpan={9}>{ablationPointLabels[point]}</th>
              </tr>
              {ablationMethodOrder.map((method) => {
                const item = report.methods.find(
                  (candidate) => candidate.method === method && candidate.operating_point === point,
                );
                return item ? <AblationRow key={method} report={item} /> : null;
              })}
            </tbody>
          ))}
        </table>
      </div>
      <div className="ablation-footer">
        <span>来源覆盖</span>
        {Object.entries(report.source_coverage).map(([source, status]) => (
          <strong className={status === "verified" ? "verified" : "gap"} key={source}>
            {familyLabel(source)} · {coverageStatusLabel(status)}
          </strong>
        ))}
        {report.failed_count > 0 && <em>失败请求 {report.failed_count}</em>}
      </div>
    </section>
  );
}

export function EvaluationPage() {
  const [data, setData] = useState<EvaluationSummary | null>(null);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    api.evaluation()
      .then((payload) => { if (active) setData(payload); })
      .catch((caught) => {
        if (active) setError(caught instanceof Error ? caught.message : "评测报告加载失败");
      });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    let active = true;
    api.health().then((payload) => { if (active) setHealth(payload); }).catch(() => undefined);
    return () => { active = false; };
  }, []);

  return (
    <main className="page">
      <header className="page-header">
        <div>
          <h1>评测中心</h1>
          <p>同一冻结测试集上的三方法对照，参数只在校准集与开发集选择。</p>
        </div>
        {data && (
          <span className={"readiness " + (data.deployment_match ? "ready" : "")}>
            {data.deployment_match ? <CheckCircle2 size={15} /> : <CircleSlash2 size={15} />}
            {data.deployment_match ? "部署校准一致" : "部署校准不一致"}
          </span>
        )}
      </header>

      <section className="stat-strip evaluation-stats" aria-label="冻结测试集摘要">
        <div><span>测试样本</span><strong>{data?.counts.total ?? "--"}</strong></div>
        <div><span>攻击样本</span><strong>{data?.counts.attacks ?? "--"}</strong></div>
        <div><span>无害样本</span><strong>{data?.counts.benign ?? "--"}</strong></div>
        <div><span>报告版本</span><strong>{data ? "Schema v" + data.schema_version : "--"}</strong></div>
      </section>

      <section className="data-section">
        <div className="table-toolbar">
          <strong><GitCompareArrows size={16} /> 总体检测能力</strong>
          <span>冻结测试结果</span>
        </div>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th rowSpan={2}>方法</th>
                <th colSpan={4}>F1 最优阈值</th>
                <th colSpan={4}>低误报阈值（开发集选择）</th>
                <th rowSpan={2}>定位能力</th>
              </tr>
              <tr>
                <th>F1</th><th>AUROC</th><th>FPR</th><th>阈值</th>
                <th>F1</th><th>AUROC</th><th>FPR</th><th>阈值</th>
              </tr>
            </thead>
            <tbody>
              {data && methodOrder.map((methodId) => {
                const method = data.methods[methodId];
                return (
                  <tr key={methodId}>
                    <td><strong>{method.display_name}</strong></td>
                    <MetricCells point={method.operating_points.f1_selected} />
                    <MetricCells point={method.operating_points.low_fpr_selected_on_dev} />
                    <td>
                      {method.localization
                        ? "起点 MAE " + method.localization.onset_mae.toFixed(2) + " Token"
                        : "不适用"}
                    </td>
                  </tr>
                );
              })}
              {!data && (
                <tr><td colSpan={10} className={"empty-row " + (error ? "error-state" : "")}>{error ?? "正在加载评测报告"}</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="data-section spaced-section">
        <div className="table-toolbar">
          <strong><BarChart3 size={16} /> 攻击族召回率</strong>
          <span>F1 最优工作点</span>
        </div>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>方法</th>
                <th>GCG</th>
                <th>AutoDAN</th>
                <th>AdvPrompter</th>
              </tr>
            </thead>
            <tbody>
              {data && methodOrder.map((methodId) => (
                <tr key={methodId}>
                  <td><strong>{data.methods[methodId].display_name}</strong></td>
                  <FamilyRecall method={data.methods[methodId]} />
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {data && (
          <div className="scope-note">
            <span>未纳入当前冻结数据</span>
            {data.not_evaluated.map((family) => (
              <strong key={family}>{familyLabel(family)} · 未评测</strong>
            ))}
          </div>
        )}
      </section>

      {data?.agent_ablation && <AgentAblationSection report={data.agent_ablation} />}

      <section className="data-section spaced-section">
        <div className="table-toolbar">
          <strong><BookOpenCheck size={16} /> 知识检索冻结评测</strong>
          <span>仅为冻结工程检索评测</span>
        </div>
        {data?.knowledge ? (
          <div className="knowledge-metrics">
            <div><span>Fixture 数</span><strong>{data.knowledge.case_count}</strong></div>
            <div><span>Hit@3</span><strong>{percent(data.knowledge.hit_at_3)}</strong></div>
            <div><span>MRR</span><strong>{data.knowledge.mrr.toFixed(4)}</strong></div>
            <div><span>引用有效率</span><strong>{percent(data.knowledge.citation_validity)}</strong></div>
            <div><span>动作一致率</span><strong>{percent(data.knowledge.decision_invariance)}</strong></div>
            <div title={data.knowledge.snapshot_hash}>
              <span>快照哈希</span>
              <strong className="mono">{data.knowledge.snapshot_hash.slice(0, 20)}…</strong>
            </div>
          </div>
        ) : (
          <div className="knowledge-evaluation-empty">知识检索评测报告未配置</div>
        )}
      </section>

      <section className="data-section spaced-section">
        <div className="table-toolbar">
          <strong><ShieldCheck size={16} /> Qwen3Guard 功能验收</strong>
          <span>{health?.semantic_guard?.ready ? "模型已就绪" : "模型未就绪"}</span>
        </div>
        <div className="semantic-acceptance">
          <div><span>模型</span><strong>{health?.semantic_guard?.model_id ?? "--"}</strong></div>
          <div><span>版本</span><strong>{health?.semantic_guard?.model_version ?? "--"}</strong></div>
          <div><span>评测边界</span><strong>尚未进行独立冻结语义评测</strong></div>
        </div>
      </section>

      {data && (
        <footer className="provenance-line">
          <span>校准版本 {data.provenance.calibration_version}</span>
          <span title={data.provenance.dataset_hash}>数据集 {data.provenance.dataset_hash.slice(0, 20)}…</span>
        </footer>
      )}
    </main>
  );
}
