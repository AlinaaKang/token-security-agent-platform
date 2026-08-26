import { BarChart3, BookOpenCheck, CheckCircle2, CircleSlash2, GitCompareArrows, ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";

import { api } from "../api";
import type { EvaluationSummary, HealthResponse, MethodSummary, OperatingPoint } from "../types";

const methodOrder = ["global_nll", "window_nll", "entropy_cpd"] as const;
const familyOrder = ["gcg", "autodan", "advprompter"] as const;

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
