import { BarChart3, CircleAlert, FlaskConical, ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";

import { api } from "../api";
import { ResultGuide } from "../components/ResultGuide";
import type { PcapEvaluationSummary } from "../types";

const methodLabels = { rule_only: "仅规则检测", behavior_only: "仅行为检测", fused: "融合检测" } as const;
const percent = (value: number) => `${(value * 100).toFixed(2)}%`;

export function PcapEvaluationPage() {
  const [data, setData] = useState<PcapEvaluationSummary | null>(null);
  const [error, setError] = useState(false);
  useEffect(() => {
    let active = true;
    api.pcapEvaluation().then((result) => { if (active) setData(result); }).catch(() => { if (active) setError(true); });
    return () => { active = false; };
  }, []);

  return <main className="page pcap-evaluation-page" aria-label="PCAP 评测中心">
    <header className="page-header">
      <div><h1>PCAP 评测中心</h1><p>使用固定、脱敏、可复现的回归样本验证检测链路与 Packet 定位能力。</p></div>
      <span className="privacy-mark"><ShieldCheck size={15} /> 冻结脱敏回归</span>
    </header>
    <section className="pcap-evaluation-boundary" data-tour="pcap-evaluation-scope">
      <FlaskConical size={19} aria-hidden="true" />
      <div><strong>结果只适用于当前内置合成回归集</strong><p>它用于验证工程链路和方法差异，不代表真实生产网络的总体准确率。</p></div>
    </section>
    {error ? <section className="pcap-evaluation-unavailable" role="alert"><CircleAlert size={22} /><div><strong>PCAP 评测报告暂不可用</strong><p>请确认后端已加载版本化回归清单，再刷新页面。当前不会用 0% 或 100% 代替缺失结果。</p></div></section> : data ? <>
      <section className="stat-strip pcap-evaluation-stats" aria-label="PCAP 回归指标" data-tour="pcap-evaluation-metrics">
        <div><span>样本数</span><strong>{data.sample_count}</strong></div>
        <div><span>Precision</span><strong>{percent(data.precision)}</strong></div>
        <div><span>Recall</span><strong>{percent(data.recall)}</strong></div>
        <div><span>F1</span><strong>{percent(data.f1)}</strong></div>
        <div><span>误报率</span><strong>{percent(data.false_positive_rate)}</strong></div>
        <div><span>Packet 定位命中率</span><strong>{percent(data.localization_hit_rate)}</strong></div>
      </section>
      <section className="data-section" data-tour="pcap-evaluation-ablation">
        <div className="table-toolbar"><strong><BarChart3 size={16} /> 检测方法消融</strong><span>同一冻结回归集</span></div>
        <div className="table-scroll"><table><thead><tr><th>方法</th><th>Precision</th><th>Recall</th><th>F1</th><th>误报率</th><th>定位命中率</th></tr></thead><tbody>{(["rule_only", "behavior_only", "fused"] as const).map((id) => { const item = data.ablations[id]; return <tr key={id}><td><strong>{methodLabels[id]}</strong></td><td>{percent(item.precision)}</td><td>{percent(item.recall)}</td><td>{percent(item.f1)}</td><td>{percent(item.false_positive_rate)}</td><td>{percent(item.localization_hit_rate)}</td></tr>; })}</tbody></table></div>
      </section>
      <footer className="provenance-line"><span>回归版本 <strong>{data.benchmark_version}</strong></span><span>生成时间 {new Date(data.generated_at).toLocaleString("zh-CN", { hour12: false })}</span></footer>
    </> : <section className="pcap-evaluation-loading" role="status">正在读取 PCAP 回归结果</section>}
    <ResultGuide title="如何理解 PCAP 评测" summary="分类指标回答是否检出，Packet 定位命中率回答是否指出正确证据区间；两者必须分开解读。" items={[{ term: "Precision", explanation: "所有告警中真实异常所占比例。" }, { term: "Recall", explanation: "所有异常中被成功发现的比例。" }, { term: "消融", explanation: "保持数据不变，分别关闭规则或行为分支，用于观察每部分的贡献。" }]} />
  </main>;
}
