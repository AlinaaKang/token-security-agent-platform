import { GitCompareArrows, Scale } from "lucide-react";

import type { AgentHypothesis } from "../agent/types";

function refs(items: string[]) { return items.length ? items.join("、") : "暂缺"; }

export function AgentHypothesisPanel({ hypotheses }: { hypotheses: AgentHypothesis[] }) {
  if (!hypotheses.length) return <div className="agent-inspector-zero"><Scale size={20} /><strong>尚未形成候选假设</strong><p>复杂调查会同时保留攻击假设与正常行为解释。</p></div>;
  return <div className="agent-hypothesis-list">{hypotheses.map((item) => <article key={item.hypothesis_id}>
    <header><div><GitCompareArrows size={14} /><strong>{item.title}</strong></div><span>{Math.round(item.confidence * 100)}%</span></header>
    <div className="agent-confidence-bar"><span style={{ width: `${Math.round(item.confidence * 100)}%` }} /></div>
    <dl><div><dt>支持证据</dt><dd>{refs(item.supporting_evidence_refs)}</dd></div><div><dt>反对证据</dt><dd>{refs(item.opposing_evidence_refs)}</dd></div></dl>
    {item.confidence_changes.length ? <section><strong>置信度变化</strong>{item.confidence_changes.map((change, index) => <div key={`${change.changed_at}-${index}`}><span>{Math.round(change.before * 100)}% → {Math.round(change.after * 100)}%</span><p>{change.reason}</p></div>)}</section> : null}
    {item.limitations.map((limit) => <small key={limit}>{limit}</small>)}
  </article>)}</div>;
}
