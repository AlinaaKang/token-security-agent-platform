import { AlertTriangle, CheckCircle2, Clipboard, FileWarning, SearchX } from "lucide-react";

import type { AgentEvidence } from "../agent/types";
import { AuthenticityBadge } from "./AuthenticityBadge";

function outcome(evidence: AgentEvidence) {
  const value = evidence.metadata.outcome;
  if (value === "failed") return { label: "检测失败", className: "failed", Icon: FileWarning };
  if (value === "no_hit") return { label: "当前范围未命中", className: "no-hit", Icon: SearchX };
  if (value === "anomaly") return { label: "发现异常候选", className: "anomaly", Icon: AlertTriangle };
  return { label: "证据已记录", className: "recorded", Icon: CheckCircle2 };
}

export function AgentEvidenceInspector({ evidence }: { evidence: AgentEvidence[] }) {
  if (!evidence.length) return <div className="agent-inspector-zero"><SearchX size={20} /><strong>尚无证据</strong><p>工具开始运行后，公开证据会按来源显示在这里。</p></div>;
  return <div className="agent-evidence-list">{evidence.map((item) => {
    const state = outcome(item);
    const packetRange = typeof item.metadata.packet_range === "string" ? item.metadata.packet_range : null;
    const filter = typeof item.metadata.wireshark_filter === "string" ? item.metadata.wireshark_filter : null;
    const purpose = typeof item.metadata.attack_purpose === "string" ? item.metadata.attack_purpose : null;
    return <article key={item.evidence_id} className={`agent-evidence-item is-${state.className}`}>
      <header><AuthenticityBadge value={item.authenticity} /><span className="agent-evidence-outcome"><state.Icon size={12} />{state.label}</span></header>
      <strong>{item.summary}</strong>
      <dl><div><dt>证据 ID</dt><dd>{item.evidence_id}</dd></div><div><dt>来源</dt><dd>{item.source_type}</dd></div>{packetRange ? <div><dt>数据包范围</dt><dd>{packetRange}</dd></div> : null}</dl>
      {purpose ? <div className="agent-evidence-purpose"><strong>攻击目的候选</strong><p>{purpose}</p><small>这是目的候选，不代表攻击已成功。</small></div> : null}
      {filter ? <div className="agent-public-filter"><span>Wireshark 显示过滤器</span><code>{filter}</code><button type="button" aria-label="复制 Wireshark 过滤器" title="复制 Wireshark 过滤器" onClick={() => void navigator.clipboard?.writeText(filter)}><Clipboard size={14} /></button></div> : null}
      <p className="agent-evidence-uncertainty">{item.uncertainty}</p>
    </article>;
  })}</div>;
}
