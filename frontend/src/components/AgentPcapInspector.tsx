import { Activity, FileText, Network, ScanLine } from "lucide-react";
import { useState } from "react";

import type { PcapDetectionMissionResult, PcapLocalizedEvidence } from "../types";

const tabs = [
  { id: "overview", label: "概况", Icon: Activity },
  { id: "packet", label: "Packet", Icon: ScanLine },
  { id: "parse", label: "解析", Icon: Network },
  { id: "report", label: "报告", Icon: FileText },
] as const;

const attackLabels: Record<PcapLocalizedEvidence["attack_candidate"], string> = {
  sql_injection: "SQL 注入候选", command_injection: "命令注入候选", path_traversal: "路径穿越候选", web_injection: "Web 注入候选", none: "未发现攻击候选",
};
const statusLabels = { queued: "等待执行", running: "检测运行中", completed: "检测完成", cancelled: "检测已取消", degraded: "检测降级完成" } as const;
const actorLabels = { coordinator: "协调器", network_evidence_analyst: "网络证据分析", knowledge_analyst: "知识复核", response_operator: "响应决策" } as const;
const eventLabels = { authorization_accepted: "隔离读取授权已接受", isolated_http_scan_running: "隔离 HTTP 扫描运行中", localized_evidence_validated: "局部证据已验证", deterministic_fusion_ready: "确定性融合已完成" } as const;
const unknownLabels = { no_localized_attack_evidence: "当前规则未取得可定位攻击证据", partial_file_failure: "部分样本处理失败" } as const;
const actionLabels = { allow_no_rule_evidence: "保留未命中结论及覆盖边界", review_localized_requests: "复核已定位的请求或 Packet", retry_failed_files: "重试失败样本" } as const;

function EmptyPcapResult() {
  return <div className="agent-inspector-zero"><Network size={20} /><strong>尚未取得可验证 PCAP 结果</strong><p>启动本机隔离检测后，这里会显示公开 mission 证据；工具失败不能算作未命中。</p></div>;
}

export function AgentPcapInspector({ mission }: { mission: PcapDetectionMissionResult | null }) {
  const [tab, setTab] = useState<(typeof tabs)[number]["id"]>("overview");
  const evidence = mission?.summary?.evidence ?? [];
  return <div className="agent-inspector-case agent-specialized-inspector is-pcap">
    <nav aria-label="PCAP 调查检查器视图">{tabs.map(({ id, label, Icon }) => <button key={id} type="button" aria-label={label} aria-pressed={tab === id} onClick={() => setTab(id)} title={label}><Icon size={15} /><span>{label}</span></button>)}</nav>
    <div className="agent-inspector-content">{!mission ? <EmptyPcapResult /> : <>
      {tab === "overview" ? <section className="agent-pcap-inspector-panel"><strong>{statusLabels[mission.status]}</strong><dl><div><dt>已分析</dt><dd>{mission.summary?.analyzed_count ?? 0}</dd></div><div><dt>成功</dt><dd className="is-success">{mission.summary?.succeeded_count ?? 0}</dd></div><div><dt>失败</dt><dd className="is-review">{mission.summary?.failed_count ?? 0}</dd></div><div><dt>异常证据</dt><dd className={evidence.length ? "is-risk" : ""}>{evidence.length}</dd></div></dl><p>未命中只表示当前可解析范围内未命中规则，不代表文件全部安全。</p></section> : null}
      {tab === "packet" ? <section className="agent-pcap-inspector-list">{evidence.length ? evidence.map((item) => <article key={item.evidence_id}><strong>{attackLabels[item.attack_candidate]}</strong><span>Packet {item.start_packet}-{item.end_packet}</span><small>置信度 {Math.round(item.confidence * 100)}% · {item.granularity}</small><code>{item.evidence_id}</code></article>) : <div className="agent-inspector-zero"><ScanLine size={20} /><strong>没有可定位的异常 Packet</strong><p>当前结果没有可高亮区间；若存在失败样本，结论仍是不完整。</p></div>}</section> : null}
      {tab === "parse" ? <section className="agent-pcap-inspector-list">{mission.events.length ? mission.events.map((event) => <article key={event.sequence}><strong>{actorLabels[event.actor]}</strong><span>{eventLabels[event.summary]}</span><small>{event.status}</small></article>) : <div className="agent-inspector-zero"><Network size={20} /><strong>暂无解析事件</strong><p>任务尚未返回可公开的 Docker 解析步骤。</p></div>}</section> : null}
      {tab === "report" ? <section className="agent-pcap-inspector-panel"><strong>结果边界与建议</strong><h3>未知项</h3><ul>{mission.report.unknowns.length ? mission.report.unknowns.map((item) => <li key={item}>{unknownLabels[item]}</li>) : <li>没有额外未知项</li>}</ul><h3>建议动作</h3><ul>{mission.report.recommended_actions.map((item) => <li key={item}>{actionLabels[item]}</li>)}</ul></section> : null}
    </>}</div>
  </div>;
}
