import { BookOpenCheck, Cable, CircleAlert, CircleCheck, ExternalLink, FileText, FlaskConical, LoaderCircle, Workflow } from "lucide-react";

import type { AgentConnector, AgentKnowledgeCatalog, AgentPlaybook, AgentReportListItem } from "../agent/types";

type Props = {
  resource: string;
  loading: boolean;
  error: string | null;
  connectors: AgentConnector[];
  knowledge: AgentKnowledgeCatalog | null;
  reports: AgentReportListItem[];
  playbooks: AgentPlaybook[];
};

const stateCopy = {
  available: { label: "真实可用", Icon: CircleCheck },
  simulated: { label: "内置仿真", Icon: FlaskConical },
  degraded: { label: "降级", Icon: CircleAlert },
  unavailable: { label: "未接入", Icon: CircleAlert },
} as const;

function ResourceState({ loading, error, label, empty }: { loading: boolean; error: string | null; label: string; empty: string }) {
  if (loading) return <div className="agent-resource-empty is-loading"><LoaderCircle className="agent-spin" size={18} />正在读取{label}</div>;
  if (error) return <div className="agent-resource-empty is-error" role="alert"><CircleAlert size={18} />{error}</div>;
  return <div className="agent-resource-empty">{empty}</div>;
}

export function AgentResourceCenter({ resource, loading, error, connectors, knowledge, reports, playbooks }: Props) {
  if (resource === "connectors") return <section className="agent-resource-center" aria-label="数据连接器">
    <header><Cable size={17} /><div><strong>数据连接器</strong><p>来源状态与真实性由后端声明。</p></div></header>
    {connectors.length ? <div className="agent-connector-list">{connectors.map((connector) => { const { label, Icon } = stateCopy[connector.state]; return <article key={connector.connector_id}><span><Icon size={15} /></span><div><strong>{connector.title}</strong><small>{connector.connector_id} · {connector.authenticity === "real" ? "真实" : connector.authenticity === "simulated" ? "仿真" : "派生"}</small></div><b data-state={connector.state}>{label}</b></article>; })}</div> : <ResourceState loading={loading} error={error} label="数据连接器" empty="当前没有连接器声明，请检查本地 API 服务。" />}
    <footer>当前没有任意 URL 接入能力；真实 EDR、防火墙和身份平台尚未连接。</footer>
  </section>;

  if (resource === "knowledge") return <section className="agent-resource-center" aria-label="安全知识库">
    <header><BookOpenCheck size={17} /><div><strong>安全知识库</strong><p>{knowledge ? `${knowledge.snapshot_version} · ${knowledge.card_count} 条知识卡片` : "离线检索只为解释和报告提供引用。"}</p></div></header>
    {knowledge?.items.length ? <div className="agent-knowledge-sources">{knowledge.items.map((item) => <article key={item.knowledge_id}><div><strong>{item.title}</strong><small>{item.publisher.toUpperCase()} · {item.version}</small></div><span>{item.risk_domain}</span></article>)}</div> : <ResourceState loading={loading} error={error} label="安全知识库" empty="知识快照中暂时没有可用卡片。" />}
    <footer>知识证据不会越过冻结检测策略直接改变处置结论。</footer>
  </section>;

  if (resource === "reports") return <section className="agent-resource-center" aria-label="调查报告">
    <header><FileText size={17} /><div><strong>调查报告</strong><p>报告必须引用当前案件的公开证据。</p></div></header>
    {reports.length ? <div className="agent-report-list">{reports.map((item) => <article key={item.report_id}><div><strong>{item.title}</strong><small>{item.task_title} · {item.final_status ?? "结论不确定"}</small></div><a href={item.download_url} target="_blank" rel="noreferrer" aria-label={`查看 ${item.title}`}><ExternalLink size={15} /></a></article>)}</div> : <ResourceState loading={loading} error={error} label="调查报告" empty="完成一次 Prompt 或 PCAP 调查后，报告会出现在这里。" />}
  </section>;

  return <section className="agent-resource-center" aria-label="检测技能">
    <header><Workflow size={17} /><div><strong>版本化安全剧本</strong><p>只组合注册工具、授权点和失败回退。</p></div></header>
    {playbooks.length ? <div className="agent-playbook-list">{playbooks.map((item) => <article key={item.playbook_id}><div><strong>{item.title}</strong><p>{item.description}</p></div><span>v{item.version ?? "1.0.0"} · {item.step_count ?? item.steps?.length ?? 0} 个受控步骤</span></article>)}</div> : <ResourceState loading={loading} error={error} label="检测技能" empty="当前没有可用的版本化安全剧本。" />}
    <footer>剧本不能创建任意代码节点，也不能扩大工具权限。</footer>
  </section>;
}
