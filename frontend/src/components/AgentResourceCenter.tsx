import { BookOpenCheck, Cable, CircleAlert, CircleCheck, FileText, FlaskConical, Workflow } from "lucide-react";

import type { AgentCapabilities, AgentPlaybook } from "../agent/types";

type Props = { resource: string; capabilities: AgentCapabilities | null; playbooks: AgentPlaybook[] };
const stateCopy = {
  available: { label: "真实可用", Icon: CircleCheck },
  simulated: { label: "内置仿真", Icon: FlaskConical },
  degraded: { label: "降级", Icon: CircleAlert },
  unavailable: { label: "未接入", Icon: CircleAlert },
} as const;
const connectorTitles: Record<string, string> = {
  prompt_runtime: "Prompt 语义与 Token 运行时", pcap_docker: "PCAP 隔离 Docker", endpoint_demo: "端点遥测演示",
  identity_demo: "身份行为演示", gateway_log_demo: "网关日志演示", autodl_guard: "AutoDL 语义 Guard", external_edr: "外部 EDR",
};

export function AgentResourceCenter({ resource, capabilities, playbooks }: Props) {
  if (resource === "connectors") return <section className="agent-resource-center" aria-label="数据连接器"><header><Cable size={17} /><div><strong>数据连接器</strong><p>来源状态与真实性由后端声明。</p></div></header><div className="agent-connector-list">{Object.entries(capabilities?.connector_states ?? {}).map(([id, state]) => { const { label, Icon } = stateCopy[state]; return <article key={id}><span><Icon size={15} /></span><div><strong>{connectorTitles[id] ?? id}</strong><small>{id}</small></div><b data-state={state}>{label}</b></article>; })}</div><footer>当前没有任意 URL 接入能力；真实 EDR、防火墙和身份平台尚未连接。</footer></section>;
  if (resource === "knowledge") return <section className="agent-resource-center" aria-label="安全知识库"><header><BookOpenCheck size={17} /><div><strong>安全知识库</strong><p>离线检索只为解释和报告提供引用。</p></div></header><div className="agent-knowledge-sources"><span>OWASP LLM Top 10</span><span>MITRE ATLAS</span><span>ATT&amp;CK 技战术</span><span>本地协议与 PCAP 说明</span></div><footer>知识证据不会越过冻结检测策略直接改变处置结论。</footer></section>;
  if (resource === "reports") return <section className="agent-resource-center" aria-label="调查报告"><header><FileText size={17} /><div><strong>调查报告</strong><p>报告必须引用当前案件的公开证据。</p></div></header><div className="agent-resource-empty">选择案件后，在“报告”页签查看可用交付物。</div></section>;
  return <section className="agent-resource-center" aria-label="检测技能"><header><Workflow size={17} /><div><strong>版本化安全剧本</strong><p>只组合注册工具、授权点和失败回退。</p></div></header><div className="agent-playbook-list">{playbooks.map((item) => <article key={item.playbook_id}><div><strong>{item.title}</strong><p>{item.description}</p></div><span>v{item.version ?? "1.0.0"} · {item.step_count ?? item.steps?.length ?? 0} 个受控步骤</span></article>)}</div><footer>剧本不能创建任意代码节点，也不能扩大工具权限。</footer></section>;
}
