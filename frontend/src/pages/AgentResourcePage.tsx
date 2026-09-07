import { ArrowLeft, BookOpenCheck, Cable, FileText, Workflow } from "lucide-react";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { api } from "../api";
import type { AgentConnector, AgentKnowledgeCatalog, AgentPlaybook, AgentReportListItem } from "../agent/types";
import { AgentResourceCenter } from "../components/AgentResourceCenter";

const resourceCopy = {
  skills: { title: "检测技能", description: "查看智能体可调用的版本化安全剧本、受控步骤与授权边界。", Icon: Workflow },
  knowledge: { title: "安全知识库", description: "查看用于安全解释和调查报告引用的离线知识快照。", Icon: BookOpenCheck },
  connectors: { title: "数据连接器", description: "核对数据来源是否真实可用、仿真、降级或尚未接入。", Icon: Cable },
  reports: { title: "调查报告", description: "集中查看已完成安全任务生成的公开调查报告。", Icon: FileText },
} as const;

type ResourceId = keyof typeof resourceCopy;

function normalizeResource(resource: string): ResourceId {
  return resource in resourceCopy ? resource as ResourceId : "skills";
}

export function AgentResourcePage({ resource }: { resource: string }) {
  const resourceId = normalizeResource(resource);
  const copy = resourceCopy[resourceId];
  const [playbooks, setPlaybooks] = useState<AgentPlaybook[]>([]);
  const [connectors, setConnectors] = useState<AgentConnector[]>([]);
  const [knowledge, setKnowledge] = useState<AgentKnowledgeCatalog | null>(null);
  const [reports, setReports] = useState<AgentReportListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError(null);
    const request = resourceId === "connectors" ? api.agentConnectors()
      : resourceId === "knowledge" ? api.agentKnowledge()
      : resourceId === "reports" ? api.agentReports()
      : api.agentPlaybooks();
    request.then((value) => {
      if (!active) return;
      if (resourceId === "connectors") setConnectors(value as AgentConnector[]);
      else if (resourceId === "knowledge") setKnowledge(value as AgentKnowledgeCatalog);
      else if (resourceId === "reports") setReports((value as { items: AgentReportListItem[] }).items);
      else {
        const catalog = value as { version: string; playbooks: AgentPlaybook[] };
        setPlaybooks(catalog.playbooks.map((item) => ({ ...item, version: catalog.version })));
      }
    }).catch((failure: unknown) => {
      if (active) setError(failure instanceof Error ? failure.message : "资源暂不可用，请检查本地后端。");
    }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [resourceId]);

  const Icon = copy.Icon;
  return <main className="agent-resource-page" aria-label={`${copy.title}资源工作区`}>
    <header className="agent-resource-page-header" data-tour="resource-header">
      <div><span><Icon size={21} /></span><div><h1>{copy.title}</h1><p>{copy.description}</p></div></div>
      <Link to="/super-agent?mode=prompt" data-tour="resource-return"><ArrowLeft size={16} />返回安全对话</Link>
    </header>
    <div className="agent-resource-page-scroll">
      <div data-tour="resource-content"><AgentResourceCenter resource={resourceId} loading={loading} error={error} connectors={connectors} knowledge={knowledge} reports={reports} playbooks={playbooks} /></div>
    </div>
  </main>;
}
