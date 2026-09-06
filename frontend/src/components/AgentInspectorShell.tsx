import { Braces, Clock3, FileText, Microscope, PanelRightClose, Scale, Wrench } from "lucide-react";
import { useState } from "react";
import { useEffect } from "react";

import { api } from "../api";
import type { AgentCapabilities, AgentPlaybook, AgentTaskSnapshot } from "../agent/types";
import { AgentAttackTimeline } from "./AgentAttackTimeline";
import { AgentEvidenceInspector } from "./AgentEvidenceInspector";
import { AgentHypothesisPanel } from "./AgentHypothesisPanel";
import { AgentReportInspector } from "./AgentReportInspector";
import { AgentToolInspector } from "./AgentToolInspector";
import { AgentResourceCenter } from "./AgentResourceCenter";

type AgentInspectorShellProps = {
  pathname: string;
  className?: string;
  onClose?: () => void;
  task?: AgentTaskSnapshot | null;
  resource?: string | null;
};

const labels: Record<string, { title: string; context: string }> = {
  "/super-agent": { title: "案件检查器", context: "证据、工具与报告会随当前任务更新" },
  "/analyze": { title: "分析检查器", context: "核对语义、Token 与知识证据" },
  "/events": { title: "事件检查器", context: "查看脱敏审计记录与运行状态" },
  "/evaluation": { title: "评测检查器", context: "核对指标口径、版本与覆盖范围" },
  "/lab": { title: "实验检查器", context: "区分真实检测、内部工具与仿真结果" },
  "/challenge": { title: "挑战检查器", context: "检查选择、证据位置与回合得分" },
};

const tabs = [
  { id: "evidence", label: "证据", Icon: Microscope },
  { id: "hypotheses", label: "假设", Icon: Scale },
  { id: "tools", label: "工具", Icon: Wrench },
  { id: "timeline", label: "时间线", Icon: Clock3 },
  { id: "report", label: "报告", Icon: FileText },
] as const;

export function AgentInspectorShell({ pathname, className = "", onClose, task = null, resource = null }: AgentInspectorShellProps) {
  const copy = labels[pathname] ?? labels["/super-agent"];
  const [tab, setTab] = useState<(typeof tabs)[number]["id"]>("evidence");
  const agentRoute = pathname === "/super-agent";
  const [capabilities, setCapabilities] = useState<AgentCapabilities | null>(null);
  const [playbooks, setPlaybooks] = useState<AgentPlaybook[]>([]);
  useEffect(() => {
    if (!resource) return;
    let active = true;
    Promise.allSettled([api.agentCapabilities(), api.agentPlaybooks()]).then(([capabilityResult, playbookResult]) => {
      if (!active) return;
      if (capabilityResult.status === "fulfilled") setCapabilities(capabilityResult.value);
      if (playbookResult.status === "fulfilled") setPlaybooks(playbookResult.value.playbooks.map((item) => ({ ...item, version: playbookResult.value.version })));
    });
    return () => { active = false; };
  }, [resource]);
  return (
    <aside className={`agent-inspector-shell ${className}`.trim()} aria-label={copy.title}>
      <header>
        <div><Braces size={17} /><strong>{copy.title}</strong></div>
        {onClose ? <button type="button" onClick={onClose} aria-label="关闭检查器"><PanelRightClose size={18} /></button> : null}
      </header>
      {agentRoute && resource ? <AgentResourceCenter resource={resource} capabilities={capabilities} playbooks={playbooks} /> : agentRoute ? <div className="agent-inspector-case">
        <nav aria-label="案件检查器视图">{tabs.map(({ id, label, Icon }) => <button key={id} type="button" aria-label={label} aria-pressed={tab === id} onClick={() => setTab(id)} title={label}><Icon size={16} /></button>)}</nav>
        <div className="agent-inspector-content">
          {tab === "evidence" ? <AgentEvidenceInspector evidence={task?.evidence ?? []} /> : null}
          {tab === "hypotheses" ? <AgentHypothesisPanel hypotheses={task?.hypotheses ?? []} /> : null}
          {tab === "tools" ? <AgentToolInspector plan={task?.plan ?? []} observations={task?.observations ?? []} /> : null}
          {tab === "timeline" ? <AgentAttackTimeline timeline={task?.timeline ?? []} /> : null}
          {tab === "report" ? <AgentReportInspector report={task?.report ?? null} /> : null}
        </div>
      </div> : <div className="agent-inspector-empty"><Microscope size={20} /><strong>等待选择</strong><p>{copy.context}</p></div>}
      <footer><span />公开结构化数据</footer>
    </aside>
  );
}
