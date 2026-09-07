import {
  BarChart3,
  Activity,
  BookOpenCheck,
  Cable,
  ChevronDown,
  ChevronRight,
  FileText,
  FlaskConical,
  Gamepad2,
  MessageSquarePlus,
  MessageSquareText,
  Network,
  ScanLine,
  ShieldCheck,
  Trash2,
  X,
} from "lucide-react";
import { useState } from "react";
import { Link, useLocation } from "react-router-dom";

import { presentAgentTaskStatus } from "../agent/taskPresentation";
import type { AgentTaskSnapshot } from "../agent/types";
import { agentWorkspaceUrl, resolveAgentWorkspaceMode, taskWorkspaceMode, type AgentWorkspaceMode } from "../agent/workspaceMode";

type AgentSidebarProps = {
  className?: string;
  onNavigate?: () => void;
  recentTasks?: AgentTaskSnapshot[];
  activeTaskId?: string | null;
  onDeleteTask?: (taskId: string, mode: AgentWorkspaceMode) => void | Promise<void>;
};

const routeGroups = [
  {
    label: "Prompt 专业工作区",
    items: [
      { to: "/analyze", label: "Prompt 安全分析", icon: ScanLine },
      { to: "/lab?surface=prompt", label: "Prompt 攻防实验", icon: FlaskConical },
      { to: "/evaluation", label: "Prompt 评测中心", icon: BarChart3 },
      { to: "/challenge", label: "Token 侦探挑战", icon: Gamepad2 },
    ],
  },
  {
    label: "PCAP 专业工作区",
    items: [
      { to: "/pcap-profile", label: "PCAP 流量画像", icon: Activity },
      { to: "/lab?surface=pcap", label: "PCAP 攻防实验", icon: FlaskConical },
      { to: "/pcap-evaluation", label: "PCAP 评测中心", icon: BarChart3 },
      { to: "/pcap-challenge", label: "PCAP 侦探挑战", icon: Gamepad2 },
    ],
  },
] as const;

const conversations = [
  { mode: "prompt", label: "Prompt 安全调查", newLabel: "新建 Prompt 对话", icon: MessageSquareText },
  { mode: "pcap", label: "PCAP 数据调查", newLabel: "新建 PCAP 对话", icon: Network },
] as const;

const resources = [
  { query: "knowledge", label: "安全知识库", icon: BookOpenCheck },
  { query: "connectors", label: "数据连接器", icon: Cable },
  { query: "reports", label: "调查报告", icon: FileText },
] as const;

const recentTaskCollapseKey = (mode: AgentWorkspaceMode) => `token-security:recent-tasks-collapsed:${mode}`;

function readRecentTaskCollapse(mode: AgentWorkspaceMode) {
  try {
    return window.localStorage.getItem(recentTaskCollapseKey(mode)) === "true";
  } catch {
    return false;
  }
}

function routeIsActive(pathname: string, search: string, to: string) {
  const [targetPath, targetSearch = ""] = to.split("?");
  if (pathname !== targetPath) return false;
  if (!targetSearch) return true;
  const currentSearch = new URLSearchParams(search);
  if (targetPath === "/lab" && targetSearch === "surface=prompt" && !currentSearch.has("surface")) return true;
  return currentSearch.toString() === targetSearch;
}

export function AgentSidebar({ className = "", onNavigate, recentTasks = [], activeTaskId = null, onDeleteTask }: AgentSidebarProps) {
  const location = useLocation();
  const params = new URLSearchParams(location.search);
  const activeResource = params.get("resource");
  const activeTask = recentTasks.find((task) => task.task_id === activeTaskId);
  const activeMode = resolveAgentWorkspaceMode(location.search, activeTask);
  const [collapsedRecent, setCollapsedRecent] = useState<Record<AgentWorkspaceMode, boolean>>(() => ({
    prompt: readRecentTaskCollapse("prompt"),
    pcap: readRecentTaskCollapse("pcap"),
  }));
  const [pendingDelete, setPendingDelete] = useState<string | null>(null);
  const recentFor = (mode: AgentWorkspaceMode) => recentTasks.filter((task) => taskWorkspaceMode(task) === mode).slice(0, 8);
  const toggleRecent = (mode: AgentWorkspaceMode) => {
    setCollapsedRecent((current) => {
      const collapsed = !current[mode];
      try {
        window.localStorage.setItem(recentTaskCollapseKey(mode), String(collapsed));
      } catch {
        // The in-memory control still works when browser storage is unavailable.
      }
      return { ...current, [mode]: collapsed };
    });
  };

  return (
    <aside className={`sidebar agent-sidebar ${className}`.trim()}>
      <Link className="agent-brand" to={agentWorkspaceUrl("prompt")} onClick={onNavigate} aria-label="Token Security 首页">
        <span className="agent-brand-mark"><ShieldCheck size={21} /></span>
        <span><strong>Token Security</strong><small>自主安全调查</small></span>
      </Link>
      <nav aria-label="主导航">
        <section className="agent-nav-group" role="group" aria-label="安全对话">
          <h2>安全对话</h2>
          <div>{conversations.map(({ mode, label, newLabel, icon: Icon }) => {
            const tasks = recentFor(mode);
            const selected = location.pathname === "/super-agent" && !activeResource && !params.has("entry") && activeMode === mode;
            const titleId = `${mode}-recent-tasks-title`;
            const listId = `${mode}-recent-tasks`;
            const recentLabel = mode === "prompt" ? "Prompt 最近任务" : "PCAP 最近任务";
            const collapsed = collapsedRecent[mode];
            return <div className="agent-nav-entry agent-conversation-entry" key={mode}>
              <Link to={agentWorkspaceUrl(mode)} onClick={onNavigate} className={`agent-conversation-link${selected ? " active" : ""}`} aria-current={selected ? "page" : undefined}><Icon size={17} aria-hidden="true" /><span>{label}</span></Link>
              <Link className="agent-new-conversation" to={agentWorkspaceUrl(mode)} onClick={onNavigate} aria-label={newLabel}><MessageSquarePlus size={14} aria-hidden="true" /><span>新建对话</span></Link>
              {tasks.length ? <><button className="agent-recent-tasks-toggle" id={titleId} type="button" aria-label={`${collapsed ? "展开" : "收起"} ${recentLabel}`} aria-expanded={!collapsed} aria-controls={listId} onClick={() => toggleRecent(mode)}><span>{recentLabel}</span><small>{tasks.length}</small>{collapsed ? <ChevronRight size={13} aria-hidden="true" /> : <ChevronDown size={13} aria-hidden="true" />}</button>{!collapsed ? <ol className="agent-recent-tasks" id={listId} aria-label={recentLabel}>{tasks.map((task) => {
                const presentation = presentAgentTaskStatus(task);
                const deleting = pendingDelete === task.task_id;
                return <li className="agent-recent-task-row" key={task.task_id}>
                  {deleting
                    ? <div className="agent-delete-confirm" role="group" aria-label={`确认删除 ${task.title}`}><span>删除后无法恢复</span><button type="button" aria-label={`取消删除 ${task.title}`} onClick={() => setPendingDelete(null)}><X size={13} /></button><button type="button" aria-label={`确认删除 ${task.title}`} onClick={() => { setPendingDelete(null); void onDeleteTask?.(task.task_id, mode); }}><Trash2 size={13} /></button></div>
                    : <><Link to={agentWorkspaceUrl(mode, task.task_id)} onClick={onNavigate} aria-current={activeTaskId === task.task_id ? "page" : undefined} data-tone={presentation.tone}><span>{task.title}</span><small>{presentation.label}</small></Link><button className="agent-delete-task" type="button" aria-label={`删除 ${task.title}`} title="删除任务" onClick={() => setPendingDelete(task.task_id)}><Trash2 size={14} /></button></>}
                </li>;
              })}</ol> : null}</> : null}
            </div>;
          })}</div>
        </section>

        {routeGroups.map((group) => <section className="agent-nav-group" role="group" aria-label={group.label} key={group.label}>
          <h2>{group.label}</h2>
          <div>{group.items.map(({ to, label, icon: Icon }) => {
            const active = (to === "/analyze" && location.pathname === "/events") || routeIsActive(location.pathname, location.search, to);
            return <Link key={to} to={to} onClick={onNavigate} className={active ? "active" : undefined} aria-current={active ? "page" : undefined}><Icon size={17} aria-hidden="true" /><span>{label}</span></Link>;
          })}</div>
        </section>)}

        <section className="agent-nav-group" role="group" aria-label="智能体资源">
          <h2>智能体资源</h2>
          <div>{resources.map(({ query, label, icon: Icon }) => {
            const active = location.pathname === "/super-agent" && activeResource === query;
            return <Link key={query} to={`/super-agent?resource=${query}`} onClick={onNavigate} className={active ? "active" : undefined} aria-current={active ? "page" : undefined}><Icon size={17} aria-hidden="true" /><span>{label}</span></Link>;
          })}</div>
        </section>
      </nav>
      <div className="agent-runtime-state"><span aria-hidden="true" />本地编排可用</div>
    </aside>
  );
}
