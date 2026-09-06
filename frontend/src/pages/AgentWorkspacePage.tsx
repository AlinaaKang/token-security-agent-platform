import { Bot, CircleAlert, FileSearch, MessageSquarePlus, Network, RotateCw, ShieldCheck, Sparkles } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { api } from "../api";
import { lastSelectedAgentTaskId, useAgentTask } from "../agent/useAgentTask";
import type { AgentCapabilities, AgentTaskSnapshot } from "../agent/types";
import { AgentAuthorizationDialog } from "../components/AgentAuthorizationDialog";
import { AgentComposer } from "../components/AgentComposer";
import { AgentConversation } from "../components/AgentConversation";
import { AgentPlan } from "../components/AgentPlan";

const terminalStatuses = new Set(["completed", "degraded", "failed", "cancelled"]);
const examples = [
  { label: "调查 PCAP 数据集", value: "调查这批 PCAP，找出异常文件并解释攻击目的", icon: Network },
  { label: "解释 packet 4-4", value: "packet 4-4 是什么？", icon: FileSearch },
  { label: "运行跨域安全演示", value: "运行跨域攻防演示并生成处置报告", icon: Sparkles },
] as const;

export function AgentWorkspacePage() {
  const [activeId, setActiveId] = useState<string | null>(() => lastSelectedAgentTaskId());
  const [snapshot, setSnapshot] = useState<AgentTaskSnapshot | null>(null);
  const [history, setHistory] = useState<AgentTaskSnapshot[]>([]);
  const [capabilities, setCapabilities] = useState<AgentCapabilities | null>(null);
  const [command, setCommand] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [authorizationOpen, setAuthorizationOpen] = useState(false);
  const live = useAgentTask(activeId);
  const task = live.task ?? snapshot;

  useEffect(() => {
    let active = true;
    Promise.allSettled([api.agentCapabilities(), api.listAgentTasks()]).then(([capabilityResult, historyResult]) => {
      if (!active) return;
      if (capabilityResult.status === "fulfilled") setCapabilities(capabilityResult.value);
      else setError("智能体能力状态暂不可用，请检查本地后端。");
      if (historyResult.status === "fulfilled") setHistory(historyResult.value.items);
    });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    if (live.task) setSnapshot(live.task);
  }, [live.task]);

  const progress = useMemo(() => {
    if (!task?.plan.length) return null;
    const finished = task.plan.filter((step) => ["succeeded", "failed", "skipped"].includes(step.status)).length;
    return { finished, total: task.plan.length };
  }, [task]);

  async function submit() {
    const message = command.trim();
    if (!message || busy) return;
    setBusy(true); setError(null);
    try {
      if (task && activeId && /^(取消|停止)(当前)?任务[。！!]?$/u.test(message)) {
        const cancelled = await api.cancelAgentTask(activeId);
        setSnapshot(cancelled); setCommand("");
        return;
      }
      const result = task && activeId
        ? await api.messageAgentTask(activeId, message)
        : await api.createAgentTask(message);
      setSnapshot(result);
      setCommand("");
      setHistory((items) => [result, ...items.filter((item) => item.task_id !== result.task_id)].slice(0, 20));
      if (!terminalStatuses.has(result.status)) setActiveId(result.task_id);
      if (result.status === "awaiting_authorization") setAuthorizationOpen(true);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "安全任务提交失败，请重试。");
    } finally { setBusy(false); }
  }

  async function authorize(scopes: string[]) {
    if (!task) return;
    setBusy(true); setError(null);
    try {
      const result = await api.authorizeAgentTask(task.task_id, scopes);
      setSnapshot(result); setActiveId(result.task_id); setAuthorizationOpen(false);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "授权失败，请核对服务状态后重试。");
    } finally { setBusy(false); }
  }

  function startNew() {
    setActiveId(null); setSnapshot(null); setCommand(""); setError(null); setAuthorizationOpen(false);
  }

  return (
    <main className="agent-workspace-page" aria-label="Token Security 安全智能体">
      <header className="agent-workspace-header">
        <div><span className="agent-workspace-avatar"><Bot size={21} /></span><div><h1>{task?.title ?? "安全智能体"}</h1><p>{task?.objective_summary ?? "描述目标，我会规划、调用工具、观察结果并在授权边界内完成调查。"}</p></div></div>
        <button type="button" onClick={startNew}><MessageSquarePlus size={16} />新建安全任务</button>
      </header>

      {history.length ? <nav className="agent-task-strip" aria-label="最近安全案件">{history.slice(0, 5).map((item) => <button key={item.task_id} type="button" aria-pressed={task?.task_id === item.task_id} onClick={() => { setSnapshot(item); setActiveId(item.task_id); setAuthorizationOpen(item.status === "awaiting_authorization"); }}><span>{item.title}</span><small>{item.status === "running" ? "运行中" : item.status === "completed" ? "已完成" : "待处理"}</small></button>)}</nav> : null}

      <div className="agent-workspace-scroll">
        {!task ? <section className="agent-welcome"><span><ShieldCheck size={24} /></span><h2>从一句安全目标开始</h2><p>我会先公开计划，再请求必要权限。知识问答直接回答，不会触发检测。</p><strong>可以这样开始</strong><div>{examples.map(({ label, value, icon: Icon }) => <button type="button" key={label} aria-label={label} onClick={() => setCommand(value)}><Icon size={17} /><span>{label}</span></button>)}</div></section> : <>
          <AgentConversation messages={task.messages} />
          <AgentPlan steps={task.plan} revision={task.replan_count} />
          {progress ? <section className="agent-progress" aria-label="任务进度"><div><span>{task.status === "running" ? "工具正在执行" : "计划进度"}</span><strong>{progress.finished} / {progress.total}</strong></div><progress max={progress.total} value={progress.finished} /></section> : null}
          {task.limitations.length ? <section className="agent-limitations"><CircleAlert size={17} /><div><strong>结论边界</strong>{task.limitations.map((item) => <p key={item}>{item}</p>)}</div></section> : null}
        </>}
        {(error || live.error) ? <div className="agent-workspace-error" role="alert"><CircleAlert size={16} /><span>{error ?? live.error}</span><button type="button" onClick={() => activeId ? void live.refresh() : void submit()}><RotateCw size={15} />重试</button></div> : null}
      </div>

      <AgentComposer value={command} busy={busy} onChange={setCommand} onSubmit={() => void submit()} onFile={(file) => setCommand(`调查已选择的 PCAP 文件（${file.name}），定位异常并生成报告`)} />
      {authorizationOpen && task ? <AgentAuthorizationDialog task={task} capabilities={capabilities} busy={busy} onCancel={() => setAuthorizationOpen(false)} onConfirm={(scopes) => void authorize(scopes)} /> : null}
    </main>
  );
}
