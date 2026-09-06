import { LockKeyhole, ShieldCheck, X } from "lucide-react";
import { useEffect, useRef } from "react";

import type { AgentCapabilities, AgentTaskSnapshot } from "../agent/types";

type Props = {
  task: AgentTaskSnapshot;
  capabilities: AgentCapabilities | null;
  busy: boolean;
  onCancel: () => void;
  onConfirm: (scopes: string[]) => void;
};

function authorization(task: AgentTaskSnapshot) {
  if (task.task_type === "prompt_investigation") return { title: "授权 Prompt 调查", scopes: ["prompt:analyze"], purpose: "仅对本次提交内容运行现有语义与 Token 检测。" };
  if (task.task_type === "cross_domain_case") return { title: "授权跨域演示", scopes: ["demo:use", "response:execute"], purpose: "读取内置仿真证据并执行平台内部处置演示。" };
  return { title: "授权 PCAP 调查", scopes: ["pcap:read"], purpose: "仅在隔离 Docker 中读取当前授权范围并执行分批检测。" };
}

export function AgentAuthorizationDialog({ task, capabilities, busy, onCancel, onConfirm }: Props) {
  const cancelRef = useRef<HTMLButtonElement>(null);
  const copy = authorization(task);
  useEffect(() => { cancelRef.current?.focus(); }, []);
  return (
    <div className="agent-dialog-layer" role="presentation">
      <section className="agent-authorization-dialog" role="dialog" aria-modal="true" aria-label={copy.title}>
        <header><span><LockKeyhole size={18} /></span><div><h2>{copy.title}</h2><p>智能体只获得下列一次性任务权限。</p></div><button type="button" aria-label="关闭授权" onClick={onCancel}><X size={18} /></button></header>
        <div className="agent-authorization-purpose"><strong>授权用途</strong><p>{copy.purpose}</p></div>
        <dl>
          <div><dt>读取范围</dt><dd>{copy.scopes.join(" + ")}</dd></div>
          <div><dt>执行上限</dt><dd>{task.task_type.includes("pcap") ? `最多每批 ${capabilities?.pcap_batch_size ?? 20} 个文件` : `最多 ${capabilities?.max_plan_steps ?? 12} 个计划步骤`}</dd></div>
          <div><dt>不会保存</dt><dd>原始 Prompt、payload、私人路径、网络身份和凭据</dd></div>
        </dl>
        <footer><button ref={cancelRef} type="button" onClick={onCancel}>暂不授权</button><button type="button" disabled={busy} onClick={() => onConfirm(copy.scopes)}><ShieldCheck size={16} />{busy ? "正在授权" : "授权并开始"}</button></footer>
      </section>
    </div>
  );
}
