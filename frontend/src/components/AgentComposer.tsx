import { ArrowUp, FileArchive, Plus, ShieldQuestion } from "lucide-react";
import { useRef } from "react";
import type { FormEvent } from "react";

type Props = {
  value: string;
  busy: boolean;
  onChange: (value: string) => void;
  onSubmit: () => void;
  onFile?: (file: File) => void;
};

export function AgentComposer({ value, busy, onChange, onSubmit, onFile }: Props) {
  const fileRef = useRef<HTMLInputElement>(null);
  function submit(event: FormEvent) { event.preventDefault(); if (value.trim() && !busy) onSubmit(); }
  return (
    <form className="agent-composer" onSubmit={submit}>
      <label htmlFor="agent-command">向安全智能体描述目标</label>
      <textarea id="agent-command" aria-label="安全任务" value={value} onChange={(event) => onChange(event.target.value)} placeholder="例如：调查这批 PCAP，找出异常文件并解释攻击目的" rows={3} onKeyDown={(event) => { if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); if (value.trim() && !busy) onSubmit(); } }} />
      <div className="agent-composer-actions">
        <input ref={fileRef} className="agent-visually-hidden" type="file" accept=".pcap,.pcapng" aria-label="选择 PCAP 文件" onChange={(event) => { const file = event.target.files?.[0]; if (file) onFile?.(file); }} />
        <button type="button" className="agent-icon-button" aria-label="添加 PCAP" title="添加 PCAP" onClick={() => fileRef.current?.click()}><Plus size={17} /></button>
        <span><FileArchive size={14} />PCAP 读取需另行授权</span>
        <span><ShieldQuestion size={14} />支持安全知识问答</span>
        <button type="submit" className="agent-send-button" aria-label="发送" title="发送" disabled={!value.trim() || busy}><ArrowUp size={18} /></button>
      </div>
    </form>
  );
}
