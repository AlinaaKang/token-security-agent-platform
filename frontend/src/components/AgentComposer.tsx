import { ArrowUp, FileArchive, Plus, ShieldQuestion, X } from "lucide-react";
import { useRef } from "react";
import type { FormEvent } from "react";

import { formatPcapFileSize } from "../agent/pcapUpload";
import type { PcapUploadCapability } from "../types";

type Props = {
  value: string;
  busy: boolean;
  onChange: (value: string) => void;
  onSubmit: () => void;
  onFile?: (file: File) => void;
  selectedPcap?: File | null;
  pcapCapability?: PcapUploadCapability | null;
  onClearFile?: () => void;
  enablePcap?: boolean;
  placeholder?: string;
};

export function AgentComposer({ value, busy, onChange, onSubmit, onFile, selectedPcap = null, pcapCapability = null, onClearFile, enablePcap = true, placeholder = "例如：描述需要调查的安全问题" }: Props) {
  const fileRef = useRef<HTMLInputElement>(null);
  function submit(event: FormEvent) { event.preventDefault(); if (value.trim() && !busy) onSubmit(); }
  return (
    <form className="agent-composer" onSubmit={submit}>
      <label htmlFor="agent-command">向安全智能体描述目标</label>
      <textarea id="agent-command" aria-label="安全任务" value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder} rows={3} onKeyDown={(event) => { if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); if (value.trim() && !busy) onSubmit(); } }} />
      {selectedPcap ? <div className="agent-composer-file"><FileArchive size={16} /><div><strong>{selectedPcap.name}</strong><span>{formatPcapFileSize(selectedPcap.size)} · 内容尚未上传</span></div><button type="button" onClick={onClearFile} aria-label="移除 PCAP"><X size={15} /></button></div> : null}
      <div className="agent-composer-actions">
        {enablePcap ? <><input ref={fileRef} className="agent-visually-hidden" type="file" accept=".pcap,.pcapng" aria-label="选择 PCAP 文件" onChange={(event) => { const file = event.target.files?.[0]; if (file) onFile?.(file); event.currentTarget.value = ""; }} />
          <button type="button" className="agent-icon-button" aria-label="添加 PCAP" title="添加 PCAP" disabled={busy || pcapCapability?.enabled === false} onClick={() => fileRef.current?.click()}><Plus size={17} /></button>
          <span><FileArchive size={14} />{pcapCapability === null ? "正在连接 PCAP 服务" : pcapCapability.enabled ? "PCAP 读取需另行授权" : "PCAP 服务不可用"}</span></> : null}
        <span><ShieldQuestion size={14} />支持安全知识问答</span>
        <button type="submit" className="agent-send-button" aria-label="发送" title="发送" disabled={!value.trim() || busy}><ArrowUp size={18} /></button>
      </div>
    </form>
  );
}
