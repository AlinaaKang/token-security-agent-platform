import { HardDriveUpload, ShieldCheck, X } from "lucide-react";

import { formatPcapFileSize } from "../agent/pcapUpload";

type AgentPcapUploadDialogProps = {
  file: File;
  busy: boolean;
  onCancel: () => void;
  onConfirm: () => void;
};

export function AgentPcapUploadDialog({ file, busy, onCancel, onConfirm }: AgentPcapUploadDialogProps) {
  return <div className="agent-dialog-layer" role="presentation">
    <section className="agent-authorization-dialog agent-pcap-upload-dialog" role="dialog" aria-modal="true" aria-label="确认 PCAP 上传检测">
      <header><div><HardDriveUpload size={18} /><div><strong>确认 PCAP 上传检测</strong><span>确认前文件仍只在当前浏览器中</span></div></div><button type="button" onClick={onCancel} aria-label="关闭"><X size={18} /></button></header>
      <div className="agent-pcap-dialog-file"><strong>{file.name}</strong><span>{formatPcapFileSize(file.size)} · PCAP 内容尚未上传</span></div>
      <dl>
        <div><dt>处理位置</dt><dd>本机隔离检测服务</dd></div>
        <div><dt>隔离边界</dt><dd>无网络、只读根文件系统、非 root Docker</dd></div>
        <div><dt>不会发送</dt><dd>AutoDL、智能体任务库、安全事件与报告</dd></div>
      </dl>
      <p><ShieldCheck size={16} />确认后只为本次文件签发一次性授权，并立即开始检测。</p>
      <footer><button type="button" onClick={onCancel} disabled={busy}>返回</button><button type="button" onClick={onConfirm} disabled={busy}>{busy ? "正在启动" : "确认上传并检测"}</button></footer>
    </section>
  </div>;
}
