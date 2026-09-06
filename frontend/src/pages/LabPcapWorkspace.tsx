import { CircleAlert, FileCheck2, HardDriveUpload, LoaderCircle, RotateCcw, ShieldCheck, Upload } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { api } from "../api";
import { PcapDetectionResult } from "../components/PcapDetectionResult";
import type { PcapDetectionMissionResult, PcapMissionStatus, PcapUploadCapability } from "../types";

const TERMINAL = new Set<PcapMissionStatus>(["completed", "cancelled", "degraded"]);
type UploadPhase = "empty" | "selected" | "confirming" | "uploading" | "running" | "terminal" | "error";

const errorMessages: Record<string, string> = {
  pcap_authorization_required: "上传授权无效，请重新确认后再试。",
  pcap_authorization_used: "本次授权已使用，请重新确认后再试。",
  pcap_authorization_expired: "上传授权已过期，请重新确认后再试。",
  pcap_upload_invalid: "文件不完整或长度不一致，请重新选择。",
  pcap_upload_too_large: "文件超过当前允许的上传大小。",
  pcap_format_unsupported: "这不是有效的 PCAP 或 PCAPNG 文件，请重新选择。",
  pcap_upload_unavailable: "本地 PCAP 后端暂不可用，请确认服务和 Docker 已启动。",
  pcap_upload_failed: "上传检测未能启动，请保留文件后重试。",
};

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

export function LabPcapWorkspace() {
  const [capability, setCapability] = useState<PcapUploadCapability | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [phase, setPhase] = useState<UploadPhase>("empty");
  const [progress, setProgress] = useState(0);
  const [mission, setMission] = useState<PcapDetectionMissionResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    let mounted = true;
    api.pcapUploadCapability()
      .then((value) => { if (mounted) setCapability(value); })
      .catch(() => { if (mounted) setCapability({ enabled: false, max_bytes: 0, accepted_formats: ["pcap", "pcapng"] }); });
    return () => { mounted = false; };
  }, []);

  useEffect(() => {
    if (!mission || TERMINAL.has(mission.status)) return;
    let mounted = true;
    let timer: number | undefined;
    const poll = async () => {
      try {
        const next = await api.getPcapMission(mission.detection_id);
        if (!mounted || next.objective !== "detect_pcap_anomalies") return;
        setMission(next);
        if (TERMINAL.has(next.status)) setPhase("terminal");
        else timer = window.setTimeout(poll, 500);
      } catch {
        if (mounted) {
          setError("无法刷新检测状态，系统将在稍后重试。");
          timer = window.setTimeout(poll, 2000);
        }
      }
    };
    timer = window.setTimeout(poll, 300);
    return () => { mounted = false; if (timer !== undefined) window.clearTimeout(timer); };
  }, [mission?.detection_id, mission?.status]);

  function clearSelection() {
    setFile(null);
    if (inputRef.current) inputRef.current.value = "";
  }

  function chooseFile(next: File | null) {
    setError(null);
    if (!next) { clearSelection(); setPhase("empty"); return; }
    const extension = next.name.split(".").pop()?.toLowerCase();
    if (extension !== "pcap" && extension !== "pcapng") {
      clearSelection();
      setPhase("error");
      setError("请选择 .pcap 或 .pcapng 文件。");
      return;
    }
    if (next.size < 1) {
      clearSelection();
      setPhase("error");
      setError("文件为空，请重新选择。");
      return;
    }
    if (capability?.max_bytes && next.size > capability.max_bytes) {
      clearSelection();
      setPhase("error");
      setError("文件超过当前允许的上传大小。");
      return;
    }
    setFile(next);
    setMission(null);
    setProgress(0);
    setPhase("selected");
  }

  async function confirmUpload() {
    if (!file || !capability?.enabled || phase !== "confirming") return;
    setPhase("uploading");
    setProgress(0);
    setError(null);
    try {
      const receipt = await api.authorizePcapUpload(file.size);
      const started = await api.uploadPcapForDetection(file, receipt.authorization_id, setProgress);
      clearSelection();
      setMission(started);
      setProgress(100);
      setPhase(TERMINAL.has(started.status) ? "terminal" : "running");
    } catch (caught) {
      const code = caught instanceof Error ? (caught as Error & { code?: string }).code : undefined;
      if (code === "pcap_format_unsupported") clearSelection();
      setError(errorMessages[code ?? ""] ?? "无法完成上传检测，请重试。");
      setPhase(code === "pcap_format_unsupported" ? "empty" : "error");
    }
  }

  async function cancel() {
    if (!mission || TERMINAL.has(mission.status)) return;
    const next = await api.cancelPcapDetectionMission(mission.detection_id);
    setMission(next);
    if (TERMINAL.has(next.status)) setPhase("terminal");
  }

  const busy = phase === "uploading" || phase === "running";
  const extension = file?.name.split(".").pop()?.toUpperCase();

  return <section className="lab-pcap-workspace" aria-label="PCAP 上传检测" aria-busy={busy}>
    <div className="lab-pcap-readiness"><span className={capability?.enabled ? "is-ready" : ""}>{capability === null ? <LoaderCircle className="spin" size={16} /> : capability.enabled ? <ShieldCheck size={16} /> : <CircleAlert size={16} />}{capability === null ? "正在连接本地 PCAP 后端" : capability.enabled ? "本地 PCAP 后端已就绪" : "本地 PCAP 后端暂不可用"}</span>{capability?.enabled ? <small>单文件上限 {formatBytes(capability.max_bytes)}</small> : null}</div>

    <div className="lab-pcap-upload-band" data-tour="lab-active-input">
      <label className="lab-pcap-drop" htmlFor="lab-pcap-file">
        <Upload size={25} aria-hidden="true" />
        <strong>{file ? "已选择检测样本" : "选择一个 PCAP 文件"}</strong>
        <span>{file ? "内容尚未上传" : "支持 .pcap 与 .pcapng"}</span>
      </label>
      <input ref={inputRef} id="lab-pcap-file" type="file" accept=".pcap,.pcapng,application/vnd.tcpdump.pcap" aria-label="选择 PCAP 文件" onChange={(event) => chooseFile(event.target.files?.[0] ?? null)} disabled={!capability?.enabled || busy} />
      {file ? <div className="lab-pcap-file"><FileCheck2 size={18} /><div><strong>{file.name}</strong><span>{extension} · {formatBytes(file.size)}</span></div><button type="button" aria-label="重新选择文件" title="重新选择文件" onClick={() => inputRef.current?.click()}><RotateCcw size={16} /></button></div> : null}
    </div>

    <div className="lab-pcap-boundary" data-tour="lab-active-boundary"><HardDriveUpload size={18} /><div><strong>检测边界</strong><span>最终确认后，文件会复制到服务器隔离区，并仅在无网络 Docker 容器中解析；原文件名不会发送。</span></div></div>

    {phase === "confirming" ? <div className="lab-pcap-confirm"><ShieldCheck size={19} /><div><strong>确认上传并检测</strong><span>这是唯一会上传文件并启动检测的操作。</span></div><button type="button" onClick={() => setPhase("selected")}>返回</button><button type="button" onClick={confirmUpload}>确认上传并检测</button></div> : null}
    {phase === "uploading" ? <div className="lab-pcap-progress" role="status"><div><span>正在上传隔离副本</span><strong>{progress}%</strong></div><progress value={progress} max="100" /></div> : null}
    {error ? <div className="lab-error" role="alert"><CircleAlert size={17} />{error}</div> : null}
    {phase !== "confirming" && !busy ? <button className="lab-pcap-command" data-tour="lab-active-command" type="button" disabled={!file || !capability?.enabled} onClick={() => setPhase("confirming")}><ShieldCheck size={17} />准备检测</button> : null}
    {mission ? <PcapDetectionResult mission={mission} sampleLabel={() => "上传样本"} onCancel={cancel} busy={false} /> : null}
  </section>;
}
