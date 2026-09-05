import { Activity, ArrowRight, BadgeCheck, CircleAlert, FileSearch, KeyRound, LoaderCircle, Network, Play, ShieldCheck, Square } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { api } from "../api";
import type { PcapDetectionMissionResult, PcapLocalizedEvidence, PcapMissionStatus, PcapPurposeCandidate } from "../types";

const TERMINAL = new Set<PcapMissionStatus>(["completed", "cancelled", "degraded"]);
const DETECTION_MISSION_KEY = "token-security-superagent-pcap-detection-id";

const candidateLabels: Record<PcapLocalizedEvidence["attack_candidate"], string> = {
  sql_injection: "SQL 注入候选", command_injection: "命令注入候选", path_traversal: "路径穿越候选", web_injection: "Web 注入候选", none: "未发现攻击候选",
};
const purposeLabels: Record<PcapPurposeCandidate, string> = { auth_bypass: "认证绕过", data_probing: "数据探测", data_extraction: "数据提取", blind_probing: "盲注探测", internal_access: "内部地址访问", script_execution: "脚本执行" };
const failureLabels: Record<string, string> = { tool_failed: "工具失败", tool_timeout: "处理超时", report_invalid: "报告格式无效", capture_invalid: "PCAP 格式无效" };

function DetectionMascots({ mission }: { mission: PcapDetectionMissionResult }) {
  const evidence = mission.summary?.evidence ?? [];
  const first = evidence[0];
  return <section className="pcap-detection-mascots" aria-label="PCAP 检测小队">
    <header><strong>检测小队</strong><span>每位公仔只汇报公开证据</span></header>
    <div className="pcap-detection-mascot-grid">
      <article><ShieldCheck aria-hidden="true" size={22} /><strong>规则侦探</strong><span>{first ? candidateLabels[first.attack_candidate] : "等待规则结果"}</span></article>
      <article><Activity aria-hidden="true" size={22} /><strong>序列侦探</strong><span>{first?.granularity === "request" ? "短请求无需调用 CPD" : "等待序列证据"}</span></article>
      <article><BadgeCheck aria-hidden="true" size={22} /><strong>小队队长</strong><span>{first ? `已锁定 Packet ${first.start_packet}` : "证据不足，不强行报警"}</span></article>
    </div>
  </section>;
}

function DetectionTimeline({ evidence }: { evidence: PcapLocalizedEvidence[] }) {
  if (!evidence.length) return <section className="pcap-detection-empty" aria-label="Packet 时间轴"><Network size={22} /><strong>没有可高亮的异常区间</strong><span>当前样本保留为允许结果。</span></section>;
  return <section className="pcap-detection-timeline" aria-label="Packet 时间轴"><header><strong>Packet 时间轴</strong><span>悬停查看公开序号</span></header><div>{evidence.map((item) => <button key={item.evidence_id} type="button" title={`Packet ${item.start_packet}-${item.end_packet} · ${item.start_offset_ms}ms`}><span>Packet {item.start_packet}-{item.end_packet}</span><b style={{ width: `${Math.max(8, item.confidence * 100)}%` }} /><small>{candidateLabels[item.attack_candidate]}</small></button>)}</div></section>;
}

export function PcapDetectionWorkspace() {
  const [overview, setOverview] = useState<{ enabled: boolean; eligible_file_count: number; max_files: 20 } | null>(null);
  const [mission, setMission] = useState<PcapDetectionMissionResult | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [maxFiles, setMaxFiles] = useState("20");
  const [batchStart, setBatchStart] = useState(0);
  const [activeSample, setActiveSample] = useState(0);
  const sampleRefs = useRef<Record<number, HTMLSpanElement | null>>({});
  useEffect(() => { let active = true; api.pcapDetectionOverview().then((value) => { if (active) { setOverview(value); setBusy(false); } }).catch(() => { if (active) { setError("PCAP 异常检测暂不可用"); setBusy(false); } }); return () => { active = false; }; }, []);
  useEffect(() => {
    if (!mission || TERMINAL.has(mission.status)) return;
    let active = true;
    let timer: number | undefined;
    const poll = async () => {
      try {
        const result = await api.getPcapMission(mission.detection_id);
        if (!active || result.objective !== "detect_pcap_anomalies") return;
        setMission(result);
        if (!TERMINAL.has(result.status)) timer = window.setTimeout(poll, 500);
      } catch {
        if (active) {
          setError("无法刷新异常检测状态，请稍后重试");
          timer = window.setTimeout(poll, 2000);
        }
      }
    };
    timer = window.setTimeout(poll, 300);
    return () => { active = false; if (timer !== undefined) window.clearTimeout(timer); };
  }, [mission?.detection_id, mission?.status]);
  useEffect(() => {
    const samples = mission?.summary?.processed_samples ?? [];
    if (!samples.length) return;
    const latestIndex = samples.length - 1;
    setActiveSample(latestIndex);
    const frame = window.requestAnimationFrame(() => {
      const sample = sampleRefs.current[samples[latestIndex].sample_index];
      if (sample && typeof sample.scrollIntoView === "function") sample.scrollIntoView({ behavior: "smooth", block: "nearest" });
    });
    return () => window.cancelAnimationFrame(frame);
  }, [mission?.detection_id, mission?.summary?.processed_samples?.length]);
  const active = mission && !TERMINAL.has(mission.status);
  const liveSamples = mission?.summary?.processed_samples ?? [];
  const currentSample = active && liveSamples.length ? liveSamples[liveSamples.length - 1] : null;
  const batchOptions = overview ? Array.from({ length: Math.ceil(overview.eligible_file_count / 20) }, (_, index) => index * 20) : [];
  async function start() { if (!overview || !confirming || busy) return; setBusy(true); setError(null); try { const receipt = await api.authorizePcapDetection({ confirmed: true, max_files: Number(maxFiles) }); const result = await api.createPcapDetectionMission({ objective: "detect_pcap_anomalies", authorization_id: receipt.authorization_id, start_index: batchStart }); setMission(result); window.sessionStorage.setItem(DETECTION_MISSION_KEY, result.detection_id); setConfirming(false); } catch { setError("无法启动异常检测，请重试"); } finally { setBusy(false); } }
  async function cancel() { if (!mission || !active || busy) return; setBusy(true); try { const result = await api.cancelPcapDetectionMission(mission.detection_id); setMission(result); } finally { setBusy(false); } }
  return <section className="pcap-detection-workspace" aria-label="PCAP 异常检测工作区" aria-busy={busy}>
    <div className="pcap-detection-authorization"><div><FileSearch size={19} /><strong>{overview ? `可选 PCAP ${overview.eligible_file_count}` : "读取检测目录"}</strong></div><label>检测批次 <select value={batchStart} onChange={(event) => setBatchStart(Number(event.target.value))} disabled={Boolean(active) || busy}>{batchOptions.map((start) => <option key={start} value={start}>样本 {String(start + 1).padStart(2, "0")}–{String(Math.min(start + 20, overview?.eligible_file_count ?? start + 20)).padStart(2, "0")}</option>)}</select></label><label>最多处理 <input type="number" min="1" max="20" value={maxFiles} onChange={(event) => setMaxFiles(event.target.value)} disabled={Boolean(active)} /> 个文件</label>{confirming ? <div className="pcap-detection-confirm"><KeyRound size={18} /><span>仅在确认后进入 Docker 隔离检测</span><button type="button" onClick={() => setConfirming(false)}>返回</button><button type="button" onClick={start} disabled={busy}><ShieldCheck size={14} />确认并开始</button></div> : <button type="button" onClick={() => setConfirming(true)} disabled={!overview?.enabled || Boolean(active) || busy}><Play size={15} />准备异常检测</button>}</div>
    {error ? <div className="superagent-error" role="alert"><CircleAlert size={16} />{error}</div> : null}
    {mission ? <><section className={`pcap-detection-status is-${mission.status}`}><strong>{mission.status === "completed" ? "检测完成" : mission.status === "cancelled" ? "检测已取消" : mission.status === "degraded" ? "检测降级完成" : "检测运行中"}</strong>{currentSample ? <span key={currentSample.sample_index} className="pcap-detection-current">正在检测样本 {String(currentSample.sample_index + batchStart).padStart(2, "0")}</span> : mission.status === "completed" ? <strong>{mission.summary?.evidence.length ? "发现异常证据" : "未发现可定位异常"}</strong> : null}{active ? <button type="button" onClick={cancel} disabled={busy}><Square size={13} />取消</button> : null}</section>{mission.summary?.processed_samples?.length ? <section className="pcap-detection-samples"><strong>已检测样本</strong><div>{mission.summary.processed_samples.map((sample, index) => <span ref={(node) => { sampleRefs.current[sample.sample_index] = node; }} key={sample.sample_index} className={`is-${sample.status}${sample.status === "succeeded" && sample.evidence_count > 0 ? " is-alert" : ""}${index === activeSample ? " is-active" : ""}`}>样本 {String(sample.sample_index + batchStart).padStart(2, "0")} · {sample.status === "succeeded" ? `完成 · 证据 ${sample.evidence_count}` : `失败 · ${failureLabels[sample.failure_code ?? "tool_failed"] ?? "工具失败"}`}</span>)}</div></section> : null}<div className="pcap-detection-findings"><div>{mission.summary ? <p className="pcap-detection-counts" aria-label="检测统计"><span className="is-success">成功 {mission.summary.succeeded_count}</span><span className="is-failed">失败 {mission.summary.failed_count}</span><span className="is-evidence">证据 {mission.summary.evidence.length}</span></p> : null}<strong>局部证据</strong>{mission.summary?.evidence.length ? mission.summary.evidence.map((item) => <article key={item.evidence_id}><span>{candidateLabels[item.attack_candidate]}</span>{item.purpose_candidates?.length ? <b>目的候选：{item.purpose_candidates.map((purpose) => purposeLabels[purpose]).join("、")}</b> : null}<code>{item.evidence_id}</code><small>Packet {item.start_packet}-{item.end_packet} · {item.start_offset_ms}ms · 置信度 {Math.round(item.confidence * 100)}%</small></article>) : <p>证据不足，保持允许。</p>}</div><DetectionTimeline evidence={mission.summary?.evidence ?? []} /></div><DetectionMascots mission={mission} /></> : <div className="pcap-detection-empty"><ArrowRight size={22} /><strong>规则侦探等待授权</strong><span>检测结果只展示局部证据，不恢复原始请求。</span></div>}
  </section>;
}
