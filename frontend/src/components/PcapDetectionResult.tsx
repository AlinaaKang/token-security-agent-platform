import { Network, Square } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import type { PcapDetectionMissionResult, PcapDetectionSummary, PcapLocalizedEvidence, PcapPurposeCandidate } from "../types";

const TERMINAL = new Set(["completed", "cancelled", "degraded"]);
const candidateLabels: Record<PcapLocalizedEvidence["attack_candidate"], string> = { sql_injection: "SQL 注入候选", command_injection: "命令注入候选", path_traversal: "路径穿越候选", web_injection: "Web 注入候选", none: "未发现攻击候选" };
const purposeLabels: Record<PcapPurposeCandidate, string> = { auth_bypass: "认证绕过", data_probing: "数据探测", data_extraction: "数据提取", blind_probing: "盲注探测", internal_access: "内部地址访问", script_execution: "脚本执行" };
const failureLabels: Record<string, string> = { tool_failed: "工具失败", tool_timeout: "处理超时", report_invalid: "报告格式无效", capture_invalid: "PCAP 格式无效" };

function completedConclusion(summary: PcapDetectionSummary | null | undefined) {
  if (summary?.evidence.length) return "发现异常候选";
  if (summary?.failed_count) return "检测不完整，存在未完成样本";
  return "未发现可定位异常";
}

function DetectionTimeline({ evidence, incomplete }: { evidence: PcapLocalizedEvidence[]; incomplete: boolean }) {
  if (!evidence.length) return <section className="pcap-detection-empty" aria-label="Packet 时间轴"><Network size={22} /><strong>没有可高亮的异常区间</strong><span>{incomplete ? "部分样本未完成，请重试失败样本。" : "当前样本保留为允许结果。"}</span></section>;
  return <section className="pcap-detection-timeline" aria-label="Packet 时间轴"><header><strong>Packet 时间轴</strong><span>悬停查看公开序号</span></header><div>{evidence.map((item) => <button key={item.evidence_id} type="button" title={`Packet ${item.start_packet}-${item.end_packet} · ${item.start_offset_ms}ms`}><span>Packet {item.start_packet}-{item.end_packet}</span><b style={{ width: `${Math.max(8, item.confidence * 100)}%` }} /><small>{candidateLabels[item.attack_candidate]}</small></button>)}</div></section>;
}

export interface PcapDetectionResultProps { mission: PcapDetectionMissionResult; sampleLabel: (sampleIndex: number) => string; onCancel?: () => void; busy: boolean; }

export function PcapDetectionResult({ mission, sampleLabel, onCancel, busy }: PcapDetectionResultProps) {
  const [activeSample, setActiveSample] = useState(0);
  const sampleRefs = useRef<Record<number, HTMLSpanElement | null>>({});
  const active = !TERMINAL.has(mission.status);
  const incomplete = Boolean(mission.summary?.failed_count);
  const liveSamples = mission.summary?.processed_samples ?? [];
  const currentSample = active && liveSamples.length ? liveSamples[liveSamples.length - 1] : null;
  useEffect(() => { if (!liveSamples.length) return; const latestIndex = liveSamples.length - 1; setActiveSample(latestIndex); const frame = window.requestAnimationFrame(() => sampleRefs.current[liveSamples[latestIndex].sample_index]?.scrollIntoView?.({ behavior: "smooth", block: "nearest" })); return () => window.cancelAnimationFrame(frame); }, [mission.detection_id, liveSamples.length]);
  return <>
    <section className={`pcap-detection-status is-${mission.status}`}><strong>{mission.status === "completed" ? "检测完成" : mission.status === "cancelled" ? "检测已取消" : mission.status === "degraded" ? "检测降级完成" : "检测运行中"}</strong>{currentSample ? <span key={currentSample.sample_index} className="pcap-detection-current">正在检测{sampleLabel(currentSample.sample_index)}</span> : mission.status === "completed" ? <strong>{completedConclusion(mission.summary)}</strong> : null}{active && onCancel ? <button type="button" onClick={onCancel} disabled={busy}><Square size={13} />取消</button> : null}</section>
    {liveSamples.length ? <section className="pcap-detection-samples"><strong>已检测样本</strong><div>{liveSamples.map((sample, index) => <span ref={(node) => { sampleRefs.current[sample.sample_index] = node; }} key={sample.sample_index} className={`is-${sample.status}${sample.status === "succeeded" && sample.evidence_count > 0 ? " is-alert" : ""}${index === activeSample ? " is-active" : ""}`}>{sampleLabel(sample.sample_index)} · {sample.status === "succeeded" ? `完成 · 证据 ${sample.evidence_count}` : `失败 · ${failureLabels[sample.failure_code ?? "tool_failed"] ?? "工具失败"}`}</span>)}</div></section> : null}
    <div className="pcap-detection-findings"><div>{mission.summary ? <p className="pcap-detection-counts" aria-label="检测统计"><span className="is-success">成功 {mission.summary.succeeded_count}</span><span className="is-failed">失败 {mission.summary.failed_count}</span><span className="is-evidence">证据 {mission.summary.evidence.length}</span></p> : null}<strong>局部证据</strong>{mission.summary?.evidence.length ? mission.summary.evidence.map((item) => <article key={item.evidence_id}><span>{candidateLabels[item.attack_candidate]}</span>{item.purpose_candidates?.length ? <b>目的候选：{item.purpose_candidates.map((purpose) => purposeLabels[purpose]).join("、")}</b> : null}<code>{item.evidence_id}</code><small>Packet {item.start_packet}-{item.end_packet} · {item.start_offset_ms}ms · 置信度 {Math.round(item.confidence * 100)}%</small></article>) : <p>{incomplete ? "部分样本未完成，请重试失败样本。" : "证据不足，保持允许。"}</p>}</div><DetectionTimeline evidence={mission.summary?.evidence ?? []} incomplete={incomplete} /></div>
  </>;
}
