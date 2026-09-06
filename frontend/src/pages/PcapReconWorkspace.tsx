import { BarChart3, CheckCircle2, CircleAlert, KeyRound, LoaderCircle, Play, ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";
import { api } from "../api";
import { ResultGuide } from "../components/ResultGuide";
import type { PcapReconMissionResult, PcapReconSummary } from "../types";

export const PCAP_RECON_MISSION_STORAGE_KEY = "token-security-superagent-pcap-recon-mission-id";
const terminal = new Set(["completed", "cancelled", "degraded"]);
const narrativeLabels: Record<string, string> = {
  authorization_accepted: "执行授权已接受",
  quartile_sample_selected: "四分位代表样本已抽取",
  isolated_full_capture_scan_running: "隔离容器扫描运行中",
  aggregate_profile_validated: "聚合画像已核验",
  method_selection_checkpoint_ready: "方法选择检查点已就绪",
};
const allowedNarratives = new Set(Object.keys(narrativeLabels));
const failureLabels: Record<string, string> = { tool_failed: "隔离工具执行失败", tool_timeout: "样本处理超时", report_invalid: "聚合报告校验失败" };
const allowedProtocols = new Set(["arp", "dns", "eth", "http", "http2", "icmp", "icmpv6", "ip", "ipv6", "quic", "sll", "sll2", "tcp", "tls", "udp", "websocket"]);
const allowedBucketKeys = new Set(["quartile_1", "quartile_2", "quartile_3", "quartile_4", "empty", "1_to_15", "16_to_63", "at_least_64", "zero", "under_1_second", "1_to_10_seconds", "over_10_seconds"]);

function bars(values: Record<string, number>) {
  return Object.entries(values).filter(([key]) => allowedBucketKeys.has(key) || allowedProtocols.has(key)).map(([key, value]) => <div className="pcap-recon-bar" key={key}><span>{key.replaceAll("_", " ")}</span><i><b style={{ width: `${Math.min(100, value * 10)}%` }} /></i><strong>{value}</strong></div>);
}

function Profile({ summary }: { summary: PcapReconSummary }) {
  return <div className="pcap-recon-profile">
    <section><h3>四分位覆盖</h3>{bars(summary.quartile_counts)}</section>
    <section><h3>数据包数量分布</h3>{bars(summary.packet_bucket_counts)}</section>
    <section><h3>持续时间分布</h3>{bars(summary.duration_bucket_counts)}</section>
    <section><h3>协议出现样本数</h3>{bars(summary.protocol_presence_counts)}</section>
    <div className="pcap-recon-stat"><strong>明文样本 {summary.plaintext_sample_count}</strong><strong>加密样本 {summary.encrypted_sample_count}</strong><strong>序列候选 {summary.sequence_candidate_count}</strong></div>
  </div>;
}

export function PcapReconWorkspace() {
  const [overview, setOverview] = useState<{ enabled: boolean; eligible_file_count: number; sample_limit: 20 } | null>(null);
  const [mission, setMission] = useState<PcapReconMissionResult | null>(null);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [loading, setLoading] = useState(true);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [restorePending, setRestorePending] = useState(false);

  useEffect(() => {
    let active = true;
    let stored: string | null = null;
    try { stored = window.sessionStorage.getItem(PCAP_RECON_MISSION_STORAGE_KEY); } catch { stored = null; }
    api.pcapReconOverview().then((nextOverview) => { if (active) setOverview(nextOverview); }).catch(() => active && setError("数据勘察暂不可用")).finally(() => active && setLoading(false));
    if (stored) {
      setRestorePending(true);
      api.getPcapMission(stored).then((storedMission) => {
      if (!active || storedMission.objective !== "reconnoiter_pcap_dataset") return;
      setMission(storedMission);
      if (terminal.has(storedMission.status)) { try { window.sessionStorage.removeItem(PCAP_RECON_MISSION_STORAGE_KEY); } catch { /* optional persistence */ } }
      }).catch((caught) => {
      if (!active) return;
      const status = caught instanceof Error ? (caught as Error & { status?: number }).status : undefined;
      if (status === 404 || status === 410) { try { window.sessionStorage.removeItem(PCAP_RECON_MISSION_STORAGE_KEY); } catch { /* optional persistence */ } return; }
        setError("无法恢复数据勘察任务，请重试。");
      }).finally(() => active && setRestorePending(false));
    }
    return () => { active = false; };
  }, []);

  useEffect(() => {
    if (!mission || terminal.has(mission.status)) return;
    const timer = window.setTimeout(async () => {
      try {
        const next = await api.getPcapMission(mission.recon_id);
        if (next.objective === "reconnoiter_pcap_dataset") setMission(next);
      } catch { setError("无法刷新数据勘察状态，请重试。"); }
    }, 1000);
    return () => window.clearTimeout(timer);
  }, [mission]);

  async function start() {
    if (!overview?.enabled || pending || restorePending) return;
    setPending(true); setError(null);
    try {
      const receipt = await api.authorizePcapRecon({ confirmed: true, sample_limit: 20 });
      const result = await api.createPcapReconMission({ objective: "reconnoiter_pcap_dataset", authorization_id: receipt.authorization_id });
      setMission(result); try { window.sessionStorage.setItem(PCAP_RECON_MISSION_STORAGE_KEY, result.recon_id); } catch { /* optional persistence */ } setConfirmOpen(false);
    } catch { setError("无法启动数据勘察，请重试。"); } finally { setPending(false); }
  }

  async function retry() {
    if (pending || restorePending) return;
    setPending(true); setError(null);
    try {
      const receipt = await api.authorizePcapRecon({ confirmed: true, sample_limit: 20 });
      const result = await api.createPcapReconMission({ objective: "reconnoiter_pcap_dataset", authorization_id: receipt.authorization_id });
      setMission(result); try { window.sessionStorage.setItem(PCAP_RECON_MISSION_STORAGE_KEY, result.recon_id); } catch { /* optional persistence */ }
    } catch { setError("无法重新启动数据勘察，请重试。"); } finally { setPending(false); }
  }

  return <section className="pcap-recon-workspace" aria-label="PCAP 数据勘察工作区">
    <div className="pcap-recon-authorization">
      <div><strong>数据勘察范围</strong>{loading ? <p>正在读取勘察范围</p> : <><p>按文件大小四分位抽取 20 个代表样本</p><small>可选文件 {overview?.eligible_file_count ?? 0}</small></>}</div>
    {!confirmOpen ? <button type="button" onClick={() => setConfirmOpen(true)} disabled={loading || restorePending || !overview?.enabled || Boolean(mission && !terminal.has(mission.status))}><Play size={16} />准备开始勘察</button> : <div className="pcap-recon-consent" role="region" aria-label="PCAP 勘察授权确认"><KeyRound size={20} /><p>本次将在无网络只读容器中完整扫描 20 个分层样本，仅返回聚合画像，不检测攻击，不展示文件身份或载荷。</p><button type="button" className="secondary-button" onClick={() => setConfirmOpen(false)}>返回</button><button type="button" onClick={start} disabled={pending}>{pending ? <LoaderCircle className="superagent-spinner" size={16} /> : <ShieldCheck size={16} />}确认并开始勘察</button></div>}
    </div>
    {error ? <div role="alert"><CircleAlert size={16} />{error}</div> : null}
    {mission?.status === "degraded" ? <section className="pcap-recon-empty is-degraded" role="alert"><CircleAlert size={24} /><strong>勘察未完成，可重新授权重试</strong><span>{failureLabels[mission.failure_code ?? "tool_failed"]}</span><button type="button" onClick={retry} disabled={pending || restorePending}>{pending ? "正在重新授权" : "重新授权勘察"}</button></section> : mission?.summary ? <><div className="pcap-recon-phase"><strong>当前阶段：认识数据</strong><span>下一阶段：根据真实画像选择规则、Request 定位、行为异常或可选 CPD</span></div><Profile summary={mission.summary} /></> : <section className="pcap-recon-empty"><BarChart3 size={24} /><strong>{mission ? "正在形成聚合画像" : "等待开始数据勘察"}</strong></section>}
    {mission && !terminal.has(mission.status) ? <div role="status">{mission.status === "running" ? "勘察运行中" : "勘察排队中"}</div> : null}
    {mission?.events?.length ? <ol className="pcap-recon-events">{mission.events.filter((event) => allowedNarratives.has(event.summary)).map((event) => <li key={event.sequence}>{narrativeLabels[event.summary]}</li>)}</ol> : null}
    {mission && terminal.has(mission.status) ? <ResultGuide
      title="如何理解数据画像"
      summary="数据勘察只形成聚合画像，不判断攻击。它用于决定下一阶段该采用哪些可解释检测方法。"
      items={[
        { term: "协议画像", explanation: "表示样本中可识别协议的覆盖情况，不是安全标签。" },
        { term: "明文 / 加密", explanation: "决定能否观察请求级内容；加密流量通常只能使用元数据和序列特征。" },
        { term: "勘察失败", explanation: "表示隔离工具或报告校验没有完成，不能将该样本视为安全。" },
      ]}
    /> : null}
  </section>;
}
