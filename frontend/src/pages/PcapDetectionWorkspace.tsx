import { ArrowRight, CircleAlert, FileSearch, KeyRound, Play, ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";

import { api } from "../api";
import { PcapDetectionResult } from "../components/PcapDetectionResult";
import { ResultGuide } from "../components/ResultGuide";
import type { PcapDetectionMissionResult, PcapMissionStatus, SuperAgentStoredMission } from "../types";

const TERMINAL = new Set<PcapMissionStatus>(["completed", "cancelled", "degraded"]);
const DETECTION_MISSION_KEY = "token-security-superagent-pcap-detection-id";

function readDetectionMissionId(): string | null {
  try {
    return window.sessionStorage.getItem(DETECTION_MISSION_KEY);
  } catch {
    return null;
  }
}

function writeDetectionMissionId(missionId: string) {
  try {
    window.sessionStorage.setItem(DETECTION_MISSION_KEY, missionId);
  } catch {
    // Storage is optional; the mounted workspace still owns the live mission.
  }
}

function removeDetectionMissionId() {
  try {
    window.sessionStorage.removeItem(DETECTION_MISSION_KEY);
  } catch {
    // Storage is optional; the mounted workspace still owns the live mission.
  }
}

function isDetectionMission(mission: SuperAgentStoredMission): mission is PcapDetectionMissionResult {
  return mission.objective === "detect_pcap_anomalies";
}

export function PcapDetectionWorkspace() {
  const [overview, setOverview] = useState<{ enabled: boolean; eligible_file_count: number; max_files: 20 } | null>(null);
  const [mission, setMission] = useState<PcapDetectionMissionResult | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [restoreError, setRestoreError] = useState<string | null>(null);
  const [restorePending, setRestorePending] = useState(false);
  const [restoreMissionId, setRestoreMissionId] = useState<string | null>(null);
  const [restoreRevision, setRestoreRevision] = useState(0);
  const [maxFiles, setMaxFiles] = useState("20");
  const [batchStart, setBatchStart] = useState(0);

  useEffect(() => { let mounted = true; api.pcapDetectionOverview().then((value) => { if (mounted) { setOverview(value); setBusy(false); } }).catch(() => { if (mounted) { setError("PCAP 异常检测暂不可用"); setBusy(false); } }); return () => { mounted = false; }; }, []);
  useEffect(() => {
    let mounted = true;
    const missionId = restoreRevision === 0 ? readDetectionMissionId() : restoreMissionId;
    if (!missionId) return () => { mounted = false; };
    setRestoreMissionId(missionId);
    setRestorePending(true);
    setRestoreError(null);
    api.getPcapMission(missionId).then((storedMission) => {
      if (!mounted) return;
      if (!isDetectionMission(storedMission)) {
        removeDetectionMissionId();
        setRestoreMissionId(null);
        return;
      }
      setMission(storedMission);
    }).catch((caught) => {
      if (!mounted) return;
      const status = (caught as Error & { status?: number }).status;
      if (status === 404 || status === 410) {
        removeDetectionMissionId();
        setRestoreMissionId(null);
        return;
      }
      setRestoreError("无法恢复异常检测任务，请重试");
    }).finally(() => {
      if (mounted) setRestorePending(false);
    });
    return () => { mounted = false; };
  }, [restoreRevision]);
  useEffect(() => {
    if (!mission || TERMINAL.has(mission.status)) return;
    let mounted = true;
    let timer: number | undefined;
    const poll = async () => {
      try {
        const result = await api.getPcapMission(mission.detection_id);
        if (!mounted || result.objective !== "detect_pcap_anomalies") return;
        setMission(result);
        if (!TERMINAL.has(result.status)) timer = window.setTimeout(poll, 500);
      } catch {
        if (mounted) { setError("无法刷新异常检测状态，请稍后重试"); timer = window.setTimeout(poll, 2000); }
      }
    };
    timer = window.setTimeout(poll, 300);
    return () => { mounted = false; if (timer !== undefined) window.clearTimeout(timer); };
  }, [mission?.detection_id, mission?.status]);

  const active = mission ? !TERMINAL.has(mission.status) : false;
  const batchOptions = overview ? Array.from({ length: Math.ceil(overview.eligible_file_count / 20) }, (_, index) => index * 20) : [];

  async function start() {
    if (!overview || !confirming || busy || restorePending) return;
    setBusy(true);
    setError(null);
    setRestoreError(null);
    try {
      const receipt = await api.authorizePcapDetection({ confirmed: true, max_files: Number(maxFiles) });
      const result = await api.createPcapDetectionMission({ objective: "detect_pcap_anomalies", authorization_id: receipt.authorization_id, start_index: batchStart });
      setMission(result);
      writeDetectionMissionId(result.detection_id);
      setConfirming(false);
    } catch { setError("无法启动异常检测，请重试"); } finally { setBusy(false); }
  }

  async function cancel() {
    if (!mission || !active || busy) return;
    setBusy(true);
    try { setMission(await api.cancelPcapDetectionMission(mission.detection_id)); } finally { setBusy(false); }
  }

  function retryRestore() {
    if (!restoreMissionId || restorePending) return;
    setRestoreRevision((revision) => revision + 1);
  }

  return <section className="pcap-detection-workspace" aria-label="PCAP 异常检测工作区" aria-busy={busy}>
    <div className="pcap-detection-authorization"><div><FileSearch size={19} /><strong>{overview ? `可选 PCAP ${overview.eligible_file_count}` : "读取检测目录"}</strong></div><label>检测批次 <select value={batchStart} onChange={(event) => setBatchStart(Number(event.target.value))} disabled={active || busy || restorePending}>{batchOptions.map((start) => <option key={start} value={start}>样本 {String(start + 1).padStart(2, "0")}–{String(Math.min(start + 20, overview?.eligible_file_count ?? start + 20)).padStart(2, "0")}</option>)}</select></label><label>最多处理 <input type="number" min="1" max="20" value={maxFiles} onChange={(event) => setMaxFiles(event.target.value)} disabled={active || restorePending} /> 个文件</label>{confirming ? <div className="pcap-detection-confirm"><KeyRound size={18} /><span>仅在确认后进入 Docker 隔离检测</span><button type="button" onClick={() => setConfirming(false)}>返回</button><button type="button" onClick={start} disabled={busy || restorePending}><ShieldCheck size={14} />确认并开始</button></div> : <button type="button" onClick={() => setConfirming(true)} disabled={!overview?.enabled || active || busy || restorePending}><Play size={15} />准备异常检测</button>}</div>
    {restoreError || error ? <div className="superagent-error" role="alert"><CircleAlert size={16} />{restoreError ?? error}{restoreError ? <button type="button" onClick={retryRestore} disabled={restorePending}>重试恢复</button> : null}</div> : null}
    {mission ? <PcapDetectionResult mission={mission} sampleLabel={(sampleIndex) => `样本 ${String(sampleIndex + batchStart).padStart(2, "0")}`} onCancel={cancel} busy={busy} /> : <div className="pcap-detection-empty"><ArrowRight size={22} /><strong>规则侦探等待授权</strong><span>检测结果只展示局部证据，不恢复原始请求。</span></div>}
    {mission && TERMINAL.has(mission.status) ? <ResultGuide
      title="如何理解异常检测结果"
      summary="结论优先回答当前范围是否出现异常候选，并保留工具失败与不可见证据的边界。"
      items={[
        { term: "发现异常", explanation: "表示至少一个成功解析样本命中了可解释规则或行为异常证据。" },
        { term: "当前范围未命中", explanation: "当前范围未命中不等于文件全部安全。" },
        { term: "工具失败", explanation: "工具失败既不能计为安全，也不能计为异常。" },
      ]}
    /> : null}
  </section>;
}
