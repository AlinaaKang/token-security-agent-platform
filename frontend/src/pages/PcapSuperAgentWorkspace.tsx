import {
  Ban,
  CheckCircle2,
  CircleAlert,
  FileArchive,
  FileSearch,
  KeyRound,
  ListChecks,
  LoaderCircle,
  Network,
  Play,
  RefreshCw,
  ShieldCheck,
  Square,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { api } from "../api";
import { PcapMascotTeam } from "../components/PcapMascotTeam";
import { PcapReconWorkspace } from "./PcapReconWorkspace";
import { PcapDetectionWorkspace } from "./PcapDetectionWorkspace";
import type {
  PcapActor,
  PcapCaptureEvidence,
  PcapMissionResult,
  PcapMissionStatus,
  PcapPublicNarrative,
} from "../types";

const PCAP_MISSION_STORAGE_KEY = "token-security-superagent-pcap-mission-id";
const POLL_INTERVAL_MS = 1000;

const terminalStatuses = new Set<PcapMissionStatus>(["completed", "cancelled", "degraded"]);

const statusLabels: Record<PcapMissionStatus, string> = {
  queued: "任务等待执行",
  running: "任务运行中",
  completed: "任务已完成",
  cancelled: "任务已取消",
  degraded: "任务降级完成",
};

const actorLabels: Record<PcapActor, string> = {
  coordinator: "任务协调",
  network_evidence_analyst: "网络证据分析",
  knowledge_analyst: "知识证据核验",
  response_operator: "响应收口",
};

const narrativeLabels: Record<PcapPublicNarrative, string> = {
  batch_triage_completed: "批次分诊已完成",
  coordinator_plan: "有界批次计划已建立",
  cpd_evidence_unavailable: "CPD 证据不可用",
  deterministic_response_ready: "确定性响应记录已就绪",
  encrypted_transport_observed: "观察到加密传输",
  evidence_level_validated: "证据级别已核验",
  insufficient_evidence: "现有证据不足",
  no_packet_payload_retained: "未保留数据包载荷",
  plaintext_application_protocol_observed: "观察到明文应用协议",
  plaintext_application_protocol_candidate_not_proven_llm_traffic: "明文应用协议候选，无法确认具体应用类型",
  retain_public_metadata: "保留公开元数据供人工复核",
  token_evidence_unavailable: "Token 证据不可用",
  tool_authorization_accepted: "执行授权已接受",
  traffic_only_evidence: "仅提供网络流量证据",
};

function readStoredMissionId(): string | null {
  try {
    return window.sessionStorage.getItem(PCAP_MISSION_STORAGE_KEY);
  } catch {
    return null;
  }
}

function rememberMissionId(missionId: string | null) {
  try {
    if (missionId) window.sessionStorage.setItem(PCAP_MISSION_STORAGE_KEY, missionId);
    else window.sessionStorage.removeItem(PCAP_MISSION_STORAGE_KEY);
  } catch {
    // Storage is optional; the mounted workspace still owns the live mission.
  }
}

function CaptureRow({ capture }: { capture: PcapCaptureEvidence }) {
  const protocols = Object.entries(capture.protocol_counts);
  const failed = capture.status === "failed";
  const skipped = capture.status === "skipped";
  return (
    <article className={`pcap-capture is-${capture.status}`}>
      <span className="pcap-capture-state">
        {failed ? <CircleAlert size={17} aria-hidden="true" /> : skipped ? <Ban size={17} aria-hidden="true" /> : <CheckCircle2 size={17} aria-hidden="true" />}
        <span>{failed ? "检查失败" : skipped ? "已跳过" : "检查成功"}</span>
      </span>
      <div className="pcap-capture-identity">
        <code>{capture.capture_id}</code>
        <small>
          {capture.packet_count} 个数据包 · {failed ? <code>{capture.error_code ?? "未提供错误代码"}</code> : capture.capability === "traffic_only" ? "仅流量证据" : capture.capability === "token_eligible" ? "明文应用协议可见" : "证据不足"}
        </small>
      </div>
      <div className="pcap-protocols" aria-label="协议计数">
        {protocols.length ? protocols.map(([protocol, count]) => (
          <span key={protocol}>{protocol.toUpperCase()} {count}</span>
        )) : <span>无协议计数</span>}
      </div>
      <span className="pcap-visibility">
        {capture.visibility.encrypted_transport_observed ? "加密传输可见" : capture.visibility.plaintext_application_protocol_observed ? "明文协议可见" : "应用层不可见"}
      </span>
    </article>
  );
}

function MissionWorkspace({
  mission,
  actionPending,
  onCancel,
}: {
  mission: PcapMissionResult;
  actionPending: boolean;
  onCancel: () => void;
}) {
  const terminal = terminalStatuses.has(mission.status);
  const reportGroups = [
    ["已确认", mission.report.confirmed],
    ["候选线索", mission.report.candidates],
    ["未知项", mission.report.unknowns],
    ["建议动作", mission.report.recommended_action],
  ] as const;

  return (
    <div className="pcap-mission-workspace">
      <section className={`pcap-mission-status is-${mission.status}`} aria-live="polite">
        <div>
          {terminal ? <CheckCircle2 size={18} /> : <LoaderCircle className="superagent-spinner" size={18} />}
          <span><strong>{statusLabels[mission.status]}</strong><code>{mission.mission_id}</code></span>
        </div>
        {!terminal ? (
          <button type="button" className="pcap-cancel-button" onClick={onCancel} disabled={actionPending}>
            <Square size={14} /> {actionPending ? "正在取消" : "取消任务"}
          </button>
        ) : null}
      </section>

      <div className="pcap-operations-grid">
        <section className="pcap-trace" aria-label="PCAP 任务轨迹">
          <div className="pcap-section-heading"><ListChecks size={16} /><strong>公开任务轨迹</strong><span>{mission.events.length} / 12</span></div>
          <ol>
            {mission.events.map((event) => (
              <li key={event.sequence} className={`is-${event.status}`}>
                <span>{String(event.sequence).padStart(2, "0")}</span>
                <div><strong>{actorLabels[event.actor]}</strong><small>{narrativeLabels[event.summary]}</small></div>
                <span>{event.status === "running" ? "执行中" : event.status === "succeeded" ? "已完成" : event.status === "failed" ? "失败" : event.status === "skipped" ? "已跳过" : "等待"}</span>
              </li>
            ))}
          </ol>
        </section>

        <section className="pcap-report" aria-label="PCAP 证据结论">
          <div className="pcap-section-heading"><ShieldCheck size={16} /><strong>证据结论</strong><span>仅公开元数据</span></div>
          <div className="pcap-report-grid">
            {reportGroups.map(([label, narratives]) => (
              <section key={label}>
                <h3>{label}</h3>
                {narratives.length ? (
                  <ul>{narratives.map((narrative) => <li key={narrative}>{narrativeLabels[narrative]}</li>)}</ul>
                ) : <p>暂无公开结论</p>}
              </section>
            ))}
          </div>
          <div className="pcap-unavailable-evidence" aria-label="不可用证据">
            <span><Ban size={14} /> CPD 证据不可用</span>
            <span><Ban size={14} /> Token 证据不可用</span>
          </div>
        </section>
      </div>

      {mission.summary ? (
        <section className="pcap-batch-evidence" aria-label="PCAP 批次证据">
          <div className="pcap-section-heading"><FileArchive size={16} /><strong>批次证据</strong><code>{mission.batch_id}</code></div>
          <div className="pcap-batch-counts">
            <strong>已选择 {mission.summary.selected_count}</strong>
            <span>成功 {mission.summary.succeeded_count}</span>
            <span>失败 {mission.summary.failed_count}</span>
            <span>跳过 {mission.summary.skipped_count}</span>
          </div>
          <div className="pcap-capture-list">
            {mission.summary.captures.map((capture) => <CaptureRow key={capture.capture_id} capture={capture} />)}
          </div>
        </section>
      ) : null}

      <div className="pcap-limitations">
        {mission.limitations.map((limitation) => <span key={limitation}>{narrativeLabels[limitation]}</span>)}
      </div>
      {terminal ? <PcapMascotTeam mission={mission} /> : null}
    </div>
  );
}

export function PcapSuperAgentWorkspace() {
  const [pcapView, setPcapView] = useState<"triage" | "recon" | "detection">("triage");
  const [overviewEnabled, setOverviewEnabled] = useState<boolean | null>(null);
  const [pendingFileCount, setPendingFileCount] = useState<number | null>(null);
  const [maxBatchSize, setMaxBatchSize] = useState(20);
  const [maxFiles, setMaxFiles] = useState("20");
  const [confirmationOpen, setConfirmationOpen] = useState(false);
  const [mission, setMission] = useState<PcapMissionResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [actionPending, setActionPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pollFailed, setPollFailed] = useState(false);
  const [pollRevision, setPollRevision] = useState(0);
  const pollEpochRef = useRef(0);

  useEffect(() => {
    if (pcapView !== "triage") return;
    let active = true;
    const storedMissionId = readStoredMissionId();
    const restoreMission = storedMissionId
      ? api.getPcapMission(storedMissionId)
      : Promise.resolve(null);

    Promise.allSettled([api.pcapOverview(), restoreMission]).then(([overviewResult, missionResult]) => {
      if (!active) return;
      if (overviewResult.status === "fulfilled") {
        setOverviewEnabled(overviewResult.value.enabled);
        setPendingFileCount(
          overviewResult.value.enabled
            ? overviewResult.value.pending_file_count
            : null,
        );
        setMaxBatchSize(overviewResult.value.max_batch_size);
        setMaxFiles(String(overviewResult.value.max_batch_size));
        if (!overviewResult.value.enabled) setError("PCAP 证据分诊暂不可用");
      } else {
        setOverviewEnabled(false);
        setPendingFileCount(null);
        setError("PCAP 证据分诊暂不可用");
      }
      if (missionResult.status === "fulfilled" && missionResult.value) {
        if (missionResult.value.objective === "triage_pcap_evidence") {
          setMission(missionResult.value);
        } else {
          rememberMissionId(null);
        }
      } else if (missionResult.status === "rejected") {
        rememberMissionId(null);
        setError("无法恢复 PCAP 任务，请重新开始。");
      }
      setLoading(false);
    });
    return () => { active = false; };
  }, [pcapView]);

  const missionId = mission?.mission_id ?? null;
  const missionStatus = mission?.status ?? null;
  useEffect(() => {
    if (pcapView !== "triage" || !missionId || !missionStatus || terminalStatuses.has(missionStatus)) return;
    let active = true;
    let timer: number | undefined;
    const pollEpoch = ++pollEpochRef.current;
    const isCurrentPoll = () => active && pollEpochRef.current === pollEpoch;
    const pollMission = async () => {
      if (!isCurrentPoll()) return;
      try {
        const result = await api.getPcapMission(missionId);
        if (!isCurrentPoll()) return;
        if (result.objective !== "triage_pcap_evidence") throw new Error("unexpected mission type");
        setPollFailed(false);
        setMission(result);
        if (result.status === "cancelled") rememberMissionId(null);
        if (!terminalStatuses.has(result.status)) {
          timer = window.setTimeout(pollMission, POLL_INTERVAL_MS);
        }
      } catch {
        if (isCurrentPoll()) {
          setPollFailed(true);
          setError("无法刷新 PCAP 任务状态，请重试。");
        }
      }
    };
    timer = window.setTimeout(pollMission, POLL_INTERVAL_MS);
    return () => {
      active = false;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [pcapView, missionId, missionStatus, pollRevision]);

  const parsedMaxFiles = Number(maxFiles);
  const validMaxFiles = /^\d+$/.test(maxFiles) && Number.isInteger(parsedMaxFiles) && parsedMaxFiles >= 1 && parsedMaxFiles <= maxBatchSize;
  const activeMission = mission ? !terminalStatuses.has(mission.status) : false;
  const canPrepare = overviewEnabled === true && validMaxFiles && !loading && !actionPending && !activeMission;

  async function confirmAndStart() {
    if (!canPrepare || !confirmationOpen) return;
    setActionPending(true);
    setError(null);
    setPollFailed(false);
    pollEpochRef.current += 1;
    setMission(null);
    rememberMissionId(null);
    try {
      const authorization = await api.authorizePcapBatch({ confirmed: true, max_files: parsedMaxFiles });
      const result = await api.createPcapMission({
        objective: "triage_pcap_evidence",
        authorization_id: authorization.authorization_id,
      });
      setMission(result);
      rememberMissionId(result.mission_id);
      setConfirmationOpen(false);
    } catch {
      setError("无法启动 PCAP 证据分诊，请重试。");
    } finally {
      setActionPending(false);
    }
  }

  async function cancelMission() {
    if (!mission || terminalStatuses.has(mission.status) || actionPending) return;
    pollEpochRef.current += 1;
    setPollFailed(false);
    setActionPending(true);
    setError(null);
    try {
      const result = await api.cancelPcapMission(mission.mission_id);
      setMission(result);
      if (terminalStatuses.has(result.status)) {
        if (result.status === "cancelled") rememberMissionId(null);
      } else {
        rememberMissionId(result.mission_id);
        setPollRevision((revision) => revision + 1);
      }
    } catch {
      setError("无法取消 PCAP 任务，请重试。");
      setPollRevision((revision) => revision + 1);
    } finally {
      setActionPending(false);
    }
  }

  function retryPolling() {
    if (!mission || terminalStatuses.has(mission.status) || actionPending) return;
    setPollFailed(false);
    setError(null);
    setPollRevision((revision) => revision + 1);
  }

  return (
    <section className="pcap-superagent" aria-label="PCAP 证据分诊工作区" aria-busy={loading || actionPending}>
      <div className="pcap-mode-switch" role="group" aria-label="PCAP 工作模式" data-tour="superagent-scope">
        <button type="button" aria-pressed={pcapView === "triage"} onClick={() => setPcapView("triage")}>批量分诊</button>
        <button type="button" aria-pressed={pcapView === "recon"} onClick={() => setPcapView("recon")}>数据勘察</button>
        <button type="button" aria-pressed={pcapView === "detection"} onClick={() => setPcapView("detection")}>异常检测</button>
      </div>
      {pcapView === "recon" ? <PcapReconWorkspace /> : pcapView === "detection" ? <PcapDetectionWorkspace /> : <>
      <div className="pcap-authorization-track">
        <section className="pcap-overview-stage" data-tour="superagent-bounds">
          <div className="pcap-stage-index"><span>阶段 1</span><strong>范围概览</strong></div>
          <div className="pcap-overview-metric">
            <FileSearch size={20} />
            <span>
              <small>证据目录</small>
              {loading ? <strong role="status">正在读取证据目录</strong> : overviewEnabled && pendingFileCount !== null ? <strong>待处理文件 {pendingFileCount}</strong> : <strong>证据目录不可用</strong>}
            </span>
          </div>
          <p>每次仅处理有界文件批次，公开结果不包含文件名、路径、载荷或摘要。</p>
          <label>
            <span>本次最多处理文件数</span>
            <input
              type="number"
              min="1"
              max={maxBatchSize}
              step="1"
              value={maxFiles}
              onChange={(event) => { setMaxFiles(event.target.value); setConfirmationOpen(false); }}
              disabled={loading || actionPending || activeMission}
            />
          </label>
          {!validMaxFiles && !loading ? <span className="pcap-field-error">请输入 1 至 {maxBatchSize} 之间的整数</span> : null}
          <button type="button" className="pcap-prepare-button" onClick={() => setConfirmationOpen(true)} disabled={!canPrepare}>
            {loading ? <LoaderCircle className="superagent-spinner" size={16} /> : <Play size={16} />}
            {loading ? "正在读取范围" : "准备开始"}
          </button>
        </section>

        <section className={`pcap-consent-stage ${confirmationOpen ? "is-active" : ""}`} data-tour="superagent-command">
          <div className="pcap-stage-index"><span>阶段 2</span><strong>执行授权</strong></div>
          {confirmationOpen ? (
            <div className="pcap-consent-surface" role="region" aria-label="PCAP 执行授权确认">
              <KeyRound size={22} />
              <div><strong>确认处理最多 {parsedMaxFiles} 个文件</strong><p>此次点击将签发一次性授权并立即启动有界批次任务。</p></div>
              <div className="pcap-consent-actions">
                <button type="button" className="secondary-button" onClick={() => setConfirmationOpen(false)} disabled={actionPending}>返回概览</button>
                <button type="button" onClick={confirmAndStart} disabled={actionPending}>
                  {actionPending ? <LoaderCircle className="superagent-spinner" size={16} /> : <ShieldCheck size={16} />}
                  {actionPending ? "正在授权" : "确认并开始"}
                </button>
              </div>
            </div>
          ) : (
            <div className="pcap-consent-locked"><KeyRound size={20} /><span><strong>等待范围确认</strong><small>阶段 1 不会签发授权或启动任务</small></span></div>
          )}
        </section>
      </div>

      {error ? (
        <div className="superagent-error" role="alert">
          <CircleAlert size={16} /><span>{error}</span>
          {pollFailed ? <button type="button" onClick={retryPolling}><RefreshCw size={14} />重试刷新</button> : null}
        </div>
      ) : null}
      {mission ? <MissionWorkspace mission={mission} actionPending={actionPending} onCancel={cancelMission} /> : (
        <section className="pcap-empty-state">
          <Network size={25} /><strong>等待有界批次任务</strong><span>范围概览与执行授权保持分离。</span>
        </section>
      )}
      </>}
    </section>
  );
}
