import { Activity, BadgeCheck, ShieldCheck } from "lucide-react";

import type { InvestigationRole } from "../challenge/investigation";
import { expectedEvidenceRelation } from "../challenge/scoring";
import type { LabRunResult } from "../types";
import { ChallengeSignalPicker } from "./ChallengeSignalPicker";

interface InvestigationDeskProps {
  run: LabRunResult;
  role: InvestigationRole;
}

const SEMANTIC_LABELS = {
  safe: "语义安全",
  controversial: "语义争议",
  unsafe: "语义危险",
  unavailable: "语义证据不可用",
} as const;

export function InvestigationDesk({ run, role }: InvestigationDeskProps) {
  const detection = run.detection;
  const relation = expectedEvidenceRelation(run);
  const conflict = relation === "semantic_only" || relation === "distribution_only";
  const evidenceSummary = relation === null
    ? "现有证据不足以形成双路关系"
    : conflict
      ? "两路证据存在分歧"
      : "两路证据结论一致";

  return (
    <section className="challenge-investigation-desk" aria-label="中央证据台" aria-live="polite">
      {role === "guard" ? (
        <>
          <header><ShieldCheck aria-hidden="true" /><strong>语义侦探汇报</strong></header>
          <div className="challenge-investigation-facts">
            <div><span>语义等级</span><strong>{SEMANTIC_LABELS[detection.semantic_severity]}</strong></div>
            <div><span>风险类别</span><strong>{detection.semantic_categories.length ? detection.semantic_categories.join("、") : "未命中风险类别"}</strong></div>
            <div><span>检测耗时</span><strong>{detection.semantic_latency_ms.toFixed(1)} ms</strong></div>
            <div><span>模型版本</span><strong>{detection.semantic_model_id} / {detection.semantic_model_version}</strong></div>
          </div>
        </>
      ) : null}
      {role === "cpd" ? (
        <>
          <header><Activity aria-hidden="true" /><strong>曲线侦探汇报</strong></header>
          <div className="challenge-investigation-facts">
            <div><span>检测状态</span><strong>{detection.detector_status === "token_anomaly_candidate" ? "发现分布候选" : "未发现分布候选"}</strong></div>
            <div><span>CPD 分数</span><strong>{detection.detector_score.toFixed(2)}</strong></div>
            <div><span>阈值 h</span><strong>{detection.provenance.thresholds.h?.toFixed(2) ?? "不可用"}</strong></div>
            <div><span>异常起点</span><strong>{detection.suspicious_span ? `Token ${detection.suspicious_span.token_start}` : "不适用"}</strong></div>
          </div>
          <p className="challenge-investigation-caveat">分布异常只代表候选信号，不单独证明恶意</p>
          <ChallengeSignalPicker signals={detection.signals} selectedIndex={null} onSelect={() => undefined} readOnly />
        </>
      ) : null}
      {role === "agent" ? (
        <>
          <header><BadgeCheck aria-hidden="true" /><strong>小队队长总结</strong></header>
          <div className="challenge-investigation-conclusion">
            <span>证据状态</span><strong>{evidenceSummary}</strong>
          </div>
        </>
      ) : null}
    </section>
  );
}
