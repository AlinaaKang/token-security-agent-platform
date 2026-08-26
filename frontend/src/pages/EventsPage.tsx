import { Database, FileWarning, LockKeyhole } from "lucide-react";
import { useEffect, useState } from "react";

import { api } from "../api";
import type { EventPage, FusionReason, SemanticCategory, SemanticSeverity } from "../types";

const decisionLabels = {
  allow: "放行",
  review: "人工复核",
  block: "拦截",
  sanitize_recheck: "净化后复检",
} as const;

const semanticLabels: Record<SemanticSeverity, string> = {
  safe: "语义安全",
  controversial: "语义争议",
  unsafe: "语义危险",
  unavailable: "语义检测不可用",
};
const categoryLabels: Record<SemanticCategory, string> = {
  violent: "暴力与武器",
  non_violent_illegal_acts: "非暴力违法行为",
  sexual_content: "性内容",
  pii: "个人敏感信息",
  suicide_self_harm: "自杀与自伤",
  unethical_acts: "不道德行为",
  politically_sensitive: "敏感政治话题",
  copyright_violation: "版权违规",
  jailbreak: "Jailbreak",
};
const fusionLabels: Record<FusionReason, string> = {
  semantic_unsafe: "语义安全策略拦截",
  semantic_controversial: "语义争议，转人工复核",
  cpd_candidate: "Token 异常策略处置",
  all_clear: "双路证据均正常",
  semantic_unavailable_cpd_candidate: "语义不可用，按 Token 异常处置",
  semantic_unavailable_gateway_fail_safe: "语义防线不可用，网关转人工复核",
  semantic_unavailable_analysis_degraded: "语义防线不可用，分析模式降级放行",
};

const reportLabels = {
  off: "未生成",
  generated: "模型生成",
  fallback: "模板降级",
  unavailable: "不可用",
} as const;

function reportLabel(value: string | null | undefined) {
  return value && value in reportLabels
    ? reportLabels[value as keyof typeof reportLabels]
    : "--";
}

function shortHash(value: string) {
  const digest = value.startsWith("sha256:") ? value.slice(7) : value;
  return "sha256:" + digest.slice(0, 12) + "…";
}

function formatTime(value: string) {
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(new Date(value));
}

export function EventsPage() {
  const [data, setData] = useState<EventPage | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    api.events()
      .then((payload) => { if (active) setData(payload); })
      .catch((caught) => {
        if (active) setError(caught instanceof Error ? caught.message : "事件记录加载失败");
      });
    return () => { active = false; };
  }, []);

  return (
    <main className="page">
      <header className="page-header">
        <div>
          <h1>安全事件</h1>
          <p>只记录哈希、检测证据和处置元数据，不保存输入原文。</p>
        </div>
        <span className="privacy-mark"><LockKeyhole size={15} /> 脱敏审计</span>
      </header>

      <section className="stat-strip" aria-label="事件摘要">
        <div><span>记录总数</span><strong>{data?.total ?? "--"}</strong></div>
        <div><span>当前页</span><strong>{data?.items.length ?? "--"}</strong></div>
        <div><span>存储边界</span><strong>哈希与元数据</strong></div>
      </section>

      <section className="data-section">
        <div className="table-toolbar">
          <strong><Database size={16} /> 最近事件</strong>
          <span>{data ? data.total + " 条记录" : error ? "加载失败" : "正在载入"}</span>
        </div>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>时间</th>
                <th>请求 ID</th>
                <th>内容哈希</th>
                <th>检测状态</th>
                <th>语义状态</th>
                <th>语义类别</th>
                <th>CPD 分数</th>
                <th>异常起点</th>
                <th>处置</th>
                <th>融合原因</th>
                <th>知识快照</th>
                <th>报告状态</th>
                <th>校准版本</th>
              </tr>
            </thead>
            <tbody>
              {data?.items.map((event) => (
                <tr key={event.request_id}>
                  <td className="mono">{formatTime(event.created_at)}</td>
                  <td className="mono">{event.request_id}</td>
                  <td className="mono" title={event.prompt_sha256}>{shortHash(event.prompt_sha256)}</td>
                  <td>
                    <span className={"status-dot " + (event.detector_status === "token_anomaly_candidate" ? "alert" : "normal")} />
                    {event.detector_status === "token_anomaly_candidate" ? "Token 异常候选" : "未发现异常"}
                  </td>
                  <td>{event.semantic_severity ? semanticLabels[event.semantic_severity] : "--"}</td>
                  <td>{event.semantic_categories?.length ? event.semantic_categories.map((item) => categoryLabels[item]).join("、") : "--"}</td>
                  <td className="mono">{event.detector_score.toFixed(3)}</td>
                  <td className="mono">{event.onset_token === null ? "--" : "T" + event.onset_token}</td>
                  <td><span className={"status-badge status-" + event.decision}>{decisionLabels[event.decision]}</span></td>
                  <td>{event.fusion_reason ? fusionLabels[event.fusion_reason] : "--"}</td>
                  <td className="mono">{event.knowledge_snapshot_version ?? "--"}</td>
                  <td>{reportLabel(event.report_status)}</td>
                  <td className="mono">{event.calibration_version}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!data?.items.length && (
          <div className={"table-empty " + (error ? "error-state" : "")}>
            <FileWarning size={24} />
            {error ?? (data ? "暂无安全事件" : "正在加载事件记录")}
          </div>
        )}
      </section>
    </main>
  );
}
