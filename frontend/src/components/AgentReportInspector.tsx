import { ExternalLink, FileQuestion, FileText } from "lucide-react";

import type { AgentReportMetadata } from "../agent/types";

export function AgentReportInspector({ report }: { report: AgentReportMetadata | null }) {
  if (!report) return <div className="agent-inspector-zero"><FileQuestion size={20} /><strong>尚未生成报告</strong><p>完成调查后可生成带证据引用和限制说明的 Markdown 报告。</p></div>;
  const ready = report.status === "ready" && Boolean(report.artifact_ref);
  return <article className="agent-report-inspector"><span><FileText size={22} /></span><h3>{report.title}</h3><p>{ready ? "报告已生成，结论均保留公开证据引用。" : "报告暂不可用，请先完成至少一项可引用的调查证据。"}</p><dl><div><dt>状态</dt><dd>{report.status === "ready" ? "可用" : report.status === "degraded" ? "降级生成" : "不可用"}</dd></div><div><dt>格式</dt><dd>Markdown</dd></div><div><dt>证据</dt><dd>引用 {report.evidence_refs.length} 条证据</dd></div></dl>{ready ? <a href={`/api/v1/agent/reports/${encodeURIComponent(report.report_id)}`} target="_blank" rel="noreferrer">打开 Markdown 报告<ExternalLink size={14} /></a> : null}</article>;
}
