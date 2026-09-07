import { FileText, ScanSearch, ShieldCheck, Split, Wrench } from "lucide-react";
import { useState } from "react";

import type { AgentEvidence, AgentTaskSnapshot } from "../agent/types";
import { AgentEvidenceInspector } from "./AgentEvidenceInspector";
import { AgentHypothesisPanel } from "./AgentHypothesisPanel";
import { AgentReportInspector } from "./AgentReportInspector";
import { AgentToolInspector } from "./AgentToolInspector";

const tabs = [
  { id: "guard", label: "Guard", Icon: ShieldCheck },
  { id: "token", label: "Token", Icon: ScanSearch },
  { id: "review", label: "复核", Icon: Split },
  { id: "tools", label: "工具", Icon: Wrench },
  { id: "report", label: "报告", Icon: FileText },
] as const;

function evidenceFor(evidence: AgentEvidence[], mode: "guard" | "token") {
  const pattern = mode === "guard" ? /(guard|semantic|语义)/i : /(token|cpd|entropy|nll)/i;
  return evidence.filter((item) => pattern.test(`${item.source_type} ${item.tool_id ?? ""} ${item.summary}`));
}

export function AgentPromptInspector({ task }: { task: AgentTaskSnapshot }) {
  const [tab, setTab] = useState<(typeof tabs)[number]["id"]>("guard");
  return <div className="agent-inspector-case agent-specialized-inspector">
    <nav aria-label="Prompt 调查检查器视图">{tabs.map(({ id, label, Icon }) => <button key={id} type="button" aria-label={label} aria-pressed={tab === id} onClick={() => setTab(id)} title={label}><Icon size={15} /><span>{label}</span></button>)}</nav>
    <div className="agent-inspector-content">
      {tab === "guard" ? <AgentEvidenceInspector evidence={evidenceFor(task.evidence, "guard")} /> : null}
      {tab === "token" ? <AgentEvidenceInspector evidence={evidenceFor(task.evidence, "token")} /> : null}
      {tab === "review" ? <AgentHypothesisPanel hypotheses={task.hypotheses} /> : null}
      {tab === "tools" ? <AgentToolInspector plan={task.plan} observations={task.observations} /> : null}
      {tab === "report" ? <AgentReportInspector report={task.report} /> : null}
    </div>
  </div>;
}
