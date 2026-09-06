import { CircleAlert, CheckCircle2, Clock3, Wrench } from "lucide-react";

import type { AgentObservation, AgentPlanStep } from "../agent/types";

export function AgentToolInspector({ plan, observations }: { plan: AgentPlanStep[]; observations: AgentObservation[] }) {
  if (!plan.length && !observations.length) return <div className="agent-inspector-zero"><Wrench size={20} /><strong>尚无工具活动</strong><p>知识问答不会调用检测或处置工具。</p></div>;
  return <div className="agent-tool-list">{plan.map((step) => {
    const observation = observations.find((item) => item.tool_id === step.tool_id);
    const Icon = step.status === "succeeded" ? CheckCircle2 : step.status === "failed" ? CircleAlert : Clock3;
    return <article key={step.step_id} data-status={step.status}><header><Icon size={14} /><strong>{step.tool_id ?? "内部规划步骤"}</strong><span>{step.status}</span></header><p>{step.summary}</p>{observation ? <div><strong>观察</strong><p>{observation.summary}</p>{observation.public_error_code ? <code>{observation.public_error_code}</code> : null}</div> : null}</article>;
  })}</div>;
}
