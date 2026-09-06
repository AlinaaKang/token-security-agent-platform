import { Check, Circle, CircleAlert, LoaderCircle, RotateCw, ShieldCheck } from "lucide-react";

import type { AgentPlanStep } from "../agent/types";

const statusCopy = {
  waiting: "等待执行",
  running: "正在执行",
  succeeded: "已完成",
  failed: "执行失败",
  skipped: "已跳过",
} as const;

function StepIcon({ status }: { status: AgentPlanStep["status"] }) {
  if (status === "succeeded") return <Check size={15} />;
  if (status === "running") return <LoaderCircle className="agent-spin" size={15} />;
  if (status === "failed") return <CircleAlert size={15} />;
  if (status === "skipped") return <RotateCw size={15} />;
  return <Circle size={14} />;
}

export function AgentPlan({ steps, revision = 0 }: { steps: AgentPlanStep[]; revision?: number }) {
  if (!steps.length) return null;
  return (
    <section className="agent-plan" aria-label="执行计划">
      <header>
        <div><ShieldCheck size={17} /><strong>公开执行计划</strong></div>
        <span>版本 {revision + 1} · 最多 12 步</span>
      </header>
      <ol>
        {steps.map((step, index) => (
          <li key={step.step_id} data-status={step.status}>
            <span className="agent-plan-index">{String(index + 1).padStart(2, "0")}</span>
            <span className="agent-plan-state"><StepIcon status={step.status} /></span>
            <div><strong>{step.summary}</strong><small>{statusCopy[step.status]}{step.attempt ? ` · 第 ${step.attempt} 次尝试` : ""}</small></div>
            {step.requires_authorization ? <span className="agent-plan-auth">需授权</span> : null}
          </li>
        ))}
      </ol>
    </section>
  );
}
