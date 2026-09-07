import { ArrowRight, MessageCircleQuestion } from "lucide-react";

import type { AgentNextAction, AgentSuggestedQuestion } from "../agent/types";

type AgentNextStepsProps = {
  questions: AgentSuggestedQuestion[];
  actions: AgentNextAction[];
  busy: boolean;
  onQuestion: (message: string) => void;
  onAction: (actionId: AgentNextAction["action_id"]) => void;
};

export function AgentNextSteps({ questions, actions, busy, onQuestion, onAction }: AgentNextStepsProps) {
  if (!questions.length && !actions.length) return null;

  return (
    <section className="agent-next-steps" aria-label="智能体下一步建议">
      {questions.length ? <div className="agent-next-step-group" role="group" aria-label="推荐追问">
        <strong><MessageCircleQuestion size={15} />推荐追问</strong>
        <div>{questions.map((question) => <button type="button" key={question.question_id} disabled={busy} onClick={() => onQuestion(question.message)}>{question.label}</button>)}</div>
      </div> : null}
      {actions.length ? <div className="agent-next-step-group is-actions" role="group" aria-label="建议动作">
        <strong><ArrowRight size={15} />建议动作</strong>
        <div>{actions.map((action) => <span key={action.action_id}>
          <button type="button" disabled={busy || !action.enabled} title={action.disabled_reason ?? undefined} onClick={() => onAction(action.action_id)}>{action.label}<ArrowRight size={13} /></button>
          {!action.enabled && action.disabled_reason ? <small>{action.disabled_reason}</small> : null}
        </span>)}</div>
      </div> : null}
    </section>
  );
}
