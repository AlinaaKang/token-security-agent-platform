import { Bot, CircleAlert, UserRound } from "lucide-react";

import type { AgentMessage, AgentNextAction, AgentSuggestedQuestion } from "../agent/types";
import { formatAgentMessageTime } from "../agent/messageTime";
import { AgentNextSteps } from "./AgentNextSteps";

type AgentConversationProps = {
  messages: AgentMessage[];
  localContentAvailable?: boolean;
  onClearLocalConversation?: () => void;
  suggestedQuestions?: AgentSuggestedQuestion[];
  nextActions?: AgentNextAction[];
  busy?: boolean;
  onQuestion?: (message: string) => void;
  onAction?: (actionId: AgentNextAction["action_id"]) => void;
  now?: Date;
};

export function AgentConversation({ messages, localContentAvailable = false, onClearLocalConversation, suggestedQuestions = [], nextActions = [], busy = false, onQuestion = () => undefined, onAction = () => undefined, now }: AgentConversationProps) {
  return (
    <section className="agent-conversation" aria-label="任务对话">
      {localContentAvailable ? <div className="agent-local-conversation-note"><span>原文已保存到当前案件，审计记录仍保持脱敏</span><button type="button" onClick={onClearLocalConversation}>清除浏览器副本</button></div> : null}
      {messages.map((message) => {
        const time = formatAgentMessageTime(message.created_at, now);
        const avatar = <span className="agent-message-avatar" aria-hidden="true">{message.role === "user" ? <UserRound size={17} /> : message.kind === "warning" ? <CircleAlert size={17} /> : <Bot size={17} />}</span>;
        const body = <div className="agent-message-body"><div className="agent-message-heading"><strong>{message.role === "user" ? "你" : "Token Security"}</strong><time dateTime={time.dateTime} title={time.full}>{time.short}</time></div><p>{message.content}</p>{message.evidence_scope !== "none" ? <small>{message.evidence_scope === "current_case" ? "基于当前案件证据" : "通用安全知识"}</small> : null}</div>;
        return <article key={message.message_id} className={`agent-message is-${message.role} is-${message.kind}`}>
          {message.role === "user" ? <>{body}{avatar}</> : <>{avatar}{body}</>}
        </article>;
      })}
      <AgentNextSteps questions={suggestedQuestions} actions={nextActions} busy={busy} onQuestion={onQuestion} onAction={onAction} />
    </section>
  );
}
