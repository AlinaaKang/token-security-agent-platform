import { Bot, CircleAlert, UserRound } from "lucide-react";

import type { AgentMessage } from "../agent/types";

export function AgentConversation({ messages }: { messages: AgentMessage[] }) {
  return (
    <section className="agent-conversation" aria-label="任务对话">
      {messages.map((message) => (
        <article key={message.message_id} className={`agent-message is-${message.role} is-${message.kind}`}>
          <span className="agent-message-avatar" aria-hidden="true">{message.role === "user" ? <UserRound size={17} /> : message.kind === "warning" ? <CircleAlert size={17} /> : <Bot size={17} />}</span>
          <div><strong>{message.role === "user" ? "你" : "Token Security"}</strong><p>{message.content}</p>{message.evidence_scope !== "none" ? <small>{message.evidence_scope === "current_case" ? "基于当前案件证据" : "通用安全知识"}</small> : null}</div>
        </article>
      ))}
    </section>
  );
}
