import type { AgentMessage, AgentTaskSnapshot } from "./types";

const STORAGE_KEY = "token-security:local-agent-conversations:v1";
const MAX_TASKS = 20;

type LocalUserMessage = {
  messageId: string;
  content: string;
  createdAt: string;
};

type LocalConversation = {
  taskId: string;
  updatedAt: string;
  messages: LocalUserMessage[];
};

function browserStorage(): Storage | undefined {
  try { return window.localStorage; } catch { return undefined; }
}

function read(storage: Storage | undefined): LocalConversation[] {
  try {
    const value = storage?.getItem(STORAGE_KEY);
    if (!value) return [];
    const parsed: unknown = JSON.parse(value);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((item): item is LocalConversation => {
      if (!item || typeof item !== "object") return false;
      const candidate = item as Partial<LocalConversation>;
      return typeof candidate.taskId === "string"
        && typeof candidate.updatedAt === "string"
        && Array.isArray(candidate.messages)
        && candidate.messages.every((message) => message
          && typeof message.messageId === "string"
          && typeof message.content === "string"
          && typeof message.createdAt === "string");
    });
  } catch {
    return [];
  }
}

function write(conversations: LocalConversation[], storage: Storage | undefined) {
  try {
    storage?.setItem(STORAGE_KEY, JSON.stringify(conversations.slice(0, MAX_TASKS)));
  } catch {
    // Local history is optional when storage is unavailable.
  }
}

export function rememberLocalUserMessage(
  taskId: string,
  content: string,
  createdAt: string,
  storage: Storage | undefined = browserStorage(),
) {
  const conversations = read(storage);
  const existing = conversations.find((item) => item.taskId === taskId);
  const messages = existing?.messages ?? [];
  const next: LocalConversation = {
    taskId,
    updatedAt: createdAt,
    messages: [...messages, {
      messageId: `local_${taskId}_${messages.length + 1}`,
      content,
      createdAt,
    }],
  };
  write([next, ...conversations.filter((item) => item.taskId !== taskId)], storage);
}

export function hasLocalConversation(
  taskId: string,
  storage: Storage | undefined = browserStorage(),
) {
  return read(storage).some((item) => item.taskId === taskId && item.messages.length > 0);
}

export function clearLocalConversation(
  taskId: string,
  storage: Storage | undefined = browserStorage(),
) {
  write(read(storage).filter((item) => item.taskId !== taskId), storage);
}

export function mergeLocalConversation(
  task: AgentTaskSnapshot,
  storage: Storage | undefined = browserStorage(),
): AgentTaskSnapshot {
  const local = read(storage).find((item) => item.taskId === task.task_id);
  if (!local?.messages.length) return task;
  let userIndex = 0;
  const messages = task.messages.map((message, serverIndex) => {
    if (message.role !== "user") return { message, sortAt: message.created_at, serverIndex };
    const replacement = local.messages[userIndex++];
    if (!replacement) return { message, sortAt: message.created_at, serverIndex };
    return {
      message: {
        ...message,
        message_id: replacement.messageId,
        content: replacement.content,
        created_at: replacement.createdAt,
      },
      sortAt: message.created_at,
      serverIndex,
    };
  });
  const remaining = local.messages.slice(userIndex).map((item) => ({
    message: {
      message_id: item.messageId,
      role: "user",
      kind: "message",
      content: item.content,
      created_at: item.createdAt,
      evidence_scope: "none",
      evidence_refs: [],
    } satisfies AgentMessage,
    sortAt: item.createdAt,
    serverIndex: null,
  }));
  return {
    ...task,
    messages: [...messages, ...remaining].sort((left, right) => {
      const order = left.sortAt.localeCompare(right.sortAt);
      if (order !== 0) return order;
      if (left.serverIndex !== null && right.serverIndex !== null) {
        return left.serverIndex - right.serverIndex;
      }
      return left.message.role === "user" && right.message.role !== "user" ? -1 : 1;
    }).map((item) => item.message),
  };
}
