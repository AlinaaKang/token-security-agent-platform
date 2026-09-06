import { Clock3 } from "lucide-react";

import type { AgentTimelineEvent } from "../agent/types";
import { AuthenticityBadge } from "./AuthenticityBadge";

export function AgentAttackTimeline({ timeline }: { timeline: AgentTimelineEvent[] }) {
  if (!timeline.length) return <div className="agent-inspector-zero"><Clock3 size={20} /><strong>尚无跨源时间线</strong><p>端点、身份和日志演示材料会明确标记为仿真。</p></div>;
  return <ol className="agent-attack-timeline">{timeline.map((item) => <li key={item.timeline_id}><span /><div><header><time>{new Date(item.occurred_at).toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</time><AuthenticityBadge value={item.authenticity} /></header><strong>{item.source_type}</strong><p>{item.summary}</p></div></li>)}</ol>;
}
