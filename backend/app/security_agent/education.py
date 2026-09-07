from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from app.security_agent.models import AgentEvidence, AgentIntent, AgentMessage


_EDUCATIONAL_INTENTS = {
    "identity",
    "smalltalk",
    "capabilities",
    "explain_attack",
    "explain_pcap",
    "explain_current_evidence",
    "clarify",
    "out_of_scope",
}


def _utc_now() -> datetime:
    return datetime.now(UTC)


class SecurityEducationService:
    def __init__(
        self,
        *,
        knowledge_service: Any | None = None,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._knowledge_service = knowledge_service
        self._clock = clock

    def answer(
        self,
        intent: AgentIntent,
        evidence: Iterable[AgentEvidence] = (),
    ) -> AgentMessage:
        if intent.kind not in _EDUCATIONAL_INTENTS:
            raise ValueError("not an educational intent")
        current = tuple(evidence)
        content, scope, references = self._render(intent.kind, current)
        created_at = self._clock().astimezone(UTC).isoformat().replace("+00:00", "Z")
        digest = sha256(f"{created_at}\0{intent.kind}\0{content}".encode()).hexdigest()[:16]
        return AgentMessage(
            message_id=f"msg_{digest}",
            role="agent",
            kind="question" if intent.kind == "clarify" else "message",
            content=content,
            created_at=created_at,
            evidence_scope=scope,
            evidence_refs=references,
        )

    def _render(
        self, kind: str, evidence: tuple[AgentEvidence, ...]
    ) -> tuple[str, str, tuple[str, ...]]:
        if kind == "identity":
            return (
                "我是 Token Security 安全智能体，专门协助调查大模型应用中的 Prompt、Token 与 PCAP 安全事件。",
                "general",
                (),
            )
        if kind == "smalltalk":
            return (
                "你好。我正在等待你的安全问题，也可以继续解释当前案件，或从一句调查目标开始建立计划。",
                "general",
                (),
            )
        if kind == "capabilities":
            return (
                "我可以执行真实 Prompt/Token 检测、受隔离的 PCAP 分诊、证据关联、攻击科普和引用式报告。"
                "端点、身份与日志目前是明确标注的仿真数据；尚未连接真实 EDR、防火墙或身份系统。",
                "general",
                (),
            )
        if kind == "explain_attack":
            return (
                "提示词注入是攻击者用输入诱导模型偏离原有安全指令的攻击。调查时需要同时查看语义意图、"
                "Token 异常、上下文位置和外部行为证据，单一关键词不能证明攻击成功。",
                "general",
                ("knowledge:owasp-llm01-prompt-injection",),
            )
        if kind == "explain_pcap":
            references = tuple(item.evidence_id for item in evidence)
            return (
                "packet 4-4 表示从第 4 个数据包到第 4 个数据包，也就是只引用一个包的数据包范围。"
                "它用于定位 Wireshark 中的证据，但一个数据包不能单独证明攻击成功。",
                "current_case" if references else "general",
                references,
            )
        if kind == "explain_current_evidence":
            if not evidence:
                return (
                    "当前还没有可引用的案件证据，因此不能解释为高风险；请先运行检测或选择已有案件。",
                    "current_case",
                    (),
                )
            summaries = "；".join(item.summary for item in evidence[:3])
            uncertainty = "；".join(item.uncertainty for item in evidence[:3])
            return (
                f"当前判断依据：{summaries}。限制：{uncertainty}",
                "current_case",
                tuple(item.evidence_id for item in evidence[:3]),
            )
        if kind == "clarify":
            return (
                "你是在询问取消的影响，还是要明确取消当前任务？只有明确取消才会停止后台执行。",
                "current_case",
                (),
            )
        return (
            "这个请求超出了我的专业范围。我可以进行简短日常交流和安全科普，但无法代替通用办公工具；"
            "我专注于大模型应用的安全调查、证据解释与处置建议。",
            "general",
            (),
        )
