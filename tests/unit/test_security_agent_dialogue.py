from __future__ import annotations

from app.security_agent.dialogue import GroundedDialogueService
from app.security_agent.models import AgentEvidence, AgentMessage, AgentObservation, AgentTaskSnapshot


class RecordingRuntime:
    def __init__(self, output: str = '{"answer":"最可能是路径穿越尝试，但尚不能证明攻击成功。"}') -> None:
        self.output = output
        self.messages: list[dict[str, str]] | None = None

    def generate_structured(self, messages, *, max_new_tokens, max_time_seconds):
        self.messages = messages
        assert max_new_tokens <= 256
        assert max_time_seconds <= 5
        return self.output


class FailingRuntime:
    def generate_structured(self, messages, *, max_new_tokens, max_time_seconds):
        raise TimeoutError("generation timed out")


def task(*, evidence: bool = True, failed: bool = False) -> AgentTaskSnapshot:
    observations = (
        AgentObservation(
            observation_id="obs_01",
            kind="pcap_detection",
            status="failed" if failed else "succeeded",
            summary="PCAP 分析失败。" if failed else "发现路径回退序列。",
            observed_at="2026-09-07T08:00:00Z",
            tool_id="explain_pcap_capture",
            public_error_code="pcap_parse_failed" if failed else None,
        ),
    )
    evidence_items = (
        AgentEvidence(
            evidence_id="ev_packet_07",
            authenticity="real",
            source_type="pcap_detection",
            source_ref="detect_public",
            tool_id="explain_pcap_capture",
            summary="Packet 7-8 出现连续目录回退候选。",
            observed_at="2026-09-07T08:00:00Z",
            uncertainty="该候选不能单独证明攻击成功。",
            metadata={"start_packet": 7, "end_packet": 8},
        ),
    ) if evidence else ()
    return AgentTaskSnapshot(
        task_id="task_dialogue",
        version=1,
        task_type="pcap_capture_investigation",
        workspace_mode="pcap",
        status="degraded" if failed else "completed",
        title="PCAP 数据调查",
        objective_summary="定位异常 Packet 并研判攻击类型。",
        created_at="2026-09-07T08:00:00Z",
        updated_at="2026-09-07T08:00:00Z",
        messages=(
            AgentMessage(
                message_id="msg_private",
                role="user",
                content="PRIVATE_PROMPT_SENTINEL",
                created_at="2026-09-07T08:00:00Z",
            ),
            AgentMessage(
                message_id="msg_agent",
                role="agent",
                content="已完成公开证据整理。",
                created_at="2026-09-07T08:00:01Z",
            ),
        ),
        observations=observations,
        evidence=evidence_items,
        limitations=("TLS 未解密区域不可见。",),
    )


def test_model_receives_bounded_case_history_and_returns_grounded_message() -> None:
    runtime = RecordingRuntime()
    answer = GroundedDialogueService(runtime).answer("可能是什么攻击类型？", task())

    assert "路径穿越" in answer.content
    assert answer.evidence_scope == "current_case"
    assert answer.evidence_refs == ("ev_packet_07",)
    serialized = str(runtime.messages)
    assert "Packet 7-8" in serialized
    assert "PRIVATE_PROMPT_SENTINEL" in serialized
    assert "start_packet" not in serialized


def test_missing_evidence_returns_actionable_case_answer_without_calling_a_model() -> None:
    runtime = RecordingRuntime()
    answer = GroundedDialogueService(runtime).answer("是什么攻击？", task(evidence=False))

    assert "属于当前 PCAP 调查范围" in answer.content
    assert "还没有可引用" in answer.content
    assert "上传" in answer.content or "检测" in answer.content
    assert runtime.messages is None


def test_generation_failure_falls_back_to_current_evidence_instead_of_scope_rejection() -> None:
    answer = GroundedDialogueService(FailingRuntime()).answer("用别的说法解释一下", task())

    assert "Packet 7-8" in answer.content
    assert "不能单独证明攻击成功" in answer.content
    assert "超出" not in answer.content


def test_failed_tool_is_distinguished_from_a_safe_result() -> None:
    answer = GroundedDialogueService(None).answer("结果怎么样？", task(evidence=False, failed=True))

    assert "执行失败" in answer.content
    assert "不能形成安全结论" in answer.content
