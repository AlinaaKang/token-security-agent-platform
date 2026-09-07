from __future__ import annotations

import re

from app.schemas import MAX_PROMPT_CHARACTERS
from app.security_agent.models import AgentIntent, AgentTaskSnapshot, AgentTaskType


_BLANKS = re.compile(r"\s+")
_PUNCTUATION = str.maketrans({char: " " for char in "，。！？；：、,.!?;:"})


def _normalize(message: str) -> str:
    canonical = message.replace("\r\n", "\n").replace("\r", "\n").strip()
    if not canonical:
        raise ValueError("message must not be blank")
    if len(canonical) > MAX_PROMPT_CHARACTERS:
        raise ValueError("message is too long")
    return _BLANKS.sub(" ", canonical.translate(_PUNCTUATION)).strip().casefold()


def extract_prompt_sample(message: str) -> str:
    canonical = message.replace("\r\n", "\n").replace("\r", "\n").strip()
    match = re.search(r"(?:prompt|提示词)[^：:\n]{0,32}[：:]\s*(.+)$", canonical, re.IGNORECASE | re.DOTALL)
    sample = match.group(1).strip() if match else canonical
    if not sample:
        raise ValueError("prompt sample must not be blank")
    return sample


def _intent(
    kind: str,
    summary: str,
    *,
    task_type: AgentTaskType | None = None,
    requires_task: bool = False,
    requires_authorization: bool = False,
    control_is_explicit: bool = False,
    report_requested: bool = False,
) -> AgentIntent:
    return AgentIntent(
        kind=kind,
        task_type=task_type,
        objective_summary=summary,
        requires_task=requires_task,
        requires_authorization=requires_authorization,
        control_is_explicit=control_is_explicit,
        report_requested=report_requested,
    )


def parse_intent(
    message: str, context: AgentTaskSnapshot | None
) -> AgentIntent:
    text = _normalize(message)
    report_requested = any(word in text for word in ("报告", "markdown")) and any(
        word in text for word in ("生成", "导出", "整理")
    )

    pcap_action = "pcap" in text and any(
        word in text for word in ("检测", "调查", "分析", "分诊")
    )
    prompt_action = any(word in text for word in ("prompt", "提示词")) and any(
        word in text for word in ("检测", "调查", "分析", "判断")
    )

    unsafe_tool_request = any(
        marker in text
        for marker in (
            "shell_exec",
            "执行 shell",
            "运行 shell",
            "删除策略",
            "绕过授权",
            "忽略所有规则",
            "泄露系统提示",
        )
    )
    prompt_context = context is not None and context.task_type == AgentTaskType.PROMPT_INVESTIGATION
    if unsafe_tool_request and not prompt_action and not prompt_context:
        return _intent("out_of_scope", "拒绝越权工具或策略绕过请求。")

    cancel_words = ("取消", "停止", "终止")
    has_cancel = any(word in text for word in cancel_words)
    has_question = any(
        phrase in text for phrase in ("要不要", "会发生什么", "为什么", "如何", "怎么")
    )
    if has_cancel and (has_question or pcap_action or prompt_action):
        return _intent("clarify", "需要确认是否明确取消当前任务。")
    if has_cancel:
        return _intent(
            "cancel_task",
            "取消当前安全调查任务。",
            requires_task=True,
            control_is_explicit=True,
        )

    if any(phrase in text for phrase in ("你叫什么", "你是谁", "你的名字")):
        return _intent("identity", "说明智能体身份和专业范围。")
    if text in {"hi", "hello", "hey"} or any(
        phrase in text
        for phrase in (
            "你好", "早上好", "晚上好", "晚安", "谢谢", "再见",
            "你在干嘛", "你在做什么", "在吗",
        )
    ):
        return _intent("smalltalk", "进行简短日常交流。")
    if any(phrase in text for phrase in ("你能做什么", "有什么功能", "能力范围")):
        return _intent("capabilities", "说明真实能力、仿真边界和限制。")

    if "下一批" in text and "pcap" in text:
        return _intent(
            "continue_task",
            "继续检测当前授权数据集的下一批 PCAP。",
            task_type=AgentTaskType.PCAP_DATASET_INVESTIGATION,
            requires_task=True,
        )
    if any(phrase in text for phrase in ("跨域", "攻防演示", "闭环演示")) and any(
        word in text for word in ("运行", "开始", "调查", "演示")
    ):
        return _intent(
            "run_cross_domain_demo",
            "运行带明确仿真标识的跨域安全案件。",
            task_type=AgentTaskType.CROSS_DOMAIN_CASE,
            requires_task=True,
            requires_authorization=True,
            report_requested=True,
        )
    if not pcap_action and not prompt_action and any(word in text for word in ("报告", "markdown")) and any(
        word in text for word in ("生成", "导出", "整理")
    ):
        return _intent(
            "generate_report",
            "基于当前案件的公开证据生成引用式报告。",
            task_type=AgentTaskType.REPORT_GENERATION,
            requires_task=True,
            report_requested=True,
        )
    if pcap_action:
        task_type = (
            AgentTaskType.PCAP_CAPTURE_INVESTIGATION
            if any(word in text for word in ("单个", "这个文件", "当前文件"))
            else AgentTaskType.PCAP_DATASET_INVESTIGATION
        )
        return _intent(
            "investigate_pcap_capture"
            if task_type is AgentTaskType.PCAP_CAPTURE_INVESTIGATION
            else "investigate_pcap_dataset",
            "调查授权范围内的 PCAP 证据。",
            task_type=task_type,
            requires_task=True,
            requires_authorization=True,
            report_requested=report_requested,
        )
    if prompt_action:
        return _intent(
            "investigate_prompt",
            "分析用户提交的 Prompt 安全风险。",
            task_type=AgentTaskType.PROMPT_INVESTIGATION,
            requires_task=True,
            requires_authorization=True,
            report_requested=report_requested,
        )

    if prompt_context and not has_question and not report_requested:
        return _intent(
            "investigate_prompt",
            "分析用户提交的 Prompt 安全风险。",
            task_type=AgentTaskType.PROMPT_INVESTIGATION,
            requires_task=True,
            requires_authorization=True,
            report_requested=report_requested,
        )

    if context is not None:
        return _intent(
            "case_question",
            "结合当前案件上下文回答用户追问。",
            task_type=context.task_type,
            requires_task=True,
        )

    if any(phrase in text for phrase in ("提示词注入", "prompt injection", "越狱攻击", "xss", "ssrf")):
        return _intent("explain_attack", "解释安全攻击的机制、迹象和防护方式。")
    if "packet" in text or ("数据包" in text and any(word in text for word in ("什么", "解释", "含义"))):
        return _intent(
            "explain_pcap",
            "解释当前 PCAP 数据包范围和证据含义。",
            task_type=AgentTaskType.PCAP_CAPTURE_INVESTIGATION,
        )
    if any(word in text for word in ("为什么", "依据", "证据")) and any(
        word in text for word in ("高风险", "异常", "1482", "这个")
    ):
        return _intent(
            "explain_current_evidence",
            "解释当前案件结论的证据、反证和限制。",
            requires_task=True,
        )

    return _intent("out_of_scope", "请求不属于当前安全调查智能体的专业范围。")
