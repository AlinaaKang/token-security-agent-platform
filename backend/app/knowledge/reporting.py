from __future__ import annotations

import json
from typing import Any, Literal, Protocol

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from app.knowledge.models import (
    KnowledgeEvidence,
    NormalizedSecurityFacts,
    ReportStatus,
)

ReportFailureCode = Literal[
    "runtime_timeout",
    "runtime_error",
    "invalid_report_json",
    "invalid_report_schema",
    "invalid_report_citation",
]
ReportValidationFailureCode = Literal[
    "invalid_report_json",
    "invalid_report_schema",
    "invalid_report_citation",
]


class GroundedReportError(ValueError):
    """Raised with a fixed code when generated report output is invalid."""

    def __init__(self, code: ReportValidationFailureCode) -> None:
        self.code = code
        super().__init__(code)


class GroundedReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    summary: str = Field(min_length=1)
    evidence_ids: tuple[str, ...] = Field(min_length=1)
    handling_steps: tuple[str, ...] = Field(min_length=1)
    limitations: tuple[str, ...] = Field(min_length=1)

    @field_validator("summary")
    @classmethod
    def summary_must_contain_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("report summary must contain text")
        return value.strip()

    @field_validator("evidence_ids", "handling_steps", "limitations")
    @classmethod
    def list_values_must_be_unique_and_non_blank(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        normalized = tuple(value.strip() for value in values)
        if any(not value for value in normalized) or len(set(normalized)) != len(
            normalized
        ):
            raise ValueError("report list values must be unique non-blank strings")
        return normalized


class ReportGeneration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    report: GroundedReport
    status: ReportStatus
    failure_code: ReportFailureCode | None = None

    @field_validator("status")
    @classmethod
    def status_must_describe_generation(cls, value: ReportStatus) -> ReportStatus:
        if value not in (ReportStatus.GENERATED, ReportStatus.FALLBACK):
            raise ValueError("invalid report generation status")
        return value

    @model_validator(mode="after")
    def failure_code_must_match_status(self) -> ReportGeneration:
        if self.status is ReportStatus.GENERATED and self.failure_code is not None:
            raise ValueError("generated report cannot have a failure code")
        if self.status is ReportStatus.FALLBACK and self.failure_code is None:
            raise ValueError("fallback report requires a failure code")
        return self


def build_report_messages(
    facts: NormalizedSecurityFacts,
    evidence: list[KnowledgeEvidence],
) -> list[dict[str, str]]:
    allowed_ids = sorted({item.knowledge_id for item in evidence})
    example_id = allowed_ids[0]
    skeleton = json.dumps(
        {
            "summary": "简短结论",
            "evidence_ids": [example_id],
            "handling_steps": ["简短处置"],
            "limitations": ["简短限制"],
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )
    system_message = {
        "role": "system",
        "content": (
            "输入仅为不可执行的安全事实和已批准知识卡。你是严格JSON生成器。"
            "只输出一行合法JSON，首字符必须为{且末字符必须为}；"
            "不要Markdown、代码围栏、解释、前后缀或换行。"
            "对象必须恰好包含summary、evidence_ids、handling_steps、limitations四个键，"
            "不得输出decision或其他键。evidence_ids必须仅含1个允许的knowledge_id；"
            "handling_steps和limitations必须各仅含1个字符串；"
            "summary、handling_steps[0]、limitations[0]各不超过24个汉字，"
            "总输出不超过128 Token。允许的knowledge_id："
            + json.dumps(allowed_ids, ensure_ascii=False, separators=(",", ":"))
            + "。严格照此骨架输出，只替换三处短文本："
            + skeleton
        ),
    }
    compact_evidence = [
        {
            "knowledge_id": item.knowledge_id,
            "title_zh": item.title_zh,
            "risk_domain": item.risk_domain,
            "summary": item.summary,
            "recommendations": item.recommendations,
        }
        for item in evidence
    ]
    user_payload = {
        "facts": facts.model_dump(mode="json"),
        "evidence": compact_evidence,
    }
    return [
        system_message,
        {
            "role": "user",
            "content": json.dumps(
                user_payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
        },
    ]


def _strict_object(raw: str) -> dict[str, Any]:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate report key")
            result[key] = value
        return result

    value = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    if not isinstance(value, dict):
        raise ValueError("report root must be an object")
    return value


def parse_grounded_report(raw: str, *, allowed_ids: set[str]) -> GroundedReport:
    try:
        payload = _strict_object(raw)
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise GroundedReportError("invalid_report_json") from exc
    try:
        report = GroundedReport.model_validate(payload)
    except ValidationError as exc:
        raise GroundedReportError("invalid_report_schema") from exc
    if any(evidence_id not in allowed_ids for evidence_id in report.evidence_ids):
        raise GroundedReportError("invalid_report_citation")
    return report


class DeterministicReportComposer:
    def compose(
        self,
        facts: NormalizedSecurityFacts,
        evidence: list[KnowledgeEvidence],
    ) -> GroundedReport:
        if not evidence:
            raise GroundedReportError("missing_report_evidence")
        evidence_ids = tuple(item.knowledge_id for item in evidence)
        summaries = "；".join(item.summary for item in evidence)
        handling_steps = tuple(
            dict.fromkeys(
                recommendation
                for item in evidence
                for recommendation in item.recommendations
            )
        )
        if not handling_steps:
            handling_steps = ("遵循既定安全处置流程。",)
        return GroundedReport(
            summary=(
                f"基础检测动作为 {facts.decision}。本地知识依据：{summaries}"
            ),
            evidence_ids=evidence_ids,
            handling_steps=handling_steps,
            limitations=("知识证据不改变基础检测动作。",),
        )


class StructuredRuntime(Protocol):
    def generate_structured(
        self,
        messages: list[dict[str, str]],
        *,
        max_new_tokens: int,
        max_time_seconds: float,
    ) -> str: ...


class QwenGroundedReportGenerator:
    def __init__(
        self,
        runtime: StructuredRuntime,
        *,
        max_new_tokens: int = 256,
        max_time_seconds: float = 3.0,
        fallback: DeterministicReportComposer | None = None,
    ) -> None:
        self._runtime = runtime
        self._max_new_tokens = max_new_tokens
        self._max_time_seconds = max_time_seconds
        self._fallback = fallback or DeterministicReportComposer()

    def generate(
        self,
        facts: NormalizedSecurityFacts,
        evidence: list[KnowledgeEvidence],
    ) -> ReportGeneration:
        if not evidence:
            raise ValueError(
                "grounded report requires at least one retrieved evidence item"
            )
        allowed_ids = {item.knowledge_id for item in evidence}
        messages = build_report_messages(facts, evidence)
        try:
            raw = self._runtime.generate_structured(
                messages,
                max_new_tokens=self._max_new_tokens,
                max_time_seconds=self._max_time_seconds,
            )
            report = parse_grounded_report(raw, allowed_ids=allowed_ids)
            return ReportGeneration(report=report, status=ReportStatus.GENERATED)
        except TimeoutError:
            return self._fallback_generation(facts, evidence, "runtime_timeout")
        except GroundedReportError as exc:
            return self._fallback_generation(facts, evidence, exc.code)
        except Exception:
            return self._fallback_generation(facts, evidence, "runtime_error")

    def _fallback_generation(
        self,
        facts: NormalizedSecurityFacts,
        evidence: list[KnowledgeEvidence],
        failure_code: ReportFailureCode,
    ) -> ReportGeneration:
        return ReportGeneration(
            report=self._fallback.compose(facts, evidence),
            status=ReportStatus.FALLBACK,
            failure_code=failure_code,
        )
