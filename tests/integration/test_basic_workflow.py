from __future__ import annotations

from app.agent.fusion import EvidenceFusionPolicy
from app.agent.policy import BasicPolicy
from app.agent.workflow import BasicSecurityWorkflow
from app.detection.calibration import CalibrationProfile
from app.detection.cpd import RobustBaseline
from app.model.runtime import ModelObservation
from app.model.token_stats import ObservedUserToken
from app.schemas import AnalysisRequest
from app.semantic.models import SemanticAssessment
from app.knowledge.service import KnowledgeEnhancement


class StaticRuntime:
    def __init__(self, entropies: list[float]) -> None:
        self.entropies = entropies
        self.calls = 0

    def score_prompt(self, system_prompt: str, user_prompt: str) -> ModelObservation:
        self.calls += 1
        tokens = tuple(
            ObservedUserToken(
                user_index=index,
                full_index=index + 1,
                token_id=index + 10,
                token_text=f"token-{index}",
                char_start=index * 5,
                char_end=(index + 1) * 5,
                entropy=entropy,
                nll=1.0,
            )
            for index, entropy in enumerate(self.entropies)
        )
        return ModelObservation(
            model_id="qwen-model",
            tokenizer_id="qwen-tokenizer",
            system_prompt_hash="sha256:system",
            system_entropies=(0.5, 1.0, 1.5),
            user_tokens=tokens,
            latency_ms=10.0,
        )


class StaticSemanticGuard:
    def __init__(self, assessment: SemanticAssessment) -> None:
        self.assessment = assessment
        self.calls = 0

    def assess(self, prompt: str) -> SemanticAssessment:
        self.calls += 1
        return self.assessment


def make_assessment(
    severity: str = "safe",
    categories: list[str] | None = None,
) -> SemanticAssessment:
    return SemanticAssessment(
        severity=severity,
        categories=categories or [],
        model_id="guard-model",
        model_version="guard-v1",
        latency_ms=4.0,
    )


def make_workflow(
    entropies: list[float],
    semantic: SemanticAssessment | None = None,
    knowledge_service=None,
) -> BasicSecurityWorkflow:
    profile = CalibrationProfile(
        version="cal-v1",
        model_id="qwen-model",
        tokenizer_id="qwen-tokenizer",
        system_prompt_hash="sha256:system",
        signal="entropy",
        baseline=RobustBaseline(median=0.0, mad_scale=1.0),
        k=0.5,
        h=4.0,
        created_at="2026-08-25T00:00:00Z",
        dataset_hash="sha256:dataset",
    )
    runtime = StaticRuntime(entropies)
    semantic_guard = StaticSemanticGuard(semantic or make_assessment())
    workflow = BasicSecurityWorkflow(
        runtime=runtime,
        calibration=profile,
        policy=BasicPolicy(review_threshold=0.5, block_threshold=0.8),
        semantic_guard=semantic_guard,
        fusion_policy=EvidenceFusionPolicy(),
        system_prompt="System policy",
        knowledge_service=knowledge_service,
    )
    workflow._test_runtime = runtime
    workflow._test_semantic_guard = semantic_guard
    return workflow


class StaticKnowledgeService:
    def enhance(
        self,
        *,
        prompt,
        result,
        mode,
        attack_family=None,
        work_mode="analysis",
    ):
        return KnowledgeEnhancement(
            knowledge_status="ready",
            knowledge_snapshot_version="official-v1",
            knowledge_latency_ms=2.0,
            knowledge_retrieval_latency_ms=1.5,
            knowledge_report_latency_ms=0.0,
            knowledge_evidence=({
                "knowledge_id": "owasp-llm01-prompt-injection",
                "title_zh": "提示词注入风险",
                "risk_domain": "prompt_injection",
                "summary": "公开安全摘要",
                "recommendations": ("保留基础动作。",),
                "source": {
                    "publisher": "owasp",
                    "title": "LLM01: Prompt Injection",
                    "url": "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
                    "version": "2025",
                    "verified_at": "2026-08-26T00:00:00Z",
                    "usage_note": "official summary",
                },
                "retrieval_score": 1.0,
                "matched_tags": ("jailbreak",),
            },),
            grounded_report=None,
            report_status="off",
        )


def test_knowledge_enhancement_preserves_complete_basic_result() -> None:
    baseline = make_workflow([0.0, 0.0, 3.0, 3.0]).analyze(
        AnalysisRequest(prompt="safe fixture", model_id="qwen-model"),
        request_id="req-off",
    )
    enhanced = make_workflow(
        [0.0, 0.0, 3.0, 3.0],
        knowledge_service=StaticKnowledgeService(),
    ).analyze(
        AnalysisRequest(
            prompt="safe fixture",
            model_id="qwen-model",
            knowledge_mode="evidence",
        ),
        request_id="req-on",
    )

    assert enhanced.decision == baseline.decision
    assert enhanced.detector_score == baseline.detector_score
    assert enhanced.suspicious_span == baseline.suspicious_span
    assert enhanced.semantic_severity == baseline.semantic_severity
    assert enhanced.semantic_categories == baseline.semantic_categories
    assert enhanced.knowledge_status == "ready"
    assert enhanced.knowledge_evidence[0].knowledge_id == (
        "owasp-llm01-prompt-injection"
    )


def test_basic_workflow_allows_stable_entropy_sequence() -> None:
    result = make_workflow([0.0, 0.1, 0.0]).analyze(
        AnalysisRequest(prompt="A harmless example", model_id="qwen-model"),
        request_id="req-normal",
    )

    assert result.decision.value == "allow"
    assert result.risk_score == 0.0
    assert result.detector_score == 0.0
    assert result.detector_status == "no_token_anomaly"
    assert result.semantic_severity == "safe"
    assert result.semantic_verification == "performed"
    assert result.fusion_reason == "all_clear"
    assert result.audit_persisted is False
    assert result.suspicious_span is None
    assert result.provenance.calibration_version == "cal-v1"


def test_basic_workflow_blocks_and_localizes_entropy_change() -> None:
    result = make_workflow([0.0, 0.0, 3.0, 3.0]).analyze(
        AnalysisRequest(prompt="A redacted test example", model_id="qwen-model"),
        request_id="req-attack",
    )

    assert result.decision.value == "block"
    assert result.risk_score == 1.0
    assert result.detector_score == 5.0
    assert result.detector_status == "token_anomaly_candidate"
    assert result.semantic_verification == "performed"
    assert result.fusion_reason == "cpd_candidate"
    assert result.suspicious_span is not None
    assert result.suspicious_span.token_start == 2
    assert result.suspicious_span.char_start == 10
    assert result.evidence[0].source == "entropy_cpd"


def test_basic_workflow_requires_review_for_gateway_anomaly_candidate() -> None:
    result = make_workflow([0.0, 0.0, 3.0, 3.0]).analyze(
        AnalysisRequest(
            prompt="A redacted test example",
            model_id="qwen-model",
            mode="gateway",
        ),
        request_id="req-gateway",
    )

    assert result.decision.value == "review"
    assert result.detector_score == 5.0
    assert result.detector_status == "token_anomaly_candidate"
    assert result.semantic_verification == "performed"
    assert result.fusion_reason == "cpd_candidate"


def test_basic_workflow_allows_before_cpd_alarm_threshold() -> None:
    result = make_workflow([0.0, 0.0, 4.0]).analyze(
        AnalysisRequest(prompt="A structured but harmless example", model_id="qwen-model"),
        request_id="req-pre-alarm",
    )

    assert result.risk_score == 0.875
    assert result.detector_score == 3.5
    assert result.detector_status == "no_token_anomaly"
    assert result.decision.value == "allow"
    assert result.suspicious_span is None


def test_basic_workflow_allows_gateway_request_without_cpd_alarm() -> None:
    result = make_workflow([0.0, 0.0, 4.0]).analyze(
        AnalysisRequest(
            prompt="A structured but harmless gateway example",
            model_id="qwen-model",
            mode="gateway",
        ),
        request_id="req-gateway-no-alarm",
    )

    assert result.detector_status == "no_token_anomaly"
    assert result.decision.value == "allow"


def test_basic_workflow_blocks_semantic_unsafe_without_token_anomaly() -> None:
    workflow = make_workflow(
        [0.0, 0.1, 0.0],
        make_assessment("unsafe", ["violent"]),
    )

    result = workflow.analyze(
        AnalysisRequest(prompt="A private fixture", model_id="qwen-model"),
        request_id="req-semantic",
    )

    assert result.detector_status == "no_token_anomaly"
    assert result.semantic_severity == "unsafe"
    assert result.semantic_categories == ["violent"]
    assert result.decision.value == "block"
    assert result.fusion_reason == "semantic_unsafe"
    assert workflow._test_runtime.calls == 1
    assert workflow._test_semantic_guard.calls == 1


def test_basic_workflow_reviews_controversial_semantic_result() -> None:
    result = make_workflow(
        [0.0, 0.1, 0.0],
        make_assessment("controversial", ["politically_sensitive"]),
    ).analyze(
        AnalysisRequest(prompt="A contextual fixture", model_id="qwen-model"),
        request_id="req-controversial",
    )

    assert result.decision.value == "review"
    assert result.fusion_reason == "semantic_controversial"


def test_basic_workflow_gateway_fails_safe_when_semantic_guard_unavailable() -> None:
    result = make_workflow(
        [0.0, 0.1, 0.0],
        make_assessment("unavailable"),
    ).analyze(
        AnalysisRequest(
            prompt="A gateway fixture",
            model_id="qwen-model",
            mode="gateway",
        ),
        request_id="req-unavailable",
    )

    assert result.detector_status == "no_token_anomaly"
    assert result.semantic_verification == "unavailable"
    assert result.decision.value == "review"
    assert result.fusion_reason == "semantic_unavailable_gateway_fail_safe"
