from __future__ import annotations

import time
from typing import Any

from app.agent.fusion import EvidenceFusionPolicy
from app.agent.policy import BasicPolicy
from app.detection.calibration import CalibrationProfile
from app.detection.cpd import run_cpd
from app.schemas import (
    AnalysisRequest,
    AnalysisResult,
    Evidence,
    Provenance,
    SuspiciousSpan,
    TokenSignal,
)
from app.semantic.models import SemanticGuard, SemanticSeverity


def merge_knowledge_enhancement(
    basic_result: AnalysisResult,
    enhancement: Any,
) -> AnalysisResult:
    return AnalysisResult.model_validate(
        {
            **basic_result.model_dump(mode="json"),
            **enhancement.model_dump(mode="json"),
        }
    )


class BasicSecurityWorkflow:
    def __init__(
        self,
        *,
        runtime: Any,
        calibration: CalibrationProfile,
        policy: BasicPolicy,
        semantic_guard: SemanticGuard,
        fusion_policy: EvidenceFusionPolicy,
        system_prompt: str,
        knowledge_service: Any | None = None,
    ) -> None:
        self.runtime = runtime
        self.calibration = calibration
        self.policy = policy
        self.semantic_guard = semantic_guard
        self.fusion_policy = fusion_policy
        self.system_prompt = system_prompt
        self.knowledge_service = knowledge_service

    def analyze(self, request: AnalysisRequest, *, request_id: str) -> AnalysisResult:
        started = time.perf_counter()
        if request.model_id != self.calibration.model_id:
            raise ValueError("request model_id does not match the calibration profile")

        semantic = self.semantic_guard.assess(request.prompt)
        observation = self.runtime.score_prompt(self.system_prompt, request.prompt)
        self.calibration.ensure_compatible(
            model_id=observation.model_id,
            tokenizer_id=observation.tokenizer_id,
            system_prompt_hash=observation.system_prompt_hash,
        )
        entropies = [token.entropy for token in observation.user_tokens]
        trace = run_cpd(
            entropies,
            self.calibration.baseline,
            k=self.calibration.k,
            h=self.calibration.h,
        )
        risk_score = min(trace.score / self.calibration.h, 1.0)
        has_alarm = trace.alarm_index is not None
        action, fusion_reason = self.fusion_policy.decide(
            mode=request.mode,
            semantic=semantic.severity,
            cpd_alarm=has_alarm,
        )

        suspicious_span = None
        if trace.onset_index is not None:
            onset_token = observation.user_tokens[trace.onset_index]
            final_token = observation.user_tokens[-1]
            suspicious_span = SuspiciousSpan(
                token_start=trace.onset_index,
                token_end=len(observation.user_tokens),
                char_start=onset_token.char_start,
                char_end=final_token.char_end,
            )

        signals = [
            TokenSignal(
                index=token.user_index,
                token_id=token.token_id,
                token_text=token.token_text,
                entropy=token.entropy,
                nll=token.nll,
                cpd_entropy=trace.cumulative[token.user_index],
                cpd_nll=0.0,
                risk=min(
                    trace.cumulative[token.user_index] / self.calibration.h,
                    1.0,
                ),
            )
            for token in observation.user_tokens
        ]
        alarm_text = (
            str(trace.alarm_index) if trace.alarm_index is not None else "none"
        )
        onset_text = (
            str(trace.onset_index) if trace.onset_index is not None else "none"
        )
        evidence = [
            Evidence(
                source="entropy_cpd",
                summary=(
                    f"CUSUM score={trace.score:.4f}; "
                    f"alarm_token={alarm_text}; onset_token={onset_text}"
                ),
            )
        ]
        basic_result = AnalysisResult(
            request_id=request_id,
            decision=action.value,
            risk_score=risk_score,
            detector_score=trace.score,
            detector_status=(
                "token_anomaly_candidate" if has_alarm else "no_token_anomaly"
            ),
            semantic_severity=semantic.severity,
            semantic_categories=semantic.categories,
            semantic_model_id=semantic.model_id,
            semantic_model_version=semantic.model_version,
            semantic_latency_ms=semantic.latency_ms,
            semantic_verification=(
                "unavailable"
                if semantic.severity is SemanticSeverity.UNAVAILABLE
                else "performed"
            ),
            fusion_reason=fusion_reason,
            suspicious_span=suspicious_span,
            signals=signals,
            evidence=evidence,
            actions=[action.value],
            provenance=Provenance(
                model_id=observation.model_id,
                tokenizer_id=observation.tokenizer_id,
                system_prompt_hash=observation.system_prompt_hash,
                calibration_version=self.calibration.version,
                thresholds={"k": self.calibration.k, "h": self.calibration.h},
            ),
            latency_ms=(time.perf_counter() - started) * 1000,
        )
        if request.knowledge_mode.value == "off":
            return basic_result
        if self.knowledge_service is None:
            return basic_result.model_copy(
                update={
                    "knowledge_status": "unavailable",
                    "report_status": "unavailable",
                }
            )
        enhancement = self.knowledge_service.enhance(
            prompt=request.prompt,
            result=basic_result,
            mode=request.knowledge_mode,
            work_mode=request.mode,
        )
        return merge_knowledge_enhancement(basic_result, enhancement)
