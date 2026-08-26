from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.schemas import AnalysisRequest, AnalysisResult, Provenance


def test_analysis_request_defaults_knowledge_mode_to_off() -> None:
    request = AnalysisRequest(prompt="safe text", model_id="qwen2.5-7b")

    assert request.knowledge_mode == "off"


def test_analysis_request_rejects_unknown_knowledge_mode() -> None:
    with pytest.raises(ValidationError):
        AnalysisRequest(
            prompt="safe text",
            model_id="qwen2.5-7b",
            knowledge_mode="online",
        )


def test_analysis_request_rejects_blank_prompt() -> None:
    with pytest.raises(ValidationError):
        AnalysisRequest(prompt="   ", model_id="qwen2.5-7b", mode="analysis")


def test_analysis_request_rejects_prompt_over_character_safety_limit() -> None:
    with pytest.raises(ValidationError):
        AnalysisRequest(prompt="x" * 32_769, model_id="qwen2.5-7b", mode="analysis")


def test_analysis_result_requires_provenance() -> None:
    payload = {
        "request_id": "req-1",
        "decision": "allow",
        "risk_score": 0.1,
        "signals": [],
        "evidence": [],
        "actions": ["allow"],
        "latency_ms": 12.5,
    }

    with pytest.raises(ValidationError):
        AnalysisResult.model_validate(payload)


def test_provenance_requires_calibration_identity() -> None:
    with pytest.raises(ValidationError):
        Provenance(
            model_id="qwen2.5-7b",
            tokenizer_id="qwen2.5-7b",
            system_prompt_hash="sha256:system",
            calibration_version="",
        )


def test_analysis_result_rejects_claimed_semantic_verification() -> None:
    payload = {
        "request_id": "req-1",
        "decision": "review",
        "risk_score": 1.0,
        "detector_score": 5.0,
        "detector_status": "token_anomaly_candidate",
        "semantic_verification": "confirmed_jailbreak",
        "signals": [],
        "evidence": [],
        "actions": ["review"],
        "provenance": {
            "model_id": "qwen2.5-7b",
            "tokenizer_id": "qwen2.5-7b",
            "system_prompt_hash": "sha256:system",
            "calibration_version": "cal-v1",
        },
        "latency_ms": 12.5,
    }

    with pytest.raises(ValidationError):
        AnalysisResult.model_validate(payload)


def test_analysis_result_accepts_only_normalized_semantic_evidence() -> None:
    result = AnalysisResult.model_validate(
        {
            "request_id": "req-1",
            "decision": "block",
            "risk_score": 0.0,
            "detector_score": 0.0,
            "detector_status": "no_token_anomaly",
            "semantic_severity": "unsafe",
            "semantic_categories": ["violent"],
            "semantic_model_id": "guard-model",
            "semantic_model_version": "guard-v1",
            "semantic_latency_ms": 4.0,
            "semantic_verification": "performed",
            "fusion_reason": "semantic_unsafe",
            "signals": [],
            "evidence": [],
            "actions": ["block"],
            "provenance": {
                "model_id": "qwen2.5-7b",
                "tokenizer_id": "qwen2.5-7b",
                "system_prompt_hash": "sha256:system",
                "calibration_version": "cal-v1",
            },
            "latency_ms": 12.5,
        }
    )

    assert result.semantic_categories == ["violent"]
    assert result.fusion_reason == "semantic_unsafe"
    assert result.knowledge_status == "off"
    assert result.report_status == "off"
    assert result.knowledge_evidence == []
