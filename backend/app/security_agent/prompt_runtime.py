from __future__ import annotations

from threading import RLock
from typing import Any
from uuid import uuid4

from app.lab.counterfactual import CounterfactualRunner
from app.schemas import AnalysisRequest, AnalysisResult


class PromptAgentRuntime:
    """Process-local bridge between agent task references and the Prompt workflow."""

    def __init__(self, workflow: Any) -> None:
        self._workflow = workflow
        self._counterfactual = CounterfactualRunner(workflow)
        self._prompts: dict[str, str] = {}
        self._results: dict[str, AnalysisResult] = {}
        self._lock = RLock()

    def put(self, task_id: str, prompt: str) -> None:
        with self._lock:
            self._prompts[task_id] = prompt

    def discard(self, task_id: str) -> None:
        with self._lock:
            self._prompts.pop(task_id, None)
            self._results.pop(task_id, None)

    def clear(self) -> None:
        with self._lock:
            self._prompts.clear()
            self._results.clear()

    def analyze_prompt(self, arguments: dict[str, object]) -> dict[str, object]:
        task_id, prompt = self._resolve(arguments)
        result = self._workflow.analyze(
            AnalysisRequest(
                prompt=prompt,
                model_id=self._workflow.calibration.model_id,
                mode="analysis",
                knowledge_mode="off",
            ),
            request_id=f"agent_prompt_{uuid4().hex}",
        )
        with self._lock:
            self._results[task_id] = result
        risk_found = (
            result.decision != "allow"
            or result.detector_status == "token_anomaly_candidate"
            or result.semantic_severity not in {"safe", "unavailable"}
        )
        return {
            "objective": "prompt_investigation",
            "status": "completed",
            "observation_kind": "direct_attack_signal" if risk_found else "benign_business_pattern",
            "summary": {
                "analyzed_count": 1,
                "failed_count": 0,
                "evidence": [{
                    "evidence_id": f"ev_prompt_{task_id.removeprefix('task_')}",
                    "detector": "prompt_token_fusion",
                    "attack_candidate": "prompt_risk_candidate" if risk_found else "no_prompt_anomaly",
                    "summary": "Prompt 检测发现风险候选。" if risk_found else "Prompt 检测未发现风险候选。",
                    "confidence": round(result.risk_score, 4),
                    "decision": str(result.decision),
                    "risk_score": round(result.risk_score, 4),
                    "detector_score": round(result.detector_score, 4),
                    "detector_status": result.detector_status,
                    "semantic_severity": str(result.semantic_severity),
                    "calibration_version": result.provenance.calibration_version,
                    "supporting_signals": [
                        f"fusion_reason:{result.fusion_reason}",
                        f"semantic_verification:{result.semantic_verification}",
                    ],
                }],
            },
        }

    def counterfactual_recheck(self, arguments: dict[str, object]) -> dict[str, object]:
        task_id, prompt = self._resolve(arguments)
        with self._lock:
            original = self._results.get(task_id)
        if original is None:
            raise RuntimeError("prompt analysis result is unavailable")
        result = self._counterfactual.run(prompt=prompt, original=original, mode="analysis")
        return {
            "objective": "prompt_counterfactual_recheck",
            "status": "completed",
            "observation_kind": (
                "prompt_evidence_conflict" if result.interpretation == "unchanged"
                else "counterfactual_recheck_completed"
            ),
            "summary": {
                "analyzed_count": 1,
                "failed_count": 0,
                "evidence": [{
                    "evidence_id": f"ev_counterfactual_{task_id.removeprefix('task_')}",
                    "detector": "prompt_counterfactual",
                    "attack_candidate": f"counterfactual_{result.interpretation}",
                    "summary": f"反事实复核结果：{result.interpretation}。",
                    "confidence": round(abs(result.risk_score_delta or 0.0), 4),
                    "counterfactual_interpretation": result.interpretation,
                    "counterfactual_reason": result.reason,
                    "calibration_version": result.calibration_version,
                }],
            },
        }

    def _resolve(self, arguments: dict[str, object]) -> tuple[str, str]:
        reference = str(arguments.get("input_ref", ""))
        if not reference.startswith("transient:task_"):
            raise KeyError("invalid transient prompt reference")
        task_id = reference.removeprefix("transient:")
        with self._lock:
            prompt = self._prompts.get(task_id)
        if prompt is None:
            raise KeyError("transient prompt is unavailable")
        return task_id, prompt
