from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from pydantic import BaseModel

from app.security_agent.models import AgentEvidence, AgentObservation


_PRIVATE_OUTPUT_KEYS = frozenset(
    {
        "body",
        "filename",
        "file_path",
        "hash",
        "header",
        "ip",
        "ip_address",
        "mac",
        "path",
        "payload",
        "port",
        "prompt",
        "raw_output",
        "sha256",
        "stderr",
        "token_id",
        "token_ids",
        "token_text",
        "uri",
    }
)


def adapt_tool_output(tool_id: str, value: Any) -> dict[str, Any]:
    raw = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    if not isinstance(raw, Mapping):
        raise ValueError("adapter output must be a structured object")
    _reject_private_output(raw)
    objective_id = _as_optional_text(raw.get("objective"))
    source_ref = _source_ref(tool_id, raw)
    observed_at = _as_optional_text(raw.get("created_at")) or _timestamp()
    status = _observation_status(raw.get("status"))
    evidence = _translate_evidence(tool_id, raw, source_ref, observed_at)
    summary = _summary(tool_id, raw, evidence)
    observation_id = "obs_" + uuid5(
        NAMESPACE_URL, f"security-agent:{tool_id}:{source_ref}:{summary}"
    ).hex
    return {
        "objective_id": objective_id,
        "observation": AgentObservation(
            observation_id=observation_id,
            kind=_observation_kind(tool_id, raw, evidence),
            status=status,
            summary=summary,
            observed_at=observed_at,
            tool_id=tool_id,
            evidence_refs=tuple(item.evidence_id for item in evidence),
            retryable=status in {"failed", "unavailable"},
            public_error_code=_as_optional_text(raw.get("failure_code")),
        ),
        "evidence": evidence,
    }


def _translate_evidence(
    tool_id: str,
    raw: Mapping[str, Any],
    source_ref: str,
    observed_at: str,
) -> tuple[AgentEvidence, ...]:
    summary = raw.get("summary")
    candidates = summary.get("evidence", ()) if isinstance(summary, Mapping) else ()
    if not isinstance(candidates, (list, tuple)):
        raise ValueError("adapter output evidence must be a list")
    translated: list[AgentEvidence] = []
    for index, candidate in enumerate(candidates):
        if not isinstance(candidate, Mapping):
            raise ValueError("adapter output evidence item must be an object")
        evidence_id = _as_optional_text(candidate.get("evidence_id"))
        if evidence_id is None:
            evidence_id = f"ev_{uuid5(NAMESPACE_URL, f'{source_ref}:{index}').hex}"
        attack = _as_optional_text(candidate.get("attack_candidate")) or "anomaly_candidate"
        detector = _as_optional_text(candidate.get("detector")) or tool_id
        metadata = {
            key: candidate[key]
            for key in (
                "confidence",
                "start_packet",
                "end_packet",
                "purpose_candidates",
                "supporting_signals",
            )
            if key in candidate
        }
        translated.append(
            AgentEvidence(
                evidence_id=evidence_id,
                authenticity="simulated" if tool_id == "query_simulated_telemetry" else (
                    "derived"
                    if tool_id
                    in {
                        "explain_attack",
                        "explain_protocol",
                        "generate_case_report",
                        "map_attack_framework",
                        "search_similar_cases",
                        "simulate_response_options",
                    }
                    else "real"
                ),
                source_type=detector,
                source_ref=source_ref,
                tool_id=tool_id,
                summary=f"{attack} 异常候选，由 {detector} 产生。",
                observed_at=observed_at,
                uncertainty="该证据表示检测候选，不单独证明攻击成功。",
                metadata=metadata,
            )
        )
    return tuple(translated)


def _source_ref(tool_id: str, raw: Mapping[str, Any]) -> str:
    for key in ("detection_id", "recon_id", "mission_id", "run_id", "report_id"):
        value = _as_optional_text(raw.get(key))
        if value is not None:
            return value
    return f"tool:{tool_id}"


def _summary(
    tool_id: str, raw: Mapping[str, Any], evidence: tuple[AgentEvidence, ...]
) -> str:
    summary = raw.get("summary")
    if isinstance(summary, Mapping):
        analyzed = summary.get("analyzed_count")
        failed = summary.get("failed_count")
        if isinstance(analyzed, int):
            return f"{tool_id} 已处理 {analyzed} 项，发现 {len(evidence)} 条候选，失败 {failed or 0} 项。"
    text = _as_optional_text(summary)
    return text or f"{tool_id} 已返回结构化观察。"


def _observation_kind(
    tool_id: str, raw: Mapping[str, Any], evidence: tuple[AgentEvidence, ...]
) -> str:
    if tool_id == "detect_pcap_batch" and evidence:
        return "http_candidate"
    if raw.get("failure_code"):
        return "temporary_tool_failure"
    return f"{tool_id}_completed"


def _observation_status(value: Any) -> str:
    normalized = str(getattr(value, "value", value or "succeeded")).casefold()
    if normalized in {"completed", "succeeded", "ready", "running", "queued"}:
        return "succeeded"
    if normalized in {"unavailable"}:
        return "unavailable"
    if normalized in {"degraded"}:
        return "degraded"
    return "failed"


def _reject_private_output(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if str(key).casefold() in _PRIVATE_OUTPUT_KEYS:
                raise ValueError(f"adapter output contains private field: {key}")
            _reject_private_output(nested)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            _reject_private_output(nested)


def _as_optional_text(value: Any) -> str | None:
    raw = getattr(value, "value", value)
    return str(raw) if raw is not None and str(raw).strip() else None


def _timestamp() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")

