from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from app.security_agent.models import AgentEvidence, EvidenceAuthenticity


class SimulatedCaseNotFound(KeyError):
    pass


class SimulatedSnapshotInvalid(ValueError):
    pass


class SimulatedEvidenceRejected(ValueError):
    pass


class SimulatedTelemetryConnector:
    def __init__(self, snapshot_path: Path | None = None) -> None:
        self._snapshot_path = snapshot_path or (
            Path(__file__).resolve().parents[3]
            / "data"
            / "demo"
            / "security-agent-cases.json"
        )
        self._raw = self._load()
        self.snapshot_version = _required_text(self._raw, "snapshot_version")
        self.snapshot_sha256 = _required_text(self._raw, "cases_sha256")
        cases = self._raw.get("cases")
        if self._raw.get("schema_version") != 1 or not isinstance(cases, list):
            raise SimulatedSnapshotInvalid("invalid simulated case schema")
        digest = _cases_digest(cases)
        if self.snapshot_sha256 != digest:
            raise SimulatedSnapshotInvalid("simulated case snapshot hash mismatch")
        self._cases = {
            _required_text(case, "case_id"): case
            for case in cases
            if isinstance(case, dict)
        }
        if len(self._cases) != len(cases):
            raise SimulatedSnapshotInvalid("simulated case IDs must be unique objects")

    def query(self, case_id: str) -> tuple[AgentEvidence, ...]:
        try:
            case = self._cases[case_id]
        except KeyError:
            raise SimulatedCaseNotFound(case_id) from None
        raw_evidence = case.get("evidence")
        if not isinstance(raw_evidence, list) or not raw_evidence:
            raise SimulatedSnapshotInvalid("simulated case must contain evidence")
        return tuple(
            AgentEvidence(
                evidence_id=_required_text(item, "evidence_id"),
                authenticity=EvidenceAuthenticity.SIMULATED,
                source_type=_required_text(item, "source_type"),
                source_ref=_required_text(item, "source_ref"),
                tool_id="query_simulated_telemetry",
                summary=_required_text(item, "summary"),
                observed_at=_required_text(item, "observed_at"),
                uncertainty=_required_text(item, "uncertainty"),
            )
            for item in raw_evidence
            if isinstance(item, dict)
        )

    def _load(self) -> dict[str, Any]:
        try:
            value = json.loads(self._snapshot_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SimulatedSnapshotInvalid("unable to load simulated case snapshot") from exc
        if not isinstance(value, dict):
            raise SimulatedSnapshotInvalid("simulated case snapshot must be an object")
        return value


def assert_real_evidence(evidence: Iterable[AgentEvidence]) -> None:
    for item in evidence:
        if item.authenticity is not EvidenceAuthenticity.REAL:
            raise SimulatedEvidenceRejected(
                "only real evidence may enter real evaluation collectors"
            )


def _cases_digest(cases: list[Any]) -> str:
    canonical = json.dumps(
        cases,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _required_text(value: dict[str, Any], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item.strip():
        raise SimulatedSnapshotInvalid(f"missing simulated case field: {key}")
    return item.strip()

