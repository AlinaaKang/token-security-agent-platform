from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict

from app.lab.execution_models import (
    CanonicalEvidenceBundle,
    LabArtifact,
    LabCaseHandlingStatus,
    LabExecutionErrorCode,
    LabExecutionStatus,
    LabSecurityCase,
    LabToolExecution,
    canonical_evidence_bundle_bytes,
)
from app.lab.execution_store import SQLiteLabExecutionStore
from app.lab.models import LabRunResult, LabToolId
from app.schemas import Decision


GatewayReceiptKind = Literal[
    "allow_authorized",
    "review_queued",
    "sanitize_recheck_queued",
    "block_enforced",
]

_GATEWAY_RECEIPTS: dict[Decision, GatewayReceiptKind] = {
    Decision.ALLOW: "allow_authorized",
    Decision.REVIEW: "review_queued",
    Decision.SANITIZE_RECHECK: "sanitize_recheck_queued",
    Decision.BLOCK: "block_enforced",
}


class ExecutionBundle(BaseModel):
    """The in-memory result of a single platform-internal tool execution."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    execution: LabToolExecution
    newly_created: bool
    summary: Literal["平台内部执行"] = "平台内部执行"
    receipt_kind: GatewayReceiptKind | None = None
    security_case: LabSecurityCase | None = None
    artifact: LabArtifact | None = None


class LabToolExecutor:
    def __init__(self, store: SQLiteLabExecutionStore) -> None:
        self._store = store

    def execute(
        self, run: LabRunResult, tool_id: LabToolId, idempotency_key: UUID
    ) -> ExecutionBundle:
        started = time.perf_counter()
        created_at = datetime.now(UTC)
        source_action = run.detection.decision
        provenance = _execution_provenance(run)
        try:
            existing = self._store.get_by_idempotency(
                run.run_id, tool_id, idempotency_key
            )
        except Exception:
            return ExecutionBundle(
                execution=_new_persistence_failed_execution(
                    run,
                    tool_id,
                    idempotency_key,
                    provenance,
                    created_at,
                    latency_ms=(time.perf_counter() - started) * 1000,
                ),
                newly_created=False,
            )
        if existing is not None:
            return ExecutionBundle(
                execution=existing,
                newly_created=False,
                receipt_kind=(
                    _GATEWAY_RECEIPTS[existing.effective_action]
                    if tool_id is LabToolId.GATEWAY_ENFORCEMENT
                    and existing.receipt_id is not None
                    else None
                ),
            )

        execution = LabToolExecution(
            execution_id=_new_id("exec_"),
            run_id=run.run_id,
            tool_id=tool_id,
            idempotency_key=idempotency_key,
            status=LabExecutionStatus.SUCCEEDED,
            source_action=source_action,
            effective_action=source_action,
            model_provenance_sha256=provenance.model,
            calibration_provenance_sha256=provenance.calibration,
            knowledge_snapshot_sha256=provenance.snapshot,
            knowledge_ids=_knowledge_ids(run),
            receipt_id=_new_id("receipt_"),
            artifact_id=None,
            error_code=None,
            evidence_sha256=None,
            latency_ms=0.0,
            created_at=created_at,
        )
        security_case: LabSecurityCase | None = None
        artifact: LabArtifact | None = None
        receipt_kind: GatewayReceiptKind | None = None

        if tool_id is LabToolId.GATEWAY_ENFORCEMENT:
            receipt_kind = _GATEWAY_RECEIPTS[source_action]
        elif tool_id is LabToolId.SECURITY_CASE:
            security_case = _build_security_case(run, execution)
        elif tool_id is LabToolId.EVIDENCE_BUNDLE:
            try:
                prior_executions = self._store.list_executions(run.run_id)
            except Exception:
                return ExecutionBundle(
                    execution=_persistence_failed_execution(
                        execution, latency_ms=(time.perf_counter() - started) * 1000
                    ),
                    newly_created=False,
                )
            payload = self.canonical_evidence_bytes(run, prior_executions)
            artifact = LabArtifact(
                artifact_id=_new_id("artifact_"),
                run_id=run.run_id,
                execution_id=execution.execution_id,
                media_type="application/json",
                payload=payload,
                sha256=_sha256(payload),
                created_at=created_at,
            )
            execution = execution.model_copy(
                update={
                    "artifact_id": artifact.artifact_id,
                    "evidence_sha256": artifact.sha256,
                }
            )
        else:  # pragma: no cover - LabToolId is an exhaustive closed enum.
            raise ValueError(f"unsupported lab tool: {tool_id}")

        execution = execution.model_copy(
            update={"latency_ms": (time.perf_counter() - started) * 1000}
        )
        if security_case is not None:
            security_case = security_case.model_copy(
                update={"execution_id": execution.execution_id}
            )
        try:
            committed = self._store.commit_result(
                execution, security_case=security_case, artifact=artifact
            )
        except sqlite3.IntegrityError:
            try:
                existing = self._store.get_by_idempotency(
                    run.run_id, tool_id, idempotency_key
                )
            except Exception:
                existing = None
            if existing is not None:
                return ExecutionBundle(
                    execution=existing,
                    newly_created=False,
                    receipt_kind=(
                        _GATEWAY_RECEIPTS[existing.effective_action]
                        if tool_id is LabToolId.GATEWAY_ENFORCEMENT
                        and existing.receipt_id is not None
                        else None
                    ),
                )
            return ExecutionBundle(
                execution=_persistence_failed_execution(
                    execution, latency_ms=(time.perf_counter() - started) * 1000
                ),
                newly_created=False,
            )
        except Exception:
            return ExecutionBundle(
                execution=_persistence_failed_execution(
                    execution, latency_ms=(time.perf_counter() - started) * 1000
                ),
                newly_created=False,
            )
        if committed.execution_id != execution.execution_id:
            return ExecutionBundle(
                execution=committed,
                newly_created=False,
                receipt_kind=(
                    _GATEWAY_RECEIPTS[committed.effective_action]
                    if tool_id is LabToolId.GATEWAY_ENFORCEMENT
                    and committed.receipt_id is not None
                    else None
                ),
            )
        return ExecutionBundle(
            execution=committed,
            newly_created=True,
            receipt_kind=receipt_kind,
            security_case=security_case,
            artifact=artifact,
        )

    def canonical_evidence_bytes(
        self, run: LabRunResult, executions: tuple[LabToolExecution, ...]
    ) -> bytes:
        provenance = _execution_provenance(run)
        prior = tuple(sorted(executions, key=lambda item: item.execution_id))
        bundle = CanonicalEvidenceBundle(
            schema_version=1,
            artifact_kind="evidence_bundle",
            detector_status=run.detection.detector_status,
            risk_score=run.detection.risk_score,
            semantic_severity=run.detection.semantic_severity,
            semantic_categories=run.detection.semantic_categories,
            fusion_reason=run.detection.fusion_reason,
            effective_action=run.detection.decision,
            model_provenance_sha256=provenance.model,
            calibration_provenance_sha256=provenance.calibration,
            knowledge_snapshot_sha256=provenance.snapshot,
            knowledge_ids=_knowledge_ids(run),
            prior_execution_ids=tuple(item.execution_id for item in prior),
            prior_receipt_ids=tuple(
                item.receipt_id for item in prior if item.receipt_id is not None
            ),
        )
        return canonical_evidence_bundle_bytes(bundle)


class _ExecutionProvenance(BaseModel):
    model_config = ConfigDict(frozen=True)

    model: str
    calibration: str
    snapshot: str | None


def _execution_provenance(run: LabRunResult) -> _ExecutionProvenance:
    detection = run.detection
    return _ExecutionProvenance(
        model=_opaque_digest(
            "model",
            {
                "detector_model_id": detection.provenance.model_id,
                "semantic_model_id": detection.semantic_model_id,
                "semantic_model_version": detection.semantic_model_version,
            },
        ),
        calibration=_opaque_digest(
            "calibration", detection.provenance.calibration_version
        ),
        snapshot=(
            _opaque_digest("knowledge_snapshot", detection.knowledge_snapshot_version)
            if detection.knowledge_snapshot_version is not None
            else None
        ),
    )


def _build_security_case(
    run: LabRunResult, execution: LabToolExecution
) -> LabSecurityCase:
    span = run.detection.suspicious_span
    return LabSecurityCase(
        case_id=_new_id("case_"),
        run_id=run.run_id,
        created_at=execution.created_at,
        risk_score=run.detection.risk_score,
        semantic_severity=run.detection.semantic_severity,
        semantic_categories=run.detection.semantic_categories,
        detector_status=run.detection.detector_status,
        anomaly_char_start=None if span is None else span["char_start"],
        fusion_reason=run.detection.fusion_reason,
        effective_action=execution.effective_action,
        handling_status=LabCaseHandlingStatus.OPEN,
        knowledge_ids=execution.knowledge_ids,
        model_id=execution.model_provenance_sha256,
        calibration_version=execution.calibration_provenance_sha256,
        knowledge_snapshot_version=execution.knowledge_snapshot_sha256,
        execution_id=execution.execution_id,
        receipt_id=execution.receipt_id,
    )


def _persistence_failed_execution(
    execution: LabToolExecution, *, latency_ms: float
) -> LabToolExecution:
    return execution.model_copy(
        update={
            "execution_id": _failed_execution_id(execution.idempotency_key),
            "status": LabExecutionStatus.FAILED,
            "receipt_id": None,
            "artifact_id": None,
            "error_code": LabExecutionErrorCode.PERSISTENCE_FAILED,
            "evidence_sha256": None,
            "latency_ms": latency_ms,
        }
    )


def _new_persistence_failed_execution(
    run: LabRunResult,
    tool_id: LabToolId,
    idempotency_key: UUID,
    provenance: _ExecutionProvenance,
    created_at: datetime,
    *,
    latency_ms: float,
) -> LabToolExecution:
    return LabToolExecution(
        execution_id=_failed_execution_id(idempotency_key),
        run_id=run.run_id,
        tool_id=tool_id,
        idempotency_key=idempotency_key,
        status=LabExecutionStatus.FAILED,
        source_action=run.detection.decision,
        effective_action=run.detection.decision,
        model_provenance_sha256=provenance.model,
        calibration_provenance_sha256=provenance.calibration,
        knowledge_snapshot_sha256=provenance.snapshot,
        knowledge_ids=_knowledge_ids(run),
        receipt_id=None,
        artifact_id=None,
        error_code=LabExecutionErrorCode.PERSISTENCE_FAILED,
        evidence_sha256=None,
        latency_ms=latency_ms,
        created_at=created_at,
    )


def _knowledge_ids(run: LabRunResult) -> tuple[str, ...]:
    return tuple(item.knowledge_id for item in run.detection.knowledge_evidence)


def _new_id(prefix: str) -> str:
    return prefix + uuid4().hex


def _failed_execution_id(idempotency_key: UUID) -> str:
    return "failed_" + idempotency_key.hex


def _opaque_digest(namespace: str, value: object) -> str:
    encoded = json.dumps(
        {"namespace": namespace, "value": value},
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return _sha256(encoded)


def _sha256(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()
