from __future__ import annotations

import hashlib
import json
import platform
import sqlite3
import statistics
import time
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.knowledge.models import KnowledgeId, KnowledgeSnapshot, RiskDomain
from app.knowledge.query import RetrievalMetadata, SafeQueryBuilder
from app.knowledge.retriever import LocalKnowledgeRetriever


EvaluationSplit = Literal["development", "test"]
TargetName = Literal["hit_at_3", "citation_validity", "decision_invariance"]
DecisionInvarianceBasis = Literal[
    "retrieval_has_no_decision_output",
    "legacy_unverified",
]


class KnowledgeEvaluationCase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: KnowledgeId
    risk_domain: RiskDomain
    safe_terms: tuple[str, ...] = Field(min_length=1)
    metadata: RetrievalMetadata
    expected_any_ids: tuple[KnowledgeId, ...] = Field(min_length=1)


class DomainRetrievalMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_count: int = Field(gt=0)
    hit_at_1: float = Field(ge=0, le=1, allow_inf_nan=False)
    hit_at_3: float = Field(ge=0, le=1, allow_inf_nan=False)


class KnowledgeEvaluationReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(ge=1, le=1)
    split: EvaluationSplit
    case_count: int = Field(gt=0)
    hit_at_1: float = Field(ge=0, le=1, allow_inf_nan=False)
    hit_at_3: float = Field(ge=0, le=1, allow_inf_nan=False)
    mrr: float = Field(ge=0, le=1, allow_inf_nan=False)
    citation_validity: float = Field(ge=0, le=1, allow_inf_nan=False)
    decision_invariance: float = Field(ge=0, le=1, allow_inf_nan=False)
    decision_invariance_basis: DecisionInvarianceBasis
    target_status: dict[TargetName, bool]
    domains: dict[RiskDomain, DomainRetrievalMetrics]
    snapshot_version: str = Field(min_length=1)
    snapshot_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    fixture_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    retrieval_weights: dict[str, float]
    latency_ms: dict[str, float]
    runtime_versions: dict[str, str]
    generated_report_count: int = Field(ge=0)
    fallback_report_count: int = Field(ge=0)

    @model_validator(mode="before")
    @classmethod
    def load_legacy_official_v1_report(cls, value: object) -> object:
        if not isinstance(value, dict) or value.get("snapshot_version") != "official-v1":
            return value
        migrated = dict(value)
        migrated.setdefault("split", "development")
        if (
            "decision_invariance_basis" not in value
            or "target_status" not in value
        ):
            migrated["decision_invariance_basis"] = "legacy_unverified"
            migrated["target_status"] = {
                "hit_at_3": migrated.get("hit_at_3", 0.0) >= 0.95,
                "citation_validity": migrated.get("citation_validity") == 1.0,
                "decision_invariance": False,
            }
        return migrated


def _digest_cases(cases: list[KnowledgeEvaluationCase]) -> str:
    payload = json.dumps(
        [case.model_dump(mode="json") for case in cases],
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    index = round((len(ordered) - 1) * percentile)
    return float(ordered[index])


def _contains_decision_field(value: object) -> bool:
    if isinstance(value, BaseModel):
        return _contains_decision_field(value.model_dump(mode="json"))
    if isinstance(value, dict):
        return any(
            str(key).casefold() == "decision" or _contains_decision_field(item)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_decision_field(item) for item in value)
    return False


def evaluate_knowledge(
    snapshot: KnowledgeSnapshot,
    cases: list[KnowledgeEvaluationCase],
    *,
    split: EvaluationSplit,
) -> KnowledgeEvaluationReport:
    if split not in ("development", "test"):
        raise ValueError("knowledge evaluation split must be development or test")
    if not cases:
        raise ValueError("knowledge evaluation cases must not be empty")
    case_ids = [case.case_id for case in cases]
    if len(case_ids) != len(set(case_ids)):
        raise ValueError("knowledge evaluation case IDs must be unique")
    snapshot_ids = {card.knowledge_id for card in snapshot.cards}
    if any(
        expected not in snapshot_ids
        for case in cases
        for expected in case.expected_any_ids
    ):
        raise ValueError("expected knowledge ID is absent from snapshot")

    retriever = LocalKnowledgeRetriever(snapshot)
    builder = SafeQueryBuilder()
    hits_1 = 0
    hits_3 = 0
    reciprocal_ranks: list[float] = []
    citation_count = 0
    valid_citation_count = 0
    latencies: list[float] = []
    domain_rows: dict[RiskDomain, list[tuple[bool, bool]]] = {}
    retrieval_has_no_decision_output = True
    for case in cases:
        started = time.perf_counter()
        query = builder.build(
            " ".join(case.safe_terms),
            char_onset=None,
            metadata=case.metadata,
        )
        evidence = retriever.search(query, top_k=3)
        retrieval_has_no_decision_output = (
            retrieval_has_no_decision_output
            and not _contains_decision_field(evidence)
        )
        latencies.append((time.perf_counter() - started) * 1000)
        returned_ids = [item.knowledge_id for item in evidence]
        expected_ids = set(case.expected_any_ids)
        rank = next(
            (
                index
                for index, knowledge_id in enumerate(returned_ids, start=1)
                if knowledge_id in expected_ids
            ),
            None,
        )
        hit_1 = rank == 1
        hit_3 = rank is not None and rank <= 3
        hits_1 += hit_1
        hits_3 += hit_3
        reciprocal_ranks.append(0.0 if rank is None else 1.0 / rank)
        citation_count += len(returned_ids)
        valid_citation_count += sum(item in snapshot_ids for item in returned_ids)
        domain_rows.setdefault(case.risk_domain, []).append((hit_1, hit_3))

    domains = {
        domain: DomainRetrievalMetrics(
            case_count=len(rows),
            hit_at_1=sum(row[0] for row in rows) / len(rows),
            hit_at_3=sum(row[1] for row in rows) / len(rows),
        )
        for domain, rows in sorted(domain_rows.items(), key=lambda item: item[0].value)
    }
    hit_at_3 = hits_3 / len(cases)
    citation_validity = (
        valid_citation_count / citation_count if citation_count else 1.0
    )
    decision_invariance = float(retrieval_has_no_decision_output)
    return KnowledgeEvaluationReport(
        schema_version=1,
        split=split,
        case_count=len(cases),
        hit_at_1=hits_1 / len(cases),
        hit_at_3=hit_at_3,
        mrr=statistics.fmean(reciprocal_ranks),
        citation_validity=citation_validity,
        decision_invariance=decision_invariance,
        decision_invariance_basis="retrieval_has_no_decision_output",
        target_status={
            "hit_at_3": hit_at_3 >= 0.95,
            "citation_validity": citation_validity == 1.0,
            "decision_invariance": decision_invariance == 1.0,
        },
        domains=domains,
        snapshot_version=snapshot.manifest.snapshot_version,
        snapshot_hash=snapshot.manifest.cards_sha256,
        fixture_hash=_digest_cases(cases),
        retrieval_weights={"tag": 2.0, "lexical": 1.0},
        latency_ms={
            "p50": _percentile(latencies, 0.5),
            "p95": _percentile(latencies, 0.95),
        },
        runtime_versions={
            "python": platform.python_version(),
            "sqlite": sqlite3.sqlite_version,
            "model": "not_applicable_retrieval_only",
        },
        generated_report_count=0,
        fallback_report_count=0,
    )
