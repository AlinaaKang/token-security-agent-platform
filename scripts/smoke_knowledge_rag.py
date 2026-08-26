from __future__ import annotations

import argparse
import json
import math
import re
import time
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any, Protocol


KNOWLEDGE_STATUSES = {"off", "ready", "unavailable", "degraded"}
REPORT_STATUSES = {"off", "generated", "fallback", "unavailable"}
KNOWLEDGE_ID_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
VERSION_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")


class JsonClient(Protocol):
    def get_json(self, url: str) -> dict[str, Any]: ...

    def post_json(self, url: str, payload: dict[str, Any]) -> dict[str, Any]: ...


class UrllibJsonClient:
    def get_json(self, url: str) -> dict[str, Any]:
        request = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(request, timeout=120) as response:
            return json.loads(response.read().decode("utf-8"))

    def post_json(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=300) as response:
            return json.loads(response.read().decode("utf-8"))


def _load_rows(path: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    identifiers: set[str] = set()
    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"row {line_number} must be an object")
            sample_id = value.get("sample_id")
            prompt = value.get("prompt")
            mode = value.get("mode", "analysis")
            if not isinstance(sample_id, str) or not sample_id.strip():
                raise ValueError(f"row {line_number} requires a non-empty sample_id")
            if sample_id in identifiers:
                raise ValueError("sample_id values must be unique")
            if not isinstance(prompt, str) or not prompt.strip():
                raise ValueError(f"row {line_number} requires non-empty private input")
            if mode not in {"analysis", "gateway"}:
                raise ValueError(f"row {line_number} has invalid mode")
            identifiers.add(sample_id)
            rows.append({"sample_id": sample_id, "prompt": prompt, "mode": mode})
    if not rows:
        raise ValueError("protected smoke input must contain at least one row")
    return rows


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return round(ordered[index], 3)


def _rate(matched: int, total: int) -> dict[str, int | float]:
    return {
        "matched": matched,
        "total": total,
        "rate": round(matched / total, 6) if total else 1.0,
    }


def _base_signature(response: dict[str, Any]) -> str:
    fields = {
        "decision": response.get("decision"),
        "detector_score": response.get("detector_score"),
        "detector_status": response.get("detector_status"),
        "suspicious_span": response.get("suspicious_span"),
        "semantic_severity": response.get("semantic_severity"),
        "semantic_categories": response.get("semantic_categories"),
        "semantic_verification": response.get("semantic_verification"),
        "fusion_reason": response.get("fusion_reason"),
    }
    return json.dumps(fields, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _validated_knowledge(response: dict[str, Any]) -> tuple[str, str, list[str], list[str]]:
    knowledge_status = response.get("knowledge_status")
    report_status = response.get("report_status")
    if knowledge_status not in KNOWLEDGE_STATUSES or report_status not in REPORT_STATUSES:
        raise ValueError("invalid knowledge response status")
    evidence = response.get("knowledge_evidence")
    if not isinstance(evidence, list) or len(evidence) > 3:
        raise ValueError("invalid knowledge evidence")
    card_ids: list[str] = []
    for item in evidence:
        knowledge_id = item.get("knowledge_id") if isinstance(item, dict) else None
        if not isinstance(knowledge_id, str) or not KNOWLEDGE_ID_PATTERN.fullmatch(knowledge_id):
            raise ValueError("invalid knowledge evidence ID")
        card_ids.append(knowledge_id)
    report = response.get("grounded_report")
    citations: list[str] = []
    if report is not None:
        if not isinstance(report, dict) or not isinstance(report.get("evidence_ids"), list):
            raise ValueError("invalid grounded report")
        for knowledge_id in report["evidence_ids"]:
            if not isinstance(knowledge_id, str) or not KNOWLEDGE_ID_PATTERN.fullmatch(knowledge_id):
                raise ValueError("invalid grounded report citation")
            citations.append(knowledge_id)
    return knowledge_status, report_status, card_ids, citations


def run_smoke(
    *,
    input_path: Path,
    api_base: str,
    output_path: Path,
    expected_snapshot_version: str,
    client: JsonClient | None = None,
) -> dict[str, Any]:
    if not VERSION_PATTERN.fullmatch(expected_snapshot_version):
        raise ValueError("expected snapshot version is invalid")
    rows = _load_rows(input_path)
    client = client or UrllibJsonClient()
    base = api_base.rstrip("/")
    health = client.get_json(base + "/health")
    model = health.get("model", {})
    knowledge = health.get("knowledge", {})
    if not model.get("ready") or not isinstance(model.get("model_id"), str):
        raise RuntimeError("primary model is not ready")
    if not knowledge.get("ready"):
        raise RuntimeError("knowledge service is not ready")
    if knowledge.get("snapshot_version") != expected_snapshot_version:
        raise RuntimeError("knowledge snapshot version mismatch")

    mode_counts: Counter[str] = Counter()
    knowledge_statuses: Counter[str] = Counter()
    report_statuses: Counter[str] = Counter()
    card_ids: Counter[str] = Counter()
    errors: Counter[str] = Counter()
    completed_pairs = 0
    invariant_matches = 0
    citation_total = 0
    valid_citations = 0
    off_latencies: list[float] = []
    report_latencies: list[float] = []
    knowledge_latencies: list[float] = []
    retrieval_latencies: list[float] = []
    generation_latencies: list[float] = []

    for row in rows:
        responses: dict[str, dict[str, Any]] = {}
        pair_failed = False
        for knowledge_mode in ("off", "report"):
            mode_counts[knowledge_mode] += 1
            started = time.perf_counter()
            try:
                response = client.post_json(
                    base + "/api/v1/analyze",
                    {
                        "prompt": row["prompt"],
                        "model_id": model["model_id"],
                        "mode": row["mode"],
                        "knowledge_mode": knowledge_mode,
                    },
                )
                elapsed = (time.perf_counter() - started) * 1000
                knowledge_status, report_status, returned_ids, citations = (
                    _validated_knowledge(response)
                )
                knowledge_statuses[knowledge_status] += 1
                report_statuses[report_status] += 1
                card_ids.update(returned_ids)
                citation_total += len(citations)
                valid_citations += sum(item in set(returned_ids) for item in citations)
                responses[knowledge_mode] = response
                (off_latencies if knowledge_mode == "off" else report_latencies).append(elapsed)
                if knowledge_mode == "report":
                    for field, target in (
                        ("knowledge_latency_ms", knowledge_latencies),
                        ("knowledge_retrieval_latency_ms", retrieval_latencies),
                        ("knowledge_report_latency_ms", generation_latencies),
                    ):
                        value = response.get(field)
                        if isinstance(value, (int, float)) and value >= 0:
                            target.append(float(value))
            except Exception as exc:
                errors[type(exc).__name__] += 1
                pair_failed = True
        if not pair_failed and set(responses) == {"off", "report"}:
            completed_pairs += 1
            invariant_matches += (
                _base_signature(responses["off"])
                == _base_signature(responses["report"])
            )

    report = {
        "schema_version": 1,
        "expected_snapshot_version": expected_snapshot_version,
        "sample_count": len(rows),
        "completed_pair_count": completed_pairs,
        "mode_counts": dict(sorted(mode_counts.items())),
        "knowledge_status_counts": dict(sorted(knowledge_statuses.items())),
        "card_id_counts": dict(sorted(card_ids.items())),
        "report_status_counts": dict(sorted(report_statuses.items())),
        "citation_validity": {
            "valid": valid_citations,
            "total": citation_total,
            "rate": round(valid_citations / citation_total, 6) if citation_total else 1.0,
        },
        "decision_invariance": _rate(invariant_matches, completed_pairs),
        "errors": dict(sorted(errors.items())),
        "latency_ms": {
            "off_end_to_end_p50": _percentile(off_latencies, 0.50),
            "off_end_to_end_p95": _percentile(off_latencies, 0.95),
            "report_end_to_end_p50": _percentile(report_latencies, 0.50),
            "report_end_to_end_p95": _percentile(report_latencies, 0.95),
            "knowledge_total_p50": _percentile(knowledge_latencies, 0.50),
            "knowledge_total_p95": _percentile(knowledge_latencies, 0.95),
            "retrieval_p50": _percentile(retrieval_latencies, 0.50),
            "retrieval_p95": _percentile(retrieval_latencies, 0.95),
            "report_generation_p50": _percentile(generation_latencies, 0.50),
            "report_generation_p95": _percentile(generation_latencies, 0.95),
        },
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a privacy-safe local knowledge RAG smoke suite")
    parser.add_argument("--input-jsonl", type=Path, required=True)
    parser.add_argument("--api-base", required=True)
    parser.add_argument("--output-json", type=Path, required=True)
    parser.add_argument("--expected-snapshot-version", required=True)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    report = run_smoke(
        input_path=args.input_jsonl,
        api_base=args.api_base,
        output_path=args.output_json,
        expected_snapshot_version=args.expected_snapshot_version,
    )
    print(
        "knowledge smoke completed "
        f"samples={report['sample_count']} errors={sum(report['errors'].values())}"
    )


if __name__ == "__main__":
    main()
