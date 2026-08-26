from __future__ import annotations

import argparse
import json
import math
import time
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any, Protocol


SEMANTIC_VALUES = {"safe", "controversial", "unsafe", "unavailable"}
ACTION_VALUES = {"allow", "review", "block", "sanitize_recheck"}
CATEGORY_VALUES = {
    "violent",
    "non_violent_illegal_acts",
    "sexual_content",
    "pii",
    "suicide_self_harm",
    "unethical_acts",
    "politically_sensitive",
    "copyright_violation",
    "jailbreak",
}
DETECTOR_VALUES = {"no_token_anomaly", "token_anomaly_candidate"}
FUSION_VALUES = {
    "semantic_unsafe",
    "semantic_controversial",
    "cpd_candidate",
    "all_clear",
    "semantic_unavailable_cpd_candidate",
    "semantic_unavailable_analysis_degraded",
    "semantic_unavailable_gateway_fail_safe",
}


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


def _load_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            row = json.loads(line)
            sample_id = row.get("sample_id")
            private_text = row.get("prompt")
            if not isinstance(sample_id, str) or not sample_id.strip():
                raise ValueError(f"row {line_number} requires a non-empty sample_id")
            if sample_id in identifiers:
                raise ValueError("sample_id values must be unique")
            if not isinstance(private_text, str) or not private_text.strip():
                raise ValueError(f"row {line_number} requires non-empty private input")
            mode = row.get("mode", "analysis")
            if mode not in {"analysis", "gateway"}:
                raise ValueError(f"row {line_number} has invalid mode")
            expected_semantic = row.get("expected_semantic")
            if expected_semantic is not None and expected_semantic not in SEMANTIC_VALUES:
                raise ValueError(f"row {line_number} has invalid semantic expectation")
            expected_action = row.get("expected_action")
            if expected_action is not None and expected_action not in ACTION_VALUES:
                raise ValueError(f"row {line_number} has invalid action expectation")
            identifiers.add(sample_id)
            rows.append(row)
    if not rows:
        raise ValueError("protected smoke input must contain at least one row")
    return rows


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return round(ordered[index], 3)


def run_smoke(
    *,
    input_path: Path,
    api_base: str,
    output_path: Path,
    expected_model_version: str,
    client: JsonClient | None = None,
) -> dict[str, Any]:
    if not expected_model_version.strip():
        raise ValueError("expected model version must not be blank")
    rows = _load_rows(input_path)
    client = client or UrllibJsonClient()
    base = api_base.rstrip("/")
    health = client.get_json(base + "/health")
    model = health.get("model", {})
    guard = health.get("semantic_guard", {})
    if not model.get("ready") or not model.get("model_id"):
        raise RuntimeError("primary model is not ready")
    if not guard.get("ready"):
        raise RuntimeError("semantic Guard is not ready")
    if guard.get("model_version") != expected_model_version:
        raise RuntimeError("semantic Guard model version mismatch")

    expected_semantic: Counter[str] = Counter()
    returned_semantic: Counter[str] = Counter()
    categories: Counter[str] = Counter()
    actions: Counter[str] = Counter()
    detector_statuses: Counter[str] = Counter()
    fusion_reasons: Counter[str] = Counter()
    evidence_combinations: Counter[str] = Counter()
    errors: Counter[str] = Counter()
    versions: Counter[str] = Counter()
    modes: Counter[str] = Counter()
    expectation_matches = {"semantic": 0, "action": 0}
    end_to_end_latencies: list[float] = []
    guard_latencies: list[float] = []

    for row in rows:
        modes[row.get("mode", "analysis")] += 1
        if row.get("expected_semantic") is not None:
            expected_semantic[row["expected_semantic"]] += 1
        started = time.perf_counter()
        try:
            response = client.post_json(
                base + "/api/v1/analyze",
                {
                    "prompt": row["prompt"],
                    "model_id": model["model_id"],
                    "mode": row.get("mode", "analysis"),
                },
            )
            elapsed = (time.perf_counter() - started) * 1000
            severity = response.get("semantic_severity")
            action = response.get("decision")
            detector_status = response.get("detector_status")
            fusion_reason = response.get("fusion_reason")
            response_categories = response.get("semantic_categories")
            version = response.get("semantic_model_version")
            if (
                severity not in SEMANTIC_VALUES
                or action not in ACTION_VALUES
                or detector_status not in DETECTOR_VALUES
                or fusion_reason not in FUSION_VALUES
            ):
                raise ValueError("invalid normalized response")
            if not isinstance(response_categories, list) or any(
                item not in CATEGORY_VALUES for item in response_categories
            ):
                raise ValueError("invalid normalized response")
            if not isinstance(version, str) or not version:
                raise ValueError("invalid normalized response")
            returned_semantic[severity] += 1
            actions[action] += 1
            detector_statuses[detector_status] += 1
            fusion_reasons[fusion_reason] += 1
            evidence_combinations[
                "|".join((severity, detector_status, fusion_reason, action))
            ] += 1
            categories.update(response_categories)
            versions[version] += 1
            end_to_end_latencies.append(elapsed)
            semantic_latency = response.get("semantic_latency_ms")
            if isinstance(semantic_latency, (int, float)) and semantic_latency >= 0:
                guard_latencies.append(float(semantic_latency))
            if row.get("expected_semantic") == severity:
                expectation_matches["semantic"] += 1
            if row.get("expected_action") == action:
                expectation_matches["action"] += 1
        except Exception as exc:
            errors[type(exc).__name__] += 1

    report = {
        "schema_version": 1,
        "sample_count": len(rows),
        "completed_count": sum(returned_semantic.values()),
        "modes": dict(sorted(modes.items())),
        "expected_semantic": dict(sorted(expected_semantic.items())),
        "returned_semantic": dict(sorted(returned_semantic.items())),
        "categories": dict(sorted(categories.items())),
        "actions": dict(sorted(actions.items())),
        "detector_statuses": dict(sorted(detector_statuses.items())),
        "fusion_reasons": dict(sorted(fusion_reasons.items())),
        "evidence_combinations": dict(sorted(evidence_combinations.items())),
        "expectation_matches": expectation_matches,
        "errors": dict(sorted(errors.items())),
        "guard_model_versions": dict(sorted(versions.items())),
        "latency_ms": {
            "end_to_end_p50": _percentile(end_to_end_latencies, 0.50),
            "end_to_end_p95": _percentile(end_to_end_latencies, 0.95),
            "guard_p50": _percentile(guard_latencies, 0.50),
            "guard_p95": _percentile(guard_latencies, 0.95),
        },
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a privacy-safe semantic Guard smoke suite")
    parser.add_argument("--input-jsonl", type=Path, required=True)
    parser.add_argument("--api-base", required=True)
    parser.add_argument("--output-json", type=Path, required=True)
    parser.add_argument("--expected-model-version", required=True)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    report = run_smoke(
        input_path=args.input_jsonl,
        api_base=args.api_base,
        output_path=args.output_json,
        expected_model_version=args.expected_model_version,
    )
    print(
        "semantic smoke completed "
        f"samples={report['sample_count']} errors={sum(report['errors'].values())}"
    )


if __name__ == "__main__":
    main()
