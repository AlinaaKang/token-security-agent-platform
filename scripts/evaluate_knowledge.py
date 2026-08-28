from __future__ import annotations

import argparse
import json
from pathlib import Path

from pydantic import TypeAdapter

from app.evaluation.knowledge import (
    EvaluationSplit,
    KnowledgeEvaluationCase,
    KnowledgeEvaluationReport,
    evaluate_knowledge,
)
from app.knowledge.loader import load_knowledge_snapshot


def run_evaluation(
    *,
    snapshot_path: Path,
    fixture_path: Path,
    output_path: Path,
    split: EvaluationSplit,
) -> KnowledgeEvaluationReport:
    raw = json.loads(fixture_path.read_text(encoding="utf-8"))
    cases = TypeAdapter(list[KnowledgeEvaluationCase]).validate_python(raw)
    report = evaluate_knowledge(
        load_knowledge_snapshot(snapshot_path),
        cases,
        split=split,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(
            report.model_dump(mode="json"),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="ascii",
    )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate offline knowledge retrieval")
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--split", choices=("development", "test"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run_evaluation(
        snapshot_path=args.snapshot,
        fixture_path=args.fixture,
        output_path=args.output,
        split=args.split,
    )
    print(
        "knowledge evaluation completed "
        f"cases={report.case_count} hit_at_3={report.hit_at_3:.4f}"
    )


if __name__ == "__main__":
    main()
