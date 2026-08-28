from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from app.evaluation.grounded_report import load_effective_report_summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read the effective grounded-report experiment status."
    )
    parser.add_argument(
        "--selected-config",
        type=Path,
        default=Path("data/report-generation-config-v2.json"),
    )
    parser.add_argument(
        "--development-report",
        type=Path,
        default=Path("data/report-generation-development-report-v2.json"),
    )
    parser.add_argument(
        "--test-report",
        type=Path,
        default=Path("data/report-generation-test-report-v2.json"),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        summary = load_effective_report_summary(
            selected_config_path=args.selected_config,
            development_report_path=args.development_report,
            test_report_path=args.test_report,
        )
    except FileNotFoundError as exc:
        parser.error(str(exc))
    except (OSError, ValueError):
        parser.error("effective report validation failed")
    print(
        json.dumps(
            summary.model_dump(mode="json"),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
