from __future__ import annotations

import csv
import json
from pathlib import Path

from scripts.build_protected_ablation_dataset import build_protected_dataset
from scripts.collect_agent_ablation import load_protected_rows


def _write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def test_builder_normalizes_four_domains_and_preserves_suffix_coordinates() -> None:
    root = Path("tmp/protected-ablation-builder")
    autodan = root / "autodan.csv"
    advprompter = root / "advprompter.csv"
    gcg = root / "gcg.csv"
    harmbench = root / "harmbench.csv"
    xstest = root / "xstest.csv"
    output = root / "protected.jsonl"
    _write_csv(
        autodan,
        ["full_prompt", "suffix", "is_adversarial", "algorithm"],
        [
            {"full_prompt": "Explain photosynthesis", "suffix": "", "is_adversarial": "False", "algorithm": ""},
            {"full_prompt": "SAFE_BASE AUTO_SUFFIX", "suffix": " AUTO_SUFFIX", "is_adversarial": "True", "algorithm": "AutoDAN"},
        ],
    )
    _write_csv(
        advprompter,
        ["instruct", "target", "suffix", "full_instruct"],
        [{"instruct": "SAFE_BASE", "target": "SAFE_TARGET", "suffix": " ADV_SUFFIX", "full_instruct": "SAFE_BASE ADV_SUFFIX"}],
    )
    _write_csv(
        gcg,
        ["prompt", "target", "trigger"],
        [{"prompt": "SAFE_BASE", "target": "SAFE_TARGET", "trigger": " GCG_SUFFIX"}],
    )
    _write_csv(
        harmbench,
        ["Behavior", "FunctionalCategory", "SemanticCategory", "Tags", "ContextString", "BehaviorID"],
        [
            {"Behavior": "SAFE_SYNTHETIC_UNSAFE_REQUEST", "FunctionalCategory": "standard", "SemanticCategory": "illegal", "Tags": "", "ContextString": "", "BehaviorID": "hb-1"},
            {"Behavior": "EXCLUDED_CONTEXTUAL", "FunctionalCategory": "contextual", "SemanticCategory": "harmful", "Tags": "", "ContextString": "SAFE_CONTEXT", "BehaviorID": "hb-2"},
        ],
    )
    _write_csv(
        xstest,
        ["id", "prompt", "type", "label", "focus", "note"],
        [
            {"id": "xs-1", "prompt": "SAFE_HARD_NEGATIVE", "type": "safe_contexts", "label": "safe", "focus": "", "note": ""},
            {"id": "xs-3", "prompt": "SAFE_HARD_NEGATIVE_TWO", "type": "safe_contexts", "label": "safe", "focus": "", "note": ""},
            {"id": "xs-2", "prompt": "EXCLUDED_UNSAFE", "type": "safe_contexts", "label": "unsafe", "focus": "", "note": ""},
        ],
    )

    try:
        summary = build_protected_dataset(
            autodan_path=autodan,
            advprompter_path=advprompter,
            gcg_path=gcg,
            harmbench_path=harmbench,
            xstest_path=xstest,
            output_path=output,
        )
        rows = load_protected_rows(output)
        serialized = output.read_text(encoding="utf-8")
    finally:
        for path in (autodan, advprompter, gcg, harmbench, xstest, output):
            path.unlink(missing_ok=True)
        root.rmdir()

    assert summary == {
        "total": 7,
        "domains": {
            "benign_plain": 1,
            "benign_shift": 2,
            "semantic_unsafe": 1,
            "optimized_suffix": 3,
        },
        "families": {"advprompter": 1, "autodan": 1, "gcg": 1},
        "excluded": {"harmbench_nonstandard": 1, "xstest_not_safe": 1},
    }
    assert {row.source_dataset for row in rows} == {
        "cpdonline_autodan",
        "cpdonline_advprompter",
        "cpdonline_gcg",
        "harmbench",
        "xstest",
    }
    optimized = [row for row in rows if row.domain.value == "optimized_suffix"]
    assert {row.attack_family for row in optimized} == {"autodan", "advprompter", "gcg"}
    assert all(row.prompt[row.suffix_start : row.suffix_end].endswith("SUFFIX") for row in optimized)  # type: ignore[index]
    xstest_rows = [row for row in rows if row.source_dataset == "xstest"]
    assert len({row.group_id for row in xstest_rows}) == 1
    assert all(row.split is None for row in rows)
    assert "SAFE_HARD_NEGATIVE" in serialized
    assert "EXCLUDED_CONTEXTUAL" not in serialized
    assert "EXCLUDED_UNSAFE" not in serialized
