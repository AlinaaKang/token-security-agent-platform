from __future__ import annotations

from app.evaluation.normalize import PromptRecord
import json
from pathlib import Path

from app.evaluation.split import build_dataset_card, split_by_group, write_split_manifests


def make_record(index: int, group: int) -> PromptRecord:
    return PromptRecord(
        sample_id=f"sample-{index}",
        prompt=f"Harmless example {index}",
        label_suffix_attack=False,
        source_dataset="synthetic",
        group_id=f"group-{group}",
    )


def test_group_split_is_deterministic_and_has_zero_group_overlap() -> None:
    records = [make_record(index, group=index // 2) for index in range(20)]

    first = split_by_group(records, seed="competition-v1")
    second = split_by_group(records, seed="competition-v1")

    assert first == second
    calibration_groups = {record.group_id for record in first.calibration}
    dev_groups = {record.group_id for record in first.dev}
    test_groups = {record.group_id for record in first.test}
    assert calibration_groups.isdisjoint(dev_groups)
    assert calibration_groups.isdisjoint(test_groups)
    assert dev_groups.isdisjoint(test_groups)
    assert tuple(map(len, (first.calibration, first.dev, first.test))) == (4, 4, 12)


def test_manifests_and_dataset_card_do_not_store_prompt_text() -> None:
    records = [make_record(index, group=index // 2) for index in range(20)]
    split = split_by_group(records, seed="competition-v1")
    output_path = Path("tmp/test-manifests")

    write_split_manifests(output_path, split, seed="competition-v1")
    card = build_dataset_card(
        split,
        seed="competition-v1",
        attributions=[
            {
                "name": "CPDonline",
                "url": "https://github.com/cpdonline/cpdonline",
                "license": "MIT",
                "copyright": "Copyright (c) 2026 cpdonline",
            }
        ],
    )

    serialized_files = "".join(path.read_text("utf-8") for path in output_path.iterdir())
    serialized_card = json.dumps(card, ensure_ascii=False)
    assert "Harmless example" not in serialized_files
    assert "Harmless example" not in serialized_card
    assert card["counts"] == {
        "total": 20,
        "calibration": 4,
        "dev": 4,
        "test": 12,
    }
    assert card["attributions"][0]["license"] == "MIT"
