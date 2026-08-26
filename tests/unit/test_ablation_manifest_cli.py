from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.build_ablation_manifest import build_manifest


FILE_HASH = "sha256:" + "b" * 64


def _paths(name: str) -> tuple[Path, Path, Path]:
    root = Path("tmp")
    root.mkdir(exist_ok=True)
    return (
        root / f"{name}-protected.jsonl",
        root / f"{name}-sources.json",
        root / f"{name}-manifest.json",
    )


def _sources(path: Path, *, verified: bool = True) -> None:
    payload = {
        "schema_version": 1,
        "sources": [
            {
                "source_id": "verified-source",
                "status": "verified" if verified else "unverified",
                "url": "https://example.test/source",
                "revision": "a" * 40,
                "license_spdx": "MIT",
                "attribution": "Safe test attribution",
                "file_sha256": FILE_HASH if verified else None,
                "reason": None if verified else "file checksum pending",
            },
            {
                "source_id": "beast",
                "status": "source_unavailable",
                "url": None,
                "revision": None,
                "license_spdx": None,
                "attribution": None,
                "file_sha256": None,
                "reason": "official artifact not verified",
            },
        ],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def _protected_rows(path: Path, *, changed_group: bool = False) -> None:
    domains = (
        "benign_plain",
        "benign_shift",
        "semantic_unsafe",
        "optimized_suffix",
    )
    rows = []
    for index in range(40):
        domain = domains[index % len(domains)]
        risky = domain in {"semantic_unsafe", "optimized_suffix"}
        prompt = f"SAFE_PRIVATE_FIXTURE_{index:02d}_WITH_PADDING"
        suffix_start = len(prompt) - 7 if domain == "optimized_suffix" else None
        rows.append(
            {
                "sample_id": f"sample-{index:02d}",
                "group_id": (
                    "group-changed" if changed_group and index == 0 else f"group-{index:02d}"
                ),
                "source_dataset": "verified-source",
                "domain": domain,
                "label_risky": risky,
                "attack_family": "gcg" if domain == "optimized_suffix" else None,
                "suffix_start": suffix_start,
                "suffix_end": len(prompt) if domain == "optimized_suffix" else None,
                "prompt": prompt,
            }
        )
    path.write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
    )


def _cleanup(*paths: Path) -> None:
    for path in paths:
        path.unlink(missing_ok=True)


def test_manifest_builder_is_reproducible_private_free_and_group_isolated() -> None:
    input_path, sources_path, output_path = _paths("ablation-manifest")
    second_path = output_path.with_name(output_path.stem + "-second.json")
    _protected_rows(input_path)
    _sources(sources_path)
    try:
        first = build_manifest(
            input_path=input_path,
            sources_path=sources_path,
            output_path=output_path,
            benchmark_version="agent-ablation-v1",
            seed="token-security-agent-ablation-v1",
        )
        second = build_manifest(
            input_path=input_path,
            sources_path=sources_path,
            output_path=second_path,
            benchmark_version="agent-ablation-v1",
            seed="token-security-agent-ablation-v1",
        )
        serialized = output_path.read_text(encoding="ascii")
        first_bytes = output_path.read_bytes()
        second_bytes = second_path.read_bytes()
    finally:
        _cleanup(input_path, sources_path, output_path, second_path)

    assert first == second
    assert "SAFE_PRIVATE" not in serialized
    assert "prompt" not in serialized.casefold()
    assert first_bytes == second_bytes
    calibration = set(first.split("calibration").group_ids)
    dev = set(first.split("dev").group_ids)
    test = set(first.split("test").group_ids)
    assert calibration.isdisjoint(dev)
    assert calibration.isdisjoint(test)
    assert dev.isdisjoint(test)
    assert sum(sum(split.domain_counts.values()) for split in first.splits) == 40
    assert first.source_coverage == {
        "beast": "source_unavailable",
        "verified-source": "verified",
    }


def test_manifest_dataset_hash_changes_when_group_identity_changes() -> None:
    input_path, sources_path, output_path = _paths("ablation-manifest-hash")
    changed_path = input_path.with_name(input_path.stem + "-changed.jsonl")
    changed_output = output_path.with_name(output_path.stem + "-changed.json")
    _protected_rows(input_path)
    _protected_rows(changed_path, changed_group=True)
    _sources(sources_path)
    try:
        original = build_manifest(
            input_path=input_path, sources_path=sources_path,
            output_path=output_path, benchmark_version="agent-ablation-v1",
            seed="token-security-agent-ablation-v1",
        )
        changed = build_manifest(
            input_path=changed_path, sources_path=sources_path,
            output_path=changed_output, benchmark_version="agent-ablation-v1",
            seed="token-security-agent-ablation-v1",
        )
    finally:
        _cleanup(input_path, changed_path, sources_path, output_path, changed_output)

    assert original.dataset_hash != changed.dataset_hash


def test_manifest_rejects_samples_from_unverified_sources_without_leaking_prompt() -> None:
    input_path, sources_path, output_path = _paths("ablation-manifest-unverified")
    _protected_rows(input_path)
    _sources(sources_path, verified=False)
    try:
        with pytest.raises(ValueError, match="not verified") as error:
            build_manifest(
                input_path=input_path, sources_path=sources_path,
                output_path=output_path, benchmark_version="agent-ablation-v1",
                seed="token-security-agent-ablation-v1",
            )
    finally:
        _cleanup(input_path, sources_path, output_path)

    assert "SAFE_PRIVATE" not in str(error.value)


def test_manifest_rejects_duplicate_sample_ids() -> None:
    input_path, sources_path, output_path = _paths("ablation-manifest-duplicate")
    _protected_rows(input_path)
    lines = input_path.read_text(encoding="utf-8").splitlines()
    input_path.write_text("\n".join((lines[0], lines[0])) + "\n", encoding="utf-8")
    _sources(sources_path)
    try:
        with pytest.raises(ValueError, match="unique"):
            build_manifest(
                input_path=input_path, sources_path=sources_path,
                output_path=output_path, benchmark_version="agent-ablation-v1",
                seed="token-security-agent-ablation-v1",
            )
    finally:
        _cleanup(input_path, sources_path, output_path)
