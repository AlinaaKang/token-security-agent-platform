from __future__ import annotations

import json
import shutil
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.evaluation.ablation import (
    AblationMethod,
    AblationObservation,
    AblationProfile,
    EvaluationDomain,
    OperatingPoint,
    evaluate_ablation,
    select_ablation_profiles,
)
from app.evaluation.ablation_io import (
    AblationProfileBundle,
    ArtifactValidationError,
    load_ablation_manifest,
    load_ablation_profiles,
    load_ablation_report,
    write_ascii_json,
)


HASH = "sha256:" + "a" * 64
FILE_HASH = "sha256:" + "b" * 64


@pytest.fixture
def artifact_dir() -> Iterator[Path]:
    path = Path("tmp") / f"ablation-io-{uuid.uuid4().hex}"
    path.mkdir(parents=True)
    try:
        yield path
    finally:
        shutil.rmtree(path)


def _source() -> dict[str, object]:
    return {
        "source_id": "cpdonline",
        "status": "verified",
        "url": "https://github.com/cpdonline/cpdonline",
        "revision": "1a6c055865c44cc1d10dfbe5d014576c7331322e",
        "license_spdx": "MIT",
        "attribution": "Copyright (c) 2026 cpdonline",
        "file_sha256": FILE_HASH,
        "reason": None,
    }


def _split(
    name: str,
    sample_id: str,
    group_id: str,
    *,
    domain: str = "benign_plain",
) -> dict[str, object]:
    return {
        "split": name,
        "sample_ids": [sample_id],
        "group_ids": [group_id],
        "domain_counts": {domain: 1},
        "family_counts": {},
    }


def _manifest() -> dict[str, object]:
    return {
        "schema_version": 1,
        "benchmark_version": "agent-ablation-v1",
        "dataset_hash": HASH,
        "split_seed": "token-security-agent-ablation-v1",
        "sources": [_source()],
        "splits": [
            _split("calibration", "cal-1", "group-cal"),
            _split("dev", "dev-1", "group-dev", domain="semantic_unsafe"),
            _split("test", "test-1", "group-test", domain="optimized_suffix")
            | {"family_counts": {"gcg": 1}},
        ],
    }


def _write(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_manifest_loader_accepts_strict_private_free_artifact(artifact_dir: Path) -> None:
    path = artifact_dir / "manifest.json"
    _write(path, _manifest())

    manifest = load_ablation_manifest(path)

    assert manifest.dataset_hash == HASH
    assert manifest.split("test").sample_ids == ("test-1",)
    assert manifest.source_coverage == {"cpdonline": "verified"}


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("private_key", "forbidden key"),
        ("duplicate_id", "sample IDs overlap"),
        ("overlap_group", "group IDs overlap"),
        ("count_mismatch", "domain counts"),
        ("bad_hash", "dataset_hash"),
        ("mutable_source", "verified sources require"),
    ],
)
def test_manifest_loader_rejects_invalid_artifacts(
    artifact_dir: Path, mutation: str, message: str
) -> None:
    payload = _manifest()
    if mutation == "private_key":
        payload["prompt"] = "SAFE_PRIVATE_PROMPT"
    elif mutation == "duplicate_id":
        payload["splits"][1]["sample_ids"] = ["cal-1"]  # type: ignore[index]
    elif mutation == "overlap_group":
        payload["splits"][2]["group_ids"] = ["group-dev"]  # type: ignore[index]
    elif mutation == "count_mismatch":
        payload["splits"][0]["domain_counts"] = {"benign_plain": 2}  # type: ignore[index]
    elif mutation == "bad_hash":
        payload["dataset_hash"] = "sha256:bad"
    elif mutation == "mutable_source":
        payload["sources"][0]["revision"] = None  # type: ignore[index]

    path = artifact_dir / "manifest.json"
    _write(path, payload)
    with pytest.raises((ArtifactValidationError, ValidationError), match=message):
        load_ablation_manifest(path)


def _profiles() -> tuple[AblationProfile, ...]:
    rows: list[AblationProfile] = []
    for method in AblationMethod:
        for point in OperatingPoint:
            production = point is OperatingPoint.PRODUCTION
            semantic_policy = (
                "controversial_or_unsafe"
                if method in {AblationMethod.SEMANTIC_ONLY, AblationMethod.FUSION}
                else None
            )
            rows.append(
                AblationProfile(
                    method=method,
                    operating_point=point,
                    dataset_hash=HASH,
                    semantic_policy=semantic_policy,
                    detector_threshold=(
                        None
                        if production or method is AblationMethod.SEMANTIC_ONLY
                        else 0.5
                    ),
                    use_production_cpd_alarm=(
                        production and method is not AblationMethod.SEMANTIC_ONLY
                    ),
                    constraint_max_fpr=(
                        None
                        if production
                        else (0.10 if point is OperatingPoint.FPR_10 else 0.05)
                    ),
                    constraint_satisfied=True,
                    dev_precision=1.0,
                    dev_recall=1.0,
                    dev_false_positive_rate=0.0,
                )
            )
    return tuple(rows)


def test_profile_loader_requires_expected_hash_and_complete_pairs(
    artifact_dir: Path,
) -> None:
    bundle = AblationProfileBundle(
        benchmark_version="agent-ablation-v1",
        dataset_hash=HASH,
        profiles=_profiles(),
    )
    path = artifact_dir / "profiles.json"
    write_ascii_json(path, bundle)

    loaded = load_ablation_profiles(path, expected_dataset_hash=HASH)
    assert len(loaded) == 9

    with pytest.raises(ArtifactValidationError, match="profile dataset hash mismatch"):
        load_ablation_profiles(path, expected_dataset_hash="sha256:" + "c" * 64)

    incomplete = bundle.model_copy(update={"profiles": bundle.profiles[:-1]})
    write_ascii_json(path, incomplete)
    with pytest.raises(ArtifactValidationError, match="each method/operating point"):
        load_ablation_profiles(path, expected_dataset_hash=HASH)


def test_ascii_writer_is_deterministic_and_refuses_identity_change(
    artifact_dir: Path,
) -> None:
    payload = AblationProfileBundle(
        benchmark_version="agent-ablation-v1",
        dataset_hash=HASH,
        profiles=_profiles(),
    )
    one = artifact_dir / "one.json"
    two = artifact_dir / "two.json"
    write_ascii_json(one, payload)
    write_ascii_json(two, payload)

    assert one.read_bytes() == two.read_bytes()
    assert one.read_bytes().endswith(b"\n")
    one.read_bytes().decode("ascii")

    changed = payload.model_copy(
        update={"benchmark_version": "agent-ablation-v2"}
    )
    with pytest.raises(ArtifactValidationError, match="refusing to overwrite"):
        write_ascii_json(one, changed)


def _report():
    dev = (
        AblationObservation(
            sample_id="dev-safe", group_id="dev-safe", split="dev",
            domain=EvaluationDomain.BENIGN_PLAIN, label_risky=False,
            semantic_severity="safe", semantic_verification="performed",
            detector_score=0.1, production_cpd_alarm=False,
            semantic_latency_ms=1, total_latency_ms=2,
        ),
        AblationObservation(
            sample_id="dev-risk", group_id="dev-risk", split="dev",
            domain=EvaluationDomain.SEMANTIC_UNSAFE, label_risky=True,
            semantic_severity="unsafe", semantic_verification="performed",
            detector_score=0.9, production_cpd_alarm=True,
            semantic_latency_ms=1, total_latency_ms=2,
        ),
    )
    test = tuple(row.model_copy(update={"sample_id": row.sample_id.replace("dev", "test"), "split": "test"}) for row in dev)
    profiles = select_ablation_profiles(dev, dataset_hash=HASH)
    return evaluate_ablation(
        test, profiles, benchmark_version="agent-ablation-v1",
        dataset_hash=HASH, source_coverage={"cpdonline": "verified"},
    )


def test_report_loader_requires_complete_matrix_and_expected_dataset_hash(
    artifact_dir: Path,
) -> None:
    path = artifact_dir / "report.json"
    report = _report()
    write_ascii_json(path, report)
    assert load_ablation_report(
        path,
        expected_benchmark_version="agent-ablation-v1",
        expected_dataset_hash=HASH,
    ) == report

    with pytest.raises(ArtifactValidationError, match="dataset hash mismatch"):
        load_ablation_report(
            path,
            expected_benchmark_version="agent-ablation-v1",
            expected_dataset_hash="sha256:" + "c" * 64,
        )

    incomplete = report.model_dump(mode="json")
    incomplete["methods"] = incomplete["methods"][:-1]
    _write(path, incomplete)
    with pytest.raises(ArtifactValidationError, match="each method/operating point"):
        load_ablation_report(
            path,
            expected_benchmark_version="agent-ablation-v1",
            expected_dataset_hash=HASH,
        )
