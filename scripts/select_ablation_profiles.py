from __future__ import annotations

import argparse
from pathlib import Path

from pydantic import ValidationError

from app.evaluation.ablation import AblationObservation, select_ablation_profiles
from app.evaluation.ablation_io import (
    AblationProfileBundle,
    load_ablation_manifest,
    write_ascii_json,
)


def load_observations(path: Path) -> tuple[AblationObservation, ...]:
    rows: list[AblationObservation] = []
    identifiers: set[str] = set()
    try:
        stream = path.open("r", encoding="ascii")
    except OSError as exc:
        raise ValueError("unable to read protected observation cache") from exc
    with stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                row = AblationObservation.model_validate_json(line)
            except ValidationError:
                raise ValueError(
                    f"protected observation row {line_number} is invalid"
                ) from None
            if row.sample_id in identifiers:
                raise ValueError("protected observation sample IDs must be unique")
            identifiers.add(row.sample_id)
            rows.append(row)
    if not rows:
        raise ValueError("protected observation cache must not be empty")
    return tuple(rows)


def select_profiles(
    *, manifest_path: Path, observations_path: Path, output_path: Path
) -> AblationProfileBundle:
    manifest = load_ablation_manifest(manifest_path)
    observations = load_observations(observations_path)
    expected = manifest.split("dev")
    if {row.sample_id for row in observations} != set(expected.sample_ids):
        raise ValueError("dev observation IDs must match the frozen manifest exactly")
    if {row.group_id for row in observations} != set(expected.group_ids):
        raise ValueError("dev observation groups must match the frozen manifest exactly")
    if any(row.split != "dev" for row in observations):
        raise ValueError("profile selection accepts dev observations only")

    bundle = AblationProfileBundle(
        benchmark_version=manifest.benchmark_version,
        dataset_hash=manifest.dataset_hash,
        profiles=select_ablation_profiles(
            observations, dataset_hash=manifest.dataset_hash
        ),
    )
    write_ascii_json(output_path, bundle)
    return bundle


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Select frozen agent ablation profiles from dev observations"
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--observations-jsonl", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    bundle = select_profiles(
        manifest_path=args.manifest,
        observations_path=args.observations_jsonl,
        output_path=args.output,
    )
    print(
        "ablation profiles selected "
        f"version={bundle.benchmark_version} profiles={len(bundle.profiles)}"
    )


if __name__ == "__main__":
    main()
