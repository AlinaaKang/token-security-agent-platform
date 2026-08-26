from __future__ import annotations

import argparse
import hashlib
import json
import urllib.request
from pathlib import Path
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from app.evaluation.ablation import AblationObservation, EvaluationDomain


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


class ProtectedAblationRow(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    sample_id: str = Field(min_length=1)
    group_id: str = Field(min_length=1)
    source_dataset: str = Field(min_length=1)
    split: Literal["calibration", "dev", "test"] | None = None
    domain: EvaluationDomain
    label_risky: bool
    attack_family: str | None = None
    suffix_start: int | None = Field(default=None, ge=0)
    suffix_end: int | None = Field(default=None, ge=0)
    prompt: str = Field(min_length=1, repr=False)

    @field_validator("sample_id", "group_id", "source_dataset")
    @classmethod
    def _strip_identifier(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("protected input identifier must not be blank")
        return stripped

    @field_validator("prompt")
    @classmethod
    def _preserve_prompt(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("protected input Prompt must not be blank")
        return value

    @field_validator("attack_family")
    @classmethod
    def _normalize_family(cls, value: str | None) -> str | None:
        return value.strip().casefold() if value is not None else None

    @model_validator(mode="after")
    def _validate_domain(self) -> "ProtectedAblationRow":
        benign = self.domain in {
            EvaluationDomain.BENIGN_PLAIN,
            EvaluationDomain.BENIGN_SHIFT,
        }
        if benign == self.label_risky:
            raise ValueError("protected row domain and label are inconsistent")
        if self.domain is EvaluationDomain.OPTIMIZED_SUFFIX:
            if (
                not self.attack_family
                or self.suffix_start is None
                or self.suffix_end is None
                or self.suffix_start >= self.suffix_end
                or self.suffix_end > len(self.prompt)
            ):
                raise ValueError("optimized suffix row metadata is invalid")
        elif any(
            value is not None
            for value in (self.attack_family, self.suffix_start, self.suffix_end)
        ):
            raise ValueError("non-suffix rows cannot contain suffix metadata")
        return self


def _metadata_path(output_path: Path) -> Path:
    return output_path.with_suffix(output_path.suffix + ".meta.json")


def _errors_path(output_path: Path) -> Path:
    return output_path.with_suffix(output_path.suffix + ".errors.json")


def load_protected_rows(path: Path) -> tuple[ProtectedAblationRow, ...]:
    rows: list[ProtectedAblationRow] = []
    identifiers: set[str] = set()
    try:
        stream = path.open("r", encoding="utf-8")
    except OSError as exc:
        raise ValueError("unable to read protected ablation input") from exc
    with stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
                row = ProtectedAblationRow.model_validate(payload)
            except (json.JSONDecodeError, ValidationError):
                raise ValueError(
                    f"protected input row {line_number} is invalid"
                ) from None
            if row.sample_id in identifiers:
                raise ValueError("protected input sample IDs must be unique")
            identifiers.add(row.sample_id)
            rows.append(row)
    if not rows:
        raise ValueError("protected ablation input must not be empty")
    return tuple(rows)


def _input_hash(rows: tuple[ProtectedAblationRow, ...]) -> str:
    identities = []
    for row in sorted(rows, key=lambda item: item.sample_id):
        metadata = row.model_dump(mode="json", exclude={"prompt"})
        metadata["prompt_sha256"] = hashlib.sha256(
            row.prompt.encode("utf-8")
        ).hexdigest()
        identities.append(metadata)
    payload = json.dumps(
        identities, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _deployment_identity(health: dict[str, Any], model_id: str) -> dict[str, str]:
    model = health.get("model")
    detector = health.get("detector")
    guard = health.get("semantic_guard")
    if not isinstance(model, dict) or not model.get("ready"):
        raise RuntimeError("primary model is not ready")
    if not isinstance(detector, dict) or not detector.get("ready"):
        raise RuntimeError("detector is not ready")
    if not isinstance(guard, dict) or not guard.get("ready"):
        raise RuntimeError("semantic guard is not ready")
    identity = {
        "model_id": model.get("model_id"),
        "calibration_version": detector.get("calibration_version"),
        "semantic_model_id": guard.get("model_id"),
        "semantic_model_version": guard.get("model_version"),
    }
    if any(not isinstance(value, str) or not value for value in identity.values()):
        raise RuntimeError("deployment identity is incomplete")
    if identity["model_id"] != model_id:
        raise RuntimeError("requested model ID does not match deployment")
    return identity


def _load_existing(output_path: Path) -> dict[str, AblationObservation]:
    observations: dict[str, AblationObservation] = {}
    if not output_path.exists():
        return observations
    try:
        with output_path.open("r", encoding="utf-8") as stream:
            for line in stream:
                if not line.strip():
                    continue
                row = AblationObservation.model_validate_json(line)
                if row.sample_id in observations:
                    raise ValueError("observation cache contains duplicate sample IDs")
                observations[row.sample_id] = row
    except (OSError, ValidationError, json.JSONDecodeError) as exc:
        raise RuntimeError("unable to load protected observation cache") from exc
    return observations


def _atomic_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n",
        encoding="ascii",
    )
    temporary.replace(path)


def _atomic_observations(
    path: Path,
    rows: tuple[ProtectedAblationRow, ...],
    observations: dict[str, AblationObservation],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="ascii", newline="\n") as stream:
        for row in rows:
            observation = observations.get(row.sample_id)
            if observation is None:
                continue
            stream.write(
                json.dumps(
                    observation.model_dump(mode="json"),
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            )
    temporary.replace(path)


def _observation_from_response(
    row: ProtectedAblationRow, response: dict[str, Any]
) -> AblationObservation:
    detector_status = response.get("detector_status")
    if detector_status not in {"no_token_anomaly", "token_anomaly_candidate"}:
        raise ValueError("analysis response has invalid detector status")
    span = response.get("suspicious_span")
    predicted_onset = span.get("char_start") if isinstance(span, dict) else None
    return AblationObservation(
        sample_id=row.sample_id,
        group_id=row.group_id,
        split=row.split,
        domain=row.domain,
        label_risky=row.label_risky,
        attack_family=row.attack_family,
        semantic_severity=response.get("semantic_severity"),
        semantic_verification=response.get("semantic_verification"),
        detector_score=response.get("detector_score"),
        production_cpd_alarm=detector_status == "token_anomaly_candidate",
        predicted_onset=predicted_onset,
        suffix_start=row.suffix_start,
        suffix_end=row.suffix_end,
        semantic_latency_ms=response.get("semantic_latency_ms"),
        total_latency_ms=response.get("latency_ms"),
    )


def collect_observations(
    *,
    input_path: Path,
    api_base: str,
    output_path: Path,
    model_id: str,
    resume: bool,
    client: JsonClient | None = None,
) -> dict[str, int]:
    rows = load_protected_rows(input_path)
    if any(row.split is None for row in rows):
        raise ValueError("protected collection rows require a frozen split")
    input_hash = _input_hash(rows)
    client = client or UrllibJsonClient()
    base = api_base.rstrip("/")
    identity = _deployment_identity(client.get_json(base + "/health"), model_id)
    metadata_path = _metadata_path(output_path)

    if output_path.exists() and not resume:
        raise RuntimeError("observation cache already exists; use --resume")
    observations = _load_existing(output_path) if resume else {}
    if resume:
        if not metadata_path.exists():
            raise RuntimeError("resume metadata is missing")
        try:
            existing_metadata = json.loads(metadata_path.read_text(encoding="ascii"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("resume metadata is invalid") from exc
        if (
            existing_metadata.get("input_hash") != input_hash
            or existing_metadata.get("deployment") != identity
        ):
            raise RuntimeError("deployment identity mismatch or protected input changed")
        input_ids = {row.sample_id for row in rows}
        if not set(observations).issubset(input_ids):
            raise RuntimeError("observation cache contains unknown sample IDs")

    skipped = len(observations)
    failures: list[dict[str, str]] = []
    for row in rows:
        if row.sample_id in observations:
            continue
        try:
            response = client.post_json(
                base + "/api/v1/analyze",
                {
                    "prompt": row.prompt,
                    "model_id": model_id,
                    "mode": "analysis",
                    "knowledge_mode": "off",
                },
            )
            observations[row.sample_id] = _observation_from_response(row, response)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            failures.append(
                {"sample_id": row.sample_id, "error_type": type(exc).__name__}
            )

    _atomic_observations(output_path, rows, observations)
    _atomic_json(
        metadata_path,
        {
            "schema_version": 1,
            "input_hash": input_hash,
            "deployment": identity,
            "completed_count": len(observations),
        },
    )
    _atomic_json(_errors_path(output_path), failures)
    return {
        "requested": len(rows),
        "completed": len(observations),
        "failed": len(failures),
        "skipped": skipped,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect privacy-safe observations for the frozen agent ablation benchmark"
    )
    parser.add_argument("--input-jsonl", type=Path, required=True)
    parser.add_argument("--api-base", required=True)
    parser.add_argument("--output-jsonl", type=Path, required=True)
    parser.add_argument("--model-id", required=True)
    parser.add_argument("--resume", action="store_true")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    summary = collect_observations(
        input_path=args.input_jsonl,
        api_base=args.api_base,
        output_path=args.output_jsonl,
        model_id=args.model_id,
        resume=args.resume,
    )
    print(
        "ablation collection completed "
        f"requested={summary['requested']} completed={summary['completed']} "
        f"failed={summary['failed']} skipped={summary['skipped']}"
    )


if __name__ == "__main__":
    main()
