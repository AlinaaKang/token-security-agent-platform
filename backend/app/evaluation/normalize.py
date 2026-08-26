from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping
from typing import Any, Protocol

from pydantic import BaseModel, Field


class DatasetValidationError(ValueError):
    """Raised when source data cannot satisfy the canonical contract."""


class PromptRecord(BaseModel):
    sample_id: str = Field(min_length=1)
    prompt: str = Field(min_length=1)
    label_suffix_attack: bool
    label_semantic_unsafe: bool | None = None
    attack_family: str | None = None
    suffix_text: str | None = None
    suffix_char_start: int | None = Field(default=None, ge=0)
    source_dataset: str = Field(min_length=1)
    group_id: str = Field(min_length=1)
    language: str | None = None


class RowAdapter(Protocol):
    def convert(self, row: Mapping[str, Any]) -> PromptRecord: ...


def _stable_id(prefix: str, *parts: str) -> str:
    payload = "\x1f".join(parts).encode("utf-8")
    return f"{prefix}_{hashlib.sha256(payload).hexdigest()[:20]}"


def _normalized_group_text(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().casefold())


def _parse_boolean(value: Any, field_name: str) -> bool:
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().casefold()
    if normalized in {"true", "1", "yes"}:
        return True
    if normalized in {"false", "0", "no"}:
        return False
    raise DatasetValidationError(f"{field_name} must be a boolean value")


class CPDonlineAdapter:
    def __init__(self, dataset_name: str) -> None:
        if not dataset_name.strip():
            raise ValueError("dataset_name must not be blank")
        self.dataset_name = dataset_name

    def convert(self, row: Mapping[str, Any]) -> PromptRecord:
        prompt = str(row.get("full_prompt", ""))
        if not prompt.strip():
            raise DatasetValidationError("full_prompt must not be blank")

        is_attack = _parse_boolean(row.get("is_adversarial"), "is_adversarial")
        suffix = str(row.get("suffix") or "")
        attack_family = str(row.get("algorithm") or "unknown").strip() or "unknown"

        if is_attack and not suffix:
            raise DatasetValidationError("adversarial row must include a suffix")
        if suffix and not prompt.endswith(suffix):
            raise DatasetValidationError("suffix must match the end of full_prompt")

        suffix_start = len(prompt) - len(suffix) if is_attack else None
        canonical_suffix = suffix if is_attack else None
        base_prompt = prompt[:suffix_start] if suffix_start is not None else prompt
        group_id = _stable_id(
            "grp",
            _normalized_group_text(base_prompt),
            attack_family.casefold() if is_attack else "benign",
        )
        sample_id = _stable_id(
            "sample",
            self.dataset_name,
            prompt,
            suffix,
            str(is_attack),
        )

        language_value = row.get("language")
        language = str(language_value).strip() if language_value else None
        source_value = row.get("source_dataset")
        source_detail = str(source_value).strip() if source_value else ""
        source_dataset = (
            f"{self.dataset_name}:{source_detail}" if source_detail else self.dataset_name
        )

        return PromptRecord(
            sample_id=sample_id,
            prompt=prompt,
            label_suffix_attack=is_attack,
            attack_family=attack_family if is_attack else None,
            suffix_text=canonical_suffix,
            suffix_char_start=suffix_start,
            source_dataset=source_dataset,
            group_id=group_id,
            language=language,
        )


class CPDonlineOptimizationAdapter:
    def __init__(self, dataset_name: str, attack_family: str) -> None:
        self._adapter = CPDonlineAdapter(dataset_name)
        self.attack_family = attack_family

    def convert(self, row: Mapping[str, Any]) -> PromptRecord:
        return self._adapter.convert(
            {
                "full_prompt": row.get("full_instruct"),
                "suffix": row.get("suffix"),
                "is_adversarial": True,
                "algorithm": self.attack_family,
                "language": row.get("language"),
            }
        )


class CPDonlineGuardBypassAdapter:
    def __init__(self, dataset_name: str) -> None:
        self._adapter = CPDonlineAdapter(dataset_name)

    def convert(self, row: Mapping[str, Any]) -> PromptRecord:
        base_prompt = str(row.get("prompt") or "")
        trigger = str(row.get("trigger") or "")
        return self._adapter.convert(
            {
                "full_prompt": base_prompt + trigger,
                "suffix": trigger,
                "is_adversarial": True,
                "algorithm": "gcg",
                "language": row.get("language"),
            }
        )


def normalize_rows(
    rows: Iterable[Mapping[str, Any]], adapter: RowAdapter
) -> list[PromptRecord]:
    records: list[PromptRecord] = []
    seen_ids: set[str] = set()
    for row in rows:
        record = adapter.convert(row)
        if record.sample_id in seen_ids:
            raise DatasetValidationError(f"duplicate sample_id: {record.sample_id}")
        seen_ids.add(record.sample_id)
        records.append(record)
    return records
