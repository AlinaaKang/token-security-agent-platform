from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.detection.cpd import RobustBaseline


class CalibrationMismatchError(RuntimeError):
    pass


class CalibrationProfile(BaseModel, frozen=True):
    version: str = Field(min_length=1)
    model_id: str = Field(min_length=1)
    tokenizer_id: str = Field(min_length=1)
    system_prompt_hash: str = Field(min_length=1)
    signal: Literal["entropy", "nll"]
    baseline: RobustBaseline
    k: float = Field(ge=0)
    h: float = Field(gt=0)
    created_at: datetime
    dataset_hash: str = Field(min_length=1)

    def ensure_compatible(
        self,
        *,
        model_id: str,
        tokenizer_id: str,
        system_prompt_hash: str,
    ) -> None:
        runtime_identity = {
            "model_id": model_id,
            "tokenizer_id": tokenizer_id,
            "system_prompt_hash": system_prompt_hash,
        }
        mismatches = [
            field_name
            for field_name, runtime_value in runtime_identity.items()
            if getattr(self, field_name) != runtime_value
        ]
        if mismatches:
            raise CalibrationMismatchError(
                "calibration identity mismatch: " + ", ".join(mismatches)
            )
