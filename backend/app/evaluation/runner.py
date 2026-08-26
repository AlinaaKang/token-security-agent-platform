from __future__ import annotations


class PredictionIdentityError(ValueError):
    pass


def validate_prediction_ids(
    *, prediction_ids: set[str], manifest_ids: set[str]
) -> None:
    unknown_ids = prediction_ids - manifest_ids
    if unknown_ids:
        raise PredictionIdentityError(
            f"predictions contain {len(unknown_ids)} unknown sample IDs"
        )
