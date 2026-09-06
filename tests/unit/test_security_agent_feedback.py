from __future__ import annotations

import pytest

from app.security_agent.feedback import AnalystFeedbackService


def test_feedback_is_append_only_and_survives_restart(tmp_path) -> None:
    database = tmp_path / "feedback.sqlite3"
    service = AnalystFeedbackService(database, detector_identity=lambda: "frozen-detector-v1")
    first = service.record_feedback(task_id="task_01", verdict="false_positive", reason_code="known_test", evidence_refs=("ev_01",))
    service.close()

    restored = AnalystFeedbackService(database, detector_identity=lambda: "frozen-detector-v1")
    records = restored.list_for_task("task_01")

    assert records == (first,)
    assert records[0].verdict == "false_positive"
    restored.close()


def test_feedback_never_changes_frozen_detector_identity(tmp_path) -> None:
    detector = {"identity": "frozen-detector-v1"}
    service = AnalystFeedbackService(tmp_path / "feedback.sqlite3", detector_identity=lambda: detector["identity"])
    before = service.detector_identity()

    service.record_feedback(task_id="task_01", verdict="missed_detection", reason_code="analyst_confirmed")

    assert service.detector_identity() == before
    service.close()


def test_feedback_rejects_private_payload_fields(tmp_path) -> None:
    service = AnalystFeedbackService(tmp_path / "feedback.sqlite3", detector_identity=lambda: "frozen-detector-v1")
    with pytest.raises(ValueError):
        service.record_feedback(task_id="task_01", verdict="confirmed", reason_code="payload=PRIVATE_SENTINEL")
    assert b"PRIVATE_SENTINEL" not in (tmp_path / "feedback.sqlite3").read_bytes()
    service.close()
