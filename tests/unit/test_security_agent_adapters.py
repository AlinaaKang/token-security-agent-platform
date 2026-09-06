from __future__ import annotations

from app.security_agent.tools import build_registry


class FakePcapDetectionService:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []
        self.cancel_calls: list[str] = []

    def __call__(self, arguments: dict[str, object]) -> dict[str, object]:
        self.calls.append(arguments)
        return {
            "objective": "detect_pcap_anomalies",
            "detection_id": "detection_" + "a" * 32,
            "status": "completed",
            "summary": {
                "analyzed_count": 2,
                "succeeded_count": 2,
                "failed_count": 0,
                "evidence": [
                    {
                        "evidence_id": "evidence_" + "b" * 32,
                        "attack_candidate": "sql_injection",
                        "detector": "http_rule",
                        "confidence": 0.95,
                        "start_packet": 4,
                        "end_packet": 4,
                        "purpose_candidates": ["auth_bypass"],
                    }
                ],
            },
        }

    def cancel(self, identifier: str) -> None:
        self.cancel_calls.append(identifier)


def test_pcap_adapter_returns_references_not_private_file_identity() -> None:
    service = FakePcapDetectionService()
    registry = build_registry({"detect_pcap_batch": service})

    result = registry.execute(
        "detect_pcap_batch",
        {"authorization_ref": "auth:pcap:dataset", "start_index": 0},
    )
    encoded = result.model_dump_json()

    assert result.observation.evidence_refs == ("evidence_" + "b" * 32,)
    assert result.evidence[0].authenticity == "real"
    assert result.evidence[0].source_ref == "detection_" + "a" * 32
    assert "path" not in encoded.casefold()
    assert "filename" not in encoded.casefold()


def test_adapter_preserves_existing_objective_id() -> None:
    registry = build_registry(
        {
            "inspect_pcap_dataset": lambda _arguments: {
                "objective": "reconnoiter_pcap_dataset",
                "recon_id": "recon_" + "c" * 32,
                "status": "completed",
                "summary": {"analyzed_count": 8, "failed_count": 1},
            }
        }
    )

    result = registry.execute(
        "inspect_pcap_dataset", {"authorization_ref": "auth:pcap:dataset"}
    )

    assert result.objective_id == "reconnoiter_pcap_dataset"


def test_task_switch_never_calls_underlying_cancellation() -> None:
    service = FakePcapDetectionService()
    registry = build_registry({"detect_pcap_batch": service})
    registry.execute(
        "detect_pcap_batch",
        {"authorization_ref": "auth:pcap:dataset", "start_index": 0},
    )
    registry.on_task_switch("task_" + "1" * 32, "task_" + "2" * 32)

    assert service.cancel_calls == []


def test_malformed_adapter_output_is_rejected() -> None:
    registry = build_registry(
        {"detect_pcap_batch": lambda _arguments: {"payload": "PRIVATE_SENTINEL"}}
    )

    try:
        registry.execute(
            "detect_pcap_batch",
            {"authorization_ref": "auth:pcap:dataset", "start_index": 0},
        )
    except ValueError as exc:
        assert "adapter output" in str(exc)
    else:
        raise AssertionError("malformed adapter output was accepted")

