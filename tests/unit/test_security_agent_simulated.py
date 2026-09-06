from __future__ import annotations

import pytest

from app.security_agent.simulated import (
    SimulatedCaseNotFound,
    SimulatedEvidenceRejected,
    SimulatedTelemetryConnector,
    assert_real_evidence,
)


def connector() -> SimulatedTelemetryConnector:
    return SimulatedTelemetryConnector()


def test_demo_connector_marks_every_item_simulated() -> None:
    evidence = connector().query("demo_llm_injection_01")

    assert evidence
    assert all(item.authenticity == "simulated" for item in evidence)


def test_demo_connector_rejects_arbitrary_identifiers() -> None:
    with pytest.raises(SimulatedCaseNotFound):
        connector().query("capture_1482.pcap")


def test_demo_snapshot_has_fixed_verified_sha256_identity() -> None:
    source = connector()

    assert source.snapshot_version == "security-agent-demo-cases-v1"
    assert source.snapshot_sha256.startswith("sha256:")
    assert len(source.snapshot_sha256) == 71


@pytest.mark.parametrize(
    "case_id",
    [
        "demo_llm_injection_01",
        "demo_internal_probe_01",
        "demo_scripted_extraction_01",
    ],
)
def test_demo_cases_use_only_abstract_public_facts(case_id: str) -> None:
    encoded = " ".join(item.model_dump_json() for item in connector().query(case_id)).casefold()

    for private_marker in (
        "ip_address",
        "username",
        "command_line",
        "payload",
        "file_path",
    ):
        assert private_marker not in encoded
    assert any(
        label in encoded
        for label in (
            "endpoint_process_anomaly",
            "identity_session_burst",
            "gateway_request_correlation",
        )
    )


def test_simulated_evidence_cannot_enter_real_evaluation_collector() -> None:
    with pytest.raises(SimulatedEvidenceRejected):
        assert_real_evidence(connector().query("demo_llm_injection_01"))

