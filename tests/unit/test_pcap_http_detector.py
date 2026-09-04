from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Sequence

import pytest

from scripts.new_attack_pcap_fixtures import write_attack_fixture


ROOT = Path(__file__).resolve().parents[2]
DETECTOR_PATH = ROOT / "pcap-inspector" / "detect_http.py"
SPEC = importlib.util.spec_from_file_location("pcap_detect_http", DETECTOR_PATH)
assert SPEC is not None and SPEC.loader is not None
DETECTOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DETECTOR)


@pytest.mark.parametrize(
    ("fixture_kind", "expected_candidate", "expected_signal"),
    [
        ("sql_injection", "sql_injection", "sql_syntax_pattern"),
        ("command_injection", "command_injection", "command_syntax_pattern"),
        ("path_traversal", "path_traversal", "path_traversal_pattern"),
    ],
)
def test_http_rules_localize_synthetic_attack_to_request_packet(
    tmp_path: Path,
    fixture_kind: str,
    expected_candidate: str,
    expected_signal: str,
) -> None:
    fixture = tmp_path / f"{fixture_kind}.pcap"
    metadata = write_attack_fixture(fixture, fixture_kind)

    assert metadata.packet_count == 3
    assert metadata.attack_packet == 2
    report = DETECTOR.analyze_http_requests(
        verified_packet_count=metadata.packet_count,
        requests=(
            DETECTOR.HttpRequestRecord(1, 0, "/health"),
            DETECTOR.HttpRequestRecord(2, 100, metadata.request_target),
            DETECTOR.HttpRequestRecord(3, 200, "/ready"),
        ),
    )

    assert report["verified_packet_count"] == 3
    assert len(report["evidence"]) == 1
    evidence = report["evidence"][0]
    assert evidence["granularity"] == "request"
    assert evidence["start_packet"] == evidence["end_packet"] == 2
    assert evidence["start_offset_ms"] == evidence["end_offset_ms"] == 100
    assert evidence["attack_candidate"] == expected_candidate
    assert evidence["detector"] == "http_rule"
    assert expected_signal in evidence["supporting_signals"]


def test_http_rules_allow_benign_synthetic_request(tmp_path: Path) -> None:
    fixture = tmp_path / "benign.pcap"
    metadata = write_attack_fixture(fixture, "benign")

    report = DETECTOR.analyze_http_requests(
        verified_packet_count=metadata.packet_count,
        requests=(
            DETECTOR.HttpRequestRecord(1, 0, "/health"),
            DETECTOR.HttpRequestRecord(2, 100, metadata.request_target),
            DETECTOR.HttpRequestRecord(3, 200, "/ready"),
        ),
    )

    assert report == {
        "schema_version": 1,
        "verified_packet_count": 3,
        "evidence": [],
    }


def test_http_detector_output_never_discloses_request_content() -> None:
    private_target = "/search?q=%27%20OR%201%3D1--&secret=PRIVATE_SENTINEL"

    report = DETECTOR.analyze_http_requests(
        verified_packet_count=1,
        requests=(DETECTOR.HttpRequestRecord(1, 0, private_target),),
    )
    serialized = json.dumps(report, sort_keys=True)

    assert "PRIVATE_SENTINEL" not in serialized
    assert private_target not in serialized
    assert "uri" not in serialized.casefold()
    assert "payload" not in serialized.casefold()


def test_http_detector_rejects_request_outside_verified_packet_range() -> None:
    with pytest.raises(ValueError, match="verified packet range"):
        DETECTOR.analyze_http_requests(
            verified_packet_count=1,
            requests=(DETECTOR.HttpRequestRecord(2, 0, "/health"),),
        )


def test_detect_capture_uses_tshark_rows_and_returns_only_public_evidence(
    tmp_path: Path,
) -> None:
    fixture = tmp_path / "synthetic.pcap"
    metadata = write_attack_fixture(fixture, "sql_injection")

    def fake_tshark(arguments: Sequence[str]) -> str:
        if "http.request" in arguments:
            return (
                "1\t0.000000000\t/health\n"
                f"2\t0.100000000\t{metadata.request_target}\n"
                "3\t0.200000000\t/ready\n"
            )
        return "1\n2\n3\n"

    report = DETECTOR.detect_capture(fixture, run_tshark=fake_tshark)
    serialized = json.dumps(report, sort_keys=True)

    assert report["verified_packet_count"] == 3
    assert report["evidence"][0]["start_packet"] == 2
    assert metadata.request_target not in serialized


def test_detect_capture_fails_closed_on_malformed_tshark_rows(tmp_path: Path) -> None:
    fixture = tmp_path / "synthetic.pcap"
    write_attack_fixture(fixture, "benign")

    def fake_tshark(arguments: Sequence[str]) -> str:
        if "http.request" in arguments:
            return "PRIVATE_SENTINEL malformed row"
        return "1\n2\n3\n"

    with pytest.raises(DETECTOR.DetectionError) as error:
        DETECTOR.detect_capture(fixture, run_tshark=fake_tshark)
    assert error.value.code == "invalid_tshark_output"
    assert "PRIVATE_SENTINEL" not in str(error.value)


def test_detect_capture_localizes_high_rate_multi_destination_behavior(
    tmp_path: Path,
) -> None:
    fixture = tmp_path / "scan.pcap"
    fixture.write_bytes(b"pcap")
    packet_rows = "\n".join(
        f"{index}\t{index / 1000:.3f}\t10.0.0.{index}" for index in range(1, 21)
    )

    def fake_tshark(arguments: tuple[str, ...]) -> str:
        if "frame.number" in arguments and "http.request" not in arguments and "ip.dst" not in arguments:
            return "\n".join(str(index) for index in range(1, 21))
        if "http.request" in arguments:
            return ""
        return packet_rows

    report = DETECTOR.detect_capture(fixture, run_tshark=fake_tshark)

    assert len(report["evidence"]) == 1
    assert report["evidence"][0]["detector"] == "behavior_anomaly"
    assert report["evidence"][0]["granularity"] == "packet"
    assert "connection_rate_increase" in report["evidence"][0]["supporting_signals"]
