from __future__ import annotations

import hashlib
import io
import os
import queue
import threading
import time
from decimal import Decimal
from pathlib import Path

import pytest

import scripts.pcap_preflight as preflight
from scripts.pcap_preflight import (
    CaptureObservation,
    PreflightError,
    ProtocolObservation,
    build_report,
    detect_capture_format,
    inspect_capture,
    parse_tshark_rows,
    validate_report,
)


EXPECTED_KEYS = {
    "schema_version",
    "sha256",
    "size_bytes",
    "capture_format",
    "packet_count",
    "duration_seconds",
    "link_types",
    "protocol_counts",
    "visibility",
    "capability",
    "reasons",
    "tool_versions",
}


def _observation(
    *,
    packet_count: int = 1,
    first_epoch: Decimal | None = None,
    last_epoch: Decimal | None = None,
    link_types: tuple[str, ...] = (),
    protocol_counts: dict[str, int] | None = None,
    sha256: str = "a" * 64,
    size_bytes: int = 0,
    capture_format: str = "pcap",
    tshark_version: str = "TShark 4.4.0",
) -> CaptureObservation:
    return CaptureObservation(
        sha256=sha256,
        size_bytes=size_bytes,
        capture_format=capture_format,
        protocols=ProtocolObservation(
            packet_count=packet_count,
            first_epoch=first_epoch,
            last_epoch=last_epoch,
            link_types=link_types,
            protocol_counts=protocol_counts or {},
        ),
        tshark_version=tshark_version,
    )


def test_plain_http_is_only_a_second_stage_candidate() -> None:
    report = build_report(_observation(protocol_counts={"http": 1, "tcp": 1}))

    assert set(report) == EXPECTED_KEYS
    assert report["capability"] == "token_eligible"
    assert report["reasons"] == ["plaintext_application_protocol_observed"]


def test_tls_is_traffic_only() -> None:
    report = build_report(_observation(protocol_counts={"tls": 3, "tcp": 3}))

    assert report["capability"] == "traffic_only"
    assert report["visibility"]["tls_observed"] is True


def test_unknown_fields_fail_closed() -> None:
    value = build_report(_observation()) | {"prompt": "PRIVATE_SENTINEL"}

    with pytest.raises(PreflightError, match="invalid_report_schema"):
        validate_report(value)


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        (bytes.fromhex("a1b2c3d4"), "pcap"),
        (bytes.fromhex("d4c3b2a1"), "pcap"),
        (bytes.fromhex("a1b23c4d"), "pcap"),
        (bytes.fromhex("4d3cb2a1"), "pcap"),
        (bytes.fromhex("0a0d0d0a"), "pcapng"),
    ],
)
def test_detect_capture_format_recognizes_supported_magic_values(
    header: bytes, expected: str
) -> None:
    assert detect_capture_format(header) == expected


@pytest.mark.parametrize("header", [b"", b"\x00", b"not a capture"])
def test_detect_capture_format_rejects_empty_and_unknown_headers(header: bytes) -> None:
    with pytest.raises(PreflightError, match="unsupported_capture_format"):
        detect_capture_format(header)


def test_parse_tshark_rows_keeps_only_allowed_protocols_and_normalizes_link_types() -> None:
    observation = parse_tshark_rows(
        [
            "10.125\t1\teth:ethertype:ip:tcp:http",
            "12.375\t113\tsll:ip:udp:dns:unknown",
        ]
    )

    assert observation.packet_count == 2
    assert observation.first_epoch == Decimal("10.125")
    assert observation.last_epoch == Decimal("12.375")
    assert observation.link_types == ("encap_1", "encap_113")
    assert dict(observation.protocol_counts) == {
        "dns": 1,
        "eth": 1,
        "http": 1,
        "ip": 2,
        "sll": 1,
        "tcp": 1,
        "udp": 1,
    }


@pytest.mark.parametrize(
    "line",
    [
        "not-enough-fields\t1",
        "nan\t1\ttcp",
        "infinity\t1\ttcp",
        "1.0\t1\ttcp\textra",
    ],
)
def test_parse_tshark_rows_rejects_malformed_or_nonfinite_rows(line: str) -> None:
    with pytest.raises(PreflightError, match="invalid_tshark_output"):
        parse_tshark_rows([line])


@pytest.mark.parametrize(
    "line",
    [
        "1.0\tLinux cooked-mode capture\ttcp",
        "1.0\t١\ttcp",
        "1.0\tencap_1\ttcp",
    ],
)
def test_parse_tshark_rows_rejects_non_decimal_encapsulation_ids(line: str) -> None:
    with pytest.raises(PreflightError, match="invalid_tshark_output"):
        parse_tshark_rows([line])


def test_build_report_uses_duration_floor_and_canonical_sorting() -> None:
    report = build_report(
        _observation(
            packet_count=2,
            first_epoch=Decimal("7.2500009"),
            last_epoch=Decimal("6.0"),
            link_types=("encap_2", "encap_1", "encap_2"),
            protocol_counts={"udp": 1, "dns": 2},
            size_bytes=9,
        )
    )

    assert report["duration_seconds"] == 0.0
    assert report["link_types"] == ["encap_1", "encap_2"]
    assert list(report["protocol_counts"]) == ["dns", "udp"]
    assert report["capability"] == "traffic_only"
    assert report["reasons"] == ["network_traffic_only"]


def test_build_report_rounds_finite_duration_to_six_places() -> None:
    report = build_report(
        _observation(
            packet_count=1,
            first_epoch=Decimal("1.0000001"),
            last_epoch=Decimal("2.2345680"),
            protocol_counts={"tcp": 1},
        )
    )

    assert report["duration_seconds"] == 1.234568


def test_no_packets_has_priority_over_observed_protocol_counts() -> None:
    report = build_report(_observation(packet_count=0, protocol_counts={"http": 1}))

    assert report["capability"] == "insufficient_evidence"
    assert report["reasons"] == ["no_packets"]


@pytest.mark.parametrize(
    "change",
    [
        {"schema_version": True},
        {"sha256": "A" * 64},
        {"sha256": "not-a-digest"},
        {"size_bytes": -1},
        {"packet_count": True},
        {"duration_seconds": float("inf")},
        {"capture_format": "pcapx"},
        {"capability": "eligible"},
        {"reasons": ["not_a_reason"]},
        {"reasons": ["no_packets", "no_packets"]},
        {"link_types": ["z", "a"]},
        {"link_types": ["free_form"]},
        {"link_types": ["encap_١"]},
        {"protocol_counts": {"udp": 1, "dns": 1}},
        {"tool_versions": {"tshark": ""}},
    ],
)
def test_validate_report_rejects_invalid_scalar_values_and_canonical_collections(
    change: dict[str, object],
) -> None:
    value = build_report(
        _observation(packet_count=1, protocol_counts={"tcp": 1})
    ) | change

    with pytest.raises(PreflightError, match="invalid_report_schema"):
        validate_report(value)


@pytest.mark.parametrize(
    "nested_change",
    [
        {"visibility": {"tls_observed": 1}},
        {"visibility": {"tls_observed": True, "extra": False}},
        {"tool_versions": {"tshark": "TShark 4.4.0", "python": "3.12"}},
    ],
)
def test_validate_report_rejects_extra_or_invalid_nested_fields(
    nested_change: dict[str, object],
) -> None:
    value = build_report(
        _observation(packet_count=1, protocol_counts={"tcp": 1})
    )
    for name, replacement in nested_change.items():
        if name == "visibility":
            value[name] = dict(value[name]) | replacement  # type: ignore[arg-type]
        else:
            value[name] = replacement

    with pytest.raises(PreflightError, match="invalid_report_schema"):
        validate_report(value)


@pytest.mark.parametrize("field", ["capture_format", "capability"])
def test_validate_report_rejects_unhashable_enum_values(field: str) -> None:
    value = build_report(
        _observation(packet_count=1, protocol_counts={"tcp": 1})
    )
    value[field] = ["unexpected"]

    with pytest.raises(PreflightError, match="invalid_report_schema"):
        validate_report(value)


def test_validate_report_rejects_nonfinite_observation_epochs() -> None:
    with pytest.raises(PreflightError, match="invalid_observation"):
        build_report(
            _observation(
                packet_count=1,
                first_epoch=Decimal("NaN"),
                last_epoch=Decimal("1"),
            )
        )


@pytest.mark.parametrize(
    "link_type",
    ["Linux cooked-mode capture", "encap_١", "encap_1/path"],
)
def test_build_report_rejects_free_form_link_types(link_type: str) -> None:
    with pytest.raises(PreflightError, match="invalid_observation"):
        build_report(_observation(link_types=(link_type,)))


@pytest.mark.parametrize(
    "version",
    [
        "https://example.invalid/tshark",
        "192.0.2.10:443",
        "C:\\capture\\tshark.exe",
        "report.pcap",
        "arbitrary captured payload",
    ],
)
def test_build_report_rejects_free_form_tshark_versions(version: str) -> None:
    with pytest.raises(PreflightError, match="invalid_observation"):
        build_report(_observation(tshark_version=version))


@pytest.mark.parametrize(
    "version",
    ["https://example.invalid/tshark", "192.0.2.10:443", "capture.pcap"],
)
def test_validate_report_rejects_free_form_tshark_versions(version: str) -> None:
    value = build_report(_observation())
    value["tool_versions"] = {"tshark": version}

    with pytest.raises(PreflightError, match="invalid_report_schema"):
        validate_report(value)


class _StaticRunner:
    version = "TShark 4.4.0"

    def iter_rows(self, path: Path):
        del path
        yield "1.0\t1\teth:ip:tcp:http\n"


def test_inspect_capture_uses_runner_and_returns_validated_report(tmp_path: Path) -> None:
    # This is a deliberately incomplete header fixture, not a real capture.
    fixture = tmp_path / "header-only.capture"
    contents = bytes.fromhex("a1b2c3d4") + b"fixture"
    fixture.write_bytes(contents)

    report = inspect_capture(fixture, runner=_StaticRunner())

    assert report["sha256"] == hashlib.sha256(contents).hexdigest()
    assert report["size_bytes"] == len(contents)
    assert report["capture_format"] == "pcap"
    assert report["packet_count"] == 1
    assert report["capability"] == "token_eligible"


def test_inspect_capture_rejects_an_injected_free_form_runner_version(
    tmp_path: Path,
) -> None:
    fixture = tmp_path / "header-only.capture"
    fixture.write_bytes(bytes.fromhex("a1b2c3d4") + b"fixture")
    runner = _StaticRunner()
    runner.version = "https://example.invalid/tshark"  # type: ignore[attr-defined]

    with pytest.raises(PreflightError, match="invalid_observation"):
        inspect_capture(fixture, runner=runner)


class _ProcessForEarlyClose:
    def __init__(self) -> None:
        self.stdout = io.StringIO("malformed\n")
        self.returncode: int | None = None
        self.killed = False
        self.wait_calls = 0

    def poll(self) -> int | None:
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9

    def wait(self, timeout: int | None = None) -> int:
        del timeout
        self.wait_calls += 1
        if self.returncode is None:
            self.returncode = 0
        return self.returncode


def test_system_runner_terminates_tshark_when_a_row_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _ProcessForEarlyClose()
    monkeypatch.setattr(preflight.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(
        preflight.tempfile,
        "SpooledTemporaryFile",
        lambda **kwargs: io.StringIO(),
    )

    with pytest.raises(PreflightError, match="invalid_tshark_output"):
        parse_tshark_rows(preflight._SystemTsharkRunner().iter_rows(Path("ignored")))

    assert process.killed is True
    assert process.wait_calls == 1


class _NeverClosingStdout:
    def __init__(self) -> None:
        self.release = threading.Event()

    def __iter__(self):
        return self

    def __next__(self) -> str:
        self.release.wait()
        raise StopIteration

    def close(self) -> None:
        self.release.set()


class _ProcessWithNeverClosingStdout:
    def __init__(self) -> None:
        self.stdout = _NeverClosingStdout()
        self.returncode: int | None = None
        self.killed = False

    def poll(self) -> int | None:
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9
        self.stdout.release.set()

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        if self.returncode is None:
            self.returncode = 0
        return self.returncode


def test_system_runner_times_out_while_stdout_remains_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _ProcessWithNeverClosingStdout()
    errors: queue.Queue[BaseException] = queue.Queue()
    monkeypatch.setattr(preflight, "_TSHARK_TIMEOUT_SECONDS", 0.01, raising=False)
    monkeypatch.setattr(preflight.subprocess, "Popen", lambda *args, **kwargs: process)

    def consume() -> None:
        try:
            list(preflight._SystemTsharkRunner().iter_rows(Path("ignored")))
        except BaseException as error:
            errors.put(error)

    consumer = threading.Thread(target=consume, daemon=True)
    consumer.start()
    consumer.join(timeout=0.25)
    if consumer.is_alive():
        process.stdout.release.set()
        consumer.join(timeout=1)
        pytest.fail("stdout consumption did not observe the configured timeout")

    error = errors.get_nowait()
    assert isinstance(error, PreflightError)
    assert str(error) == "tshark_timeout"
    assert process.killed is True


class _RapidStdout:
    def __init__(self, line_count: int = 128) -> None:
        self.line_count = line_count
        self.produced = 0
        self.saturated = threading.Event()

    def __iter__(self):
        return self

    def __next__(self) -> str:
        if self.produced == self.line_count:
            raise StopIteration
        self.produced += 1
        if self.produced == 3:
            self.saturated.set()
        return f"{self.produced}.0\t1\ttcp\n"

    def close(self) -> None:
        return None


class _ProcessWithRapidStdout:
    def __init__(self) -> None:
        self.stdout = _RapidStdout()
        self.returncode: int | None = None
        self.killed = False

    def poll(self) -> int | None:
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        if self.returncode is None:
            self.returncode = 0
        return self.returncode


def test_system_runner_backs_up_saturated_stdout_and_still_times_out(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _ProcessWithRapidStdout()
    monkeypatch.setattr(preflight, "_STDOUT_QUEUE_MAXSIZE", 1, raising=False)
    monkeypatch.setattr(preflight, "_TSHARK_TIMEOUT_SECONDS", 0.01, raising=False)
    monkeypatch.setattr(preflight.subprocess, "Popen", lambda *args, **kwargs: process)

    rows = preflight._SystemTsharkRunner().iter_rows(Path("ignored"))
    assert next(rows) == "1.0\t1\ttcp\n"
    assert process.stdout.saturated.wait(timeout=0.1)
    time.sleep(0.02)

    with pytest.raises(PreflightError, match="tshark_timeout"):
        next(rows)

    assert process.killed is True
    assert process.stdout.produced <= 3


def test_bounded_stderr_sink_discards_output_after_eight_kib() -> None:
    with preflight._BoundedStderrSink() as sink:
        sink.start()
        try:
            remaining = b"x" * (16 * 1024)
            while remaining:
                written = os.write(sink.fileno(), remaining)
                remaining = remaining[written:]
        finally:
            sink.close_writer()
        sink.join()

    assert sink.stored_bytes == 8192
