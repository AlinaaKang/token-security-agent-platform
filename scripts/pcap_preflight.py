from __future__ import annotations

import hashlib
import math
import subprocess
import tempfile
from collections import Counter
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from pathlib import Path
from typing import Protocol


ALLOWED_PROTOCOLS = (
    "arp",
    "dns",
    "eth",
    "http",
    "http2",
    "icmp",
    "icmpv6",
    "ip",
    "ipv6",
    "quic",
    "sll",
    "sll2",
    "tcp",
    "tls",
    "udp",
    "websocket",
)
PLAINTEXT_CANDIDATES = frozenset({"http", "http2", "websocket"})
ENCRYPTED_PROTOCOLS = frozenset({"tls", "quic"})
ALLOWED_REASONS = frozenset(
    {
        "plaintext_application_protocol_observed",
        "encrypted_transport_observed",
        "network_traffic_only",
        "no_packets",
        "no_supported_protocols",
    }
)

_ALLOWED_PROTOCOL_SET = frozenset(ALLOWED_PROTOCOLS)
_CAPTURE_FORMATS = frozenset({"pcap", "pcapng"})
_CAPABILITIES = frozenset(
    {"token_eligible", "traffic_only", "insufficient_evidence"}
)
_PCAP_MAGIC = frozenset(
    {
        bytes.fromhex("a1b2c3d4"),
        bytes.fromhex("d4c3b2a1"),
        bytes.fromhex("a1b23c4d"),
        bytes.fromhex("4d3cb2a1"),
    }
)
_PCAPNG_MAGIC = bytes.fromhex("0a0d0d0a")
_MAX_INTEGER = (1 << 63) - 1
_SCHEMA_VERSION = 1
_REPORT_KEYS = frozenset(
    {
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
)
_VISIBILITY_KEYS = frozenset(
    {
        "plaintext_application_protocol_observed",
        "encrypted_transport_observed",
        "tls_observed",
        "quic_observed",
    }
)
_TOOL_VERSION_KEYS = frozenset({"tshark"})


class PreflightError(ValueError):
    """A fixed public error code emitted by the capture preflight."""


@dataclass(frozen=True)
class ProtocolObservation:
    packet_count: int
    first_epoch: Decimal | None
    last_epoch: Decimal | None
    link_types: tuple[str, ...]
    protocol_counts: Mapping[str, int]


@dataclass(frozen=True)
class CaptureObservation:
    sha256: str
    size_bytes: int
    capture_format: str
    protocols: ProtocolObservation
    tshark_version: str


class TsharkRunner(Protocol):
    @property
    def version(self) -> str: ...

    def iter_rows(self, path: Path) -> Iterable[str]: ...


class _SystemTsharkRunner:
    """Runs the fixed metadata-only TShark field extraction command."""

    version = "tshark"

    def iter_rows(self, path: Path) -> Iterator[str]:
        command = [
            "tshark",
            "-n",
            "-r",
            str(path),
            "-o",
            "tcp.desegment_tcp_streams:FALSE",
            "-o",
            "http.desegment_body:FALSE",
            "-T",
            "fields",
            "-E",
            "separator=/t",
            "-E",
            "occurrence=f",
            "-e",
            "frame.time_epoch",
            "-e",
            "frame.encap_type",
            "-e",
            "frame.protocols",
        ]
        try:
            with tempfile.SpooledTemporaryFile(
                max_size=8192,
                mode="w+t",
                encoding="utf-8",
                errors="replace",
                dir="/tmp",
            ) as error_stream:
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=error_stream,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                )
                try:
                    if process.stdout is None:
                        raise PreflightError("tshark_failed")
                    for line in process.stdout:
                        yield line
                    process.wait(timeout=120)
                except subprocess.TimeoutExpired as error:
                    process.kill()
                    process.wait()
                    raise PreflightError("tshark_timeout") from error
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait()
                    if process.stdout is not None:
                        process.stdout.close()
                error_stream.seek(0)
                error_stream.read(8192)
                if process.returncode != 0:
                    raise PreflightError("tshark_failed")
        except FileNotFoundError as error:
            raise PreflightError("tshark_unavailable") from error
        except OSError as error:
            raise PreflightError("tshark_failed") from error


def detect_capture_format(header: bytes) -> str:
    if header in _PCAP_MAGIC:
        return "pcap"
    if header == _PCAPNG_MAGIC:
        return "pcapng"
    raise PreflightError("unsupported_capture_format")


def parse_tshark_rows(lines: Iterable[str]) -> ProtocolObservation:
    packet_count = 0
    first_epoch: Decimal | None = None
    last_epoch: Decimal | None = None
    link_types: set[str] = set()
    protocol_counts: Counter[str] = Counter()

    for raw_line in lines:
        fields = raw_line.rstrip("\r\n").split("\t")
        if len(fields) != 3:
            raise PreflightError("invalid_tshark_output")
        try:
            epoch = Decimal(fields[0])
        except (InvalidOperation, ValueError) as error:
            raise PreflightError("invalid_tshark_output") from error
        if not epoch.is_finite():
            raise PreflightError("invalid_tshark_output")
        packet_count += 1
        first_epoch = epoch if first_epoch is None else min(first_epoch, epoch)
        last_epoch = epoch if last_epoch is None else max(last_epoch, epoch)

        link_type = fields[1]
        if link_type.isascii() and link_type.isdigit():
            link_type = f"encap_{link_type}"
        if link_type:
            link_types.add(link_type)
        for protocol in fields[2].split(":"):
            if protocol in _ALLOWED_PROTOCOL_SET:
                protocol_counts[protocol] += 1

    return ProtocolObservation(
        packet_count=packet_count,
        first_epoch=first_epoch,
        last_epoch=last_epoch,
        link_types=tuple(sorted(link_types)),
        protocol_counts=dict(sorted(protocol_counts.items())),
    )


def build_report(observation: CaptureObservation) -> dict[str, object]:
    _validate_observation(observation)
    protocols = observation.protocols
    counts = dict(sorted(protocols.protocol_counts.items()))
    capability, reasons = _policy(protocols.packet_count, counts)
    duration = _duration(protocols.first_epoch, protocols.last_epoch)
    visibility = _visibility(counts)

    return {
        "schema_version": _SCHEMA_VERSION,
        "sha256": observation.sha256,
        "size_bytes": observation.size_bytes,
        "capture_format": observation.capture_format,
        "packet_count": protocols.packet_count,
        "duration_seconds": duration,
        "link_types": sorted(set(protocols.link_types)),
        "protocol_counts": counts,
        "visibility": visibility,
        "capability": capability,
        "reasons": reasons,
        "tool_versions": {"tshark": observation.tshark_version},
    }


def validate_report(value: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != _REPORT_KEYS:
        _invalid_schema()

    schema_version = value["schema_version"]
    if not _is_integer(schema_version) or schema_version != _SCHEMA_VERSION:
        _invalid_schema()
    sha256 = value["sha256"]
    if not _is_sha256(sha256):
        _invalid_schema()
    size_bytes = value["size_bytes"]
    packet_count = value["packet_count"]
    if not _is_bounded_integer(size_bytes) or not _is_bounded_integer(packet_count):
        _invalid_schema()
    capture_format = value["capture_format"]
    if not isinstance(capture_format, str) or capture_format not in _CAPTURE_FORMATS:
        _invalid_schema()
    duration = value["duration_seconds"]
    if not _is_finite_number(duration) or float(duration) < 0:
        _invalid_schema()

    link_types = value["link_types"]
    if not _is_sorted_unique_strings(link_types):
        _invalid_schema()
    protocol_counts = value["protocol_counts"]
    if not isinstance(protocol_counts, Mapping):
        _invalid_schema()
    protocol_names = list(protocol_counts)
    if not all(isinstance(name, str) for name in protocol_names):
        _invalid_schema()
    if protocol_names != sorted(protocol_names):
        _invalid_schema()
    for name, count in protocol_counts.items():
        if name not in _ALLOWED_PROTOCOL_SET or not _is_bounded_integer(count):
            _invalid_schema()

    visibility = value["visibility"]
    if not isinstance(visibility, Mapping) or set(visibility) != _VISIBILITY_KEYS:
        _invalid_schema()
    expected_visibility = _visibility(protocol_counts)
    if any(visibility[name] is not expected_visibility[name] for name in _VISIBILITY_KEYS):
        _invalid_schema()

    capability = value["capability"]
    reasons = value["reasons"]
    if (
        not isinstance(capability, str)
        or capability not in _CAPABILITIES
        or not _is_sorted_unique_strings(reasons)
    ):
        _invalid_schema()
    if any(reason not in ALLOWED_REASONS for reason in reasons):
        _invalid_schema()
    expected_capability, expected_reasons = _policy(int(packet_count), protocol_counts)
    if capability != expected_capability or reasons != expected_reasons:
        _invalid_schema()

    tool_versions = value["tool_versions"]
    if not isinstance(tool_versions, Mapping) or set(tool_versions) != _TOOL_VERSION_KEYS:
        _invalid_schema()
    tshark_version = tool_versions["tshark"]
    if not isinstance(tshark_version, str) or not tshark_version.strip():
        _invalid_schema()

    return dict(value)


def inspect_capture(
    path: Path, *, runner: TsharkRunner | None = None
) -> dict[str, object]:
    try:
        with path.open("rb") as capture:
            capture_format = detect_capture_format(capture.read(4))
            digest = hashlib.sha256()
            capture.seek(0)
            while chunk := capture.read(1024 * 1024):
                digest.update(chunk)
            size_bytes = capture.tell()
    except PreflightError:
        raise
    except OSError as error:
        raise PreflightError("capture_read_failed") from error

    selected_runner = runner or _SystemTsharkRunner()
    protocols = parse_tshark_rows(selected_runner.iter_rows(path))
    return validate_report(
        build_report(
            CaptureObservation(
                sha256=digest.hexdigest(),
                size_bytes=size_bytes,
                capture_format=capture_format,
                protocols=protocols,
                tshark_version=selected_runner.version,
            )
        )
    )


def _validate_observation(observation: CaptureObservation) -> None:
    if not _is_sha256(observation.sha256):
        _invalid_observation()
    if not _is_bounded_integer(observation.size_bytes):
        _invalid_observation()
    if observation.capture_format not in _CAPTURE_FORMATS:
        _invalid_observation()
    if not isinstance(observation.tshark_version, str) or not observation.tshark_version.strip():
        _invalid_observation()

    protocols = observation.protocols
    if not _is_bounded_integer(protocols.packet_count):
        _invalid_observation()
    if (protocols.first_epoch is None) != (protocols.last_epoch is None):
        _invalid_observation()
    for epoch in (protocols.first_epoch, protocols.last_epoch):
        if epoch is not None and (not isinstance(epoch, Decimal) or not epoch.is_finite()):
            _invalid_observation()
    if not all(isinstance(link_type, str) and link_type for link_type in protocols.link_types):
        _invalid_observation()
    for name, count in protocols.protocol_counts.items():
        if name not in _ALLOWED_PROTOCOL_SET or not _is_bounded_integer(count):
            _invalid_observation()


def _duration(first_epoch: Decimal | None, last_epoch: Decimal | None) -> float:
    if first_epoch is None or last_epoch is None:
        return 0.0
    duration = max(Decimal(0), last_epoch - first_epoch)
    rounded = duration.quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)
    return float(rounded)


def _policy(packet_count: int, counts: Mapping[str, int]) -> tuple[str, list[str]]:
    if packet_count == 0:
        return "insufficient_evidence", ["no_packets"]
    if any(count > 0 for name, count in counts.items() if name in PLAINTEXT_CANDIDATES):
        return "token_eligible", ["plaintext_application_protocol_observed"]
    if any(count > 0 for name, count in counts.items() if name in ENCRYPTED_PROTOCOLS):
        return "traffic_only", ["encrypted_transport_observed"]
    if sum(counts.values()) > 0:
        return "traffic_only", ["network_traffic_only"]
    return "insufficient_evidence", ["no_supported_protocols"]


def _visibility(counts: Mapping[str, int]) -> dict[str, bool]:
    return {
        "encrypted_transport_observed": any(
            count > 0 for name, count in counts.items() if name in ENCRYPTED_PROTOCOLS
        ),
        "plaintext_application_protocol_observed": any(
            count > 0 for name, count in counts.items() if name in PLAINTEXT_CANDIDATES
        ),
        "quic_observed": counts.get("quic", 0) > 0,
        "tls_observed": counts.get("tls", 0) > 0,
    }


def _is_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_bounded_integer(value: object) -> bool:
    return _is_integer(value) and 0 <= value <= _MAX_INTEGER


def _is_finite_number(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return True if isinstance(value, int) else math.isfinite(value)


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_sorted_unique_strings(value: object) -> bool:
    return (
        isinstance(value, list)
        and all(isinstance(item, str) and item for item in value)
        and value == sorted(value)
        and len(value) == len(set(value))
    )


def _invalid_schema() -> None:
    raise PreflightError("invalid_report_schema")


def _invalid_observation() -> None:
    raise PreflightError("invalid_observation")
