from __future__ import annotations

import hashlib
import math
import os
import re
import subprocess
import tempfile
from collections import Counter
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from pathlib import Path
from queue import Empty, Full, Queue
from threading import Event, Thread
from time import monotonic
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
_ENCAP_LINK_TYPE_PATTERN = re.compile(r"encap_[0-9]+\Z")
_TSHARK_VERSION_PATTERN = re.compile(
    r"(?:tshark|TShark [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\Z"
)
_STDERR_LIMIT_BYTES = 8192
_TSHARK_TIMEOUT_SECONDS = 120.0
_STDOUT_QUEUE_MAXSIZE = 64
_STDOUT_HANDOFF_POLL_SECONDS = 0.01
_PREFLIGHT_ERROR_CODES = frozenset(
    {
        "capture_read_failed",
        "invalid_observation",
        "invalid_report_schema",
        "invalid_tshark_output",
        "tshark_failed",
        "tshark_timeout",
        "tshark_unavailable",
        "unsupported_capture_format",
    }
)


class PreflightError(ValueError):
    """A fixed public error code emitted by the capture preflight."""

    def __init__(self, code: str) -> None:
        if not isinstance(code, str) or code not in _PREFLIGHT_ERROR_CODES:
            raise ValueError("invalid_preflight_error_code")
        self.code = code
        super().__init__(code)


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


class _BoundedStderrSink:
    """Drains child stderr without retaining more than the fixed limit."""

    def __init__(self) -> None:
        self._read_fd, write_fd = os.pipe()
        self._writer = os.fdopen(write_fd, "wb", buffering=0)
        self._temporary = tempfile.TemporaryFile(mode="w+b", dir="/tmp")
        self._stored_bytes = 0
        self._reader = Thread(target=self._drain, daemon=True)

    @property
    def stored_bytes(self) -> int:
        return self._stored_bytes

    def __enter__(self) -> _BoundedStderrSink:
        return self

    def __exit__(self, *arguments: object) -> None:
        del arguments
        self.close_writer()
        self.join()
        self._temporary.close()

    def fileno(self) -> int:
        return self._writer.fileno()

    def start(self) -> None:
        self._reader.start()

    def close_writer(self) -> None:
        if not self._writer.closed:
            self._writer.close()

    def join(self) -> None:
        self._reader.join()

    def _drain(self) -> None:
        try:
            while chunk := os.read(self._read_fd, _STDERR_LIMIT_BYTES):
                remaining = _STDERR_LIMIT_BYTES - self._stored_bytes
                if remaining > 0:
                    retained = chunk[:remaining]
                    self._temporary.write(retained)
                    self._stored_bytes += len(retained)
        finally:
            os.close(self._read_fd)


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
            with _BoundedStderrSink() as error_stream:
                error_stream.start()
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=error_stream,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                )
                error_stream.close_writer()
                try:
                    if process.stdout is None:
                        raise PreflightError("tshark_failed")
                    deadline = monotonic() + _TSHARK_TIMEOUT_SECONDS
                    for line in _read_stdout_until_deadline(process, deadline):
                        yield line
                    process.wait(timeout=_remaining_time(deadline))
                except subprocess.TimeoutExpired as error:
                    _terminate_process(process)
                    raise PreflightError("tshark_timeout") from error
                finally:
                    _terminate_process(process)
                    if process.stdout is not None:
                        process.stdout.close()
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
        if not (link_type.isascii() and link_type.isdecimal()):
            raise PreflightError("invalid_tshark_output")
        link_types.add(f"encap_{link_type}")
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
    if not all(_is_encap_link_type(link_type) for link_type in link_types):
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
    if not _is_tshark_version(tshark_version):
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
    if not _is_tshark_version(observation.tshark_version):
        _invalid_observation()

    protocols = observation.protocols
    if not _is_bounded_integer(protocols.packet_count):
        _invalid_observation()
    if (protocols.first_epoch is None) != (protocols.last_epoch is None):
        _invalid_observation()
    for epoch in (protocols.first_epoch, protocols.last_epoch):
        if epoch is not None and (not isinstance(epoch, Decimal) or not epoch.is_finite()):
            _invalid_observation()
    if not all(_is_encap_link_type(link_type) for link_type in protocols.link_types):
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


def _is_encap_link_type(value: object) -> bool:
    return isinstance(value, str) and _ENCAP_LINK_TYPE_PATTERN.fullmatch(value) is not None


def _is_tshark_version(value: object) -> bool:
    return isinstance(value, str) and _TSHARK_VERSION_PATTERN.fullmatch(value) is not None


def _read_stdout_until_deadline(process: subprocess.Popen[str], deadline: float) -> Iterator[str]:
    if process.stdout is None:
        raise PreflightError("tshark_failed")
    messages: Queue[str] = Queue(maxsize=_STDOUT_QUEUE_MAXSIZE)
    cancelled = Event()
    reader_done = Event()
    reader_failed = Event()

    def handoff(line: str) -> bool:
        while not cancelled.is_set():
            remaining = deadline - monotonic()
            if remaining <= 0:
                return False
            try:
                messages.put(
                    line,
                    timeout=min(remaining, _STDOUT_HANDOFF_POLL_SECONDS),
                )
                return True
            except Full:
                continue
        return False

    def drain_stdout() -> None:
        try:
            for line in process.stdout:
                if not handoff(line):
                    return
        except OSError:
            reader_failed.set()
        finally:
            reader_done.set()

    reader = Thread(target=drain_stdout, daemon=True)
    reader.start()
    try:
        while True:
            try:
                line = messages.get(
                    timeout=min(
                        _remaining_time(deadline), _STDOUT_HANDOFF_POLL_SECONDS
                    )
                )
            except Empty:
                if reader_failed.is_set():
                    raise PreflightError("tshark_failed")
                if reader_done.is_set():
                    return
                continue
            yield line
    finally:
        cancelled.set()


def _remaining_time(deadline: float) -> float:
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise PreflightError("tshark_timeout")
    return remaining


def _terminate_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        process.kill()
        process.wait()


def _invalid_schema() -> None:
    raise PreflightError("invalid_report_schema")


def _invalid_observation() -> None:
    raise PreflightError("invalid_observation")
