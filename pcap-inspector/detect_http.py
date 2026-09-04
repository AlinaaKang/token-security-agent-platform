from __future__ import annotations

import json
import re
import subprocess
import sys
from decimal import Decimal, InvalidOperation
from pathlib import Path
from collections.abc import Callable, Sequence
from typing import NamedTuple
from urllib.parse import unquote
from uuid import uuid4


class HttpRequestRecord(NamedTuple):
    packet_number: int
    offset_ms: int
    request_target: str
    request_body: str = ""


class PacketRecord(NamedTuple):
    packet_number: int
    offset_ms: int
    destination: str


class DetectionError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


_RULES = (
    (
        "sql_injection",
        "sql_syntax_pattern",
        re.compile(r"(?:\bunion\s+(?:all\s+)?select\b|['\"]\s*or\s+\d+\s*=\s*\d+)", re.I),
        0.95,
    ),
    (
        "command_injection",
        "command_syntax_pattern",
        re.compile(
            r"(?:;|\|\||&&|\|)\s*(?:id|whoami|cat|curl|wget|sh|bash|cmd|powershell)\b",
            re.I,
        ),
        0.94,
    ),
    (
        "path_traversal",
        "path_traversal_pattern",
        re.compile(r"(?:\.\.[/\\]){2,}", re.I),
        0.96,
    ),
    (
        "web_injection",
        "xss_pattern",
        re.compile(r"(?:<\s*script\b|javascript\s*:|on(?:error|load|click)\s*=)", re.I),
        0.91,
    ),
    (
        "web_injection",
        "template_injection_pattern",
        re.compile(r"(?:\{\{[^{}]{1,80}\}\}|\$\{[^{}]{1,80}\}|<%[^%]{1,80}%>)", re.I),
        0.89,
    ),
    (
        "web_injection",
        "ssrf_pattern",
        re.compile(r"(?:https?://(?:127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.169\.254))", re.I),
        0.9,
    ),
)


def _purpose_candidates(candidate: str, target: str) -> list[str]:
    """Return bounded intent hypotheses without exposing the matched request text."""
    purposes: list[str] = []
    if candidate == "sql_injection":
        if re.search(r"['\"]\s*or\s+\d+\s*=\s*\d+", target, re.I):
            purposes.append("auth_bypass")
        if re.search(r"\bunion\s+(?:all\s+)?select\b", target, re.I):
            purposes.append("data_extraction")
        if re.search(r"\b(?:sleep|benchmark)\s*\(", target, re.I):
            purposes.append("blind_probing")
        if not purposes:
            purposes.append("data_probing")
    elif candidate == "command_injection":
        purposes.append("script_execution")
    elif candidate == "web_injection" and re.search(r"https?://(?:127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.169\.254)", target, re.I):
        purposes.append("internal_access")
    return purposes


def _decode_request_target(value: str) -> str:
    decoded = value
    for _ in range(2):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    return decoded[:8192]


def analyze_http_requests(
    *, verified_packet_count: int, requests: tuple[HttpRequestRecord, ...]
) -> dict[str, object]:
    if isinstance(verified_packet_count, bool) or verified_packet_count < 0:
        raise ValueError("verified_packet_count must be a nonnegative integer")
    evidence: list[dict[str, object]] = []
    for request in requests:
        if request.packet_number < 1 or request.packet_number > verified_packet_count:
            raise ValueError("request is outside the verified packet range")
        if request.offset_ms < 0:
            raise ValueError("request offset must be nonnegative")
        normalized_target = _decode_request_target(
            f"{request.request_target}\n{request.request_body}"
        )
        for candidate, signal, pattern, confidence in _RULES:
            if pattern.search(normalized_target) is None:
                continue
            evidence.append(
                {
                    "evidence_id": f"evidence_{uuid4().hex}",
                    "granularity": "request",
                    "verified_packet_count": verified_packet_count,
                    "start_packet": request.packet_number,
                    "end_packet": request.packet_number,
                    "start_offset_ms": request.offset_ms,
                    "end_offset_ms": request.offset_ms,
                    "attack_candidate": candidate,
                    "detector": "http_rule",
                    "confidence": confidence,
                    "supporting_signals": [signal, "request_boundary"],
                    "purpose_candidates": _purpose_candidates(candidate, normalized_target),
                }
            )
            break
    return {
        "schema_version": 1,
        "verified_packet_count": verified_packet_count,
        "evidence": evidence,
    }


def analyze_behavior(
    *, verified_packet_count: int, packets: tuple[PacketRecord, ...]
) -> list[dict[str, object]]:
    """Return a coarse, content-free signal for bursty multi-destination scans."""
    if len(packets) < 20:
        return []
    ordered = tuple(sorted(packets, key=lambda item: item.packet_number))
    if ordered[-1].offset_ms - ordered[0].offset_ms > 1000:
        return []
    if len({packet.destination for packet in ordered}) < 5:
        return []
    return [
        {
            "evidence_id": f"evidence_{uuid4().hex}",
            "granularity": "packet",
            "verified_packet_count": verified_packet_count,
            "start_packet": ordered[0].packet_number,
            "end_packet": ordered[-1].packet_number,
            "start_offset_ms": ordered[0].offset_ms,
            "end_offset_ms": ordered[-1].offset_ms,
            "attack_candidate": "none",
            "detector": "behavior_anomaly",
            "confidence": 0.82,
            "supporting_signals": [
                "connection_rate_increase",
                "destination_density_increase",
            ],
        }
    ]


def _run_tshark(arguments: Sequence[str]) -> str:
    try:
        result = subprocess.run(
            list(arguments),
            capture_output=True,
            check=False,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DetectionError("tshark_failed") from exc
    if result.returncode != 0:
        raise DetectionError("tshark_failed")
    if len(result.stdout) > 4 * 1024 * 1024:
        raise DetectionError("tshark_output_too_large")
    return result.stdout


def _parse_packet_count(text: str) -> int:
    if not text.strip():
        return 0
    try:
        packet_numbers = tuple(int(line) for line in text.splitlines())
    except ValueError as exc:
        raise DetectionError("invalid_tshark_output") from exc
    if any(number < 1 for number in packet_numbers):
        raise DetectionError("invalid_tshark_output")
    return max(packet_numbers)


def _parse_http_requests(text: str) -> tuple[HttpRequestRecord, ...]:
    requests: list[HttpRequestRecord] = []
    try:
        for line in text.splitlines():
            fields = line.split("\t")
            if len(fields) < 3:
                raise ValueError
            packet_number = int(fields[0])
            offset_ms = int(Decimal(fields[1]) * 1000)
            if packet_number < 1 or offset_ms < 0 or not fields[2]:
                raise ValueError
            requests.append(
                HttpRequestRecord(
                    packet_number,
                    offset_ms,
                    fields[2],
                    "\n".join(fields[3:]),
                )
            )
    except (InvalidOperation, ValueError) as exc:
        raise DetectionError("invalid_tshark_output") from exc
    return tuple(requests)


def _parse_packet_records(text: str) -> tuple[PacketRecord, ...]:
    records: list[PacketRecord] = []
    try:
        for line in text.splitlines():
            fields = line.split("\t")
            if len(fields) != 3:
                raise ValueError
            packet_number = int(fields[0])
            offset_ms = int(Decimal(fields[1]) * 1000)
            destination = fields[2]
            if packet_number < 1 or offset_ms < 0 or not destination:
                raise ValueError
            records.append(PacketRecord(packet_number, offset_ms, destination))
    except (InvalidOperation, ValueError) as exc:
        raise DetectionError("invalid_tshark_output") from exc
    return tuple(records)


def detect_capture(
    capture: Path,
    *,
    run_tshark: Callable[[Sequence[str]], str] = _run_tshark,
) -> dict[str, object]:
    packet_output = run_tshark(
        (
            "tshark",
            "-n",
            "-r",
            str(capture),
            "-c",
            "100000",
            "-T",
            "fields",
            "-e",
            "frame.number",
        )
    )
    verified_packet_count = _parse_packet_count(packet_output)
    request_output = run_tshark(
        (
            "tshark",
            "-n",
            "-r",
            str(capture),
            "-c",
            "100000",
            "-Y",
            "http.request",
            "-T",
            "fields",
            "-E",
            "separator=/t",
            "-E",
            "occurrence=f",
            "-e",
            "frame.number",
            "-e",
            "frame.time_relative",
            "-e",
            "http.request.uri",
            "-e",
            "http.file_data",
            "-e",
            "urlencoded-form.value",
        )
    )
    requests = _parse_http_requests(request_output)
    report = analyze_http_requests(
        verified_packet_count=verified_packet_count,
        requests=requests,
    )
    behavior_output = run_tshark(
        (
            "tshark", "-n", "-r", str(capture), "-c", "100000", "-T", "fields",
            "-E", "separator=/t", "-E", "occurrence=f", "-e", "frame.number",
            "-e", "frame.time_relative", "-e", "ip.dst",
        )
    )
    if behavior_output.strip() and "\t" in behavior_output:
        report["evidence"].extend(
            analyze_behavior(
                verified_packet_count=verified_packet_count,
                packets=_parse_packet_records(behavior_output),
            )
        )
    return report


def main() -> int:
    try:
        report = detect_capture(Path("/input/capture"))
    except DetectionError as exc:
        print(f"pcap_detection_error={exc.code}", file=sys.stderr)
        return 2
    except Exception:
        print("pcap_detection_error=unexpected_failure", file=sys.stderr)
        return 2
    print(json.dumps(report, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
