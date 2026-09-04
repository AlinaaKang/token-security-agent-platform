from __future__ import annotations

import argparse
import ipaddress
import struct
from pathlib import Path
from typing import NamedTuple


_SOURCE_IP = ipaddress.ip_address("192.0.2.10").packed
_DESTINATION_IP = ipaddress.ip_address("198.51.100.20").packed
_REQUEST_TARGETS = {
    "benign": "/search?q=weather",
    "sql_injection": "/search?q=%27%20OR%201%3D1--",
    "command_injection": "/status?host=localhost%3Bid",
    "path_traversal": "/files/..%2F..%2Fetc%2Fpasswd",
}


class AttackFixtureMetadata(NamedTuple):
    packet_count: int
    attack_packet: int | None
    request_target: str


def _internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    words = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _build_http_packet(request_target: str, packet_number: int) -> bytes:
    payload = (
        f"GET {request_target} HTTP/1.1\r\nHost: synthetic.example\r\n\r\n"
    ).encode("ascii")
    ethernet = bytes.fromhex("0200000000200200000000100800")
    total_length = 20 + 20 + len(payload)
    ipv4_without_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        0x1200 + packet_number,
        0x4000,
        64,
        6,
        0,
        _SOURCE_IP,
        _DESTINATION_IP,
    )
    ipv4_checksum = _internet_checksum(ipv4_without_checksum)
    ipv4 = (
        ipv4_without_checksum[:10]
        + struct.pack("!H", ipv4_checksum)
        + ipv4_without_checksum[12:]
    )
    tcp_without_checksum = struct.pack(
        "!HHIIHHHH",
        40000 + packet_number,
        80,
        1,
        1,
        (5 << 12) | 0x18,
        64240,
        0,
        0,
    )
    tcp_length = len(tcp_without_checksum) + len(payload)
    pseudo_header = (
        _SOURCE_IP
        + _DESTINATION_IP
        + b"\x00\x06"
        + struct.pack("!H", tcp_length)
    )
    tcp_checksum = _internet_checksum(pseudo_header + tcp_without_checksum + payload)
    tcp = (
        tcp_without_checksum[:16]
        + struct.pack("!H", tcp_checksum)
        + tcp_without_checksum[18:]
    )
    return ethernet + ipv4 + tcp + payload


def write_attack_fixture(path: Path, fixture_kind: str) -> AttackFixtureMetadata:
    if fixture_kind not in _REQUEST_TARGETS:
        raise ValueError("unsupported synthetic fixture kind")
    selected_target = _REQUEST_TARGETS[fixture_kind]
    targets = ("/health", selected_target, "/ready")
    capture = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for index, target in enumerate(targets, start=1):
        packet = _build_http_packet(target, index)
        capture.extend(
            struct.pack(
                "<IIII", 1_704_067_200, (index - 1) * 100_000, len(packet), len(packet)
            )
        )
        capture.extend(packet)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes(capture))
    return AttackFixtureMetadata(
        packet_count=3,
        attack_packet=None if fixture_kind == "benign" else 2,
        request_target=selected_target,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a synthetic HTTP PCAP.")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--kind", required=True, choices=tuple(_REQUEST_TARGETS))
    args = parser.parse_args()
    metadata = write_attack_fixture(args.output, args.kind)
    print(f"fixture_kind={args.kind}")
    print(f"packet_count={metadata.packet_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
