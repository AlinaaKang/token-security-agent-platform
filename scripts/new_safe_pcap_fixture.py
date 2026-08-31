from __future__ import annotations

import argparse
import hashlib
import ipaddress
import struct
from pathlib import Path


_SOURCE_IP = ipaddress.ip_address("192.0.2.10").packed
_DESTINATION_IP = ipaddress.ip_address("198.51.100.20").packed
_HTTP_PAYLOAD = b"GET /health HTTP/1.1\r\nHost: example.test\r\n\r\n"


def _internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    words = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _build_packet() -> bytes:
    ethernet = bytes.fromhex("0200000000200200000000100800")

    total_length = 20 + 20 + len(_HTTP_PAYLOAD)
    ipv4_without_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        0x1234,
        0x4000,
        64,
        6,
        0,
        _SOURCE_IP,
        _DESTINATION_IP,
    )
    ipv4_checksum = _internet_checksum(ipv4_without_checksum)
    ipv4 = ipv4_without_checksum[:10] + struct.pack("!H", ipv4_checksum) + ipv4_without_checksum[12:]

    tcp_without_checksum = struct.pack(
        "!HHIIHHHH",
        40000,
        80,
        1,
        1,
        (5 << 12) | 0x18,
        64240,
        0,
        0,
    )
    tcp_length = len(tcp_without_checksum) + len(_HTTP_PAYLOAD)
    pseudo_header = _SOURCE_IP + _DESTINATION_IP + b"\x00\x06" + struct.pack("!H", tcp_length)
    tcp_checksum = _internet_checksum(pseudo_header + tcp_without_checksum + _HTTP_PAYLOAD)
    tcp = tcp_without_checksum[:16] + struct.pack("!H", tcp_checksum) + tcp_without_checksum[18:]

    return ethernet + ipv4 + tcp + _HTTP_PAYLOAD


def _build_capture() -> bytes:
    packet = _build_packet()
    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    record_header = struct.pack("<IIII", 1_704_067_200, 0, len(packet), len(packet))
    return global_header + record_header + packet


def write_safe_fixture(path: Path) -> str:
    data = _build_capture()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate one deterministic benign PCAP fixture.")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    sha256 = write_safe_fixture(args.output)
    print(f"safe_fixture_sha256={sha256}")
    print(f"safe_fixture_size={args.output.stat().st_size}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
