from __future__ import annotations

import hashlib
import ipaddress
import struct
from pathlib import Path

from scripts.new_safe_pcap_fixture import write_safe_fixture


PCAP_GLOBAL_HEADER_SIZE = 24
PCAP_RECORD_HEADER_SIZE = 16
ETHERNET_HEADER_SIZE = 14
IPV4_HEADER_SIZE = 20
TCP_HEADER_SIZE = 20


def _internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def test_safe_fixture_is_deterministic_and_self_hashing(tmp_path: Path) -> None:
    first = tmp_path / "first.pcap"
    second = tmp_path / "second.pcap"

    first_hash = write_safe_fixture(first)
    second_hash = write_safe_fixture(second)

    assert first.read_bytes() == second.read_bytes()
    assert first_hash == second_hash == hashlib.sha256(first.read_bytes()).hexdigest()


def test_safe_fixture_contains_one_benign_documentation_packet(tmp_path: Path) -> None:
    capture = tmp_path / "fixture.pcap"
    write_safe_fixture(capture)
    data = capture.read_bytes()

    assert data[:4] == bytes.fromhex("d4c3b2a1")
    assert len(data) < 1024

    captured_length, original_length = struct.unpack_from("<II", data, 32)
    packet = data[PCAP_GLOBAL_HEADER_SIZE + PCAP_RECORD_HEADER_SIZE :]
    assert captured_length == original_length == len(packet)

    ipv4 = packet[ETHERNET_HEADER_SIZE : ETHERNET_HEADER_SIZE + IPV4_HEADER_SIZE]
    tcp = packet[
        ETHERNET_HEADER_SIZE + IPV4_HEADER_SIZE :
        ETHERNET_HEADER_SIZE + IPV4_HEADER_SIZE + TCP_HEADER_SIZE
    ]
    payload = packet[ETHERNET_HEADER_SIZE + IPV4_HEADER_SIZE + TCP_HEADER_SIZE :]

    assert ipaddress.ip_address(ipv4[12:16]) == ipaddress.ip_address("192.0.2.10")
    assert ipaddress.ip_address(ipv4[16:20]) == ipaddress.ip_address("198.51.100.20")
    assert struct.unpack_from("!H", tcp, 2)[0] == 80
    assert payload == b"GET /health HTTP/1.1\r\nHost: example.test\r\n\r\n"
    assert _internet_checksum(ipv4) == 0

    pseudo_header = ipv4[12:20] + b"\x00\x06" + struct.pack("!H", len(tcp) + len(payload))
    assert _internet_checksum(pseudo_header + tcp + payload) == 0


def test_safe_fixture_excludes_private_and_attack_material(tmp_path: Path) -> None:
    capture = tmp_path / "fixture.pcap"
    write_safe_fixture(capture)
    lowered = capture.read_bytes().lower()

    for forbidden in (
        b"private_sentinel",
        b"authorization:",
        b"cookie:",
        b"jailbreak",
        b"ignore previous",
        b"attack suffix",
        b"prompt",
    ):
        assert forbidden not in lowered
