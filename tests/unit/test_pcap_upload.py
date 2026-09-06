from __future__ import annotations

import asyncio
import importlib
import os
from pathlib import Path
import subprocess

import pytest


PCAP_MAGICS = (
    bytes.fromhex("a1b2c3d4"),
    bytes.fromhex("d4c3b2a1"),
    bytes.fromhex("a1b23c4d"),
    bytes.fromhex("4d3cb2a1"),
)
PCAPNG_MAGIC = bytes.fromhex("0a0d0d0a")


class MutableClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value


async def byte_chunks(*chunks: bytes):
    for chunk in chunks:
        yield chunk


def upload_module():
    return importlib.import_module("app.pcap.upload")


def accept(service: object, payload: bytes, *, chunks: int = 1):
    split = max(1, len(payload) // chunks)
    body = tuple(payload[index : index + split] for index in range(0, len(payload), split))
    return asyncio.run(
        service.accept(  # type: ignore[attr-defined]
            byte_chunks(*body),
            authorization_id="pcap_auth_" + "a" * 32,
            content_length=len(payload),
        )
    )


@pytest.mark.parametrize("magic", PCAP_MAGICS)
def test_upload_accepts_each_classic_pcap_magic_and_uses_private_random_names(
    tmp_path: Path, magic: bytes
) -> None:
    module = upload_module()
    service = module.PcapUploadService(tmp_path, max_bytes=128)
    payload = magic + bytes(20)

    first = accept(service, payload, chunks=3)
    second = accept(service, payload, chunks=2)

    assert first.capture_format == "pcap"
    assert first.byte_count == 24
    assert first.capture_path.parent == tmp_path / "uploads"
    assert first.capture_path.name.startswith("upload_")
    assert first.capture_path.suffix == ".pcap"
    assert first.capture_path.read_bytes() == payload
    assert first.handle_id != second.handle_id
    assert first.capture_path != second.capture_path
    assert "a" * 32 not in first.capture_path.name


def test_upload_accepts_pcapng_minimum_header(tmp_path: Path) -> None:
    module = upload_module()
    service = module.PcapUploadService(tmp_path, max_bytes=128)
    payload = PCAPNG_MAGIC + bytes(24)

    handle = accept(service, payload, chunks=4)

    assert handle.capture_format == "pcapng"
    assert handle.capture_path.suffix == ".pcapng"
    assert handle.capture_path.read_bytes() == payload


@pytest.mark.parametrize(
    ("payload", "declared_length", "exception_name"),
    [
        (b"", 0, "PcapUploadInvalid"),
        (PCAP_MAGICS[0] + bytes(19), 23, "PcapUploadInvalid"),
        (PCAPNG_MAGIC + bytes(23), 27, "PcapUploadInvalid"),
        (b"not-a-capture" + bytes(20), 33, "PcapUploadUnsupported"),
    ],
)
def test_upload_rejects_empty_truncated_or_unsupported_content_and_cleans_partial_file(
    tmp_path: Path,
    payload: bytes,
    declared_length: int,
    exception_name: str,
) -> None:
    module = upload_module()
    service = module.PcapUploadService(tmp_path, max_bytes=128)

    with pytest.raises(getattr(module, exception_name)):
        asyncio.run(
            service.accept(
                byte_chunks(payload),
                authorization_id="pcap_auth_" + "a" * 32,
                content_length=declared_length,
            )
        )

    assert list((tmp_path / "uploads").iterdir()) == []


def test_upload_enforces_declared_and_streamed_size_bounds(tmp_path: Path) -> None:
    module = upload_module()
    service = module.PcapUploadService(tmp_path, max_bytes=24)
    valid = PCAP_MAGICS[0] + bytes(20)

    with pytest.raises(module.PcapUploadTooLarge):
        asyncio.run(
            service.accept(
                byte_chunks(valid + b"x"),
                authorization_id="pcap_auth_" + "a" * 32,
                content_length=25,
            )
        )
    with pytest.raises(module.PcapUploadTooLarge):
        asyncio.run(
            service.accept(
                byte_chunks(valid, b"x"),
                authorization_id="pcap_auth_" + "a" * 32,
                content_length=24,
            )
        )
    with pytest.raises(module.PcapUploadInvalid):
        asyncio.run(
            service.accept(
                byte_chunks(valid[:-1]),
                authorization_id="pcap_auth_" + "a" * 32,
                content_length=24,
            )
        )

    assert list((tmp_path / "uploads").iterdir()) == []


def test_upload_handle_is_claimed_once_and_discard_deletes_its_capture(
    tmp_path: Path,
) -> None:
    module = upload_module()
    service = module.PcapUploadService(tmp_path, max_bytes=128)
    handle = accept(service, PCAP_MAGICS[0] + bytes(20))

    assert service.claim(handle.handle_id) == handle
    with pytest.raises(module.PcapUploadInvalid):
        service.claim(handle.handle_id)

    service.discard(handle.handle_id)
    assert not handle.capture_path.exists()


def test_upload_store_caps_live_handles_and_expires_unclaimed_files(
    tmp_path: Path,
) -> None:
    module = upload_module()
    clock = MutableClock()
    service = module.PcapUploadService(
        tmp_path,
        max_bytes=128,
        capacity=1,
        ttl_seconds=5,
        clock=clock,
    )
    first = accept(service, PCAP_MAGICS[0] + bytes(20))

    with pytest.raises(module.PcapUploadUnavailable):
        accept(service, PCAP_MAGICS[1] + bytes(20))

    clock.value = 6
    second = accept(service, PCAP_MAGICS[1] + bytes(20))

    assert not first.capture_path.exists()
    assert second.capture_path.exists()
    with pytest.raises(module.PcapUploadInvalid):
        service.claim(first.handle_id)


def test_upload_cleans_interrupted_parts_or_owned_orphans_and_closes_handles(
    tmp_path: Path,
) -> None:
    module = upload_module()
    uploads = tmp_path / "uploads"
    uploads.mkdir()
    (uploads / "upload_orphan.pcap").write_bytes(b"orphan")
    (uploads / "stale.part").write_bytes(b"partial")
    (uploads / "unrelated.txt").write_bytes(b"keep")
    service = module.PcapUploadService(tmp_path, max_bytes=128)

    assert sorted(path.name for path in uploads.iterdir()) == ["unrelated.txt"]

    async def interrupted():
        yield PCAP_MAGICS[0]
        raise RuntimeError("interrupted")

    with pytest.raises(RuntimeError, match="interrupted"):
        asyncio.run(
            service.accept(
                interrupted(),
                authorization_id="pcap_auth_" + "a" * 32,
                content_length=24,
            )
        )
    handle = accept(service, PCAP_MAGICS[0] + bytes(20))
    service.close()

    assert not handle.capture_path.exists()
    assert sorted(path.name for path in uploads.iterdir()) == ["unrelated.txt"]


def test_upload_rejects_an_existing_reparse_upload_directory(tmp_path: Path) -> None:
    module = upload_module()
    target = tmp_path / "target"
    target.mkdir()
    uploads = tmp_path / "uploads"
    result = subprocess.run(
        [os.environ["ComSpec"], "/d", "/c", "mklink", "/J", str(uploads), str(target)],
        capture_output=True,
        check=False,
        encoding="utf-8",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    try:
        with pytest.raises(module.PcapUploadUnavailable, match="reparse"):
            module.PcapUploadService(tmp_path, max_bytes=128)
    finally:
        uploads.rmdir()
