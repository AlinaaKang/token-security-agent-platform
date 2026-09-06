from __future__ import annotations

from collections.abc import AsyncIterable, Callable
from dataclasses import dataclass
import os
from pathlib import Path
import re
from secrets import token_hex
import stat
from threading import RLock
from time import monotonic
from typing import Literal


_AUTHORIZATION_ID = re.compile(r"^pcap_auth_[0-9a-f]{32}$")
_CLASSIC_PCAP_MAGICS = frozenset(
    {
        bytes.fromhex("a1b2c3d4"),
        bytes.fromhex("d4c3b2a1"),
        bytes.fromhex("a1b23c4d"),
        bytes.fromhex("4d3cb2a1"),
    }
)
_PCAPNG_MAGIC = bytes.fromhex("0a0d0d0a")
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


class PcapUploadInvalid(RuntimeError):
    pass


class PcapUploadTooLarge(RuntimeError):
    pass


class PcapUploadUnsupported(RuntimeError):
    pass


class PcapUploadUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class PcapUploadHandle:
    handle_id: str
    capture_path: Path
    byte_count: int
    capture_format: Literal["pcap", "pcapng"]


@dataclass
class _StoredUpload:
    handle: PcapUploadHandle
    expires_at: float
    claimed: bool = False


class PcapUploadService:
    def __init__(
        self,
        quarantine_root: Path,
        *,
        max_bytes: int,
        ttl_seconds: float = 300,
        capacity: int = 32,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        if type(max_bytes) is not int or max_bytes < 1:
            raise ValueError("max_bytes must be a positive integer")
        if type(capacity) is not int or capacity < 1:
            raise ValueError("capacity must be a positive integer")
        if type(ttl_seconds) not in (int, float) or ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self._root = _require_regular_directory(quarantine_root, "quarantine root")
        self._uploads_root = self._root / "uploads"
        try:
            self._uploads_root.mkdir(exist_ok=True)
            self._uploads_root = _require_regular_directory(
                self._uploads_root, "upload directory"
            )
        except PcapUploadUnavailable:
            raise
        except OSError:
            raise PcapUploadUnavailable("upload directory is unavailable") from None
        self._max_bytes = max_bytes
        self._ttl_seconds = float(ttl_seconds)
        self._capacity = capacity
        self._clock = clock
        self._uploads: dict[str, _StoredUpload] = {}
        self._reservations = 0
        self._lock = RLock()
        self._remove_owned_orphans()

    @property
    def uploads_root(self) -> Path:
        return self._uploads_root

    async def accept(
        self,
        chunks: AsyncIterable[bytes],
        *,
        authorization_id: str,
        content_length: int,
    ) -> PcapUploadHandle:
        if _AUTHORIZATION_ID.fullmatch(authorization_id or "") is None:
            raise PcapUploadInvalid("pcap_upload_invalid")
        if type(content_length) is not int or content_length < 1:
            raise PcapUploadInvalid("pcap_upload_invalid")
        if content_length > self._max_bytes:
            raise PcapUploadTooLarge("pcap_upload_too_large")

        self._reserve_slot()
        temporary_path = self._uploads_root / f"upload_{token_hex(16)}.part"
        final_path: Path | None = None
        try:
            header = bytearray()
            byte_count = 0
            try:
                with temporary_path.open("xb") as output:
                    async for chunk in chunks:
                        if not isinstance(chunk, bytes):
                            raise PcapUploadInvalid("pcap_upload_invalid")
                        byte_count += len(chunk)
                        if byte_count > self._max_bytes:
                            raise PcapUploadTooLarge("pcap_upload_too_large")
                        if len(header) < 32:
                            header.extend(chunk[: 32 - len(header)])
                        output.write(chunk)
                    output.flush()
                    os.fsync(output.fileno())
            except (PcapUploadInvalid, PcapUploadTooLarge):
                raise
            except BaseException:
                raise

            if byte_count != content_length:
                raise PcapUploadInvalid("pcap_upload_invalid")
            capture_format = _capture_format(bytes(header), byte_count)
            handle_id = "pcap_upload_" + token_hex(16)
            final_path = self._uploads_root / f"upload_{token_hex(16)}.{capture_format}"
            temporary_path.rename(final_path)
            handle = PcapUploadHandle(
                handle_id=handle_id,
                capture_path=final_path,
                byte_count=byte_count,
                capture_format=capture_format,
            )
            with self._lock:
                self._uploads[handle_id] = _StoredUpload(
                    handle=handle,
                    expires_at=self._clock() + self._ttl_seconds,
                )
            return handle
        except (PcapUploadInvalid, PcapUploadTooLarge, PcapUploadUnsupported):
            _unlink(temporary_path)
            if final_path is not None:
                _unlink(final_path)
            raise
        except BaseException as error:
            _unlink(temporary_path)
            if final_path is not None:
                _unlink(final_path)
            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                raise
            if error.__class__.__name__ == "CancelledError":
                raise
            if isinstance(error, RuntimeError):
                raise
            raise PcapUploadUnavailable("pcap_upload_unavailable") from None
        finally:
            with self._lock:
                self._reservations -= 1

    def claim(self, handle_id: str) -> PcapUploadHandle:
        with self._lock:
            self._purge_expired_locked()
            stored = self._uploads.get(handle_id)
            if stored is None or stored.claimed:
                raise PcapUploadInvalid("pcap_upload_invalid")
            _require_regular_file_within(stored.handle.capture_path, self._uploads_root)
            stored.claimed = True
            return stored.handle

    def discard(self, handle_id: str) -> None:
        with self._lock:
            stored = self._uploads.pop(handle_id, None)
        if stored is not None:
            _unlink(stored.handle.capture_path)

    def close(self) -> None:
        with self._lock:
            stored = tuple(self._uploads.values())
            self._uploads.clear()
        for item in stored:
            _unlink(item.handle.capture_path)

    def _reserve_slot(self) -> None:
        with self._lock:
            self._purge_expired_locked()
            if len(self._uploads) + self._reservations >= self._capacity:
                raise PcapUploadUnavailable("pcap_upload_unavailable")
            self._reservations += 1

    def _purge_expired_locked(self) -> None:
        now = self._clock()
        expired = [
            handle_id
            for handle_id, stored in self._uploads.items()
            if not stored.claimed and now >= stored.expires_at
        ]
        for handle_id in expired:
            stored = self._uploads.pop(handle_id)
            _unlink(stored.handle.capture_path)

    def _remove_owned_orphans(self) -> None:
        try:
            candidates = tuple(self._uploads_root.iterdir())
        except OSError:
            raise PcapUploadUnavailable("upload directory is unavailable") from None
        for path in candidates:
            if path.is_file() and (
                path.suffix == ".part"
                or (path.name.startswith("upload_") and path.suffix in {".pcap", ".pcapng"})
            ):
                _unlink(path)


def _capture_format(
    header: bytes, byte_count: int
) -> Literal["pcap", "pcapng"]:
    if byte_count < 4:
        raise PcapUploadInvalid("pcap_upload_invalid")
    magic = header[:4]
    if magic in _CLASSIC_PCAP_MAGICS:
        if byte_count < 24:
            raise PcapUploadInvalid("pcap_upload_invalid")
        return "pcap"
    if magic == _PCAPNG_MAGIC:
        if byte_count < 28:
            raise PcapUploadInvalid("pcap_upload_invalid")
        return "pcapng"
    raise PcapUploadUnsupported("pcap_format_unsupported")


def _require_regular_directory(path: Path, label: str) -> Path:
    path = Path(path)
    if not path.is_absolute():
        raise PcapUploadUnavailable(f"{label} must be absolute")
    current = path
    while True:
        try:
            metadata = current.lstat()
        except OSError:
            raise PcapUploadUnavailable(f"{label} is unavailable") from None
        if _is_reparse_or_symlink(metadata):
            raise PcapUploadUnavailable(f"{label} cannot be a reparse point")
        parent = current.parent
        if parent == current:
            break
        current = parent
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode):
        raise PcapUploadUnavailable(f"{label} must be a directory")
    return path.resolve()


def _require_regular_file_within(path: Path, root: Path) -> None:
    try:
        path.resolve().relative_to(root.resolve())
        metadata = path.lstat()
    except (OSError, ValueError):
        raise PcapUploadInvalid("pcap_upload_invalid") from None
    if _is_reparse_or_symlink(metadata) or not stat.S_ISREG(metadata.st_mode):
        raise PcapUploadInvalid("pcap_upload_invalid")


def _is_reparse_or_symlink(metadata: os.stat_result) -> bool:
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT
    )


def _unlink(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass
