from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from math import isfinite
import re
from secrets import token_hex
from threading import RLock
from time import monotonic
from typing import Literal


_MAX_FILES = 20
_MAX_RECON_FILES = 10_000
_DEFAULT_UPLOAD_MAX_BYTES = 536870912
_DEFAULT_STORE_CAPACITY = 256
_AUTHORIZATION_ID = re.compile(r"^pcap_auth_[0-9a-f]{32}$")
PcapAuthorizationPurpose = Literal[
    "triage", "reconnaissance", "detection", "upload_detection"
]


class PcapAuthorizationUnknown(RuntimeError):
    pass


class PcapAuthorizationAlreadyUsed(RuntimeError):
    pass


class PcapAuthorizationExpired(RuntimeError):
    pass


class PcapAuthorizationPurposeMismatch(RuntimeError):
    pass


@dataclass(frozen=True)
class PcapAuthorizationReceipt:
    authorization_id: str
    max_files: int


@dataclass(frozen=True)
class ConsumedPcapAuthorization:
    authorization_id: str
    max_files: int


@dataclass
class _Authorization:
    max_files: int
    expires_at: float
    purpose: PcapAuthorizationPurpose = "triage"
    expected_byte_count: int | None = None
    used: bool = False


class PcapAuthorizationStore:
    def __init__(
        self,
        *,
        ttl_seconds: float = 300,
        clock: Callable[[], float] = monotonic,
        capacity: int = _DEFAULT_STORE_CAPACITY,
        upload_max_bytes: int = _DEFAULT_UPLOAD_MAX_BYTES,
    ) -> None:
        if type(ttl_seconds) not in (int, float) or not isfinite(ttl_seconds) or ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if type(capacity) is not int or capacity < 1:
            raise ValueError("capacity must be a positive integer")
        if type(upload_max_bytes) is not int or upload_max_bytes < 1:
            raise ValueError("upload_max_bytes must be a positive integer")
        self._ttl_seconds = ttl_seconds
        self._clock = clock
        self._capacity = capacity
        self._upload_max_bytes = upload_max_bytes
        self._authorizations: OrderedDict[str, _Authorization] = OrderedDict()
        self._lock = RLock()

    def issue(
        self,
        max_files: int,
        purpose: PcapAuthorizationPurpose = "triage",
        expected_byte_count: int | None = None,
    ) -> PcapAuthorizationReceipt:
        if purpose not in (
            "triage",
            "reconnaissance",
            "detection",
            "upload_detection",
        ):
            raise ValueError(
                "purpose must be triage, reconnaissance, detection, or upload_detection"
            )
        if purpose == "reconnaissance":
            if type(max_files) is not int or not 1 <= max_files <= _MAX_RECON_FILES:
                raise ValueError("reconnaissance max_files must be between 1 and 10000")
        else:
            _validate_max_files(max_files)
        if purpose == "upload_detection":
            if max_files != 1:
                raise ValueError("upload_detection max_files is fixed at 1")
            self._validate_expected_byte_count(expected_byte_count)
        elif expected_byte_count is not None:
            raise ValueError("expected_byte_count is only valid for upload_detection")
        authorization_id = "pcap_auth_" + token_hex(16)
        with self._lock:
            self._authorizations[authorization_id] = _Authorization(
                max_files=max_files,
                expires_at=self._clock() + self._ttl_seconds,
                purpose=purpose,
                expected_byte_count=expected_byte_count,
            )
            while len(self._authorizations) > self._capacity:
                self._authorizations.popitem(last=False)
        return PcapAuthorizationReceipt(
            authorization_id=authorization_id,
            max_files=max_files,
        )

    def consume(
        self,
        authorization_id: str,
        purpose: PcapAuthorizationPurpose = "triage",
        expected_byte_count: int | None = None,
    ) -> ConsumedPcapAuthorization:
        with self._lock:
            authorization = self._require_usable(
                authorization_id,
                purpose=purpose,
                expected_byte_count=expected_byte_count,
            )
            authorization.used = True
            return ConsumedPcapAuthorization(
                authorization_id=authorization_id,
                max_files=authorization.max_files,
            )

    def assert_usable(
        self,
        authorization_id: str,
        purpose: PcapAuthorizationPurpose = "triage",
        expected_byte_count: int | None = None,
    ) -> None:
        with self._lock:
            self._require_usable(
                authorization_id,
                purpose=purpose,
                expected_byte_count=expected_byte_count,
            )

    def _require_usable(
        self,
        authorization_id: str,
        *,
        purpose: PcapAuthorizationPurpose,
        expected_byte_count: int | None,
    ) -> _Authorization:
        if (
            type(authorization_id) is not str
            or _AUTHORIZATION_ID.fullmatch(authorization_id) is None
        ):
            raise PcapAuthorizationUnknown("pcap_authorization_required")
        authorization = self._authorizations.get(authorization_id)
        if authorization is None:
            raise PcapAuthorizationUnknown("pcap_authorization_required")
        if authorization.purpose != purpose:
            raise PcapAuthorizationPurposeMismatch(
                "pcap_authorization_purpose_mismatch"
            )
        if authorization.used:
            raise PcapAuthorizationAlreadyUsed("pcap_authorization_used")
        if self._clock() >= authorization.expires_at:
            raise PcapAuthorizationExpired("pcap_authorization_expired")
        if purpose == "upload_detection":
            self._validate_expected_byte_count(expected_byte_count)
            if authorization.expected_byte_count != expected_byte_count:
                raise ValueError("expected_byte_count does not match authorization")
        elif expected_byte_count is not None:
            raise ValueError("expected_byte_count is only valid for upload_detection")
        return authorization

    def _validate_expected_byte_count(self, expected_byte_count: int | None) -> None:
        if (
            type(expected_byte_count) is not int
            or not 1 <= expected_byte_count <= self._upload_max_bytes
        ):
            raise ValueError(
                "expected_byte_count must be a positive integer within upload_max_bytes"
            )


def _validate_max_files(max_files: int) -> None:
    if type(max_files) is not int or not 1 <= max_files <= _MAX_FILES:
        raise ValueError("max_files must be an integer between 1 and 20")
