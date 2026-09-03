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
_DEFAULT_STORE_CAPACITY = 256
_AUTHORIZATION_ID = re.compile(r"^pcap_auth_[0-9a-f]{32}$")


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
    purpose: Literal["triage", "reconnaissance"] = "triage"
    used: bool = False


class PcapAuthorizationStore:
    def __init__(
        self,
        *,
        ttl_seconds: float = 300,
        clock: Callable[[], float] = monotonic,
        capacity: int = _DEFAULT_STORE_CAPACITY,
    ) -> None:
        if type(ttl_seconds) not in (int, float) or not isfinite(ttl_seconds) or ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if type(capacity) is not int or capacity < 1:
            raise ValueError("capacity must be a positive integer")
        self._ttl_seconds = ttl_seconds
        self._clock = clock
        self._capacity = capacity
        self._authorizations: OrderedDict[str, _Authorization] = OrderedDict()
        self._lock = RLock()

    def issue(
        self,
        max_files: int,
        purpose: Literal["triage", "reconnaissance"] = "triage",
    ) -> PcapAuthorizationReceipt:
        _validate_max_files(max_files)
        if purpose not in ("triage", "reconnaissance"):
            raise ValueError("purpose must be triage or reconnaissance")
        if purpose == "reconnaissance" and max_files != _MAX_FILES:
            raise ValueError("reconnaissance max_files is fixed at 20")
        authorization_id = "pcap_auth_" + token_hex(16)
        with self._lock:
            self._authorizations[authorization_id] = _Authorization(
                max_files=max_files,
                expires_at=self._clock() + self._ttl_seconds,
                purpose=purpose,
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
        purpose: Literal["triage", "reconnaissance"] = "triage",
    ) -> ConsumedPcapAuthorization:
        with self._lock:
            authorization = self._require_usable(authorization_id, purpose=purpose)
            authorization.used = True
            return ConsumedPcapAuthorization(
                authorization_id=authorization_id,
                max_files=authorization.max_files,
            )

    def assert_usable(
        self,
        authorization_id: str,
        purpose: Literal["triage", "reconnaissance"] = "triage",
    ) -> None:
        with self._lock:
            self._require_usable(authorization_id, purpose=purpose)

    def _require_usable(
        self,
        authorization_id: str,
        *,
        purpose: Literal["triage", "reconnaissance"],
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
        return authorization


def _validate_max_files(max_files: int) -> None:
    if type(max_files) is not int or not 1 <= max_files <= _MAX_FILES:
        raise ValueError("max_files must be an integer between 1 and 20")
