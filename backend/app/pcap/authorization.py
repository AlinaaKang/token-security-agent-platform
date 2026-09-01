from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from math import isfinite
from secrets import token_hex
from threading import RLock
from time import monotonic


_MAX_FILES = 20
_DEFAULT_STORE_CAPACITY = 256


class PcapAuthorizationUnknown(RuntimeError):
    pass


class PcapAuthorizationAlreadyUsed(RuntimeError):
    pass


class PcapAuthorizationExpired(RuntimeError):
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

    def issue(self, max_files: int) -> PcapAuthorizationReceipt:
        _validate_max_files(max_files)
        authorization_id = "pcap_auth_" + token_hex(16)
        with self._lock:
            self._authorizations[authorization_id] = _Authorization(
                max_files=max_files,
                expires_at=self._clock() + self._ttl_seconds,
            )
            while len(self._authorizations) > self._capacity:
                self._authorizations.popitem(last=False)
        return PcapAuthorizationReceipt(
            authorization_id=authorization_id,
            max_files=max_files,
        )

    def consume(self, authorization_id: str) -> ConsumedPcapAuthorization:
        with self._lock:
            authorization = self._authorizations.get(authorization_id)
            if authorization is None:
                raise PcapAuthorizationUnknown("pcap_authorization_required")
            if authorization.used:
                raise PcapAuthorizationAlreadyUsed("pcap_authorization_used")
            if self._clock() >= authorization.expires_at:
                raise PcapAuthorizationExpired("pcap_authorization_expired")
            authorization.used = True
            return ConsumedPcapAuthorization(
                authorization_id=authorization_id,
                max_files=authorization.max_files,
            )


def _validate_max_files(max_files: int) -> None:
    if type(max_files) is not int or not 1 <= max_files <= _MAX_FILES:
        raise ValueError("max_files must be an integer between 1 and 20")
