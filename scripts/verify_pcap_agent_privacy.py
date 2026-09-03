from __future__ import annotations

import argparse
import fnmatch
import json
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urljoin
from urllib.request import Request, urlopen


_UNKNOWN_MISSION = "mission_" + "0" * 32
_UNKNOWN_RECON = "recon_" + "0" * 32
_UNKNOWN_AUTHORIZATION = "pcap_auth_" + "0" * 32
_OVERVIEW_KEYS = frozenset(
    {
        "enabled",
        "pending_file_count",
        "tool_id",
        "max_batch_size",
        "max_trace_events",
        "actors",
    }
)
_PCAP_ACTORS = [
    "coordinator",
    "network_evidence_analyst",
    "knowledge_analyst",
    "response_operator",
]
_RECON_OVERVIEW_KEYS = frozenset(
    {"enabled", "eligible_file_count", "sample_limit", "sampling_method"}
)
_FORBIDDEN_KEYS = frozenset(
    {
        "absolute_path",
        "authorization_id",
        "batch_id",
        "body",
        "capture_id",
        "capture_ids",
        "capture_filename",
        "capture_path",
        "created_at",
        "file_name",
        "file_path",
        "filename",
        "http_body",
        "ip",
        "ip_address",
        "issued_at",
        "mac",
        "mission_id",
        "path",
        "payload",
        "port",
        "prompt",
        "private_pcap_path",
        "private_capture_id",
        "private_file_name",
        "private_filename",
        "private_mapping",
        "private_path",
        "receipt_id",
        "request_body",
        "relative_path",
        "response_body",
        "request_id",
        "raw_stderr",
        "run_id",
        "sha256",
        "suffix",
        "suffix_text",
        "timestamp",
        "token",
        "token_id",
        "token_ids",
        "token_text",
    }
)
_FORBIDDEN_SENTINELS = (
    "private_sentinel",
    "private_capture_sentinel",
    "private_database_value",
    "private_pcap_path",
    "secret_sentinel",
)
_PRIVATE_ARTIFACT_PATTERNS = (
    "*.pcap",
    "*.pcapng",
    "*.cancel",
    "pcap-batch*.json",
    "pcap-batch-private*",
    "pcap-preflight-*.json",
    "*pcap-recon*.json",
    "*pcap-recon-private*",
)


@dataclass(frozen=True)
class _EndpointCheck:
    method: str
    path: str
    expected_status: int
    request_body: dict[str, object] | None
    validate: Callable[[object], bool]


def _is_strict_int(value: object) -> bool:
    return type(value) is int


def _valid_overview(payload: object) -> bool:
    if not isinstance(payload, dict) or set(payload) != _OVERVIEW_KEYS:
        return False
    return (
        type(payload["enabled"]) is bool
        and _is_strict_int(payload["pending_file_count"])
        and 0 <= payload["pending_file_count"] <= 2_147_483_647
        and payload["tool_id"] == "pcap_batch_triage"
        and payload["max_batch_size"] == 20
        and type(payload["max_batch_size"]) is int
        and payload["max_trace_events"] == 12
        and type(payload["max_trace_events"]) is int
        and payload["actors"] == _PCAP_ACTORS
    )


def _valid_recon_overview(payload: object) -> bool:
    if not isinstance(payload, dict) or set(payload) != _RECON_OVERVIEW_KEYS:
        return False
    return (
        type(payload["enabled"]) is bool
        and _is_strict_int(payload["eligible_file_count"])
        and 0 <= payload["eligible_file_count"] <= 2_147_483_647
        and payload["sample_limit"] == 20
        and type(payload["sample_limit"]) is int
        and payload["sampling_method"] == "size_quartile_v1"
    )


def _fixed_error_validator(
    *, code: str, message: str
) -> Callable[[object], bool]:
    def validate(payload: object) -> bool:
        if not isinstance(payload, dict) or set(payload) != {"error"}:
            return False
        error = payload["error"]
        return (
            isinstance(error, dict)
            and set(error) == {"code", "message"}
            and error["code"] == code
            and error["message"] == message
        )

    return validate


def _endpoint_checks() -> tuple[_EndpointCheck, ...]:
    validation_error = _fixed_error_validator(
        code="request_validation_failed", message="request validation failed"
    )
    return (
        _EndpointCheck(
            method="GET",
            path="/api/v1/superagent/pcap/capabilities",
            expected_status=200,
            request_body=None,
            validate=_valid_overview,
        ),
        _EndpointCheck(
            method="GET",
            path="/api/v1/superagent/pcap/overview",
            expected_status=200,
            request_body=None,
            validate=_valid_overview,
        ),
        _EndpointCheck(
            method="GET",
            path="/api/v1/superagent/pcap/reconnaissance/overview",
            expected_status=200,
            request_body=None,
            validate=_valid_recon_overview,
        ),
        _EndpointCheck(
            method="POST",
            path="/api/v1/superagent/pcap/authorizations",
            expected_status=422,
            request_body={"confirmed": False, "max_files": 0},
            validate=validation_error,
        ),
        _EndpointCheck(
            method="POST",
            path="/api/v1/superagent/pcap/reconnaissance/authorizations",
            expected_status=422,
            request_body={"confirmed": False, "sample_limit": 20},
            validate=validation_error,
        ),
        _EndpointCheck(
            method="POST",
            path="/api/v1/superagent/missions",
            expected_status=422,
            request_body={
                "objective": "triage_pcap_evidence",
                "authorization_id": _UNKNOWN_AUTHORIZATION,
                "scenario_kind": "frozen",
            },
            validate=validation_error,
        ),
        _EndpointCheck(
            method="POST",
            path="/api/v1/superagent/missions",
            expected_status=422,
            request_body={
                "objective": "reconnoiter_pcap_dataset",
                "authorization_id": _UNKNOWN_AUTHORIZATION,
                "scenario_kind": "frozen",
            },
            validate=validation_error,
        ),
        _EndpointCheck(
            method="GET",
            path=f"/api/v1/superagent/missions/{_UNKNOWN_MISSION}",
            expected_status=404,
            request_body=None,
            validate=_fixed_error_validator(
                code="superagent_mission_not_found",
                message="bounded superagent mission was not found",
            ),
        ),
        _EndpointCheck(
            method="GET",
            path=f"/api/v1/superagent/missions/{_UNKNOWN_RECON}",
            expected_status=404,
            request_body=None,
            validate=_fixed_error_validator(
                code="superagent_mission_not_found",
                message="bounded superagent mission was not found",
            ),
        ),
        _EndpointCheck(
            method="POST",
            path=f"/api/v1/superagent/missions/{_UNKNOWN_MISSION}/cancel",
            expected_status=409,
            request_body=None,
            validate=_fixed_error_validator(
                code="pcap_mission_not_cancellable",
                message="pcap mission is not cancellable",
            ),
        ),
        _EndpointCheck(
            method="POST",
            path=f"/api/v1/superagent/missions/{_UNKNOWN_RECON}/cancel",
            expected_status=409,
            request_body=None,
            validate=_fixed_error_validator(
                code="pcap_mission_not_cancellable",
                message="pcap mission is not cancellable",
            ),
        ),
    )


def _contains_forbidden_data(value: object) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized_key = str(key).casefold().replace("-", "_")
            if normalized_key in _FORBIDDEN_KEYS:
                return True
            if _contains_forbidden_data(child):
                return True
        return False
    if isinstance(value, (list, tuple)):
        return any(_contains_forbidden_data(child) for child in value)
    if isinstance(value, str):
        normalized_value = value.casefold()
        return any(
            sentinel in normalized_value for sentinel in _FORBIDDEN_SENTINELS
        )
    return False


def _request_json(
    base_url: str, check: _EndpointCheck
) -> tuple[int, object] | None:
    data = None
    headers = {"Accept": "application/json"}
    if check.request_body is not None:
        data = json.dumps(check.request_body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = Request(
        urljoin(base_url.rstrip("/") + "/", check.path.lstrip("/")),
        data=data,
        headers=headers,
        method=check.method,
    )
    try:
        with urlopen(request, timeout=5) as response:
            status = response.status
            raw_body = response.read(1_048_577)
    except HTTPError as error:
        status = error.code
        raw_body = error.read(1_048_577)
    except Exception:
        return None
    if len(raw_body) > 1_048_576:
        return None
    try:
        return status, json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def _check_endpoints(base_url: str) -> int:
    violation_count = 0
    for check in _endpoint_checks():
        response = _request_json(base_url, check)
        if response is None:
            violation_count += 1
            continue
        status, payload = response
        if (
            status != check.expected_status
            or _contains_forbidden_data(payload)
            or not check.validate(payload)
        ):
            violation_count += 1
    return violation_count


def _is_private_artifact(path_text: str) -> bool:
    normalized = path_text.replace("\\", "/").casefold()
    name = normalized.rsplit("/", maxsplit=1)[-1]
    return any(
        fnmatch.fnmatchcase(name, pattern)
        for pattern in _PRIVATE_ARTIFACT_PATTERNS
    )


def _tracked_private_artifacts(repo_root: Path) -> tuple[int, bool]:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root.resolve()), "ls-files", "-z"],
            check=False,
            capture_output=True,
            timeout=10,
        )
    except Exception:
        return 0, True
    if result.returncode != 0:
        return 0, True
    try:
        tracked_paths = result.stdout.decode("utf-8").split("\0")
    except UnicodeDecodeError:
        return 0, True
    return sum(_is_private_artifact(path) for path in tracked_paths if path), False


def _print_summary(
    *, violation_count: int, tracked_private_artifact_count: int
) -> None:
    passed = violation_count == 0 and tracked_private_artifact_count == 0
    print(
        "pcap_agent_privacy_verification="
        + ("passed" if passed else "failed")
    )
    print(f"checked_endpoint_count={len(_endpoint_checks())}")
    print(f"privacy_violation_count={violation_count}")
    print(
        "tracked_private_artifact_count="
        f"{tracked_private_artifact_count}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify the public PCAP Agent boundary with fixed aggregates."
    )
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--repo-root", type=Path, required=True)
    args = parser.parse_args()

    try:
        violation_count = _check_endpoints(args.base_url)
        tracked_count, scan_failed = _tracked_private_artifacts(args.repo_root)
        if scan_failed:
            violation_count += 1
    except Exception:
        violation_count = 1
        tracked_count = 0
    _print_summary(
        violation_count=violation_count,
        tracked_private_artifact_count=tracked_count,
    )
    return 0 if violation_count == 0 and tracked_count == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
