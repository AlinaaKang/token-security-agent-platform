from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "verify_pcap_agent_privacy.py"
sys.path.insert(0, str(ROOT))

from scripts.verify_pcap_agent_privacy import _contains_forbidden_data


def valid_public_batch_summary() -> dict[str, object]:
    return {
        "enabled": True,
        "pending_file_count": 2,
        "tool_id": "pcap_batch_triage",
        "max_batch_size": 20,
        "max_trace_events": 12,
        "actors": [
            "coordinator",
            "network_evidence_analyst",
            "knowledge_analyst",
            "response_operator",
        ],
    }


def valid_public_recon_overview() -> dict[str, object]:
    return {
        "enabled": True,
        "eligible_file_count": 2318,
        "sample_limit": 100,
        "sampling_method": "size_quartile_v1",
    }


def valid_public_detection_overview() -> dict[str, object]:
    return {
        "enabled": True,
        "eligible_file_count": 2318,
        "max_files": 20,
        "localization": "request_or_packet",
    }


def test_upload_capability_shape_does_not_contain_private_data() -> None:
    capability = {
        "enabled": True,
        "max_bytes": 536870912,
        "accepted_formats": ["pcap", "pcapng"],
    }
    assert _contains_forbidden_data(capability) is False


def _fixed_error(code: str, message: str) -> dict[str, object]:
    return {"error": {"code": code, "message": message}}


class PublicApiFixture:
    def __init__(
        self,
        *,
        pcap_summary: dict[str, object],
        recon_summary: dict[str, object] | None = None,
        capability_summary: dict[str, object] | None = None,
        create_error: dict[str, object] | None = None,
        create_status: int = 422,
    ) -> None:
        self.requests: list[tuple[str, str, object | None]] = []
        self._responses: dict[tuple[str, str], tuple[int, dict[str, object]]] = {
            ("GET", "/api/v1/superagent/pcap/capabilities"): (
                200,
                capability_summary or valid_public_batch_summary(),
            ),
            ("GET", "/api/v1/superagent/pcap/overview"): (200, pcap_summary),
            ("GET", "/api/v1/superagent/pcap/reconnaissance/overview"): (
                200,
                recon_summary or valid_public_recon_overview(),
            ),
            ("GET", "/api/v1/superagent/pcap/detection/overview"): (
                200,
                valid_public_detection_overview(),
            ),
            ("POST", "/api/v1/superagent/pcap/authorizations"): (
                422,
                _fixed_error(
                    "request_validation_failed", "request validation failed"
                ),
            ),
            ("POST", "/api/v1/superagent/pcap/reconnaissance/authorizations"): (
                422,
                _fixed_error(
                    "request_validation_failed", "request validation failed"
                ),
            ),
            ("POST", "/api/v1/superagent/pcap/detection/authorizations"): (
                422,
                _fixed_error(
                    "request_validation_failed", "request validation failed"
                ),
            ),
            ("POST", "/api/v1/superagent/missions"): (
                create_status,
                create_error
                or _fixed_error(
                    "request_validation_failed", "request validation failed"
                ),
            ),
            (
                "GET",
                "/api/v1/superagent/missions/mission_00000000000000000000000000000000",
            ): (
                404,
                _fixed_error(
                    "superagent_mission_not_found",
                    "bounded superagent mission was not found",
                ),
            ),
            (
                "GET",
                "/api/v1/superagent/missions/recon_00000000000000000000000000000000",
            ): (
                404,
                _fixed_error(
                    "superagent_mission_not_found",
                    "bounded superagent mission was not found",
                ),
            ),
            (
                "POST",
                "/api/v1/superagent/missions/mission_00000000000000000000000000000000/cancel",
            ): (
                409,
                _fixed_error(
                    "pcap_mission_not_cancellable",
                    "pcap mission is not cancellable",
                ),
            ),
            (
                "POST",
                "/api/v1/superagent/missions/recon_00000000000000000000000000000000/cancel",
            ): (
                409,
                _fixed_error(
                    "pcap_mission_not_cancellable",
                    "pcap mission is not cancellable",
                ),
            ),
        }
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self._respond("GET")

            def do_POST(self) -> None:
                self._respond("POST")

            def _respond(self, method: str) -> None:
                body: object | None = None
                content_length = int(self.headers.get("Content-Length", "0"))
                if content_length:
                    body = json.loads(self.rfile.read(content_length))
                fixture.requests.append((method, self.path, body))
                status, payload = fixture._responses[(method, self.path)]
                if (
                    method == "POST"
                    and self.path == "/api/v1/superagent/missions"
                    and isinstance(body, dict)
                    and body.get("objective") == "reconnoiter_pcap_dataset"
                ):
                    status, payload = 422, _fixed_error(
                        "request_validation_failed", "request validation failed"
                    )
                if (
                    method == "POST"
                    and self.path == "/api/v1/superagent/missions"
                    and isinstance(body, dict)
                    and body.get("objective") == "detect_pcap_anomalies"
                ):
                    status, payload = 403, _fixed_error(
                        "pcap_authorization_required",
                        "pcap authorization is required",
                    )
                encoded = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def log_message(self, _format: str, *args: object) -> None:
                return None

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = Thread(target=self._server.serve_forever, daemon=True)
        self.base_url = f"http://127.0.0.1:{self._server.server_port}"

    def __enter__(self) -> PublicApiFixture:
        self._thread.start()
        return self

    def __exit__(self, *args: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )


def _initialize_repo(repo: Path) -> None:
    _git(repo, "init", "--quiet")


def run_verifier(repo: Path, base_url: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--base-url",
            base_url,
            "--repo-root",
            str(repo),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


@contextmanager
def clean_repo(tmp_path: Path) -> Iterator[Path]:
    repo = tmp_path / "public-repo"
    repo.mkdir()
    _initialize_repo(repo)
    yield repo


def test_verifier_rejects_private_keys_and_tracked_capture_files(
    tmp_path: Path,
) -> None:
    with clean_repo(tmp_path) as repo:
        private_capture = repo / "PRIVATE_CAPTURE_SENTINEL.pcap"
        private_capture.write_bytes(b"not a capture")
        _git(repo, "add", "-f", private_capture.name)
        with PublicApiFixture(
            pcap_summary={
                **valid_public_batch_summary(),
                "path": "PRIVATE_SENTINEL",
            }
        ) as server:
            result = run_verifier(repo, server.base_url)

    assert result.returncode == 1
    assert "privacy_violation_count=1" in result.stdout
    assert "tracked_private_artifact_count=1" in result.stdout
    assert "PRIVATE_SENTINEL" not in result.stdout + result.stderr
    assert private_capture.name not in result.stdout + result.stderr


def test_verifier_accepts_redacted_pcap_agent_responses(tmp_path: Path) -> None:
    with clean_repo(tmp_path) as repo:
        with PublicApiFixture(
            pcap_summary=valid_public_batch_summary()
        ) as server:
            result = run_verifier(repo, server.base_url)

    assert result.returncode == 0
    assert result.stdout.splitlines() == [
        "pcap_agent_privacy_verification=passed",
        "checked_endpoint_count=14",
        "privacy_violation_count=0",
        "tracked_private_artifact_count=0",
    ]
    assert result.stderr == ""
    assert [(method, path) for method, path, _body in server.requests] == [
        ("GET", "/api/v1/superagent/pcap/capabilities"),
        ("GET", "/api/v1/superagent/pcap/overview"),
            ("GET", "/api/v1/superagent/pcap/reconnaissance/overview"),
            ("GET", "/api/v1/superagent/pcap/detection/overview"),
            ("POST", "/api/v1/superagent/pcap/authorizations"),
            ("POST", "/api/v1/superagent/pcap/reconnaissance/authorizations"),
            ("POST", "/api/v1/superagent/pcap/detection/authorizations"),
            ("POST", "/api/v1/superagent/missions"),
            ("POST", "/api/v1/superagent/missions"),
            ("POST", "/api/v1/superagent/missions"),
        (
            "GET",
            "/api/v1/superagent/missions/mission_00000000000000000000000000000000",
        ),
        (
            "GET",
            "/api/v1/superagent/missions/recon_00000000000000000000000000000000",
        ),
        (
            "POST",
            "/api/v1/superagent/missions/mission_00000000000000000000000000000000/cancel",
        ),
        (
            "POST",
            "/api/v1/superagent/missions/recon_00000000000000000000000000000000/cancel",
        ),
    ]
    assert server.requests[4][2] == {"confirmed": False, "max_files": 0}
    assert server.requests[5][2] == {"confirmed": False, "sample_limit": 20}
    assert server.requests[6][2] == {"confirmed": False, "max_files": 0}
    assert server.requests[7][2] == {
        "objective": "triage_pcap_evidence",
        "authorization_id": "pcap_auth_00000000000000000000000000000000",
        "scenario_kind": "frozen",
    }
    assert server.requests[8][2] == {
        "objective": "detect_pcap_anomalies",
        "authorization_id": "pcap_auth_00000000000000000000000000000000",
    }
    assert server.requests[9][2] == {
        "objective": "reconnoiter_pcap_dataset",
        "authorization_id": "pcap_auth_00000000000000000000000000000000",
        "scenario_kind": "frozen",
    }


def test_verifier_rejects_forbidden_sentinels_without_reflecting_them(
    tmp_path: Path,
) -> None:
    sentinel = "PRIVATE_SENTINEL_IN_FIXED_ERROR"
    with clean_repo(tmp_path) as repo:
        with PublicApiFixture(
            pcap_summary=valid_public_batch_summary(),
            create_error=_fixed_error("request_validation_failed", sentinel),
        ) as server:
            result = run_verifier(repo, server.base_url)

    assert result.returncode == 1
    assert "privacy_violation_count=1" in result.stdout
    assert sentinel not in result.stdout + result.stderr


def test_verifier_rejects_prompt_objective_fields_on_pcap_surface(
    tmp_path: Path,
) -> None:
    with clean_repo(tmp_path) as repo:
        with PublicApiFixture(
            pcap_summary=valid_public_batch_summary(),
            capability_summary={
                **valid_public_batch_summary(),
                "objectives": ["investigate_and_respond"],
            },
        ) as server:
            result = run_verifier(repo, server.base_url)

    assert result.returncode == 1
    assert "privacy_violation_count=1" in result.stdout
    assert "investigate_and_respond" not in result.stdout + result.stderr


def test_verifier_rejects_forbidden_nested_recon_overview_data(
    tmp_path: Path,
) -> None:
    with clean_repo(tmp_path) as repo:
        with PublicApiFixture(
            pcap_summary=valid_public_batch_summary(),
            recon_summary={
                **valid_public_recon_overview(),
                "nested": {"private_pcap_path": "PRIVATE_SENTINEL"},
            },
        ) as server:
            result = run_verifier(repo, server.base_url)

    assert result.returncode == 1
    assert "privacy_violation_count=1" in result.stdout
    assert "PRIVATE_SENTINEL" not in result.stdout + result.stderr


def test_verifier_rejects_private_keys_in_nested_recon_responses(
    tmp_path: Path,
) -> None:
    assert _contains_forbidden_data({"details": {"private_pcap_path": "opaque"}})
    with clean_repo(tmp_path) as repo:
        with PublicApiFixture(
            pcap_summary=valid_public_batch_summary(),
            recon_summary={
                **valid_public_recon_overview(),
                "details": {"private_pcap_path": "opaque"},
            },
        ) as server:
            result = run_verifier(repo, server.base_url)

    assert result.returncode == 1
    assert "privacy_violation_count=1" in result.stdout
    assert "opaque" not in result.stdout + result.stderr


def test_verifier_rejects_server_accepting_prompt_only_pcap_fields(
    tmp_path: Path,
) -> None:
    with clean_repo(tmp_path) as repo:
        with PublicApiFixture(
            pcap_summary=valid_public_batch_summary(),
            create_status=403,
            create_error=_fixed_error(
                "pcap_authorization_required", "pcap authorization is required"
            ),
        ) as server:
            result = run_verifier(repo, server.base_url)

    assert result.returncode == 1
    assert "privacy_violation_count=1" in result.stdout
    assert "pcap_auth_" not in result.stdout + result.stderr
    assert server.requests[7][2] == {
        "objective": "triage_pcap_evidence",
        "authorization_id": "pcap_auth_00000000000000000000000000000000",
        "scenario_kind": "frozen",
    }


def test_verifier_rejects_each_private_report_or_state_pattern(
    tmp_path: Path,
) -> None:
    tracked_names = (
        "evidence.pcapng",
        "pcap-preflight-private.json",
        "archive-pcap-recon-private-map.txt",
        "archive-pcap-recon-summary.json",
        "pcap-recon-recon_00000000000000000000000000000000.json",
        "pcap-recon-private.json",
        "pcap-batch-state.json",
        "pcap-batch-private-mapping.txt",
        "pcap-batch.cancel",
    )
    with clean_repo(tmp_path) as repo:
        for name in tracked_names:
            path = repo / name
            path.write_text("PRIVATE_SENTINEL", encoding="utf-8")
            _git(repo, "add", "-f", name)
        with PublicApiFixture(
            pcap_summary=valid_public_batch_summary()
        ) as server:
            result = run_verifier(repo, server.base_url)

    assert result.returncode == 1
    assert "privacy_violation_count=0" in result.stdout
    assert "tracked_private_artifact_count=9" in result.stdout
    assert all(name not in result.stdout + result.stderr for name in tracked_names)
