from __future__ import annotations

import json
import shutil
import sqlite3
import subprocess
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from app.audit.store import SQLiteEventStore
from app.lab.execution_store import SQLiteLabExecutionStore
from app.lab.models import FORBIDDEN_PUBLIC_KEYS


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "verify_lab_privacy.ps1"
POWERSHELL = shutil.which("pwsh") or shutil.which("powershell")
WINDOWS_POWERSHELL = Path(
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
)
PRIVATE_SENTINEL = "TASK9_PRIVATE_SENTINEL_7f7a355f"


class _PrivacyApiHandler(BaseHTTPRequestHandler):
    requests: list[tuple[str, str]] = []
    reflected_sentinel: str | None = None

    def log_message(self, _format: str, *args: object) -> None:
        del args

    def _json(self, status: int, payload: object) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        type(self).requests.append(("GET", self.path))
        if self.path == "/health":
            payload = {
                "status": "ok",
                "lab": {
                    "enabled": True,
                    "ready": True,
                    "reason": "ready",
                    "tool_storage": "sqlite",
                },
            }
            if getattr(self.server, "health_forbidden", False):
                payload["hidden_reasoning"] = "PRIVATE_HEALTH_BODY"
            self._json(
                getattr(self.server, "health_status", 200),
                payload,
            )
        elif self.path == "/api/v1/lab/scenarios":
            self._json(200, [])
        elif self.path == "/api/v1/lab/runs/lab_1":
            self._json(200, {"run_id": "lab_1"})
        elif self.path == "/api/v1/lab/runs/lab_1/executions":
            self._json(200, [])
        elif self.path == "/api/v1/lab/artifacts/artifact_1/download":
            self._json(200, {"artifact_kind": "evidence_bundle"})
        else:
            self._json(404, {"error": {"code": "not_found"}})

    def do_POST(self) -> None:  # noqa: N802
        type(self).requests.append(("POST", self.path))
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length))
        if self.path == "/api/v1/lab/runs":
            type(self).reflected_sentinel = payload["custom_input"]
            response = {"run_id": "lab_1"}
            if getattr(self.server, "reflect_private", False):
                response["summary"] = payload["custom_input"]
            self._json(201, response)
        elif self.path.endswith("/tools/gateway_enforcement/dry-run"):
            self._json(200, {"run_id": "lab_1"})
        elif self.path.endswith("/tools/evidence_bundle/execute"):
            self._json(201, {"artifact_id": "artifact_1"})
        elif self.path.endswith("/tools/security_case/execute"):
            self._json(
                422,
                {
                    "error": {
                        "code": "request_validation_failed",
                        "message": "request validation failed",
                    }
                },
            )
        else:
            self._json(404, {"error": {"code": "not_found"}})


@contextmanager
def _privacy_api(
    *,
    reflect_private: bool = False,
    health_status: int = 200,
    health_forbidden: bool = False,
):
    _PrivacyApiHandler.requests = []
    _PrivacyApiHandler.reflected_sentinel = None
    server = ThreadingHTTPServer(("127.0.0.1", 0), _PrivacyApiHandler)
    server.reflect_private = reflect_private  # type: ignore[attr-defined]
    server.health_status = health_status  # type: ignore[attr-defined]
    server.health_forbidden = health_forbidden  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def _run(
    *arguments: str,
    cwd: Path | None = None,
    shell: str | Path | None = None,
) -> subprocess.CompletedProcess[str]:
    selected_shell = str(shell or POWERSHELL or "")
    if not selected_shell:
        pytest.skip("PowerShell is unavailable")
    return subprocess.run(
        [
            selected_shell,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(SCRIPT),
            *arguments,
        ],
        cwd=cwd or ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def _create_scan_database(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE security_events (public_data TEXT);
        CREATE TABLE lab_execution_schema (schema_version INTEGER);
        INSERT INTO lab_execution_schema VALUES (1);
        CREATE TABLE lab_tool_executions (public_data TEXT);
        CREATE TABLE lab_security_cases (public_data TEXT);
        CREATE TABLE lab_artifacts (payload BLOB);
        """
    )
    return connection


def _assert_private_output_is_redacted(
    result: subprocess.CompletedProcess[str], *private_values: str
) -> None:
    combined = result.stdout + result.stderr
    for value in private_values:
        assert value not in combined


def test_privacy_verifier_accepts_safe_redacted_json(tmp_path: Path) -> None:
    fixture = tmp_path / "safe.json"
    fixture.write_text(
        json.dumps({"run_id": "lab_1", "signals": [{"index": 0, "risk": 0.1}]}),
        encoding="utf-8",
    )

    result = _run("-JsonPath", str(fixture), "-SkipTrackedPathScan")

    assert result.returncode == 0, result.stderr
    assert "privacy_verification=passed" in result.stdout
    assert "forbidden_key_hits=0" in result.stdout


@pytest.mark.skipif(
    not WINDOWS_POWERSHELL.exists(), reason="Windows PowerShell is unavailable"
)
def test_privacy_verifier_supports_the_documented_windows_powershell_command(
    tmp_path: Path,
) -> None:
    fixture = tmp_path / "safe.json"
    fixture.write_text(json.dumps({"run_id": "lab_1"}), encoding="utf-8")

    result = _run(
        "-JsonPath", str(fixture), "-SkipTrackedPathScan", shell=WINDOWS_POWERSHELL
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "privacy_verification=passed" in result.stdout


def test_privacy_verifier_counts_malformed_json_in_summary(tmp_path: Path) -> None:
    fixture = tmp_path / "malformed.json"
    fixture.write_text("{bad", encoding="utf-8")

    result = _run("-JsonPath", str(fixture), "-SkipTrackedPathScan")

    assert result.returncode != 0
    assert "surface=json category=parse_error count=1" in result.stdout
    assert "json_errors=1" in result.stdout


def test_privacy_verifier_reports_only_surface_category_and_count(
    tmp_path: Path,
) -> None:
    fixture = tmp_path / "unsafe.json"
    private_value = "DO_NOT_PRINT_PRIVATE_VALUE"
    fixture.write_text(
        json.dumps({"outer": [{"token_text": private_value}]}),
        encoding="utf-8",
    )

    result = _run("-JsonPath", str(fixture), "-SkipTrackedPathScan")

    assert result.returncode != 0
    assert "surface=json category=forbidden_key count=1" in result.stdout
    assert "$.outer" not in result.stdout
    _assert_private_output_is_redacted(result, private_value)


def test_privacy_verifier_rejects_tracked_protected_artifact_paths(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
    protected = {
        ".secrets/key.txt": "PRIVATE_KEY_VALUE",
        "tmp/runtime.sqlite3": "PRIVATE_DATABASE_VALUE",
        "data/source-prompts.jsonl": "PRIVATE_PROMPT_VALUE",
        "tmp/observation-cache.json": "PRIVATE_OBSERVATION_VALUE",
    }
    for relative, value in protected.items():
        target = repository / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value, encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repository, check=True)

    result = _run("-RepositoryRoot", str(repository), cwd=repository)

    assert result.returncode != 0
    assert "surface=repository category=protected_path count=4" in result.stdout
    for value in protected.values():
        _assert_private_output_is_redacted(result, value)


@pytest.mark.parametrize("forbidden_key", sorted(FORBIDDEN_PUBLIC_KEYS))
def test_privacy_verifier_rejects_every_forbidden_json_key_in_sqlite(
    tmp_path: Path, forbidden_key: str
) -> None:
    database = tmp_path / "forbidden-key.sqlite3"
    with _create_scan_database(database) as connection:
        connection.execute(
            "INSERT INTO security_events VALUES (?)",
            (json.dumps({"outer": [{forbidden_key: "PRIVATE_DATABASE_VALUE"}]}),),
        )

    result = _run(
        "-DatabasePath", str(database), "-SkipTrackedPathScan"
    )

    assert result.returncode != 0
    assert "surface=sqlite.security_events category=forbidden_key count=1" in result.stdout
    _assert_private_output_is_redacted(result, "PRIVATE_DATABASE_VALUE")


def test_privacy_verifier_rejects_forbidden_artifact_key_without_opening_store(
    tmp_path: Path,
) -> None:
    database = tmp_path / "pre-marker.sqlite3"
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE lab_artifacts (payload BLOB)")
    connection.execute(
        "INSERT INTO lab_artifacts VALUES (?)",
        (json.dumps({"hidden_reasoning": "PRIVATE_ARTIFACT_BODY"}).encode(),),
    )
    connection.commit()
    connection.close()

    result = _run("-DatabasePath", str(database), "-SkipTrackedPathScan")

    assert result.returncode != 0
    assert "surface=sqlite.lab_artifacts category=forbidden_key count=1" in result.stdout
    _assert_private_output_is_redacted(result, "PRIVATE_ARTIFACT_BODY")
    with sqlite3.connect(database) as check:
        assert check.execute(
            "SELECT name FROM sqlite_master WHERE name='lab_execution_schema'"
        ).fetchone() is None


def test_privacy_verifier_rejects_forbidden_sqlite_column_name(
    tmp_path: Path,
) -> None:
    database = tmp_path / "forbidden-column.sqlite3"
    with _create_scan_database(database) as connection:
        connection.execute("ALTER TABLE lab_security_cases ADD COLUMN query_text TEXT")

    result = _run("-DatabasePath", str(database), "-SkipTrackedPathScan")

    assert result.returncode != 0
    assert "surface=sqlite.lab_security_cases category=forbidden_column count=1" in result.stdout


@pytest.mark.parametrize(
    "table_name, value",
    [
        ("lab_tool_executions", PRIVATE_SENTINEL),
        ("lab_security_cases", json.dumps({"safe": PRIVATE_SENTINEL})),
    ],
)
def test_privacy_verifier_rejects_exact_sentinel_in_sqlite_values(
    tmp_path: Path, table_name: str, value: str
) -> None:
    database = tmp_path / "sentinel.sqlite3"
    with _create_scan_database(database) as connection:
        connection.execute(f"INSERT INTO {table_name} VALUES (?)", (value,))

    result = _run(
        "-DatabasePath", str(database),
        "-Sentinel", PRIVATE_SENTINEL,
        "-SkipTrackedPathScan",
    )

    assert result.returncode != 0
    assert f"surface=sqlite.{table_name} category=sentinel count=1" in result.stdout
    _assert_private_output_is_redacted(result, PRIVATE_SENTINEL)


def test_privacy_verifier_does_not_treat_forbidden_words_as_private_values(
    tmp_path: Path,
) -> None:
    database = tmp_path / "safe-values.sqlite3"
    with _create_scan_database(database) as connection:
        connection.execute(
            "INSERT INTO security_events VALUES (?)",
            (json.dumps({"label": "prompt suffix hidden_reasoning"}),),
        )

    result = _run("-DatabasePath", str(database), "-SkipTrackedPathScan")

    assert result.returncode == 0, result.stdout + result.stderr


def test_privacy_verifier_accepts_empty_current_schema_database(
    tmp_path: Path,
) -> None:
    database = tmp_path / "current.sqlite3"
    execution_store = SQLiteLabExecutionStore(database)
    execution_store.close()
    event_store = SQLiteEventStore(database)
    event_store.close()

    result = _run(
        "-DatabasePath", str(database),
        "-Sentinel", PRIVATE_SENTINEL,
        "-SkipTrackedPathScan",
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "sqlite_databases=1" in result.stdout
    assert "sqlite_violations=0" in result.stdout
    _assert_private_output_is_redacted(result, PRIVATE_SENTINEL)


def test_privacy_verifier_scans_every_advanced_api_surface() -> None:
    with _privacy_api() as base_url:
        result = _run("-BaseUrl", base_url, "-SkipTrackedPathScan")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "api_requests=9" in result.stdout
    assert _PrivacyApiHandler.requests == [
        ("GET", "/health"),
        ("GET", "/api/v1/lab/scenarios"),
        ("POST", "/api/v1/lab/runs"),
        ("GET", "/api/v1/lab/runs/lab_1"),
        ("POST", "/api/v1/lab/runs/lab_1/tools/gateway_enforcement/dry-run"),
        ("POST", "/api/v1/lab/runs/lab_1/tools/evidence_bundle/execute"),
        ("GET", "/api/v1/lab/runs/lab_1/executions"),
        ("GET", "/api/v1/lab/artifacts/artifact_1/download"),
        ("POST", "/api/v1/lab/runs/lab_1/tools/security_case/execute"),
    ]
    assert _PrivacyApiHandler.reflected_sentinel is not None
    _assert_private_output_is_redacted(
        result, _PrivacyApiHandler.reflected_sentinel
    )


def test_privacy_verifier_fails_without_printing_reflected_api_sentinel() -> None:
    with _privacy_api(reflect_private=True) as base_url:
        result = _run("-BaseUrl", base_url, "-SkipTrackedPathScan")

    assert result.returncode != 0
    assert "surface=api.create_run category=sentinel count=1" in result.stdout
    assert _PrivacyApiHandler.reflected_sentinel is not None
    _assert_private_output_is_redacted(
        result, _PrivacyApiHandler.reflected_sentinel
    )


@pytest.mark.parametrize(
    "health_status, health_forbidden",
    [(500, False), (200, True)],
)
def test_privacy_verifier_never_writes_after_an_unhealthy_or_unsafe_health_body(
    health_status: int, health_forbidden: bool
) -> None:
    with _privacy_api(
        health_status=health_status, health_forbidden=health_forbidden
    ) as base_url:
        result = _run("-BaseUrl", base_url, "-SkipTrackedPathScan")

    assert result.returncode != 0
    assert _PrivacyApiHandler.requests == [("GET", "/health")]
    _assert_private_output_is_redacted(result, "PRIVATE_HEALTH_BODY")
