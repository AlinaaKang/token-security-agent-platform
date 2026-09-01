from __future__ import annotations

import json
import os
import subprocess
import time
from hashlib import sha256
from pathlib import Path

import pytest

from app.pcap.models import PcapBatchSummary


WINDOWS_POWERSHELL = Path(os.environ["SystemRoot"]) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "inspect_pcap_batch.ps1"
BATCH_ID = "batch_0123456789abcdef0123456789abcdef"
PRIVATE_SENTINEL = "PRIVATE_SENTINEL_capture-name_203.0.113.10_443_aabbccddeeff"


def add_capture(root: Path, *, size: int, suffix: str = ".pcap", name: str | None = None) -> Path:
    capture = root / "input" / (name or f"capture-{size}{suffix}")
    capture.parent.mkdir(parents=True, exist_ok=True)
    capture.write_bytes(b"x" * size)
    return capture


def make_capture_batch(tmp_path: Path, *, count: int) -> tuple[Path, list[Path]]:
    root = tmp_path / "pcap-quarantine"
    captures = [add_capture(root, size=index + 1, name=f"capture-{index:02}.pcap") for index in range(count)]
    return root, captures


def fake_inspector(
    tmp_path: Path,
    *,
    fail_names: set[str] | None = None,
    malformed_names: set[str] | None = None,
    cancel_after: int | None = None,
) -> Path:
    script = tmp_path / "fake-inspector.ps1"
    script.write_text(
        r'''param([string]$Path, [string]$QuarantineRoot, [string]$DockerExecutable)
$ErrorActionPreference = 'Stop'
$logRoot = $env:FAKE_INSPECTOR_LOG_ROOT
$activePath = Join-Path $logRoot 'active.txt'
$active = 0
if (Test-Path -LiteralPath $activePath) { $active = [int](Get-Content -LiteralPath $activePath -Raw) }
$active += 1
[System.IO.File]::WriteAllText($activePath, [string]$active)
Add-Content -LiteralPath (Join-Path $logRoot 'concurrency.txt') -Value $active
try {
    $item = Get-Item -LiteralPath $Path
    Add-Content -LiteralPath (Join-Path $logRoot 'invocations.txt') -Value ($item.Name + '|' + $item.Length)
    $fail = @($env:FAKE_INSPECTOR_FAIL_NAMES -split ';') -contains $item.Name
    if ($fail) {
        [Console]::Error.WriteLine('PRIVATE_CHILD_STDERR')
        exit 9
    }
    $hash = [System.Security.Cryptography.SHA256]::Create()
    $stream = [System.IO.File]::OpenRead($Path)
    try { $sha = (($hash.ComputeHash($stream) | ForEach-Object { $_.ToString('x2') }) -join '') }
    finally { $stream.Dispose(); $hash.Dispose() }
    $report = [ordered]@{
        schema_version = 1
        sha256 = $sha
        size_bytes = [int64]$item.Length
        capture_format = if ($item.Extension.ToLowerInvariant() -eq '.pcapng') { 'pcapng' } else { 'pcap' }
        packet_count = 1
        duration_seconds = 0.0
        link_types = @()
        protocol_counts = [ordered]@{ http = 1 }
        visibility = [ordered]@{
            plaintext_application_protocol_observed = $true
            encrypted_transport_observed = $false
            tls_observed = $false
            quic_observed = $false
        }
        capability = 'token_eligible'
        reasons = @('plaintext_application_protocol_observed')
        tool_versions = [ordered]@{ tshark = 'tshark' }
    }
    if ((@($env:FAKE_INSPECTOR_MALFORMED_NAMES -split ';') -contains $item.Name)) { $report['private_extra'] = 'PRIVATE_CHILD_REPORT' }
    $output = Join-Path $QuarantineRoot 'output'
    New-Item -ItemType Directory -Path $output -Force | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $output ('pcap-preflight-' + $sha.Substring(0, 16) + '.json')), ($report | ConvertTo-Json -Depth 5 -Compress), [System.Text.UTF8Encoding]::new($false))
    $cancelAfter = [int]$env:FAKE_INSPECTOR_CANCEL_AFTER
    if ($cancelAfter -gt 0 -and (Get-Content -LiteralPath (Join-Path $logRoot 'invocations.txt')).Count -eq $cancelAfter) {
        New-Item -ItemType File -Path $env:FAKE_INSPECTOR_CANCEL_MARKER -Force | Out-Null
    }
    $pauseAt = [int]$env:FAKE_INSPECTOR_PAUSE_AT
    if ($pauseAt -gt 0 -and (Get-Content -LiteralPath (Join-Path $logRoot 'invocations.txt')).Count -eq $pauseAt) {
        New-Item -ItemType File -Path $env:FAKE_INSPECTOR_PAUSE_MARKER -Force | Out-Null
        while ($true) { Start-Sleep -Milliseconds 100 }
    }
    exit 0
}
finally {
    $remaining = [int](Get-Content -LiteralPath $activePath -Raw) - 1
    [System.IO.File]::WriteAllText($activePath, [string]$remaining)
}
''',
        encoding="utf-8",
    )
    return script


def run_batch(
    root: Path,
    inspector: Path,
    *,
    max_files: int,
    batch_id: str = BATCH_ID,
    quarantine_argument: str | None = None,
) -> subprocess.CompletedProcess[str]:
    environment = batch_environment(root, inspector, batch_id=batch_id)
    result = subprocess.run(
        batch_command(
            root,
            inspector,
            max_files=max_files,
            batch_id=batch_id,
            quarantine_argument=quarantine_argument,
        ),
        capture_output=True,
        check=False,
        encoding="utf-8",
        env=environment,
    )
    if result.returncode == 0:
        result.public_summary = json.loads(
            (root / "output" / f"pcap-batch-{batch_id}.json").read_text(encoding="utf-8")
        )
    return result


def batch_command(
    root: Path,
    inspector: Path,
    *,
    max_files: int,
    batch_id: str = BATCH_ID,
    quarantine_argument: str | None = None,
) -> list[str]:
    return [
        str(WINDOWS_POWERSHELL), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-File", str(SCRIPT), "-QuarantineRoot", quarantine_argument or str(root), "-BatchId", batch_id,
        "-MaxFiles", str(max_files), "-InspectorScript", str(inspector),
    ]


def batch_environment(root: Path, inspector: Path, *, batch_id: str = BATCH_ID) -> dict[str, str]:
    log_root = inspector.parent / "fake-inspector-log"
    log_root.mkdir(exist_ok=True)
    environment = os.environ.copy()
    environment.update(
        {
            "FAKE_INSPECTOR_LOG_ROOT": str(log_root),
            "FAKE_INSPECTOR_FAIL_NAMES": environment.get("FAKE_INSPECTOR_FAIL_NAMES", ""),
            "FAKE_INSPECTOR_MALFORMED_NAMES": environment.get("FAKE_INSPECTOR_MALFORMED_NAMES", ""),
            "FAKE_INSPECTOR_CANCEL_AFTER": environment.get("FAKE_INSPECTOR_CANCEL_AFTER", "0"),
            "FAKE_INSPECTOR_CANCEL_MARKER": str(root / "state" / f"{batch_id}.cancel"),
            "FAKE_INSPECTOR_PAUSE_AT": environment.get("FAKE_INSPECTOR_PAUSE_AT", "0"),
            "FAKE_INSPECTOR_PAUSE_MARKER": str(log_root / "paused.txt"),
        }
    )
    return environment


def make_directory_junction(link: Path, target: Path) -> None:
    result = subprocess.run(
        [os.environ["ComSpec"], "/d", "/c", "mklink", "/J", str(link), str(target)],
        capture_output=True,
        check=False,
        encoding="utf-8",
    )
    assert result.returncode == 0, result.stdout + result.stderr


def load_public_summary(root: Path, result: subprocess.CompletedProcess[str]) -> dict[str, object]:
    assert result.stdout.strip() == f"pcap_batch_result={BATCH_ID}", result.stdout + result.stderr
    return json.loads((root / "output" / f"pcap-batch-{BATCH_ID}.json").read_text(encoding="utf-8"))


def recorded_sizes(tmp_path: Path) -> list[int]:
    log = tmp_path / "fake-inspector-log" / "invocations.txt"
    return [int(line.rsplit("|", 1)[1]) for line in log.read_text(encoding="utf-8").splitlines()]


def max_recorded_concurrency(tmp_path: Path) -> int:
    return max(int(line) for line in (tmp_path / "fake-inspector-log" / "concurrency.txt").read_text(encoding="utf-8").splitlines())


def invocation_count(tmp_path: Path, capture: Path) -> int:
    return sum(line.split("|", 1)[0] == capture.name for line in (tmp_path / "fake-inspector-log" / "invocations.txt").read_text(encoding="utf-8").splitlines())


def public_counts(result: subprocess.CompletedProcess[str]) -> dict[str, int]:
    report = result.public_summary
    return {"succeeded": report["succeeded_count"], "failed": report["failed_count"], "skipped": report["skipped_count"]}


def test_batch_selects_smallest_twenty_and_runs_serially(tmp_path: Path) -> None:
    root, captures = make_capture_batch(tmp_path, count=23)
    result = run_batch(root, fake_inspector(tmp_path), max_files=20)
    summary = load_public_summary(root, result)
    assert result.returncode == 0
    assert summary["selected_count"] == 20
    assert recorded_sizes(tmp_path) == sorted(path.stat().st_size for path in captures)[:20]
    assert max_recorded_concurrency(tmp_path) == 1


def test_batch_resume_skips_unchanged_success_retries_failure_and_adds_new_file(tmp_path: Path) -> None:
    root, captures = make_capture_batch(tmp_path, count=3)
    os.environ["FAKE_INSPECTOR_FAIL_NAMES"] = captures[1].name
    first = run_batch(root, fake_inspector(tmp_path), max_files=3)
    add_capture(root, size=999)
    os.environ.pop("FAKE_INSPECTOR_FAIL_NAMES")
    second = run_batch(root, fake_inspector(tmp_path), max_files=4)
    assert public_counts(first) == {"succeeded": 2, "failed": 1, "skipped": 0}
    assert public_counts(second) == {"succeeded": 2, "failed": 0, "skipped": 2}
    assert invocation_count(tmp_path, captures[0]) == 1
    assert invocation_count(tmp_path, captures[1]) == 2


def test_batch_discovers_uppercase_extensions_and_nested_regular_directories(tmp_path: Path) -> None:
    root, _ = make_capture_batch(tmp_path, count=0)
    add_capture(root, size=3, suffix=".PCAP", name="nested/upper.PCAP")
    add_capture(root, size=2, suffix=".PCAPNG", name="nested/deeper/upper.PCAPNG")
    result = run_batch(root, fake_inspector(tmp_path), max_files=20)
    summary = load_public_summary(root, result)
    assert result.returncode == 0
    assert summary["selected_count"] == 2
    assert recorded_sizes(tmp_path) == [2, 3]


def test_batch_rejects_nested_input_junction(tmp_path: Path) -> None:
    root, _ = make_capture_batch(tmp_path, count=1)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "linked.pcap").write_bytes(b"x")
    link = root / "input" / "linked"
    make_directory_junction(link, outside)
    try:
        result = run_batch(root, fake_inspector(tmp_path), max_files=20)
    finally:
        link.rmdir()
    assert result.returncode != 0
    assert result.stdout.strip() == "pcap_batch_error=input_reparse_point"


def test_batch_cancellation_stops_before_the_next_file(tmp_path: Path) -> None:
    root, _ = make_capture_batch(tmp_path, count=3)
    os.environ["FAKE_INSPECTOR_CANCEL_AFTER"] = "1"
    result = run_batch(root, fake_inspector(tmp_path, cancel_after=1), max_files=3)
    os.environ.pop("FAKE_INSPECTOR_CANCEL_AFTER")
    summary = load_public_summary(root, result)
    assert result.returncode == 0
    assert summary["selected_count"] == 1
    assert recorded_sizes(tmp_path) == [1]
    assert not (root / "state" / f"{BATCH_ID}.cancel").exists()


def test_batch_replaces_private_state_atomically(tmp_path: Path) -> None:
    root, _ = make_capture_batch(tmp_path, count=1)
    first = run_batch(root, fake_inspector(tmp_path), max_files=1)
    second = run_batch(root, fake_inspector(tmp_path), max_files=1)
    assert first.returncode == second.returncode == 0
    state_path = root / "state" / "pcap-batch-private.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["schema_version"] == 1
    assert not list(state_path.parent.glob("pcap-batch-private.json.*.tmp"))


def test_batch_rejects_malformed_child_reports_without_exposing_private_content(tmp_path: Path) -> None:
    root, captures = make_capture_batch(tmp_path, count=1)
    os.environ["FAKE_INSPECTOR_MALFORMED_NAMES"] = captures[0].name
    result = run_batch(root, fake_inspector(tmp_path, malformed_names={captures[0].name}), max_files=1)
    os.environ.pop("FAKE_INSPECTOR_MALFORMED_NAMES")
    summary = load_public_summary(root, result)
    assert result.returncode == 0
    assert public_counts(result) == {"succeeded": 0, "failed": 1, "skipped": 0}
    assert summary["captures"][0]["error_code"] == "invalid_report_schema"
    assert "PRIVATE_CHILD_REPORT" not in result.stdout + result.stderr + json.dumps(summary)


def test_batch_rejects_junction_input_root(tmp_path: Path) -> None:
    root = tmp_path / "pcap-quarantine"
    root.mkdir()
    outside = tmp_path / "outside-input"
    outside.mkdir()
    (outside / "capture.pcap").write_bytes(b"x")
    link = root / "input"
    make_directory_junction(link, outside)
    try:
        result = run_batch(root, fake_inspector(tmp_path), max_files=1)
    finally:
        link.rmdir()
    assert result.returncode != 0
    assert result.stdout.strip() == "pcap_batch_error=input_reparse_point"


@pytest.mark.parametrize(
    ("directory", "error"),
    [("output", "output_reparse_point"), ("state", "state_reparse_point")],
)
def test_batch_rejects_junction_output_and_state_directories(
    tmp_path: Path, directory: str, error: str
) -> None:
    root, _ = make_capture_batch(tmp_path, count=1)
    outside = tmp_path / f"outside-{directory}"
    outside.mkdir()
    link = root / directory
    make_directory_junction(link, outside)
    try:
        result = run_batch(root, fake_inspector(tmp_path), max_files=1)
    finally:
        link.rmdir()
    assert result.returncode != 0
    assert result.stdout.strip() == f"pcap_batch_error={error}"


def test_batch_public_report_uses_only_model_keys_and_hides_private_identity(tmp_path: Path) -> None:
    root, _ = make_capture_batch(tmp_path, count=1)
    private_capture = root / "input" / f"{PRIVATE_SENTINEL}.pcap"
    add_capture(root, size=9, name=f"{PRIVATE_SENTINEL}.pcap")
    result = run_batch(root, fake_inspector(tmp_path), max_files=1)
    summary = load_public_summary(root, result)
    assert result.returncode == 0
    assert set(summary) == {"schema_version", "batch_id", "selected_count", "succeeded_count", "failed_count", "skipped_count", "captures"}
    assert set(summary["captures"][0]) == {"capture_id", "status", "packet_count", "protocol_counts", "visibility", "capability", "error_code"}
    PcapBatchSummary.model_validate(summary)
    public_text = json.dumps(summary)
    assert PRIVATE_SENTINEL not in public_text
    assert private_capture.name not in public_text
    assert sha256(private_capture.read_bytes()).hexdigest() not in public_text
    assert "PRIVATE_CHILD_STDERR" not in result.stdout + result.stderr + public_text


def test_batch_rejects_tampered_private_state_before_resuming(tmp_path: Path) -> None:
    root, _ = make_capture_batch(tmp_path, count=1)
    assert run_batch(root, fake_inspector(tmp_path), max_files=1).returncode == 0
    state_path = root / "state" / "pcap-batch-private.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["entries"][0]["capture_id"] = f"{PRIVATE_SENTINEL}.pcap"
    state_path.write_text(json.dumps(state), encoding="utf-8")

    result = run_batch(root, fake_inspector(tmp_path), max_files=1)

    assert result.returncode != 0
    assert result.stdout.strip() == "pcap_batch_error=invalid_state"
    assert PRIVATE_SENTINEL not in result.stdout + result.stderr


def test_batch_honors_preexisting_cancellation_before_discovery(tmp_path: Path) -> None:
    root, _ = make_capture_batch(tmp_path, count=1)
    marker = root / "state" / f"{BATCH_ID}.cancel"
    marker.parent.mkdir(parents=True)
    marker.write_text("cancel", encoding="utf-8")

    result = run_batch(root, fake_inspector(tmp_path), max_files=1)
    summary = load_public_summary(root, result)

    assert result.returncode == 0
    assert summary["selected_count"] == 0
    assert not (tmp_path / "fake-inspector-log" / "invocations.txt").exists()


def test_batch_checkpoints_completed_file_before_abrupt_interruption(tmp_path: Path) -> None:
    root, captures = make_capture_batch(tmp_path, count=2)
    inspector = fake_inspector(tmp_path)
    environment = batch_environment(root, inspector)
    environment["FAKE_INSPECTOR_PAUSE_AT"] = "2"
    pause_marker = Path(environment["FAKE_INSPECTOR_PAUSE_MARKER"])
    interrupted = subprocess.Popen(
        batch_command(root, inspector, max_files=2),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
    )
    try:
        deadline = time.monotonic() + 10
        while not pause_marker.exists():
            assert interrupted.poll() is None, interrupted.communicate()
            assert time.monotonic() < deadline, "second inspector did not reach the pause point"
            time.sleep(0.05)

        state = json.loads((root / "state" / "pcap-batch-private.json").read_text(encoding="utf-8"))
        assert [entry["internal_path"] for entry in state["entries"]] == [captures[0].name]
    finally:
        if interrupted.poll() is None:
            killed = subprocess.run(
                ["taskkill.exe", "/PID", str(interrupted.pid), "/T", "/F"],
                capture_output=True,
                check=False,
                text=True,
            )
            assert killed.returncode == 0, killed.stdout + killed.stderr
        interrupted.communicate(timeout=5)

    resumed = run_batch(root, inspector, max_files=2)

    assert resumed.returncode == 0
    assert invocation_count(tmp_path, captures[0]) == 1
    assert invocation_count(tmp_path, captures[1]) == 2


def test_batch_passes_trailing_separator_and_special_root_to_child(tmp_path: Path) -> None:
    root = tmp_path / "quarantine & special (path) [100%]!"
    add_capture(root, size=1, name="capture ^ $value ; [1].pcap")
    inspector_root = tmp_path / "inspector & tools (special) [100%]!"
    inspector_root.mkdir()

    result = run_batch(
        root,
        fake_inspector(inspector_root),
        max_files=1,
        quarantine_argument=str(root) + "\\",
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert load_public_summary(root, result)["succeeded_count"] == 1
