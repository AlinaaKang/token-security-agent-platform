# PCAP Safe Preflight Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a temporary, networkless, non-root Docker preflight that accepts one read-only PCAP/PCAPNG file and writes a fixed-field, payload-free capability report outside the Git repository.

**Architecture:** A pure Python policy module validates capture metadata, aggregates only allowlisted protocol names, and emits a strict report. A thin container CLI invokes TShark with fixed fields; a PowerShell launcher validates one quarantine path, applies all Docker restrictions, verifies the file hash after execution, validates the JSON again on the host, and writes the report. A separate verifier uses a synthetic benign capture and Docker inspection to prove the restrictions without touching real PCAP files.

**Tech Stack:** Python 3.12 standard library, pytest, the digest-pinned Microsoft Container Registry Ubuntu 24.04 runtime-deps base, TShark, Docker Desktop with WSL 2, Windows PowerShell 5.1 and PowerShell 7 compatible scripts.

## Global Constraints

- Real PCAP/PCAPNG files remain outside Git under `E:\Codex\pcap-quarantine\input` and are never used by tests, screenshots, examples, AutoDL, or Web APIs.
- Runtime containers use `--network none`, `--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges=true`, `--cpus 1`, `--memory 512m`, `--pids-limit 64`, `--rm`, and a size-limited `noexec` `/tmp` tmpfs.
- The only bind mount is one explicitly selected regular file at `/input/capture`, mounted read-only; the Docker socket, repository, user directory, secrets, and output directory are never mounted.
- The report never contains Prompt, suffix, Token text, application payload, Cookie, Authorization, URL parameters, domain, IP, port, request path, or the original filename.
- Protocol tools may parse packet bytes internally, but no application payload is extracted, displayed, searched, saved, logged, or propagated.
- `token_eligible` means only that a plaintext protocol is eligible for a separately authorized second-stage inspection; it does not mean the traffic is an LLM API or that Token analysis has run.
- Docker/image/tool failure is fail-closed; the launcher never falls back to native host capture analysis.
- Existing API, Web pages, Entropy-CPD results, frozen metrics, and AutoDL services remain unchanged.

---

## File Map

- Create `scripts/pcap_preflight.py`: pure report schema, capture magic validation, allowlisted protocol aggregation, capability policy, TShark adapter, and strict JSON validation.
- Create `pcap-inspector/inspect.py`: container-only CLI that calls `inspect_capture(Path('/input/capture'))` and prints exactly one ASCII JSON object.
- Create `pcap-inspector/Dockerfile`: minimal non-root TShark image with the two Python files copied in.
- Create `tests/unit/test_pcap_preflight.py`: pure unit tests for schema, parsing, policy, redaction, and tool failures.
- Create `scripts/inspect_pcap.ps1`: host launcher, Docker discovery, quarantine-path validation, fixed Docker arguments, post-run hash verification, host-side report validation, and output writing.
- Create `tests/unit/test_inspect_pcap_script.py`: PowerShell launcher tests using a fake Docker executable so unit tests never open a real capture.
- Create `scripts/new_safe_pcap_fixture.py`: deterministic synthetic one-packet PCAP generator with documentation-only HTTP content and reserved example addresses.
- Create `scripts/verify_pcap_sandbox.ps1`: builds the image, runs the synthetic fixture, inspects Docker configuration, and checks runtime identity/filesystem/capabilities/cgroups.
- Create `tests/unit/test_safe_pcap_fixture.py`: validates deterministic fixture bytes and absence of private or attack content.
- Create `docs/pcap-safe-preflight.md`: user instructions, report interpretation, security boundary, and exact competition wording.
- Modify `.gitignore`: explicitly ignore local quarantine and generated preflight reports if a user overrides the default location into the repository.
- Modify `.dockerignore`: exclude quarantine/report patterns from every Docker build context.
- Modify `README.md`: link the optional PCAP preflight and preserve the distinction between network evidence and internal Token evidence.

---

### Task 1: Strict Preflight Policy and Report Model

**Files:**
- Create: `scripts/pcap_preflight.py`
- Create: `tests/unit/test_pcap_preflight.py`

**Interfaces:**
- Produces: `detect_capture_format(header: bytes) -> str` returning `pcap`, `pcapng`, or raising `PreflightError('unsupported_capture_format')`.
- Produces: `parse_tshark_rows(lines: Iterable[str]) -> ProtocolObservation`.
- Produces: `build_report(observation: CaptureObservation) -> dict[str, object]`.
- Produces: `validate_report(value: Mapping[str, object]) -> dict[str, object]`.
- Produces: `inspect_capture(path: Path, *, runner: TsharkRunner | None = None) -> dict[str, object]`.

- [ ] **Step 1: Write failing schema and policy tests**

Create tests that define the exact public contract:

```python
EXPECTED_KEYS = {
    "schema_version", "sha256", "size_bytes", "capture_format",
    "packet_count", "duration_seconds", "link_types", "protocol_counts",
    "visibility", "capability", "reasons", "tool_versions",
}

def test_plain_http_is_only_a_second_stage_candidate() -> None:
    report = build_report(_observation(protocol_counts={"http": 1, "tcp": 1}))
    assert set(report) == EXPECTED_KEYS
    assert report["capability"] == "token_eligible"
    assert report["reasons"] == ["plaintext_application_protocol_observed"]

def test_tls_is_traffic_only() -> None:
    report = build_report(_observation(protocol_counts={"tls": 3, "tcp": 3}))
    assert report["capability"] == "traffic_only"
    assert report["visibility"]["tls_observed"] is True

def test_unknown_fields_fail_closed() -> None:
    value = build_report(_observation()) | {"prompt": "PRIVATE_SENTINEL"}
    with pytest.raises(PreflightError, match="invalid_report_schema"):
        validate_report(value)
```

Also cover PCAP magic values `a1b2c3d4`, `d4c3b2a1`, `a1b23c4d`, `4d3cb2a1`, PCAPNG `0a0d0d0a`, empty input, unsupported input, negative/non-finite numbers, duplicate/unknown reason values, malformed SHA-256, extra nested fields, and blank tool versions.

- [ ] **Step 2: Run focused tests and verify failure**

Run:

```powershell
python -m pytest tests/unit/test_pcap_preflight.py -q
```

Expected: collection fails because `scripts.pcap_preflight` does not exist.

- [ ] **Step 3: Implement the fixed enums and value objects**

Define immutable dataclasses and allowlists:

```python
ALLOWED_PROTOCOLS = (
    "arp", "dns", "eth", "http", "http2", "icmp", "icmpv6", "ip",
    "ipv6", "quic", "sll", "sll2", "tcp", "tls", "udp", "websocket",
)
PLAINTEXT_CANDIDATES = frozenset({"http", "http2", "websocket"})
ENCRYPTED_PROTOCOLS = frozenset({"tls", "quic"})
ALLOWED_REASONS = frozenset({
    "plaintext_application_protocol_observed",
    "encrypted_transport_observed",
    "network_traffic_only",
    "no_packets",
    "no_supported_protocols",
})

@dataclass(frozen=True)
class ProtocolObservation:
    packet_count: int
    first_epoch: Decimal | None
    last_epoch: Decimal | None
    link_types: tuple[str, ...]
    protocol_counts: Mapping[str, int]

@dataclass(frozen=True)
class CaptureObservation:
    sha256: str
    size_bytes: int
    capture_format: str
    protocols: ProtocolObservation
    tshark_version: str
```

Use `Decimal` for epochs, reject non-finite values, sort all arrays/maps, calculate duration as `max(0, last-first)`, and serialize it as a finite float rounded to six decimal places.

- [ ] **Step 4: Implement strict report construction and validation**

`build_report()` applies this deterministic policy in this order:

```python
if observation.protocols.packet_count == 0:
    capability = "insufficient_evidence"
    reasons = ["no_packets"]
elif any(count > 0 for name, count in counts.items() if name in PLAINTEXT_CANDIDATES):
    capability = "token_eligible"
    reasons = ["plaintext_application_protocol_observed"]
elif any(count > 0 for name, count in counts.items() if name in ENCRYPTED_PROTOCOLS):
    capability = "traffic_only"
    reasons = ["encrypted_transport_observed"]
elif sum(counts.values()) > 0:
    capability = "traffic_only"
    reasons = ["network_traffic_only"]
else:
    capability = "insufficient_evidence"
    reasons = ["no_supported_protocols"]
```

`validate_report()` checks exact top-level and nested key sets, exact enum membership, booleans rather than integers, non-negative bounded integers, finite numbers, lowercase `64`-hex SHA-256, sorted unique `link_types`, sorted protocol keys, and rejects all unrecognized data.

- [ ] **Step 5: Implement capture inspection with a replaceable runner**

Define a `TsharkRunner` protocol that yields text lines and exposes a version string. The production runner invokes only:

```text
tshark -n -r /input/capture \
  -o tcp.desegment_tcp_streams:FALSE -o http.desegment_body:FALSE \
  -T fields -E separator=/t -E occurrence=f \
  -e frame.time_epoch -e frame.encap_type -e frame.protocols
```

It must call `subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=error_stream, text=True, encoding="utf-8", errors="replace")` with an explicit argument list, consume stdout line-by-line, direct stderr to a size-limited temporary file under `/tmp` to avoid pipe deadlock, read at most 8 KiB after the child exits, enforce a 120-second timeout, and map all failures to fixed `PreflightError` codes without returning stderr. `parse_tshark_rows()` splits only the three selected fields, counts only `ALLOWED_PROTOCOLS`, converts numeric encapsulation IDs to `encap_<digits>`, and never retains raw lines.

`inspect_capture()` reads only the first four bytes for format validation, hashes the file in 1 MiB chunks, gets its size, runs TShark, builds the report, and passes the result through `validate_report()` before returning.

- [ ] **Step 6: Run policy tests**

Run:

```powershell
python -m pytest tests/unit/test_pcap_preflight.py -q
```

Expected: all tests pass and no test output contains the private sentinel.

- [ ] **Step 7: Commit the policy layer**

```powershell
git add scripts/pcap_preflight.py tests/unit/test_pcap_preflight.py
git commit -m "feat: add strict pcap preflight policy"
```

---

### Task 2: Non-Root Inspector Image

**Files:**
- Create: `pcap-inspector/inspect.py`
- Create: `pcap-inspector/Dockerfile`
- Modify: `.dockerignore`
- Test: `tests/unit/test_pcap_preflight.py`

**Interfaces:**
- Consumes: `inspect_capture(Path) -> dict[str, object]` and `PreflightError.code` from Task 1.
- Produces: image `token-security-pcap-preflight:local` whose default process prints one ASCII JSON document on success and a fixed code to stderr on failure.

- [ ] **Step 1: Add failing CLI contract tests**

Use `runpy` with a fake `pcap_preflight` module. Define `_run_inspector(monkeypatch, capsys, report=None, error_code=None)` in the test: it installs a `types.ModuleType("pcap_preflight")` in `sys.modules`, gives it a local `PreflightError` class with a `.code`, supplies `inspect_capture`, runs `pcap-inspector/inspect.py` as `__main__`, catches `SystemExit`, and returns `(exit_code, captured.out, captured.err)`. Then assert:

```python
def test_container_cli_prints_one_ascii_json_document(monkeypatch, capsys) -> None:
    report = {"schema_version": 1, "capability": "traffic_only"}
    code, stdout, stderr = _run_inspector(
        monkeypatch, capsys, report=report, error_code=None
    )
    assert code == 0
    assert json.loads(stdout) == report
    assert stdout.count("\n") == 1
    assert stderr == ""

def test_container_cli_reports_only_fixed_error_code(monkeypatch, capsys) -> None:
    code, stdout, stderr = _run_inspector(
        monkeypatch, capsys, report=None, error_code="tool_failed"
    )
    assert code == 2
    assert stdout == ""
    assert stderr == "pcap_preflight_error=tool_failed\n"
    assert "PRIVATE_SENTINEL" not in stderr
```

- [ ] **Step 2: Run the new tests and verify failure**

Run:

```powershell
python -m pytest tests/unit/test_pcap_preflight.py -q
```

Expected: failure because `pcap-inspector/inspect.py` does not exist.

- [ ] **Step 3: Implement the container CLI**

The CLI must have no command-line path argument and always inspect `/input/capture`:

```python
def main() -> int:
    try:
        report = inspect_capture(Path("/input/capture"))
    except PreflightError as exc:
        print(f"pcap_preflight_error={exc.code}", file=sys.stderr)
        return 2
    print(json.dumps(report, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
```

Catch unexpected exceptions and emit only `pcap_preflight_error=unexpected_failure`; never print `repr(exc)`, tool stderr, paths, or capture-derived values.

- [ ] **Step 4: Create the minimal image**

Use the reachable Microsoft Container Registry Linux/AMD64 manifest exactly as follows:

```dockerfile
# mcr.microsoft.com/dotnet/runtime-deps:8.0-noble, linux/amd64 manifest resolved 2026-08-31
FROM mcr.microsoft.com/dotnet/runtime-deps:8.0-noble@sha256:5aa56f5fdf83434f14a7b877912999ee8daa69a43fa1d6106753c4adbe21dc9b
```

Install only `python3`, `tshark`, and `ca-certificates` with noninteractive package configuration, remove apt lists, create fixed user/group `pcap` UID/GID `65532`, copy the policy and CLI to `/opt/pcap`, set ownership at build time, and use:

```dockerfile
USER 65532:65532
WORKDIR /opt/pcap
ENV PYTHONPATH=/opt/pcap PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENTRYPOINT ["python3", "/opt/pcap/inspect.py"]
```

Do not add `sudo`, shells beyond the base image, curl, network clients, compilers, packet capture capabilities, volumes, ports, or a health endpoint.

- [ ] **Step 5: Exclude all quarantine material from build contexts**

Append to `.dockerignore`:

```gitignore
pcap-quarantine
**/pcap-quarantine
**/*.pcap
**/*.pcapng
**/pcap-preflight-*.json
```

This is defense in depth; the real quarantine remains outside the repository.

- [ ] **Step 6: Build and inspect the image**

Use the discovered Docker executable:

```powershell
$docker = "$env:LOCALAPPDATA\Programs\DockerDesktop\resources\bin\docker.exe"
& $docker build --pull -f pcap-inspector/Dockerfile -t token-security-pcap-preflight:local .
& $docker image inspect token-security-pcap-preflight:local --format '{{json .Config}}'
```

Expected: build succeeds; config has user `65532:65532`, no exposed ports, no volumes, and the fixed entrypoint. `docker image inspect` must show the Dockerfile's pinned MCR base in the build history; do not substitute an unpinned tag if the digest becomes unavailable.

- [ ] **Step 7: Run unit tests and commit**

```powershell
python -m pytest tests/unit/test_pcap_preflight.py -q
git add pcap-inspector scripts/pcap_preflight.py tests/unit/test_pcap_preflight.py .dockerignore
git commit -m "build: add non-root pcap inspector image"
```

---

### Task 3: Fail-Closed Windows Launcher

**Files:**
- Create: `scripts/inspect_pcap.ps1`
- Create: `tests/unit/test_inspect_pcap_script.py`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: image `token-security-pcap-preflight:local` and Task 1 report schema.
- Produces: `scripts/inspect_pcap.ps1 -Path <absolute pcap> [-QuarantineRoot <absolute root>] [-DockerExecutable <test override>]`.
- Produces: exactly one report named `pcap-preflight-<first-16-sha256>.json` in the allowed output directory.

- [ ] **Step 1: Write failing launcher tests with a fake Docker executable**

Define `_write_fake_docker(tmp_path: Path, report: dict[str, object], exit_code: int = 0) -> Path` to create a temporary `.cmd` that appends each received argument to `docker-args.txt`, writes `json.dumps(report)` to stdout, optionally writes `PRIVATE_SENTINEL` to stderr, and exits with the requested code. Define `_run_launcher(path: Path, root: Path, fake_docker: Path) -> CompletedProcess[str]` to invoke Windows PowerShell with `-Path`, `-QuarantineRoot`, and `-DockerExecutable`. These helpers let the tests run without real Docker. Test all of the following:

```python
def test_launcher_uses_exact_sandbox_arguments(tmp_path: Path) -> None:
    root, capture = _make_quarantine_capture(tmp_path)
    fake = _write_fake_docker(tmp_path, _valid_report(capture))
    result = _run_launcher(capture, root, fake)
    args = (tmp_path / "docker-args.txt").read_text(encoding="utf-8").splitlines()
    assert result.returncode == 0, result.stdout + result.stderr
    assert "--network" in args and args[args.index("--network") + 1] == "none"
    assert "--read-only" in args
    cap_index = args.index("--cap-drop")
    assert args[cap_index : cap_index + 2] == ["--cap-drop", "ALL"]
    assert "no-new-privileges=true" in args
    assert args[args.index("--cpus") + 1] == "1"
    assert args[args.index("--memory") + 1] == "512m"
    assert args[args.index("--pids-limit") + 1] == "64"
    mounts = [args[index + 1] for index, value in enumerate(args[:-1]) if value == "--mount"]
    assert len(mounts) == 1
    assert "target=/input/capture" in mounts[0]
    assert mounts[0].endswith(",readonly")

def test_launcher_rejects_path_outside_quarantine(tmp_path: Path) -> None:
    root = tmp_path / "quarantine"
    outside = tmp_path / "outside.pcap"
    outside.write_bytes(PCAP_HEADER)
    result = _run_launcher(outside, root, tmp_path / "unused.cmd")
    assert result.returncode != 0
    assert "pcap_preflight_error=input_outside_quarantine" in result.stdout

def test_launcher_rejects_directory_input(tmp_path: Path) -> None:
    root = tmp_path / "quarantine"
    directory = root / "input" / "capture.pcap"
    directory.mkdir(parents=True)
    result = _run_launcher(directory, root, tmp_path / "unused.cmd")
    assert result.returncode != 0
    assert "pcap_preflight_error=input_not_regular_file" in result.stdout

def test_launcher_rejects_extra_report_field(tmp_path: Path) -> None:
    root, capture = _make_quarantine_capture(tmp_path)
    report = _valid_report(capture) | {"prompt": "PRIVATE_SENTINEL"}
    result = _run_launcher(capture, root, _write_fake_docker(tmp_path, report))
    assert result.returncode != 0
    assert "PRIVATE_SENTINEL" not in result.stdout + result.stderr

def test_launcher_rejects_changed_post_run_hash(tmp_path: Path) -> None:
    root, capture = _make_quarantine_capture(tmp_path)
    report = _valid_report(capture) | {"sha256": "0" * 64}
    result = _run_launcher(capture, root, _write_fake_docker(tmp_path, report))
    assert result.returncode != 0
    assert "pcap_preflight_error=input_changed" in result.stdout

def test_launcher_never_prints_private_docker_stderr(tmp_path: Path) -> None:
    root, capture = _make_quarantine_capture(tmp_path)
    fake = _write_fake_docker(tmp_path, _valid_report(capture), exit_code=9)
    result = _run_launcher(capture, root, fake)
    assert result.returncode != 0
    assert "PRIVATE_SENTINEL" not in result.stdout + result.stderr
```

Add separate parametrized tests for `.pcap`/`.pcapng` case-insensitively, JSON output naming, no original filename in the report, reparse-point rejection when `os.symlink()` is permitted, and Windows PowerShell 5.1 compatibility.

- [ ] **Step 2: Run launcher tests and verify failure**

Run:

```powershell
python -m pytest tests/unit/test_inspect_pcap_script.py -q
```

Expected: tests fail because the script is absent.

- [ ] **Step 3: Implement Docker discovery and path validation**

`Resolve-DockerExecutable` checks, in order:

1. explicit `-DockerExecutable` test override;
2. `Get-Command docker`;
3. `$env:LOCALAPPDATA\Programs\DockerDesktop\resources\bin\docker.exe`;
4. `$env:ProgramFiles\Docker\Docker\resources\bin\docker.exe`.

If none exists, terminate with `pcap_preflight_error=docker_unavailable`.

Resolve the input and quarantine root with `[System.IO.Path]::GetFullPath()`. `-QuarantineRoot` defaults to `E:\Codex\pcap-quarantine` and exists so tests can use a unique temporary root; the operator guide documents only the default. Require the input to be strictly below `<QuarantineRoot>\input`, be a regular leaf, not have `ReparsePoint`, and end in `.pcap` or `.pcapng`. Compare paths with `OrdinalIgnoreCase` and a trailing directory separator so `input-evil` cannot pass a prefix check.

- [ ] **Step 4: Implement a fixed Docker argument builder**

Construct a string array, never a shell command string:

```powershell
$dockerArgs = @(
    'run', '--rm',
    '--network', 'none',
    '--read-only',
    '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges=true',
    '--cpus', '1',
    '--memory', '512m',
    '--pids-limit', '64',
    '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=16m',
    '--mount', ("type=bind,source={0},target=/input/capture,readonly" -f $fullPath),
    'token-security-pcap-preflight:local'
)
```

Capture stdout and stderr separately in temporary files created with `New-TemporaryFile`; always remove them in `finally`. Do not print container stderr. Apply a 150-second host timeout using `Start-Process -PassThru -WindowStyle Hidden`, kill only the exact child process on timeout, and return a fixed category.

- [ ] **Step 5: Validate and persist the report**

Require stdout to be one nonblank JSON document. Reject unknown top-level/nested keys, invalid enums, invalid counts, invalid hash, arrays containing unknown values, and exact forbidden keys such as `prompt`, `suffix`, `token_text`, `payload`, `cookie`, `authorization`, `url`, `domain`, `ip`, `port`, and `path`. Because the schema is closed, do not use substring scanning that could reject legitimate enum values such as `no_supported_protocols`. Tests additionally require that a unique private sentinel never appears in stdout, stderr, or a saved report.

After the container exits, compute `Get-FileHash -Algorithm SHA256` on the same resolved file and require it to match `report.sha256`. Create only `<QuarantineRoot>\output`, serialize with stable property order, and write with UTF-8 without BOM. Do not create any fallback file elsewhere.

- [ ] **Step 6: Ignore generated local material**

Append to `.gitignore`:

```gitignore
pcap-quarantine/
**/pcap-quarantine/
**/pcap-preflight-*.json
*.pcap
*.pcapng
```

Confirm no existing tracked fixture uses these extensions before adding the broad rules:

```powershell
git ls-files '*.pcap' '*.pcapng'
```

Expected: no output.

- [ ] **Step 7: Run tests and commit**

```powershell
python -m pytest tests/unit/test_inspect_pcap_script.py -q
git diff --check
git add scripts/inspect_pcap.ps1 tests/unit/test_inspect_pcap_script.py .gitignore
git commit -m "feat: add fail-closed pcap launcher"
```

---

### Task 4: Synthetic Fixture and Mechanical Sandbox Verification

**Files:**
- Create: `scripts/new_safe_pcap_fixture.py`
- Create: `scripts/verify_pcap_sandbox.ps1`
- Create: `tests/unit/test_safe_pcap_fixture.py`

**Interfaces:**
- Produces: `write_safe_fixture(path: Path) -> str`, returning the deterministic SHA-256 of a one-packet PCAP.
- Consumes: launcher and image from Tasks 2 and 3.
- Produces: a verifier summary ending in `pcap_sandbox_verification=passed` or a nonzero exit with fixed category counts.

- [ ] **Step 1: Write failing deterministic fixture tests**

Build the packet from `struct.pack` rather than committing binary data. Use only reserved documentation addresses `192.0.2.10` and `198.51.100.20`, destination TCP port `80`, and a benign HTTP request `GET /health HTTP/1.1` with `Host: example.test`. Tests assert identical bytes and SHA across two runs, recognized PCAP magic, length below 1 KiB, and absence of attack/private sentinel terms.

- [ ] **Step 2: Run fixture tests and verify failure**

```powershell
python -m pytest tests/unit/test_safe_pcap_fixture.py -q
```

Expected: module import fails because the generator is absent.

- [ ] **Step 3: Implement the fixture generator**

Construct:

- little-endian PCAP global header with Ethernet link type;
- one Ethernet frame;
- IPv4 header with protocol TCP and documentation addresses;
- TCP header with destination port 80 and PSH/ACK flags;
- benign HTTP bytes.

Calculate IPv4 and TCP checksums in pure Python. Expose `write_safe_fixture()` for tests and a CLI `--output` for the verifier. The CLI prints only `safe_fixture_sha256=<hex>` and `safe_fixture_size=<int>`.

- [ ] **Step 4: Write the sandbox verifier**

The verifier must:

1. create a unique temporary directory outside the repository;
2. generate the benign capture there;
3. build the image from the repository root;
4. copy the fixture into the quarantine input directory;
5. invoke `inspect_pcap.ps1`;
6. assert the report contains HTTP counts and `token_eligible` only as a second-stage candidate;
7. create a separate probe container with the exact same runtime flags and inspect `HostConfig` for network, read-only root, dropped capabilities, no-new-privileges, CPU, memory, PID, tmpfs, mount count and mount read-only state;
8. run a probe entrypoint that reports only `uid`, `CapEff`, root write result, input write result, `memory.max`, `pids.max`, and `cpu.max`;
9. assert UID is `65532`, `CapEff` is all zeros, root/input writes fail, and cgroup limits match;
10. verify no container with the unique test label remains;
11. delete only the unique synthetic files in `finally`.

Use a Docker label such as `token-security-purpose=pcap-sandbox-verification` and an unpredictable run UUID so cleanup targets can be resolved exactly. Never use a wildcard or recursive delete against the quarantine root.

- [ ] **Step 5: Run pure tests, then the Docker verifier**

```powershell
python -m pytest tests/unit/test_safe_pcap_fixture.py tests/unit/test_pcap_preflight.py tests/unit/test_inspect_pcap_script.py -q
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/verify_pcap_sandbox.ps1
```

Expected: all Python tests pass and the script ends with:

```text
pcap_sandbox_verification=passed network_none=1 readonly_root=1 non_root=1 cap_drop_all=1 no_new_privileges=1 resource_limits=1 payload_leaks=0 residual_containers=0
```

- [ ] **Step 6: Commit the verification harness**

```powershell
git add scripts/new_safe_pcap_fixture.py scripts/verify_pcap_sandbox.ps1 tests/unit/test_safe_pcap_fixture.py
git commit -m "test: verify pcap sandbox boundaries"
```

---

### Task 5: User Documentation and Full Regression

**Files:**
- Create: `docs/pcap-safe-preflight.md`
- Modify: `README.md`
- Modify: `docs/basic-task/design.md`
- Modify: `docs/advanced-task/design.md`

**Interfaces:**
- Consumes: exact launcher command and report semantics from Tasks 1-4.
- Produces: Chinese operator guide and competition-safe capability statement.

- [ ] **Step 1: Write the operator guide**

Document these exact phases and why each exists:

```text
安装/启动 Docker
→ 构建固定分析镜像（此阶段可联网下载工具）
→ 机械验证隔离边界
→ 用户把单个 PCAP 放进仓库外 input
→ 运行无网络预检
→ 阅读三档能力结论
→ token_eligible 时再次授权，才设计第二阶段
```

Include the exact commands with separate labels for “本机 PowerShell” and make clear that no AutoDL terminal is used. Explain that TShark parses packet bytes internally but no payload content is output or stored. Explain recovery from Docker unavailable, invalid capture, timeout, hash mismatch, and insufficient evidence without suggesting unsafe fallbacks.

- [ ] **Step 2: Update project claims without changing task metrics**

In `README.md`, link the guide under an “optional PCAP evidence preflight” heading. In the basic and advanced design documents, replace only the current blanket “PCAP not implemented” wording with:

```text
PCAP 安全预检是独立的证据可用性鉴定器，不进入基础或进阶冻结指标，不恢复 Prompt，不运行 Entropy-CPD，也不改变任何既有动作。
```

Retain the statement that full PCAP-to-Prompt/Token correlation is not implemented.

- [ ] **Step 3: Run privacy and regression verification**

Run:

```powershell
python -m pytest tests/unit/test_pcap_preflight.py tests/unit/test_inspect_pcap_script.py tests/unit/test_safe_pcap_fixture.py -q
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/verify_pcap_sandbox.ps1
python -m pytest -q
Set-Location frontend
npm.cmd test -- --run
npm.cmd run build
```

Expected:

- PCAP unit tests all pass;
- sandbox summary reports every required boundary as `1` and leaks/residual containers as `0`;
- existing backend suite has no new failure (the configured GPU integration test may remain skipped when its environment variable is absent);
- all frontend tests pass;
- production build succeeds.

- [ ] **Step 4: Scan tracked files and reports for forbidden material**

From repository root, run:

```powershell
git ls-files '*.pcap' '*.pcapng' '*pcap-preflight-*.json'
rg -n -i 'authorization:|cookie:|PRIVATE_SENTINEL|attack suffix' pcap-inspector scripts tests docs README.md
git diff --check
git status --short
```

Expected: the tracked binary/report query has no output; text scan finds only intentional test assertions or explanatory prohibitions, never a real value; diff check is clean; status contains only intended source and documentation changes.

- [ ] **Step 5: Commit documentation and final verified state**

```powershell
git add README.md docs/pcap-safe-preflight.md docs/basic-task/design.md docs/advanced-task/design.md
git commit -m "docs: document safe pcap preflight"
```

- [ ] **Step 6: Record honest completion evidence**

Append a dated verification section to `docs/pcap-safe-preflight.md` containing only aggregate test counts, Docker/image versions, sandbox pass/fail fields, and known limitations. Do not record the real PCAP path, filename, hash, network indicators, or content. Commit the evidence only after rerunning the commands against the final tree:

```powershell
git add docs/pcap-safe-preflight.md
git commit -m "docs: record pcap preflight verification"
```

---

## Final Acceptance Checklist

- [ ] Docker Desktop engine is reachable through either PATH or the per-user install path.
- [ ] Image runs as UID/GID `65532:65532` and has no ports, volumes, or runtime capture capabilities.
- [ ] Launcher exposes exactly one read-only file and no host directory.
- [ ] Runtime has no network, writable root, privilege escalation, capabilities, or unrestricted resources.
- [ ] Synthetic HTTP capture produces `token_eligible` with wording that still requires second-stage authorization.
- [ ] Synthetic TLS/network-only cases produce `traffic_only`; invalid/empty cases produce `insufficient_evidence` or a fixed fail-closed error.
- [ ] Report schema is exact and contains no original filename, address, port, path, payload, Prompt, suffix, or Token content.
- [ ] Real PCAP files and generated reports remain untracked and outside the repository.
- [ ] Existing backend, frontend, build, and privacy behavior remains stable.
- [ ] Documentation explicitly states that full PCAP-to-Prompt/Token correlation is not implemented.
