from __future__ import annotations

import json, os, subprocess
from pathlib import Path

WINDOWS_POWERSHELL = Path(os.environ["SystemRoot"]) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "inspect_pcap_recon_batch.ps1"
RECON_ID = "recon_" + "a" * 32
STATE_ID = "state_" + "b" * 32

def fake_inspector(tmp: Path) -> Path:
    p = tmp / "fake.ps1"
    p.write_text(r'''param([string]$Path,[string]$QuarantineRoot)
$i=Get-Item -LiteralPath $Path
$h=[Security.Cryptography.SHA256]::Create();$s=[IO.File]::OpenRead($Path);try{$sha=(($h.ComputeHash($s)|%{$_.ToString('x2')})-join '')}finally{$s.Dispose();$h.Dispose()}
$r=[ordered]@{schema_version=1;sha256=$sha;size_bytes=[int64]$i.Length;capture_format='pcap';packet_count=64;duration_seconds=1.5;link_types=@('encap_1');protocol_counts=[ordered]@{http=1};visibility=[ordered]@{plaintext_application_protocol_observed=$true;encrypted_transport_observed=$false;tls_observed=$false;quic_observed=$false};capability='token_eligible';reasons=@('plaintext_application_protocol_observed');tool_versions=[ordered]@{tshark='tshark'}}
New-Item -ItemType Directory -Force (Join-Path $QuarantineRoot 'output')|Out-Null
[IO.File]::WriteAllText((Join-Path $QuarantineRoot ('output/pcap-preflight-'+$sha.Substring(0,16)+'.json')),$r|ConvertTo-Json -Depth 6)
''', encoding="utf-8")
    return p


def configurable_inspector(tmp: Path) -> Path:
    p = tmp / "configurable-fake.ps1"
    p.write_text(r'''param([string]$Path,[string]$QuarantineRoot)
$ErrorActionPreference = 'Stop'
$log = Join-Path $env:FAKE_RECON_LOG_ROOT 'invocations.txt'
$item = Get-Item -LiteralPath $Path
Add-Content -LiteralPath $log -Value $item.Name
$hash = [Security.Cryptography.SHA256]::Create()
$stream = [IO.File]::OpenRead($Path)
try { $sha = (($hash.ComputeHash($stream) | % { $_.ToString('x2') }) -join '') } finally { $stream.Dispose(); $hash.Dispose() }
$report = [ordered]@{
  schema_version = 1; sha256 = $sha; size_bytes = [int64]$item.Length
  capture_format = if ($item.Extension -eq '.pcapng') { 'pcapng' } else { 'pcap' }
  packet_count = 64; duration_seconds = 1.0; link_types = @('encap_1')
  protocol_counts = [ordered]@{ http = 1 }
  visibility = [ordered]@{ plaintext_application_protocol_observed = $true; encrypted_transport_observed = $false; tls_observed = $false; quic_observed = $false }
  capability = 'token_eligible'; reasons = @('plaintext_application_protocol_observed')
  tool_versions = [ordered]@{ tshark = 'tshark' }
}
$out = Join-Path $QuarantineRoot 'output'; New-Item -ItemType Directory -Force $out | Out-Null
[IO.File]::WriteAllText((Join-Path $out ('pcap-preflight-' + $sha.Substring(0,16) + '.json')), ($report | ConvertTo-Json -Depth 6 -Compress))
if ($env:FAKE_RECON_CANCEL_AFTER -and (Get-Content -LiteralPath $log).Count -eq [int]$env:FAKE_RECON_CANCEL_AFTER) {
  New-Item -ItemType File -Force $env:FAKE_RECON_CANCEL_MARKER | Out-Null
}
if ($env:FAKE_RECON_FAIL_NAME -eq $item.Name) { exit 9 }
''', encoding="utf-8")
    return p


def malformed_inspector(tmp: Path, *, exit_code: int = 0) -> Path:
    p = tmp / f"malformed-{exit_code}.ps1"
    p.write_text(f'''param([string]$Path,[string]$QuarantineRoot)
$out = Join-Path $QuarantineRoot 'output'
New-Item -ItemType Directory -Force $out | Out-Null
[IO.File]::WriteAllText((Join-Path $out 'pcap-preflight-stale.json'), '{{"private":"PRIVATE_CHILD"}}')
exit {exit_code}
''', encoding="utf-8")
    return p

def run(root: Path, inspector: Path):
    env = os.environ.copy()
    env['FAKE_RECON_LOG_ROOT'] = str(inspector.parent / 'recon-log')
    Path(env['FAKE_RECON_LOG_ROOT']).mkdir(exist_ok=True)
    env['FAKE_RECON_CANCEL_MARKER'] = str(root / 'state' / f'{RECON_ID}.cancel')
    return subprocess.run([str(WINDOWS_POWERSHELL), '-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(SCRIPT),'-QuarantineRoot',str(root),'-InspectorScript',str(inspector),'-ReconId',RECON_ID,'-StateId',STATE_ID],capture_output=True,text=True,env=env)


def run_with_env(root: Path, inspector: Path, updates: dict[str, str]):
    env = os.environ.copy()
    env.update(updates)
    env['FAKE_RECON_LOG_ROOT'] = str(inspector.parent / 'recon-log')
    Path(env['FAKE_RECON_LOG_ROOT']).mkdir(exist_ok=True)
    env['FAKE_RECON_CANCEL_MARKER'] = str(root / 'state' / f'{RECON_ID}.cancel')
    return subprocess.run([str(WINDOWS_POWERSHELL), '-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(SCRIPT),'-QuarantineRoot',str(root),'-InspectorScript',str(inspector),'-ReconId',RECON_ID,'-StateId',STATE_ID],capture_output=True,text=True,env=env)

def test_recon_selects_five_midpoints_per_quartile(tmp_path: Path):
    root=tmp_path/'q'; inp=root/'input'; inp.mkdir(parents=True)
    for n in range(1,41): (inp/f'{n:02}.pcap').write_bytes(b'x'*n)
    result=run(root,fake_inspector(tmp_path)); assert result.returncode==0, result.stdout+result.stderr
    state=json.loads((root/'state'/'pcap-recon-private.json').read_text())
    assert [e['size_bytes'] for e in state['entries']]==[2,4,6,8,10,12,14,16,18,20,22,24,26,28,30,32,34,36,38,40]

def test_recon_public_summary_is_aggregate_only(tmp_path: Path):
    root=tmp_path/'q'; inp=root/'input'; inp.mkdir(parents=True); (inp/'PRIVATE_SENTINEL.pcap').write_bytes(b'x'*4)
    result=run(root,fake_inspector(tmp_path)); assert result.returncode==0, result.stdout+result.stderr
    summary=json.loads((root/'output'/f'pcap-recon-{RECON_ID}.json').read_text())
    assert set(summary)=={'schema_version','sampled_count','succeeded_count','failed_count','quartile_counts','size_bucket_counts','packet_bucket_counts','duration_bucket_counts','protocol_presence_counts','plaintext_sample_count','encrypted_sample_count','sequence_candidate_count'}
    assert 'PRIVATE_SENTINEL' not in json.dumps(summary)

def test_recon_required_population_sizes_are_bounded_and_unique(tmp_path: Path):
    for count in (1, 4, 7, 19, 21):
        root=tmp_path/f'q{count}'; inp=root/'input'; inp.mkdir(parents=True)
        for n in range(1,count+1): (inp/f'{n:02}.pcap').write_bytes(b'x'*n)
        result=run(root,fake_inspector(tmp_path)); assert result.returncode==0, result.stdout+result.stderr
        state=json.loads((root/'state'/'pcap-recon-private.json').read_text())
        ordinals=[e['internal_path'] for e in state['entries']]
        assert len(ordinals)==len(set(ordinals))<=20
        summary=json.loads((root/'output'/f'pcap-recon-{RECON_ID}.json').read_text())
        assert summary['sampled_count']==count if count < 20 else summary['sampled_count']<=20

def test_recon_equal_size_paths_use_ordinal_order(tmp_path: Path):
    root=tmp_path/'q'; inp=root/'input'; inp.mkdir(parents=True)
    for name in ('z.pcap','a.pcap','m.pcap'): (inp/name).write_bytes(b'xx')
    result=run(root,fake_inspector(tmp_path)); assert result.returncode==0
    state=json.loads((root/'state'/'pcap-recon-private.json').read_text())
    assert [e['internal_path'] for e in state['entries']]==['a.pcap','m.pcap','z.pcap']

def test_recon_missing_parameters_emit_fixed_error(tmp_path: Path):
    result=subprocess.run([str(WINDOWS_POWERSHELL),'-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(SCRIPT)],capture_output=True,text=True)
    assert result.returncode != 0
    assert 'pcap_recon_error=' in result.stdout
    assert 'ParameterBinding' not in result.stdout+result.stderr


def test_recon_cancellation_resumes_without_duplicate_inspection(tmp_path: Path):
    root=tmp_path/'q'; inp=root/'input'; inp.mkdir(parents=True)
    for n in range(1, 5): (inp/f'{n:02}.pcap').write_bytes(b'x'*n)
    inspector = configurable_inspector(tmp_path)
    first = run_with_env(root, inspector, {'FAKE_RECON_CANCEL_AFTER': '1'})
    assert first.returncode == 0, first.stdout + first.stderr
    log = inspector.parent / 'recon-log' / 'invocations.txt'
    assert log.read_text().splitlines() == ['01.pcap']
    second = run_with_env(root, inspector, {'FAKE_RECON_CANCEL_AFTER': '0'})
    assert second.returncode == 0, second.stdout + second.stderr
    assert log.read_text().splitlines() == ['01.pcap', '02.pcap', '03.pcap', '04.pcap']
    summary=json.loads((root/'output'/f'pcap-recon-{RECON_ID}.json').read_text())
    assert summary['sampled_count'] == 4
    assert summary['succeeded_count'] == 4
    assert summary['failed_count'] == 0


def test_recon_malformed_child_schema_is_fixed_failure_and_cleaned(tmp_path: Path):
    root=tmp_path/'q'; inp=root/'input'; inp.mkdir(parents=True); (inp/'one.pcap').write_bytes(b'x')
    result = run(root, malformed_inspector(tmp_path))
    assert result.returncode == 0, result.stdout + result.stderr
    state=json.loads((root/'state'/'pcap-recon-private.json').read_text())
    assert state['entries'][0]['status'] == 'failed'
    assert state['entries'][0]['error_code'] == 'invalid_report_schema'
    assert not list((root/'output').glob('pcap-preflight-*.json'))
    assert 'PRIVATE_CHILD' not in result.stdout + result.stderr


def test_recon_cleans_child_report_when_inspector_exits_nonzero(tmp_path: Path):
    root=tmp_path/'q'; inp=root/'input'; inp.mkdir(parents=True); (inp/'one.pcap').write_bytes(b'x')
    result = run(root, malformed_inspector(tmp_path, exit_code=9))
    assert result.returncode == 0, result.stdout + result.stderr
    state=json.loads((root/'state'/'pcap-recon-private.json').read_text())
    assert state['entries'][0]['error_code'] == 'inspector_failed'
    assert not list((root/'output').glob('pcap-preflight-*.json'))


def test_recon_resume_retries_failed_changed_and_new_captures_only(tmp_path: Path):
    root=tmp_path/'q'; inp=root/'input'; inp.mkdir(parents=True)
    captures=[]
    for n in range(1, 4):
        capture=inp/f'{n:02}.pcap'; capture.write_bytes(b'x'*n); captures.append(capture)
    inspector=configurable_inspector(tmp_path)
    first=run_with_env(root, inspector, {'FAKE_RECON_FAIL_NAME': captures[1].name})
    assert first.returncode == 0, first.stdout + first.stderr
    captures[2].write_bytes(b'x'*5)
    (inp/'04.pcap').write_bytes(b'x'*4)
    second=run_with_env(root, inspector, {'FAKE_RECON_FAIL_NAME': ''})
    assert second.returncode == 0, second.stdout + second.stderr
    calls=(inspector.parent/'recon-log'/'invocations.txt').read_text().splitlines()
    assert calls == ['01.pcap','02.pcap','03.pcap','02.pcap','04.pcap','03.pcap']
    state=json.loads((root/'state'/'pcap-recon-private.json').read_text())
    assert len(state['entries']) == len({entry['internal_path'] for entry in state['entries']}) == 4
    summary=json.loads((root/'output'/f'pcap-recon-{RECON_ID}.json').read_text())
    assert (summary['sampled_count'], summary['succeeded_count'], summary['failed_count']) == (4,4,0)


def test_recon_rejects_unknown_private_state_fields_without_reflection(tmp_path: Path):
    root=tmp_path/'q'; inp=root/'input'; inp.mkdir(parents=True); (inp/'one.pcap').write_bytes(b'x')
    inspector=configurable_inspector(tmp_path)
    assert run(root, inspector).returncode == 0
    state_path=root/'state'/'pcap-recon-private.json'; state=json.loads(state_path.read_text())
    state['entries'][0]['PRIVATE_SENTINEL'] = 'raw exception content'
    state_path.write_text(json.dumps(state))
    result=run(root, inspector)
    assert result.returncode != 0
    assert result.stdout.strip() == 'pcap_recon_error=invalid_state'
    assert result.stderr == ''
    assert 'PRIVATE_SENTINEL' not in result.stdout + result.stderr


def test_recon_state_replacement_is_atomic_and_pre_cancel_cleans_children(tmp_path: Path):
    root=tmp_path/'q'; inp=root/'input'; inp.mkdir(parents=True); (inp/'one.pcap').write_bytes(b'x')
    output=root/'output'; state_dir=root/'state'; output.mkdir(); state_dir.mkdir()
    (output/'pcap-preflight-stale.json').write_text('PRIVATE_STALE')
    (state_dir/f'{RECON_ID}.cancel').write_text('cancel')
    result=run(root, configurable_inspector(tmp_path))
    assert result.returncode == 0, result.stdout + result.stderr
    assert not list(output.glob('pcap-preflight-*.json'))
    assert not list(state_dir.glob('pcap-recon-private.json.*.tmp'))
    assert not (state_dir/f'{RECON_ID}.cancel').exists()
    summary=json.loads((output/f'pcap-recon-{RECON_ID}.json').read_text())
    assert summary['sampled_count'] == 0
