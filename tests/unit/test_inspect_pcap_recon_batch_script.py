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

def run(root: Path, inspector: Path):
    return subprocess.run([str(WINDOWS_POWERSHELL), '-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(SCRIPT),'-QuarantineRoot',str(root),'-InspectorScript',str(inspector),'-ReconId',RECON_ID,'-StateId',STATE_ID],capture_output=True,text=True)

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
