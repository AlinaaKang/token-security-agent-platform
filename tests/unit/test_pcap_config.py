from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest

import app.pcap.config as config_module
from app.pcap.config import PcapConfig


def make_directory_junction(link: Path, target: Path) -> None:
    result = subprocess.run(
        [os.environ["ComSpec"], "/d", "/c", "mklink", "/J", str(link), str(target)],
        capture_output=True,
        check=False,
        encoding="utf-8",
    )
    assert result.returncode == 0, result.stdout + result.stderr


def enabled_environment(quarantine_root: Path, powershell: Path) -> dict[str, str]:
    return {
        "TOKEN_SECURITY_PCAP_ENABLED": "true",
        "TOKEN_SECURITY_PCAP_QUARANTINE_ROOT": str(quarantine_root.absolute()),
        "TOKEN_SECURITY_PCAP_POWERSHELL_EXECUTABLE": str(powershell.absolute()),
    }


def test_pcap_config_is_disabled_without_explicit_flag(tmp_path: Path) -> None:
    assert PcapConfig.from_environ({}) is None


def test_enabled_pcap_config_requires_absolute_existing_paths(tmp_path: Path) -> None:
    env = {
        "TOKEN_SECURITY_PCAP_ENABLED": "true",
        "TOKEN_SECURITY_PCAP_QUARANTINE_ROOT": str(tmp_path / "missing"),
        "TOKEN_SECURITY_PCAP_POWERSHELL_EXECUTABLE": str(tmp_path / "missing.exe"),
    }

    with pytest.raises(ValueError, match="PCAP quarantine root"):
        PcapConfig.from_environ(env)


@pytest.mark.parametrize("enabled", ["true", "TRUE", "1", "yes", "on"])
def test_enabled_pcap_config_requires_input_directory_and_powershell_file(
    tmp_path: Path, enabled: str
) -> None:
    quarantine_root = tmp_path / "quarantine"
    quarantine_root.mkdir()
    powershell = tmp_path / "pwsh.exe"
    powershell.touch()
    env = {
        "TOKEN_SECURITY_PCAP_ENABLED": enabled,
        "TOKEN_SECURITY_PCAP_QUARANTINE_ROOT": str(quarantine_root.resolve()),
        "TOKEN_SECURITY_PCAP_POWERSHELL_EXECUTABLE": str(powershell.resolve()),
    }

    with pytest.raises(ValueError, match="PCAP quarantine root.*input"):
        PcapConfig.from_environ(env)


def test_enabled_pcap_config_uses_repository_owned_scripts(tmp_path: Path) -> None:
    quarantine_root = tmp_path / "quarantine"
    (quarantine_root / "input").mkdir(parents=True)
    powershell = tmp_path / "pwsh.exe"
    powershell.touch()
    env = {
        "TOKEN_SECURITY_PCAP_ENABLED": "true",
        "TOKEN_SECURITY_PCAP_QUARANTINE_ROOT": str(quarantine_root.resolve()),
        "TOKEN_SECURITY_PCAP_POWERSHELL_EXECUTABLE": str(powershell.resolve()),
        "TOKEN_SECURITY_PCAP_BATCH_SCRIPT": str((tmp_path / "outside.ps1").resolve()),
        "TOKEN_SECURITY_PCAP_INSPECT_SCRIPT": str((tmp_path / "outside-single.ps1").resolve()),
    }

    with pytest.raises(ValueError, match="PCAP script override"):
        PcapConfig.from_environ(env)

    config = PcapConfig.from_environ(
        {
            key: value
            for key, value in env.items()
            if key
            not in {
                "TOKEN_SECURITY_PCAP_BATCH_SCRIPT",
                "TOKEN_SECURITY_PCAP_INSPECT_SCRIPT",
            }
        }
    )

    assert config is not None
    assert config.batch_script.name == "inspect_pcap_batch.ps1"
    assert config.inspect_script.name == "inspect_pcap.ps1"
    assert config.batch_script.parent.name == "scripts"
    assert config.inspect_script.parent == config.batch_script.parent


@pytest.mark.parametrize(
    ("variable", "value", "message"),
    [
        (
            "TOKEN_SECURITY_PCAP_QUARANTINE_ROOT",
            "relative-quarantine",
            "PCAP quarantine root",
        ),
        (
            "TOKEN_SECURITY_PCAP_POWERSHELL_EXECUTABLE",
            "relative-pwsh.exe",
            "PCAP PowerShell executable",
        ),
    ],
)
def test_enabled_pcap_config_rejects_relative_paths(
    tmp_path: Path, variable: str, value: str, message: str
) -> None:
    quarantine_root = tmp_path / "quarantine"
    (quarantine_root / "input").mkdir(parents=True)
    powershell = tmp_path / "pwsh.exe"
    powershell.touch()
    env = {
        "TOKEN_SECURITY_PCAP_ENABLED": "true",
        "TOKEN_SECURITY_PCAP_QUARANTINE_ROOT": str(quarantine_root.resolve()),
        "TOKEN_SECURITY_PCAP_POWERSHELL_EXECUTABLE": str(powershell.resolve()),
        variable: value,
    }

    with pytest.raises(ValueError, match=message):
        PcapConfig.from_environ(env)


def test_enabled_pcap_config_rejects_quarantine_inside_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository_root = tmp_path / "repository"
    quarantine_root = repository_root / "private-quarantine"
    (quarantine_root / "input").mkdir(parents=True)
    powershell = tmp_path / "powershell.exe"
    powershell.touch()
    fake_config_file = repository_root / "backend" / "app" / "pcap" / "config.py"
    monkeypatch.setattr(config_module, "__file__", str(fake_config_file))

    with pytest.raises(ValueError, match="outside the repository"):
        PcapConfig.from_environ(enabled_environment(quarantine_root, powershell))


@pytest.mark.parametrize("junction_target", ["root", "root_ancestor", "input"])
def test_enabled_pcap_config_rejects_supplied_quarantine_reparse_points(
    tmp_path: Path, junction_target: str
) -> None:
    powershell = tmp_path / "powershell.exe"
    powershell.touch()
    target = tmp_path / "junction-target"
    (target / "input").mkdir(parents=True)
    quarantine_root = tmp_path / "quarantine"
    if junction_target == "root":
        make_directory_junction(quarantine_root, target)
    elif junction_target == "root_ancestor":
        (target / "quarantine" / "input").mkdir(parents=True)
        linked_parent = tmp_path / "linked-parent"
        make_directory_junction(linked_parent, target)
        quarantine_root = linked_parent / "quarantine"
    else:
        quarantine_root.mkdir()
        make_directory_junction(quarantine_root / "input", target / "input")
    try:
        with pytest.raises(ValueError, match="reparse point"):
            PcapConfig.from_environ(
                enabled_environment(quarantine_root, powershell)
            )
    finally:
        if junction_target == "root":
            quarantine_root.rmdir()
        elif junction_target == "root_ancestor":
            (tmp_path / "linked-parent").rmdir()
        else:
            (quarantine_root / "input").rmdir()
