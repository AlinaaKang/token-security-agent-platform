from __future__ import annotations

from pathlib import Path

import pytest

from app.pcap.config import PcapConfig


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
