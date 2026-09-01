from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path


_TRUTHY_VALUES = frozenset({"1", "on", "true", "yes"})
_SCRIPT_OVERRIDE_VARIABLES = (
    "TOKEN_SECURITY_PCAP_BATCH_SCRIPT",
    "TOKEN_SECURITY_PCAP_INSPECT_SCRIPT",
)


@dataclass(frozen=True)
class PcapConfig:
    quarantine_root: Path
    powershell_executable: Path
    batch_script: Path
    inspect_script: Path

    @classmethod
    def from_environ(cls, environ: Mapping[str, str]) -> PcapConfig | None:
        enabled = environ.get("TOKEN_SECURITY_PCAP_ENABLED", "")
        if enabled.strip().lower() not in _TRUTHY_VALUES:
            return None

        quarantine_root = _existing_directory(
            environ.get("TOKEN_SECURITY_PCAP_QUARANTINE_ROOT", ""),
            "PCAP quarantine root",
        )
        if not (quarantine_root / "input").is_dir():
            raise ValueError("PCAP quarantine root must contain an input directory")
        powershell_executable = _existing_file(
            environ.get("TOKEN_SECURITY_PCAP_POWERSHELL_EXECUTABLE", ""),
            "PCAP PowerShell executable",
        )

        repository_root = Path(__file__).resolve().parents[3]
        _reject_external_script_overrides(environ, repository_root)
        scripts = repository_root / "scripts"
        return cls(
            quarantine_root=quarantine_root,
            powershell_executable=powershell_executable,
            batch_script=scripts / "inspect_pcap_batch.ps1",
            inspect_script=scripts / "inspect_pcap.ps1",
        )


def _existing_directory(value: str, label: str) -> Path:
    path = _absolute_path(value, label)
    if not path.is_dir():
        raise ValueError(f"{label} must be an existing directory")
    return path.resolve()


def _existing_file(value: str, label: str) -> Path:
    path = _absolute_path(value, label)
    if not path.is_file():
        raise ValueError(f"{label} must be an existing file")
    return path.resolve()


def _absolute_path(value: str, label: str) -> Path:
    path = Path(value)
    if not value or not path.is_absolute():
        raise ValueError(f"{label} must be an absolute path")
    return path


def _reject_external_script_overrides(
    environ: Mapping[str, str], repository_root: Path
) -> None:
    for variable in _SCRIPT_OVERRIDE_VARIABLES:
        value = environ.get(variable)
        if value and not _is_within_repository(Path(value), repository_root):
            raise ValueError("PCAP script override must remain inside the repository")


def _is_within_repository(path: Path, repository_root: Path) -> bool:
    try:
        path.resolve().relative_to(repository_root.resolve())
    except ValueError:
        return False
    return True
