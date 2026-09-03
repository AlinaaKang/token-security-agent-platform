from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
import stat


_TRUTHY_VALUES = frozenset({"1", "on", "true", "yes"})
_SCRIPT_OVERRIDE_VARIABLES = (
    "TOKEN_SECURITY_PCAP_BATCH_SCRIPT",
    "TOKEN_SECURITY_PCAP_INSPECT_SCRIPT",
    "TOKEN_SECURITY_PCAP_RECON_BATCH_SCRIPT",
)
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_DEFAULT_RECON_BATCH_SCRIPT = (
    Path(__file__).resolve().parents[3] / "scripts" / "inspect_pcap_recon_batch.ps1"
)


@dataclass(frozen=True)
class PcapConfig:
    quarantine_root: Path
    powershell_executable: Path
    batch_script: Path
    inspect_script: Path
    recon_batch_script: Path = _DEFAULT_RECON_BATCH_SCRIPT

    @classmethod
    def from_environ(cls, environ: Mapping[str, str]) -> PcapConfig | None:
        enabled = environ.get("TOKEN_SECURITY_PCAP_ENABLED", "")
        if enabled.strip().lower() not in _TRUTHY_VALUES:
            return None

        quarantine_root = _existing_directory(
            environ.get("TOKEN_SECURITY_PCAP_QUARANTINE_ROOT", ""),
            "PCAP quarantine root",
        )
        _existing_directory(
            quarantine_root / "input",
            "PCAP quarantine root input",
        )
        powershell_executable = _existing_file(
            environ.get("TOKEN_SECURITY_PCAP_POWERSHELL_EXECUTABLE", ""),
            "PCAP PowerShell executable",
        )

        repository_root = Path(__file__).resolve().parents[3]
        if _is_within_repository(quarantine_root, repository_root):
            raise ValueError("PCAP quarantine root must remain outside the repository")
        _reject_external_script_overrides(environ, repository_root)
        scripts = repository_root / "scripts"
        return cls(
            quarantine_root=quarantine_root,
            powershell_executable=powershell_executable,
            batch_script=scripts / "inspect_pcap_batch.ps1",
            inspect_script=scripts / "inspect_pcap.ps1",
            recon_batch_script=scripts / "inspect_pcap_recon_batch.ps1",
        )


def _existing_directory(value: str | Path, label: str) -> Path:
    path = _absolute_path(value, label)
    _reject_reparse_components(path, label)
    try:
        metadata = path.lstat()
    except OSError:
        raise ValueError(f"{label} must be an existing directory") from None
    if _is_reparse_or_symlink(metadata):
        raise ValueError(f"{label} cannot be a symlink or reparse point")
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"{label} must be an existing directory")
    return path.resolve()


def _reject_reparse_components(path: Path, label: str) -> None:
    current = path
    while True:
        try:
            metadata = current.lstat()
        except OSError:
            if current == path:
                return
            raise ValueError(f"{label} path could not be inspected") from None
        if _is_reparse_or_symlink(metadata):
            raise ValueError(f"{label} cannot contain a symlink or reparse point")
        parent = current.parent
        if parent == current:
            return
        current = parent


def _existing_file(value: str, label: str) -> Path:
    path = _absolute_path(value, label)
    if not path.is_file():
        raise ValueError(f"{label} must be an existing file")
    return path.resolve()


def _absolute_path(value: str | Path, label: str) -> Path:
    path = Path(value)
    if not str(value) or not path.is_absolute():
        raise ValueError(f"{label} must be an absolute path")
    return path


def _is_reparse_or_symlink(metadata: object) -> bool:
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0)
        & _FILE_ATTRIBUTE_REPARSE_POINT
    )


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
