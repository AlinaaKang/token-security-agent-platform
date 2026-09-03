from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from pathlib import Path

_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_FILE_ADD_FILE = 0x0002
_FILE_ADD_SUBDIRECTORY = 0x0004
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_LIST_DIRECTORY = 0x0001
_FILE_READ_ATTRIBUTES = 0x0080
_FILE_NON_DIRECTORY_FILE = 0x0040
_FILE_CREATE = 2
_FILE_DIRECTORY_FILE = 0x0001
_FILE_OPEN = 1
_FILE_OPEN_REPARSE_POINT = 0x00200000
_FILE_SHARE_ALL = 0x00000007
_FILE_SYNCHRONOUS_IO_NONALERT = 0x0020
_GENERIC_WRITE = 0x40000000
_GENERIC_READ = 0x80000000
_WIN32_OPEN_EXISTING = 3
_STATUS_OBJECT_NAME_COLLISION = ctypes.c_long(0xC0000035).value
_SYNCHRONIZE = 0x00100000
_MAX_RELATIVE_READ_BYTES = 256 * 1024


class _UnicodeString(ctypes.Structure):
    _fields_ = [("length", ctypes.c_ushort), ("maximum_length", ctypes.c_ushort), ("buffer", ctypes.c_wchar_p)]


class _ObjectAttributes(ctypes.Structure):
    _fields_ = [
        ("length", wintypes.ULONG),
        ("root_directory", wintypes.HANDLE),
        ("object_name", ctypes.POINTER(_UnicodeString)),
        ("attributes", wintypes.ULONG),
        ("security_descriptor", ctypes.c_void_p),
        ("security_quality_of_service", ctypes.c_void_p),
    ]


class _IoStatusBlock(ctypes.Structure):
    _fields_ = [("status", wintypes.LONG), ("information", ctypes.c_size_t)]


class _ByHandleFileInformation(ctypes.Structure):
    _fields_ = [
        ("file_attributes", wintypes.DWORD),
        ("creation_time", ctypes.c_byte * 8),
        ("last_access_time", ctypes.c_byte * 8),
        ("last_write_time", ctypes.c_byte * 8),
        ("volume_serial_number", wintypes.DWORD),
        ("file_size_high", wintypes.DWORD),
        ("file_size_low", wintypes.DWORD),
        ("number_of_links", wintypes.DWORD),
        ("file_index_high", wintypes.DWORD),
        ("file_index_low", wintypes.DWORD),
    ]


def _directory_access() -> int:
    return _FILE_LIST_DIRECTORY | _FILE_ADD_FILE | _FILE_ADD_SUBDIRECTORY | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE


def _open_quarantine_root(quarantine_root: Path) -> wintypes.HANDLE:
    if os.name != "nt":
        raise OSError("PCAP execution requires Windows directory handles")
    create_file = ctypes.windll.kernel32.CreateFileW
    create_file.restype = wintypes.HANDLE
    handle = create_file(str(quarantine_root), _directory_access(), _FILE_SHARE_ALL, None, _WIN32_OPEN_EXISTING, _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT, None)
    if handle == wintypes.HANDLE(-1).value:
        raise OSError("could not open PCAP state directory")
    typed_handle = wintypes.HANDLE(handle)
    try:
        _reject_handle_reparse_point(typed_handle)
    except Exception:
        _close_handle(typed_handle)
        raise
    return typed_handle


def _open_or_create_directory_relative(parent_handle: wintypes.HANDLE, directory_name: str) -> wintypes.HANDLE:
    handle, status = _nt_create_relative(parent_handle, directory_name, _directory_access(), _FILE_CREATE, _FILE_DIRECTORY_FILE | _FILE_SYNCHRONOUS_IO_NONALERT)
    if status == 0:
        return _verified_handle(handle)
    if status != _STATUS_OBJECT_NAME_COLLISION:
        raise OSError("could not create PCAP state directory")
    return _open_directory_relative(parent_handle, directory_name)


def _open_directory_relative(parent_handle: wintypes.HANDLE, directory_name: str) -> wintypes.HANDLE:
    handle, status = _nt_create_relative(parent_handle, directory_name, _directory_access(), _FILE_OPEN, _FILE_DIRECTORY_FILE | _FILE_SYNCHRONOUS_IO_NONALERT | _FILE_OPEN_REPARSE_POINT)
    if status != 0:
        raise OSError("could not open PCAP directory")
    return _verified_handle(handle)


def _create_marker_relative_to(directory_handle: wintypes.HANDLE, marker_name: str) -> None:
    marker_handle, status = _nt_create_relative(directory_handle, marker_name, _GENERIC_WRITE | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE, _FILE_CREATE, _FILE_NON_DIRECTORY_FILE | _FILE_SYNCHRONOUS_IO_NONALERT)
    if status == 0:
        _close_handle(marker_handle)
        return
    if status != _STATUS_OBJECT_NAME_COLLISION:
        raise OSError("could not create PCAP cancellation marker")
    marker_handle, status = _nt_create_relative(directory_handle, marker_name, _GENERIC_WRITE | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE, _FILE_OPEN, _FILE_NON_DIRECTORY_FILE | _FILE_SYNCHRONOUS_IO_NONALERT | _FILE_OPEN_REPARSE_POINT)
    if status != 0:
        raise OSError("could not open PCAP cancellation marker")
    try:
        _reject_handle_reparse_point(marker_handle)
    finally:
        _close_handle(marker_handle)


def _read_file_relative(directory_handle: wintypes.HANDLE, file_name: str) -> str:
    report_handle, status = _nt_create_relative(directory_handle, file_name, _GENERIC_READ | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE, _FILE_OPEN, _FILE_NON_DIRECTORY_FILE | _FILE_SYNCHRONOUS_IO_NONALERT | _FILE_OPEN_REPARSE_POINT)
    if status != 0:
        raise OSError("could not open PCAP public summary")
    descriptor = None
    try:
        _reject_handle_reparse_point(report_handle)
        import msvcrt

        descriptor = msvcrt.open_osfhandle(report_handle.value, os.O_RDONLY)
    except Exception:
        _close_handle(report_handle)
        raise
    try:
        with os.fdopen(descriptor, "rb") as report:
            data = report.read(_MAX_RELATIVE_READ_BYTES + 1)
        if len(data) > _MAX_RELATIVE_READ_BYTES:
            raise ValueError("PCAP public summary exceeds size limit")
        return data.decode("utf-8")
    except Exception:
        raise


def _nt_create_relative(parent_handle: wintypes.HANDLE, name_value: str, desired_access: int, disposition: int, options: int) -> tuple[wintypes.HANDLE, int]:
    buffer = ctypes.create_unicode_buffer(name_value)
    name = _UnicodeString(length=len(name_value) * ctypes.sizeof(ctypes.c_wchar), maximum_length=(len(name_value) + 1) * ctypes.sizeof(ctypes.c_wchar), buffer=ctypes.cast(buffer, ctypes.c_wchar_p))
    attributes = _ObjectAttributes(length=ctypes.sizeof(_ObjectAttributes), root_directory=parent_handle, object_name=ctypes.pointer(name), attributes=0, security_descriptor=None, security_quality_of_service=None)
    status_block = _IoStatusBlock()
    marker_handle = wintypes.HANDLE()
    create_file = ctypes.windll.ntdll.NtCreateFile
    create_file.restype = wintypes.LONG
    status = create_file(ctypes.byref(marker_handle), desired_access, ctypes.byref(attributes), ctypes.byref(status_block), None, 0, _FILE_SHARE_ALL, disposition, options, None, 0)
    return marker_handle, status


def _verified_handle(handle: wintypes.HANDLE) -> wintypes.HANDLE:
    try:
        _reject_handle_reparse_point(handle)
    except Exception:
        _close_handle(handle)
        raise
    return handle


def _reject_handle_reparse_point(handle: wintypes.HANDLE) -> None:
    information = _ByHandleFileInformation()
    if not ctypes.windll.kernel32.GetFileInformationByHandle(handle, ctypes.byref(information)):
        raise OSError("could not inspect PCAP state path")
    if information.file_attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
        raise ValueError("PCAP state paths cannot be reparse points")


def _close_handle(handle: wintypes.HANDLE) -> None:
    if not ctypes.windll.kernel32.CloseHandle(handle):
        raise OSError("could not close PCAP state handle")
