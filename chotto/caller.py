"""Caller Detection: liên kết có xuất phát từ Zalo hay không.

Windows: ``CreateToolhelp32Snapshot`` (chuỗi tiến trình cha, có kiểm tra thời điểm tạo để chống
tái sử dụng PID) + ``GetForegroundWindow``. macOS: ``lsappinfo`` (ứng dụng ở foreground).

Quy ước kết quả ``from_zalo``:
- ``True``: có bằng chứng xuất phát từ Zalo.
- ``False``: có bằng chứng dương tính là ứng dụng KHÁC (không phải Zalo, không phải chính CHOTTO,
  không phải shell hệ thống) ⇒ được phép chuyển thẳng.
- ``None``: không xác định ⇒ áp dụng ``unknown_caller_policy`` (mặc định: vẫn kiểm tra).
"""
from __future__ import annotations

import logging
import os
import re
import subprocess
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

__all__ = ["Caller", "detect_caller", "decide_from_evidence"]

_LOG = logging.getLogger(__name__)

_MAX_ANCESTORS: Final[int] = 6
_LSAPPINFO_TIMEOUT_S: Final[float] = 0.75
# Tiến trình không cho biết nguồn thật của link (shell, dịch vụ hệ thống, chính CHOTTO lúc đóng gói).
_AMBIGUOUS_PROCESSES: Final[frozenset[str]] = frozenset({
    "explorer.exe", "svchost.exe", "sihost.exe", "runtimebroker.exe", "shellexperiencehost.exe",
    "startmenuexperiencehost.exe", "searchhost.exe", "applicationframehost.exe", "openwith.exe",
    "dllhost.exe", "cmd.exe", "conhost.exe", "python.exe", "pythonw.exe", "chotto.exe",
})
_OWN_BUNDLE: Final[str] = "vn.chotto.app"


@dataclass(frozen=True)
class Caller:
    """Kết quả nhận diện nguồn gọi.

    Attributes:
        from_zalo: ``True``/``False``/``None`` theo quy ước của module.
        evidence: Mô tả bằng chứng (ghi log, không chứa URL).
    """

    from_zalo: bool | None
    evidence: str = ""


def decide_from_evidence(
    ancestors: list[str], foreground: str | None, zalo_names: set[str], own_names: set[str]
) -> Caller:
    """Quy tắc quyết định thuần (kiểm thử được trên mọi nền tảng).

    Args:
        ancestors: Tên file thực thi của các tiến trình tổ tiên (gần nhất trước), chữ thường.
        foreground: Tên tiến trình sở hữu cửa sổ foreground (chữ thường) hoặc ``None``.
        zalo_names: Tên tiến trình Zalo (chữ thường).
        own_names: Tên tiến trình của chính CHOTTO (chữ thường).

    Returns:
        ``Caller``.
    """
    chain = ",".join(ancestors)
    if zalo_names.intersection(ancestors):
        return Caller(True, f"tiến trình cha: {chain}")
    if foreground in zalo_names:
        return Caller(True, f"cửa sổ foreground: {foreground}")
    if foreground and foreground not in own_names and foreground not in _AMBIGUOUS_PROCESSES:
        return Caller(False, f"foreground={foreground}, cha={chain}")
    return Caller(None, f"không xác định (foreground={foreground}, cha={chain})")


# ---------------- Windows ----------------
def _windows_evidence() -> tuple[list[str], str | None]:
    """Thu thập (chuỗi tổ tiên đã kiểm chứng thời điểm tạo, tiến trình foreground) trên Windows.

    Raises:
        OSError: Không chụp được danh sách tiến trình.
    """
    if sys.platform != "win32":
        raise OSError("Chỉ dùng trên Windows")
    import ctypes
    from ctypes import wintypes

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD), ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD),
            ("szExeFile", ctypes.c_wchar * 260),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    kernel32.GetProcessTimes.restype = wintypes.BOOL
    user32.GetForegroundWindow.argtypes = []
    user32.GetForegroundWindow.restype = wintypes.HWND
    user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user32.GetWindowThreadProcessId.restype = wintypes.DWORD

    invalid_handle = wintypes.HANDLE(-1).value
    th32cs_snapprocess = 0x00000002
    process_query_limited_information = 0x1000

    snapshot = kernel32.CreateToolhelp32Snapshot(th32cs_snapprocess, 0)
    if not snapshot or snapshot == invalid_handle:
        raise ctypes.WinError(ctypes.get_last_error())
    processes: dict[int, tuple[int, str]] = {}
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            processes[int(entry.th32ProcessID)] = (int(entry.th32ParentProcessID), entry.szExeFile.lower())
            ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)

    def creation_time(pid: int) -> int | None:
        handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
        if not handle:
            return None
        try:
            created, exited, kernel, user = (wintypes.FILETIME() for _ in range(4))
            if not kernel32.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(exited),
                                            ctypes.byref(kernel), ctypes.byref(user)):
                return None
            return (int(created.dwHighDateTime) << 32) | int(created.dwLowDateTime)
        finally:
            kernel32.CloseHandle(handle)

    ancestors: list[str] = []
    pid = os.getpid()
    child_created = creation_time(pid)
    for _ in range(_MAX_ANCESTORS):
        parent = processes.get(pid, (0, ""))[0]
        if not parent or parent not in processes:
            break
        parent_created = creation_time(parent)
        # PID cha có thể đã bị cấp lại cho tiến trình khác sinh SAU tiến trình con: dừng chuỗi.
        if parent_created is None or (child_created is not None and parent_created > child_created):
            break
        ancestors.append(processes[parent][1])
        pid, child_created = parent, parent_created

    foreground: str | None = None
    hwnd = user32.GetForegroundWindow()
    if hwnd:
        fg_pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(fg_pid))
        foreground = processes.get(int(fg_pid.value), (0, ""))[1] or None
    return ancestors, foreground


def _own_process_names() -> set[str]:
    """Tên tiến trình của chính CHOTTO (để không nhầm CHOTTO là "ứng dụng khác")."""
    return {os.path.basename(sys.executable).lower(), "chotto.exe", "python.exe", "pythonw.exe"}


# ---------------- macOS ----------------
def _macos_front_bundle() -> str | None:
    """Bundle id ứng dụng ở foreground qua ``lsappinfo``; lỗi/timeout trả ``None``."""
    try:
        asn = subprocess.run(["lsappinfo", "front"], capture_output=True, text=True,
                             timeout=_LSAPPINFO_TIMEOUT_S, check=False).stdout.strip()
        if not asn:
            return None
        info = subprocess.run(["lsappinfo", "info", "-only", "bundleid", asn], capture_output=True, text=True,
                              timeout=_LSAPPINFO_TIMEOUT_S, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        _LOG.warning("lsappinfo lỗi", exc_info=True)
        return None
    match = re.search(r'="([^"]+)"', info)
    return match.group(1).lower() if match else None


def detect_caller(cfg: Mapping[str, Any]) -> Caller:
    """Nhận diện nguồn gọi theo nền tảng; mọi lỗi trả ``Caller(None, ...)``.

    Args:
        cfg: Cấu hình chứa ``zalo_processes`` và ``zalo_bundle_ids``.
    """
    try:
        if sys.platform == "win32":
            ancestors, foreground = _windows_evidence()
            zalo = {str(p).lower() for p in cfg["zalo_processes"]}
            return decide_from_evidence(ancestors, foreground, zalo, _own_process_names())
        if sys.platform == "darwin":
            bundle = _macos_front_bundle()
            zalo_bundles = {str(b).lower() for b in cfg["zalo_bundle_ids"]}
            return decide_from_evidence([], bundle, zalo_bundles, {_OWN_BUNDLE})
    except (OSError, ValueError, AttributeError) as exc:
        _LOG.warning("Nhận diện nguồn gọi lỗi", exc_info=True)
        return Caller(None, f"lỗi: {exc}")
    return Caller(None, "nền tảng không hỗ trợ")
