"""Đăng ký CHOTTO làm Default URL Handler (cấp User, không cần quyền Admin) và chuyển tiếp sang trình duyệt thật.

Anti-Loop: trình duyệt đích được xác định theo ProgId/bundle id đã lưu lúc cài đặt; mọi ứng viên trỏ về
chính CHOTTO (so sánh đường dẫn file thực thi, không so chuỗi con) đều bị loại. URL được truyền cho
trình duyệt dưới dạng một phần tử argv riêng (không ghép chuỗi lệnh) nên không thể chèn tham số.
"""
from __future__ import annotations

import logging
import os
import plistlib
import shutil
import subprocess
import sys
from collections.abc import Iterator, Mapping, MutableMapping
from pathlib import Path
from typing import Any, Final

from .core.url import SUPPORTED_SCHEMES, get_scheme

__all__ = [
    "APP_KEY",
    "agent_argv",
    "disable_autostart",
    "enable_autostart",
    "spawn_agent",
    "OWN_BUNDLE",
    "PROGID",
    "PlatformSetupError",
    "build_browser_argv",
    "install",
    "open_in_real_browser",
    "our_command",
    "split_windows_command",
    "uninstall",
]

_LOG = logging.getLogger(__name__)

PROGID: Final[str] = "ChottoURL"
APP_NAME: Final[str] = "CHOTTO"
APP_KEY: Final[str] = r"Software\Clients\StartMenuInternet\CHOTTO"
OWN_BUNDLE: Final[str] = "vn.chotto.app"
_URL_ASSOC: Final[str] = r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\{scheme}"
_PLACEHOLDERS: Final[tuple[str, ...]] = ("%1", "%l", "%L")
_DETACHED_PROCESS: Final[int] = 0x00000008
_CREATE_NEW_PROCESS_GROUP: Final[int] = 0x00000200
_CREATE_NO_WINDOW: Final[int] = 0x08000000
_RUN_KEY: Final[str] = r"Software\Microsoft\Windows\CurrentVersion\Run"
_LAUNCH_AGENT_LABEL: Final[str] = "vn.chotto.agent"
_BROWSER_PREFERENCE: Final[tuple[str, ...]] = ("chrome", "edge", "coccoc", "cốc cốc", "firefox", "brave", "opera")

_WIN_FALLBACKS: Final[tuple[str, ...]] = (
    r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe",
    r"%ProgramFiles%\Google\Chrome\Application\chrome.exe",
    r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe",
    r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe",
    r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe",
    r"%LOCALAPPDATA%\CocCoc\Browser\Application\browser.exe",
    r"%ProgramFiles%\CocCoc\Browser\Application\browser.exe",
    r"%ProgramFiles%\Mozilla Firefox\firefox.exe",
    r"%ProgramFiles(x86)%\Mozilla Firefox\firefox.exe",
    r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\Application\brave.exe",
    r"%ProgramFiles%\BraveSoftware\Brave-Browser\Application\brave.exe",
)
_MAC_FALLBACKS: Final[tuple[tuple[str, str], ...]] = (
    ("com.google.chrome", "/Applications/Google Chrome.app"),
    ("com.apple.safari", "/Applications/Safari.app"),
    ("org.mozilla.firefox", "/Applications/Firefox.app"),
    ("com.microsoft.edgemac", "/Applications/Microsoft Edge.app"),
    ("com.coccoc.coccoc", "/Applications/CocCoc.app"),
    ("com.brave.browser", "/Applications/Brave Browser.app"),
)


class PlatformSetupError(RuntimeError):
    """Không đăng ký/gỡ đăng ký được handler (thông điệp tiếng Việt để hiển thị)."""


# ---------------- Tiện ích dùng chung (kiểm thử được trên mọi nền tảng) ----------------
def split_windows_command(command: str) -> list[str]:
    """Tách chuỗi lệnh Windows thành argv theo đúng quy tắc của ``CommandLineToArgvW``.

    Phần tử đầu (đường dẫn chương trình) chỉ dùng ngoặc kép để bao, không xử lý ``\\``; các phần tử
    sau theo quy tắc ``2n`` / ``2n+1`` dấu ``\\`` trước ``"`` của Microsoft C runtime.
    """
    args: list[str] = []
    text = command.strip()
    length = len(text)
    index = 0
    if index < length and text[index] == '"':
        end = text.find('"', index + 1)
        end = length if end == -1 else end
        args.append(text[index + 1 : end])
        index = end + 1
    else:
        end = index
        while end < length and text[end] not in " \t":
            end += 1
        args.append(text[index:end])
        index = end
    while True:
        while index < length and text[index] in " \t":
            index += 1
        if index >= length:
            break
        buffer: list[str] = []
        in_quotes = False
        while index < length:
            char = text[index]
            if char == "\\":
                run_end = index
                while run_end < length and text[run_end] == "\\":
                    run_end += 1
                count = run_end - index
                if run_end < length and text[run_end] == '"':
                    buffer.append("\\" * (count // 2))
                    if count % 2:
                        buffer.append('"')
                        index = run_end + 1
                    else:
                        index = run_end
                else:
                    buffer.append("\\" * count)
                    index = run_end
            elif char == '"':
                if in_quotes and index + 1 < length and text[index + 1] == '"':
                    buffer.append('"')
                    index += 2
                else:
                    in_quotes = not in_quotes
                    index += 1
            elif char in " \t" and not in_quotes:
                break
            else:
                buffer.append(char)
                index += 1
        args.append("".join(buffer))
    return args if args and args[0] else []


def build_browser_argv(command_args: list[str], url: str) -> list[str]:
    """Thay ``%1``/``%l``/``%L`` bằng ``url`` trong từng phần tử argv; bỏ ``%*``; không có chỗ thì nối ``url`` vào cuối."""
    replaced = False
    result: list[str] = []
    for arg in command_args:
        if arg == "%*":
            continue
        new = arg
        for placeholder in _PLACEHOLDERS:
            if placeholder in new:
                new = new.replace(placeholder, url)
                replaced = True
        result.append(new)
    if not replaced:
        result.append(url)
    return result


def _main_script() -> Path:
    """Đường dẫn ``main.py`` khi chạy từ mã nguồn."""
    return Path(__file__).resolve().parent.parent / "main.py"


def _same_file(a: str, b: str) -> bool:
    """So sánh hai đường dẫn file theo nội dung hệ thống tệp (không phân biệt hoa thường trên Windows)."""
    try:
        return os.path.samefile(a, b)
    except OSError:
        return os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b))


def _is_self(argv: list[str]) -> bool:
    """``True`` nếu lệnh ``argv`` sẽ khởi chạy lại chính CHOTTO (nguyên nhân vòng lặp vô hạn)."""
    if not argv or not argv[0]:
        return False
    if _same_file(argv[0], sys.executable):
        return True
    main_script = str(_main_script())
    return any(arg.lower().endswith("main.py") and _same_file(arg, main_script) for arg in argv[1:])


def our_command() -> str:
    """Lệnh mà hệ điều hành dùng để gọi CHOTTO với một URL."""
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}" "%1"'
    python = Path(sys.executable)
    pythonw = python.with_name("pythonw.exe")
    return f'"{pythonw if pythonw.exists() else python}" "{_main_script()}" "%1"'


def agent_argv() -> list[str]:
    """Lệnh khởi động agent thường trú (argv, không qua shell)."""
    if getattr(sys, "frozen", False):
        if sys.platform == "darwin":
            # Qua LaunchServices để chỉ có một CHOTTO.app (nhận được Apple Event mở link).
            return ["/usr/bin/open", "-g", "-b", OWN_BUNDLE, "--args", "agent"]
        return [sys.executable, "agent"]
    python = Path(sys.executable)
    pythonw = python.with_name("pythonw.exe")
    return [str(pythonw if pythonw.exists() else python), str(_main_script()), "agent"]


def spawn_agent() -> bool:
    """Khởi động agent tách rời khỏi tiến trình hiện tại; ``False`` nếu không chạy được lệnh."""
    argv = agent_argv()
    try:
        if sys.platform == "win32":
            subprocess.Popen(argv, creationflags=_DETACHED_PROCESS | _CREATE_NEW_PROCESS_GROUP | _CREATE_NO_WINDOW,
                             close_fds=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        else:
            subprocess.Popen(argv, start_new_session=True, close_fds=True, stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError:
        _LOG.exception("Không khởi động được agent")
        return False
    _LOG.info("Đã khởi động agent: %s", argv[0])
    return True


def _launch_agent_plist() -> Path:
    """Đường dẫn LaunchAgent của CHOTTO trên macOS."""
    return Path.home() / "Library" / "LaunchAgents" / f"{_LAUNCH_AGENT_LABEL}.plist"


def enable_autostart() -> None:
    """Cho agent tự chạy khi đăng nhập (Windows: khóa ``Run`` trong HKCU; macOS: LaunchAgent).

    Raises:
        PlatformSetupError: Không ghi được registry/plist.
    """
    argv = agent_argv()
    if sys.platform == "win32":
        import winreg

        try:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, _RUN_KEY) as key:
                winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, subprocess.list2cmdline(argv))
        except OSError as exc:
            raise PlatformSetupError(f"Không ghi được khóa tự khởi động: {exc}") from exc
    elif sys.platform == "darwin":
        path = _launch_agent_plist()
        payload = {"Label": _LAUNCH_AGENT_LABEL, "ProgramArguments": argv, "RunAtLoad": True,
                   "ProcessType": "Interactive"}
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_name(path.name + ".tmp")
            tmp.write_bytes(plistlib.dumps(payload))
            os.replace(tmp, path)
        except OSError as exc:
            raise PlatformSetupError(f"Không ghi được {path}: {exc}") from exc


def disable_autostart() -> None:
    """Gỡ tự khởi động; không có gì để gỡ thì bỏ qua. Không ném lỗi."""
    if sys.platform == "win32":
        import winreg

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, APP_NAME)
        except OSError:
            pass
    elif sys.platform == "darwin":
        try:
            _launch_agent_plist().unlink()
        except FileNotFoundError:
            pass
        except OSError:
            _LOG.warning("Không xóa được LaunchAgent", exc_info=True)


def _is_http_url(url: str) -> bool:
    """Chỉ chuyển tiếp http/https (CHOTTO chỉ đăng ký hai scheme này)."""
    return get_scheme(url) in SUPPORTED_SCHEMES


# ---------------- Windows ----------------
def _reg_read(root: int, path: str, name: str = "", flags: int = 0) -> str | None:
    """Đọc một giá trị chuỗi trong registry; không có thì ``None``."""
    if sys.platform != "win32":
        raise PlatformSetupError("Chức năng chỉ có trên Windows")
    import winreg

    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ | flags) as key:
            value, _ = winreg.QueryValueEx(key, name)
    except OSError:
        return None
    return str(value) if isinstance(value, str) and value else None


def _user_choice_progid(scheme: str = "https") -> str | None:
    """ProgId trình duyệt mặc định hiện tại (ưu tiên ``UserChoiceLatest`` của Windows 11 mới)."""
    if sys.platform != "win32":
        raise PlatformSetupError("Chức năng chỉ có trên Windows")
    import winreg

    base = _URL_ASSOC.format(scheme=scheme)
    for sub in ("UserChoiceLatest", "UserChoice"):
        progid = _reg_read(winreg.HKEY_CURRENT_USER, base + "\\" + sub, "ProgId")
        if progid:
            return progid
    return None


def _progid_command(progid: str) -> str | None:
    """Lệnh ``shell\\open\\command`` của một ProgId (khung nhìn gộp HKCU + HKLM)."""
    if sys.platform != "win32":
        raise PlatformSetupError("Chức năng chỉ có trên Windows")
    import winreg

    return _reg_read(winreg.HKEY_CLASSES_ROOT, progid + r"\shell\open\command")


def _start_menu_clients() -> Iterator[tuple[str, str]]:
    """Các trình duyệt đã đăng ký trong ``StartMenuInternet`` (tên khóa, lệnh mở), trừ CHOTTO."""
    if sys.platform != "win32":
        raise PlatformSetupError("Chức năng chỉ có trên Windows")
    import winreg

    locations = (
        (winreg.HKEY_CURRENT_USER, 0),
        (winreg.HKEY_LOCAL_MACHINE, 0),
        (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY),
    )
    for root, flags in locations:
        try:
            with winreg.OpenKey(root, r"Software\Clients\StartMenuInternet", 0, winreg.KEY_READ | flags) as key:
                index = 0
                while True:
                    try:
                        name = winreg.EnumKey(key, index)
                    except OSError:
                        break
                    index += 1
                    if name.upper() == APP_NAME:
                        continue
                    command = _reg_read(root, rf"Software\Clients\StartMenuInternet\{name}\shell\open\command",
                                        flags=flags)
                    if command:
                        yield name, command
        except OSError:
            continue


def _preference_rank(name: str) -> int:
    """Thứ tự ưu tiên khi phải tự chọn trình duyệt."""
    lowered = name.lower()
    for rank, keyword in enumerate(_BROWSER_PREFERENCE):
        if keyword in lowered:
            return rank
    return len(_BROWSER_PREFERENCE)


def _usable_windows_argv(command: str) -> list[str] | None:
    """Argv mẫu nếu lệnh trỏ tới một file thực thi tồn tại và không phải CHOTTO."""
    args = split_windows_command(command)
    if not args:
        return None
    args[0] = os.path.expandvars(args[0])
    if not os.path.isfile(args[0]) or _is_self(args):
        return None
    return args


def _windows_candidates(cfg: Mapping[str, Any]) -> Iterator[list[str]]:
    """Các argv mẫu của trình duyệt thật theo thứ tự ưu tiên (đã loại CHOTTO)."""
    commands: list[str] = []
    saved_progid = str(cfg.get("browser_progid") or "")
    if saved_progid and saved_progid != PROGID:
        command = _progid_command(saved_progid)
        if command:
            commands.append(command)
    if cfg.get("browser_command"):
        commands.append(str(cfg["browser_command"]))
    current = _user_choice_progid()
    if current and current != PROGID:
        command = _progid_command(current)
        if command:
            commands.append(command)
    clients = sorted(_start_menu_clients(), key=lambda item: _preference_rank(item[0]))
    commands.extend(command for _, command in clients)
    commands.extend(f'"{os.path.expandvars(path)}"' for path in _WIN_FALLBACKS)
    seen: set[str] = set()
    for command in commands:
        argv = _usable_windows_argv(command)
        if argv is None:
            continue
        key = os.path.normcase(argv[0])
        if key in seen and len(argv) == 1:
            continue
        seen.add(key)
        yield argv


def install_windows(cfg: MutableMapping[str, Any]) -> str:
    """Đăng ký CHOTTO trong HKCU và mở trang chọn ứng dụng mặc định.

    Raises:
        PlatformSetupError: Không ghi được registry.
    """
    if sys.platform != "win32":
        raise PlatformSetupError("Chức năng chỉ có trên Windows")
    import winreg

    current = _user_choice_progid()
    if current and current != PROGID:
        cfg["browser_progid"] = current
        command = _progid_command(current)
        if command and _usable_windows_argv(command) is not None:
            cfg["browser_command"] = command
    if not cfg.get("browser_command"):
        first = next(_windows_candidates(cfg), None)
        if first is not None:
            cfg["browser_command"] = subprocess.list2cmdline(first) + ' "%1"'

    hive = winreg.HKEY_CURRENT_USER

    def set_value(path: str, name: str, value: str) -> None:
        with winreg.CreateKey(hive, path) as key:
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)

    icon = f"{sys.executable},0"
    try:
        set_value(rf"Software\Classes\{PROGID}", "", "CHOTTO URL")
        set_value(rf"Software\Classes\{PROGID}", "FriendlyTypeName", "CHOTTO")
        try:
            with winreg.OpenKey(hive, rf"Software\Classes\{PROGID}", 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, "URL Protocol")     # bản cũ biến ProgId thành scheme gọi được từ web
        except OSError:
            pass
        set_value(rf"Software\Classes\{PROGID}\DefaultIcon", "", icon)
        set_value(rf"Software\Classes\{PROGID}\shell\open\command", "", our_command())
        set_value(APP_KEY, "", APP_NAME)
        set_value(APP_KEY + r"\DefaultIcon", "", icon)
        set_value(APP_KEY + r"\shell\open\command", "", our_command().replace(' "%1"', ""))
        set_value(APP_KEY + r"\Capabilities", "ApplicationName", APP_NAME)
        set_value(APP_KEY + r"\Capabilities", "ApplicationDescription", "Khoan đã! Kiểm tra link Zalo trước khi mở")
        set_value(APP_KEY + r"\Capabilities\URLAssociations", "http", PROGID)
        set_value(APP_KEY + r"\Capabilities\URLAssociations", "https", PROGID)
        set_value(r"Software\RegisteredApplications", APP_NAME, APP_KEY + r"\Capabilities")
    except OSError as exc:
        raise PlatformSetupError(f"Không ghi được registry: {exc}") from exc
    for target in (f"ms-settings:defaultapps?registeredAppUser={APP_NAME}", "ms-settings:defaultapps"):
        try:
            os.startfile(target)
            break
        except OSError:
            continue
    if not cfg.get("browser_command"):
        return ("Đã đăng ký CHOTTO nhưng KHÔNG tìm thấy trình duyệt thật để chuyển tiếp. Hãy cài Chrome, Edge, "
                "Cốc Cốc hoặc Firefox rồi bấm cài đặt lại.")
    return ("Đã đăng ký CHOTTO. Windows không cho phần mềm tự đặt mặc định: trong cửa sổ Cài đặt vừa mở, "
            "đặt CHOTTO cho HTTP và HTTPS.")


def uninstall_windows() -> str:
    """Xóa mọi khóa registry CHOTTO đã tạo trong HKCU."""
    if sys.platform != "win32":
        raise PlatformSetupError("Chức năng chỉ có trên Windows")
    import winreg

    hive = winreg.HKEY_CURRENT_USER

    def remove_tree(path: str) -> None:
        try:
            with winreg.OpenKey(hive, path) as key:
                children: list[str] = []
                index = 0
                while True:
                    try:
                        children.append(winreg.EnumKey(key, index))
                    except OSError:
                        break
                    index += 1
        except OSError:
            return
        for child in children:
            remove_tree(path + "\\" + child)
        try:
            winreg.DeleteKey(hive, path)
        except OSError:
            _LOG.warning("Không xóa được khóa registry %s", path)

    remove_tree(rf"Software\Classes\{PROGID}")
    remove_tree(APP_KEY)
    try:
        with winreg.OpenKey(hive, r"Software\RegisteredApplications", 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, APP_NAME)
    except OSError:
        pass
    return "Đã gỡ đăng ký. Hãy chọn lại trình duyệt mặc định trong Cài đặt Windows."


def _open_windows(url: str, cfg: Mapping[str, Any]) -> bool:
    """Mở ``url`` bằng trình duyệt thật đầu tiên khởi chạy được."""
    for template in _windows_candidates(cfg):
        argv = build_browser_argv(template, url)
        try:
            subprocess.Popen(argv, creationflags=_DETACHED_PROCESS | _CREATE_NEW_PROCESS_GROUP, close_fds=True)
        except OSError:
            _LOG.warning("Không khởi chạy được %s, thử trình duyệt kế tiếp", template[0], exc_info=True)
            continue
        return True
    return False


# ---------------- macOS ----------------
def _mac_current_default_bundle() -> str | None:
    """Bundle id trình duyệt mặc định trong LaunchServices (bỏ qua CHOTTO)."""
    path = Path.home() / "Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist"
    try:
        handlers = plistlib.loads(path.read_bytes()).get("LSHandlers", [])
    except (OSError, ValueError, plistlib.InvalidFileException):
        return None
    for scheme in ("https", "http"):
        for handler in handlers:
            if isinstance(handler, dict) and handler.get("LSHandlerURLScheme") == scheme:
                bundle = str(handler.get("LSHandlerRoleAll") or "").lower()
                if bundle and bundle != OWN_BUNDLE:
                    return bundle
    return None


def install_macos(cfg: MutableMapping[str, Any]) -> str:
    """Ghi nhớ trình duyệt thật hiện tại để chuyển tiếp (đăng ký handler do CHOTTO.app đảm nhiệm)."""
    cfg["browser_bundle_id"] = _mac_current_default_bundle() or next(
        (bundle for bundle, path in _MAC_FALLBACKS if os.path.exists(path)), "com.apple.safari"
    )
    return ("macOS cần CHOTTO.app (build bằng packaging/macos_setup.py). Sau khi cài vào /Applications, mở "
            "Cài đặt Hệ thống > Máy tính để bàn & Dock > Trình duyệt web mặc định và chọn CHOTTO.")


def _mac_candidates(cfg: Mapping[str, Any]) -> Iterator[str]:
    """Các bundle id trình duyệt thật theo thứ tự ưu tiên (đã loại CHOTTO)."""
    seen: set[str] = set()
    ordered = [str(cfg.get("browser_bundle_id") or ""), _mac_current_default_bundle() or ""]
    ordered += [bundle for bundle, path in _MAC_FALLBACKS if os.path.exists(path)]
    for bundle in ordered:
        bundle = bundle.lower()
        if bundle and bundle != OWN_BUNDLE and bundle not in seen:
            seen.add(bundle)
            yield bundle


def _open_macos(url: str, cfg: Mapping[str, Any]) -> bool:
    """Mở ``url`` bằng ``open -b <bundle>``; kiểm tra mã thoát, thử bundle kế tiếp nếu lỗi."""
    for bundle in _mac_candidates(cfg):
        try:
            completed = subprocess.run(["open", "-b", bundle, url], capture_output=True, timeout=10, check=False)
        except (OSError, subprocess.SubprocessError):
            _LOG.warning("Không chạy được 'open -b %s'", bundle, exc_info=True)
            continue
        if completed.returncode == 0:
            return True
        _LOG.warning("'open -b %s' trả mã %s", bundle, completed.returncode)
    return False


# ---------------- Linux (ngoài phạm vi chính, chỉ để thử nghiệm) ----------------
def _open_linux(url: str) -> bool:
    """Mở bằng ``xdg-open`` trừ khi CHOTTO đang là trình duyệt mặc định (tránh vòng lặp)."""
    xdg_open = shutil.which("xdg-open")
    if not xdg_open:
        return False
    settings = shutil.which("xdg-settings")
    if settings:
        try:
            current = subprocess.run([settings, "get", "default-web-browser"], capture_output=True, text=True,
                                     timeout=3, check=False).stdout
        except (OSError, subprocess.SubprocessError):
            current = ""
        if "chotto" in current.lower():
            _LOG.error("CHOTTO đang là trình duyệt mặc định trên Linux, không thể chuyển tiếp an toàn")
            return False
    try:
        subprocess.Popen([xdg_open, url], close_fds=True)
    except OSError:
        _LOG.exception("xdg-open lỗi")
        return False
    return True


# ---------------- API công khai ----------------
def install(cfg: MutableMapping[str, Any]) -> str:
    """Đăng ký CHOTTO theo nền tảng, bật tự khởi động agent và khởi động agent ngay.

    ``cfg`` được cập nhật với trình duyệt thật cần chuyển tiếp (người gọi lưu lại).

    Raises:
        PlatformSetupError: Không đăng ký được.
    """
    if sys.platform not in ("win32", "darwin"):
        return "Chỉ hỗ trợ Windows và macOS."
    message = install_windows(cfg) if sys.platform == "win32" else install_macos(cfg)
    if cfg.get("agent_enabled", True):
        try:
            enable_autostart()
        except PlatformSetupError:
            _LOG.exception("Không bật được tự khởi động")
            return message + " (Không bật được chạy nền cùng hệ thống; CHOTTO vẫn hoạt động nhưng chậm hơn.)"
        spawn_agent()
    return message


def uninstall() -> str:
    """Gỡ đăng ký CHOTTO theo nền tảng."""
    disable_autostart()
    if sys.platform == "win32":
        return uninstall_windows()
    return "Xóa CHOTTO.app và chọn lại trình duyệt mặc định."


def open_in_real_browser(url: str, cfg: Mapping[str, Any]) -> bool:
    """Chuyển ``url`` cho trình duyệt thật, không bao giờ gọi lại CHOTTO.

    Args:
        url: URL http/https đã chuẩn hóa (``Result.open_url``).
        cfg: Cấu hình chứa trình duyệt đã lưu lúc cài đặt.

    Returns:
        ``True`` nếu đã khởi chạy trình duyệt; ``False`` nếu không có trình duyệt dùng được hoặc URL
        không phải http/https (người gọi phải báo cho người dùng).
    """
    if not _is_http_url(url):
        _LOG.error("Từ chối chuyển tiếp URL không phải http/https")
        return False
    if sys.platform == "win32":
        return _open_windows(url, cfg)
    if sys.platform == "darwin":
        return _open_macos(url, cfg)
    return _open_linux(url)
