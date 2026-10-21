"""Vòng đời giao diện: chế độ một tiến trình (dự phòng) và agent thường trú.

- ``run_once``: xử lý một link rồi thoát, hoặc mở cửa sổ cài đặt (như bản 1.0). Dùng khi agent chưa
  chạy hoặc bị tắt trong cấu hình.
- ``run_resident``: agent thường trú. Giữ engine trong RAM, nhận link qua IPC (Windows) hoặc Apple Event
  (macOS), hiển thị lần lượt từng màn hình đệm, tự nạp lại cấu hình khi file thay đổi và tự cập nhật
  danh sách đen mỗi ngày trên luồng nền.
"""
from __future__ import annotations

import collections
import logging
import os
import sys
import threading
from collections.abc import Callable
from concurrent.futures import Future
from typing import TYPE_CHECKING, Any, Final

from .. import logdb, platform_setup
from ..caller import Caller, detect_caller
from ..config import Config, data_dir, load_config, load_rules, save_config
from ..engine import Engine, Result
from ..tier1 import BlacklistError, update_due, update_from_sources
from . import agent as agent_mod
from . import ipc
from .handler import LinkHandler, SecondsFor

if TYPE_CHECKING:
    import tkinter as tk

    from ..ui import SettingsActions

__all__ = ["AutoUpdater", "build_handler", "run_once", "run_resident"]

_LOG = logging.getLogger("chotto")

_MAC_EVENT_WAIT_MS: Final[int] = 2500
_POLL_MS: Final[int] = 50
_AUTO_UPDATE_FIRST_MS: Final[int] = 2 * 60 * 1000       # để máy khởi động xong rồi mới tải
_AUTO_UPDATE_EVERY_MS: Final[int] = 15 * 60 * 1000
_SETTINGS_KEYS: Final[tuple[str, ...]] = (
    "tier3_enabled", "ai_advice", "log_decisions", "unknown_caller_policy", "friction_seconds",
)


def _record_desktop(cfg: Config) -> Callable[[Result, str, int], bool]:
    """Hàm ghi nhật ký cho Desktop theo cấu hình lưu giữ."""
    def record(result: Result, decision: str, dwell_ms: int) -> bool:
        return logdb.record(result, decision, dwell_ms, "desktop", cfg["log_retention_days"])

    return record


def save_settings(values: dict[str, Any]) -> None:
    """Lưu các khóa của cửa sổ cài đặt lên cấu hình mới nhất trên đĩa (không ghi đè trình duyệt đã lưu).

    Raises:
        OSError: Không ghi được ``config.json``.
    """
    current: dict[str, Any] = dict(load_config())
    current.update({key: values[key] for key in _SETTINGS_KEYS if key in values})
    save_config(current)


def install_action() -> str:
    """Tác vụ cài đặt từ cửa sổ cài đặt.

    Raises:
        PlatformSetupError: Không đăng ký được.
        OSError: Không lưu được cấu hình.
    """
    cfg: dict[str, Any] = dict(load_config())
    message = platform_setup.install(cfg)
    save_config(cfg)
    return message


def uninstall_action() -> str:
    """Tác vụ gỡ đăng ký: gỡ handler, tắt tự khởi động và tắt agent đang chạy."""
    message = platform_setup.uninstall()
    agent_mod.stop_agent()
    return message


def update_action() -> str:
    """Tác vụ cập nhật danh sách đen từ cửa sổ cài đặt."""
    count = update_from_sources(load_rules(), log=lambda line: _LOG.info("%s", line))
    if count == 0:
        return ("Không có dữ liệu mới (các nguồn không đổi hoặc không tải được); danh sách hiện tại vẫn được giữ. "
                "Xem chotto.log để biết chi tiết.")
    return f"Đã nạp {count} mục vào danh sách đen."


def export_action(path: str) -> str:
    """Tác vụ xuất nhật ký từ cửa sổ cài đặt."""
    return f"Đã xuất {logdb.export_csv(path)} dòng ra {path}."


def build_handler(cfg: Config, root: tk.Tk | None) -> LinkHandler:
    """Dựng ``LinkHandler`` dùng giao diện Tk thật (hoặc hộp thoại hệ thống nếu không có Tk)."""
    from .. import ui

    def present(result: Result, seconds_for: SecondsFor, pending: Future[Result] | None) -> tuple[bool, int, Result]:
        if root is None:
            raise RuntimeError("Không có giao diện Tk")
        return ui.show_friction(root, result, seconds_for, pending)

    return LinkHandler(
        cfg=cfg,
        engine_factory=lambda: Engine(cfg),
        present=present,
        open_url=lambda target: platform_setup.open_in_real_browser(target, cfg),
        alert=lambda message: ui.native_alert("CHOTTO", message),
        record=_record_desktop(cfg),
    )


def _settings_actions() -> SettingsActions:
    """Các tác vụ nút bấm của cửa sổ cài đặt."""
    from .. import ui

    return ui.SettingsActions(install=install_action, uninstall=uninstall_action,
                              update_blacklist=update_action, export_log=export_action)


def _create_root() -> tk.Tk | None:
    """Tạo cửa sổ gốc Tk ẩn; ``None`` nếu máy không có Tk/không có màn hình."""
    try:
        import tkinter as tk

        created = tk.Tk()
        created.withdraw()
        return created
    except Exception:  # noqa: BLE001 - không có Tk: vẫn xử lý link với chính sách fail-safe
        _LOG.exception("Không khởi tạo được Tk")
        return None


def run_once(url: str | None = None, force: bool = False, gui: bool = False, caller: Caller | None = None) -> int:
    """Chế độ một tiến trình: xử lý ``url`` (và link đến thêm qua Apple Event) rồi thoát, hoặc mở cài đặt.

    Args:
        url: Link nhận qua argv; ``None`` để mở cửa sổ cài đặt.
        force: Bỏ qua bước nhận diện Zalo.
        gui: macOS: mở cài đặt ngay thay vì chờ Apple Event.
        caller: Nguồn gọi đã đo sẵn (launcher đo trước khi thử gửi cho agent).

    Returns:
        Mã thoát tiến trình.
    """
    from .. import ui

    ui.enable_dpi_awareness()
    cfg = load_config()
    if url and not force and caller is None:
        caller = detect_caller(cfg)        # phải đo TRƯỚC khi tạo cửa sổ
    root = _create_root()
    handler = build_handler(cfg, root)

    if root is None:
        if url:
            handler.handle(url, caller, force)
            return 0
        ui.native_alert("CHOTTO", "Không mở được giao diện CHOTTO (thiếu Tk).")
        return 1
    window: tk.Tk = root

    pending: collections.deque[tuple[str, Caller | None]] = collections.deque()
    state = {"busy": False, "settings": False, "handled": False}

    def drain() -> None:
        if state["busy"]:
            return
        state["busy"] = True
        try:
            while pending:
                link, link_caller = pending.popleft()
                handler.handle(link, link_caller, force)
        finally:
            state["busy"] = False
        if not state["settings"] and window.winfo_exists():
            window.destroy()

    def on_url(link: str, link_caller: Caller | None = None) -> None:
        state["handled"] = True
        if link_caller is None and not force:
            link_caller = detect_caller(cfg)
        pending.append((link, link_caller))
        window.after(0, drain)

    def open_settings() -> None:
        state["settings"] = True
        ui.show_settings(window, cfg, save_settings, _settings_actions())

    if sys.platform == "darwin":
        window.createcommand("::tk::mac::LaunchURL", lambda link: on_url(str(link)))   # Apple Event kAEGetURL

    if url:
        window.after(10, lambda: on_url(url, caller))
    elif sys.platform == "darwin" and not gui:
        window.after(_MAC_EVENT_WAIT_MS, lambda: None if state["handled"] else open_settings())
    else:
        open_settings()
    window.mainloop()
    return 0


class AutoUpdater:
    """Tự cập nhật danh sách đen trên luồng nền khi đến hạn (mỗi ngày; thử lại sau 1 giờ nếu lỗi).

    Engine đang chạy tự thấy danh sách mới ở lần tra sau (file dấu vân tay đổi), không cần khởi động lại.
    """

    def __init__(self, enabled: Callable[[], bool], due: Callable[[], bool] = update_due,
                 run: Callable[[], int] | None = None) -> None:
        """Tạo bộ tự cập nhật.

        Args:
            enabled: Đọc cấu hình ``auto_update`` hiện hành.
            due: Đã đến hạn cập nhật chưa.
            run: Hàm cập nhật (mặc định: ``update_from_sources`` với bộ luật đóng gói).
        """
        self._enabled = enabled
        self._due = due
        self._run = run or (lambda: update_from_sources(load_rules(), log=lambda line: _LOG.info("%s", line)))
        self._thread: threading.Thread | None = None

    def _work(self) -> None:
        """Thân luồng nền: không bao giờ để lỗi thoát ra ngoài."""
        try:
            count = self._run()
            _LOG.info("Tự cập nhật danh sách đen: %s", f"{count} mục" if count else "không thay đổi")
        except BlacklistError:
            _LOG.exception("Tự cập nhật danh sách đen thất bại")
        except Exception:  # noqa: BLE001 - luồng nền của agent không được chết im lặng
            _LOG.exception("Lỗi không lường trước khi tự cập nhật danh sách đen")

    def tick(self) -> bool:
        """Kiểm tra và khởi chạy cập nhật nếu cần; ``True`` nếu vừa khởi chạy."""
        if self._thread is not None and self._thread.is_alive():
            return False
        try:
            if not self._enabled() or not self._due():
                return False
        except Exception:  # noqa: BLE001 - đọc cấu hình/trạng thái lỗi: bỏ qua lượt này
            _LOG.exception("Không kiểm tra được lịch tự cập nhật")
            return False
        self._thread = threading.Thread(target=self._work, name="chotto-auto-update", daemon=True)
        self._thread.start()
        return True

    def join(self, timeout: float | None = None) -> None:
        """Chờ lượt cập nhật đang chạy (dùng trong kiểm thử)."""
        if self._thread is not None:
            self._thread.join(timeout)


class _HandlerCache:
    """Giữ ``LinkHandler`` (và engine trong RAM); dựng lại khi ``config.json`` thay đổi."""

    def __init__(self, root: tk.Tk) -> None:
        """Tạo bộ đệm cho cửa sổ gốc ``root``."""
        self._root = root
        self._stamp: tuple[int, int] | None = None
        self._handler: LinkHandler | None = None

    @staticmethod
    def _config_stamp() -> tuple[int, int] | None:
        """(mtime_ns, kích thước) của ``config.json`` hoặc ``None`` nếu chưa có."""
        try:
            info = os.stat(data_dir() / "config.json")
        except OSError:
            return None
        return info.st_mtime_ns, info.st_size

    def get(self) -> LinkHandler:
        """Handler hiện hành (nạp lại cấu hình nếu file đã đổi)."""
        stamp = self._config_stamp()
        if self._handler is None or stamp != self._stamp:
            if self._handler is not None:
                _LOG.info("config.json thay đổi, nạp lại cấu hình")
            self._stamp = stamp
            self._handler = build_handler(load_config(), self._root)
        return self._handler

    @property
    def cfg(self) -> Config:
        """Cấu hình hiện hành."""
        return self.get().cfg


def run_resident(open_settings_after_ms: int | None = None, show_settings_now: bool = False) -> int:
    """Agent thường trú: chạy đến khi nhận lệnh tắt.

    Args:
        open_settings_after_ms: macOS: mở cửa sổ cài đặt nếu sau ngần ấy mili-giây chưa có link nào
            (người dùng tự mở CHOTTO.app). ``None`` để không tự mở.
        show_settings_now: Mở cửa sổ cài đặt ngay khi khởi động.

    Returns:
        Mã thoát: 0 khi tắt bình thường hoặc đã có agent khác, 1 khi không chạy được.
    """
    from .. import ui

    ui.enable_dpi_awareness()
    root = _create_root()
    if root is None:
        return 1
    window: tk.Tk = root
    core = agent_mod.AgentCore()
    server: ipc.IPCServer | None = None
    try:
        candidate = ipc.IPCServer(core.handle)
        candidate.start()
        server = candidate
    except ipc.AgentAlreadyRunning:
        _LOG.info("Đã có agent khác đang chạy, thoát")
        window.destroy()
        return 0
    except ipc.IPCError:
        _LOG.exception("Không mở được kênh IPC")
        if sys.platform != "darwin":       # Windows không có kênh nào khác để nhận link: vô dụng nếu chạy tiếp
            window.destroy()
            return 1

    handlers = _HandlerCache(window)
    state: dict[str, Any] = {"busy": False, "handled": False, "settings": None}

    def drain() -> None:
        if core.quit_requested.is_set() and not state["busy"]:
            shutdown()         # không bao giờ đóng ngang màn hình đệm người dùng đang cân nhắc
            return
        if not state["busy"]:
            state["busy"] = True
            try:
                while not core.links.empty() and not core.quit_requested.is_set():
                    request = core.links.get_nowait()
                    state["handled"] = True
                    handlers.get().handle(request.url, request.caller, request.force)
            except Exception:  # noqa: BLE001 - agent không bao giờ được chết vì một link
                _LOG.exception("Agent xử lý link lỗi")
            finally:
                state["busy"] = False
        if window.winfo_exists():
            window.after(_POLL_MS, drain)

    def shutdown() -> None:
        if server is not None:
            server.stop()
        if window.winfo_exists():
            window.destroy()

    def open_settings() -> None:
        existing = state["settings"]
        if existing is not None and existing.winfo_exists():
            existing.deiconify()
            existing.lift()
            return
        import tkinter as tk

        top = tk.Toplevel(window)
        state["settings"] = top
        ui.show_settings(top, handlers.cfg, save_settings, _settings_actions(), on_close=top.destroy)

    if sys.platform == "darwin":
        def on_url(link: object) -> None:
            caller = detect_caller(handlers.cfg)
            core.submit(agent_mod.LinkRequest(str(link), caller, False))

        window.createcommand("::tk::mac::LaunchURL", on_url)                 # Apple Event kAEGetURL
        window.createcommand("::tk::mac::ReopenApplication", open_settings)  # người dùng mở lại CHOTTO.app
        window.createcommand("::tk::mac::Quit", shutdown)

    updater = AutoUpdater(enabled=lambda: handlers.cfg["auto_update"])

    def auto_update() -> None:
        updater.tick()
        if window.winfo_exists():
            window.after(_AUTO_UPDATE_EVERY_MS, auto_update)

    window.after(_AUTO_UPDATE_FIRST_MS, auto_update)
    if show_settings_now:
        window.after(0, open_settings)
    elif open_settings_after_ms is not None:
        window.after(open_settings_after_ms, lambda: None if state["handled"] else open_settings())
    window.after(0, drain)
    _LOG.info("Agent sẵn sàng (pid %s)", os.getpid())
    try:
        window.mainloop()
    finally:
        if server is not None:
            server.stop()
    return 0
