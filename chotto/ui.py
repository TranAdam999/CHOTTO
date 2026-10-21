"""Giao diện Tkinter Dark Mode: màn hình đệm "Độ trễ có chủ ý" + cửa sổ cài đặt.

Nguyên tắc:
- Nút "vẫn mở" là ``Label`` (không nhận Enter/Space) nên không thể bấm theo phản xạ bằng bàn phím.
- Đếm ngược theo ``time.monotonic`` (không trôi khi luồng UI bận).
- Mọi chuỗi lấy từ URL đều được lọc ký tự điều khiển/đảo chiều trước khi hiển thị, và tên miền
  thật được hiển thị tách riêng để không bị che bởi subdomain dài.
- Tác vụ chậm (cập nhật danh sách đen, cài đặt) chạy trên luồng nền; luồng UI không bao giờ bị treo.
"""
from __future__ import annotations

import logging
import math
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
from collections.abc import Callable, Mapping
from concurrent.futures import Future
from dataclasses import dataclass
from tkinter import filedialog, messagebox
from tkinter import font as tkfont
from typing import TYPE_CHECKING, Any, Final

from .core.url import domain_to_unicode
from .util import sanitize_for_display

if TYPE_CHECKING:
    from .engine import Result

__all__ = [
    "SettingsActions",
    "enable_dpi_awareness",
    "middle_truncate",
    "native_alert",
    "show_friction",
    "show_settings",
    "tier_text",
]

_LOG = logging.getLogger(__name__)

BG: Final[str] = "#14161c"
PANEL: Final[str] = "#1d2029"
FG: Final[str] = "#e8eaf0"
MUTED: Final[str] = "#8b90a0"
DISABLED_BG: Final[str] = "#3a3e4b"
DISABLED_FG: Final[str] = "#7a7f90"
ADVICE_FG: Final[str] = "#d6d9e2"
COLORS: Final[dict[str, str]] = {"WARN": "#f5a623", "HIGH": "#ff4d4f", "BLOCKED": "#ff4d4f", "SAFE": "#3ecf8e"}
TITLES: Final[dict[str, str]] = {
    "WARN": "Khoan đã! Liên kết này đáng ngờ",
    "HIGH": "Khoan đã! Liên kết này rất nguy hiểm",
    "BLOCKED": "Đã chặn! Liên kết nằm trong danh sách lừa đảo",
}
UNPARSEABLE_TITLE: Final[str] = "Khoan đã! CHOTTO không đọc được liên kết này"
_WRAP: Final[int] = 470
_URL_DISPLAY_LIMIT: Final[int] = 120
_TICK_MS: Final[int] = 200
_POLL_MS: Final[int] = 100
_OWN_BUNDLE: Final[str] = "vn.chotto.app"
_DWMWA_DARK_MODE_OLD: Final[int] = 19
_DWMWA_DARK_MODE: Final[int] = 20
_DWMWA_CAPTION_COLOR: Final[int] = 35
CHECKING_TEXT: Final[str] = "Đang xác minh tuổi tên miền…"


def enable_dpi_awareness() -> None:
    """Bật DPI awareness trên Windows (chữ sắc nét ở màn hình 125–200%); nền tảng khác bỏ qua."""
    if sys.platform != "win32":
        return
    import ctypes

    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except (AttributeError, OSError):
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except (AttributeError, OSError):
            _LOG.info("Không bật được DPI awareness")


def native_alert(title: str, message: str) -> None:
    """Hộp thoại thông báo không cần Tk (dùng khi Tk hỏng); lỗi chỉ được ghi log."""
    try:
        if sys.platform == "win32":
            import ctypes

            mb_iconwarning, mb_topmost, mb_setforeground = 0x30, 0x40000, 0x10000
            ctypes.windll.user32.MessageBoxW(None, message, title, mb_iconwarning | mb_topmost | mb_setforeground)
        elif sys.platform == "darwin":
            script = f"display alert {_applescript_str(title)} message {_applescript_str(message)} as critical"
            subprocess.run(["osascript", "-e", script], capture_output=True, timeout=120, check=False)
        else:
            _LOG.error("%s: %s", title, message)
    except (OSError, AttributeError, subprocess.SubprocessError):
        _LOG.exception("Không hiển thị được thông báo hệ thống")


def _applescript_str(text: str) -> str:
    """Chuỗi AppleScript an toàn (escape ``\\`` và ``"``)."""
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def middle_truncate(text: str, limit: int) -> str:
    """Cắt giữa chuỗi dài (giữ đầu và cuối) để phần tên miền cuối không bị che."""
    if len(text) <= limit:
        return text
    head = (limit - 1) * 2 // 3
    tail = limit - 1 - head
    return text[:head] + "…" + text[-tail:]


def _pick_family(root: tk.Misc, preferred: tuple[str, ...], fallback: str) -> str:
    """Chọn font đầu tiên có trên máy."""
    try:
        available = set(tkfont.families(root))
    except tk.TclError:
        return fallback
    return next((family for family in preferred if family in available), fallback)


def _fonts(root: tk.Misc) -> tuple[str, str]:
    """(font giao diện, font đơn cách) phù hợp nền tảng và hiển thị đủ dấu tiếng Việt."""
    if sys.platform == "win32":
        return _pick_family(root, ("Segoe UI",), "TkDefaultFont"), _pick_family(root, ("Consolas",), "TkFixedFont")
    if sys.platform == "darwin":
        return (_pick_family(root, ("Helvetica Neue", "Helvetica"), "TkDefaultFont"),
                _pick_family(root, ("Menlo", "Monaco"), "TkFixedFont"))
    return (_pick_family(root, ("Noto Sans", "DejaVu Sans"), "TkDefaultFont"),
            _pick_family(root, ("Noto Sans Mono", "DejaVu Sans Mono"), "TkFixedFont"))


def _bring_to_front(window: tk.Toplevel | tk.Tk) -> None:
    """Đưa cửa sổ lên trên cùng và lấy focus (macOS: kích hoạt ứng dụng LSUIElement)."""
    window.lift()
    window.attributes("-topmost", True)
    window.focus_force()
    if sys.platform == "darwin" and getattr(sys, "frozen", False):
        try:
            subprocess.Popen(["osascript", "-e", f'tell application id "{_OWN_BUNDLE}" to activate'],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            _LOG.info("Không kích hoạt được ứng dụng trên macOS")


class FlatButton(tk.Label):
    """Label đóng vai nút (``tk.Button`` bỏ qua màu nền trên macOS; Label không nhận Enter/Space)."""

    def __init__(self, master: tk.Misc, text: str, command: Callable[[], None], bg: str, font: tuple[str, int, str],
                 fg: str = "#101010") -> None:
        """Tạo nút phẳng; ``command`` chỉ chạy khi nút đang bật và được bấm bằng chuột."""
        super().__init__(master, text=text, bg=bg, fg=fg, padx=18, pady=10, font=font, cursor="hand2")
        self._command = command
        self._bg = bg
        self._fg = fg
        self._enabled = True
        self.bind("<ButtonRelease-1>", self._on_click)

    def _on_click(self, _event: tk.Event[Any]) -> None:
        if self._enabled:
            self._command()

    def set_enabled(self, enabled: bool, text: str | None = None) -> None:
        """Bật/tắt nút và tùy chọn đổi chữ."""
        self._enabled = enabled
        self.config(bg=self._bg if enabled else DISABLED_BG, fg=self._fg if enabled else DISABLED_FG,
                    cursor="hand2" if enabled else "arrow")
        if text is not None:
            self.config(text=text)


def tier_text(result: Result) -> str:
    """Mô tả tầng đã phát hiện rủi ro."""
    tier = result.tier_reached
    if tier == 0:
        return "Không phân tích được liên kết"
    if tier == 1:
        return "Tầng 1 – Danh sách đen lừa đảo"
    if tier == 3 and result.domain_age_days is not None:
        return "Tầng 3 – Tuổi tên miền (sau khi chấm điểm ở Tầng 2)"
    if tier == 3:
        return "Tầng 2 – Phân tích tên miền (Tầng 3 đã thử nhưng không tra được)"
    return "Tầng 2 – Phân tích tên miền"


def _domain_line(result: Result) -> str:
    """Dòng "Trang sẽ mở" với tên miền thật; IDN hiển thị cả dạng Unicode và punycode."""
    domain = result.display_domain or result.host
    if not domain:
        return "Trang sẽ mở: (không xác định)"
    readable = domain_to_unicode(domain)
    if readable != domain:
        return f"Trang sẽ mở: {sanitize_for_display(readable)}  ({domain})"
    return f"Trang sẽ mở: {domain}"


def _set_dark_title_bar(window: tk.Toplevel | tk.Tk) -> None:
    """Thanh tiêu đề tối trên Windows 10 (1809+) và 11 cho hợp với nền tối; nền tảng khác bỏ qua.

    Không bao giờ ném lỗi: Windows cũ không hỗ trợ thì giữ thanh tiêu đề mặc định.
    """
    if sys.platform != "win32":
        return
    import ctypes
    from ctypes import wintypes

    try:
        window.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(window.winfo_id()) or window.winfo_id()
        set_attribute = ctypes.windll.dwmapi.DwmSetWindowAttribute
        set_attribute.argtypes = [wintypes.HWND, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]
        set_attribute.restype = ctypes.c_long
        enabled = ctypes.c_int(1)
        # 20 = DWMWA_USE_IMMERSIVE_DARK_MODE (Windows 10 20H1+), 19 = cùng thuộc tính trên 1809–1909.
        for attribute in (_DWMWA_DARK_MODE, _DWMWA_DARK_MODE_OLD):
            if set_attribute(hwnd, attribute, ctypes.byref(enabled), ctypes.sizeof(enabled)) == 0:
                break
        red, green, blue = (int(BG[i:i + 2], 16) for i in (1, 3, 5))
        caption = wintypes.DWORD(red | green << 8 | blue << 16)      # COLORREF 0x00BBGGRR
        set_attribute(hwnd, _DWMWA_CAPTION_COLOR, ctypes.byref(caption), ctypes.sizeof(caption))  # Windows 11
        # Ép Windows vẽ lại khung cửa sổ ngay (nếu không, thanh tiêu đề chỉ đổi màu sau khi mất/nhận focus).
        swp_flags = 0x0001 | 0x0002 | 0x0004 | 0x0020          # NOSIZE | NOMOVE | NOZORDER | FRAMECHANGED
        ctypes.windll.user32.SetWindowPos(hwnd, None, 0, 0, 0, 0, swp_flags)
    except (AttributeError, OSError, tk.TclError):
        _LOG.info("Không đặt được thanh tiêu đề tối", exc_info=True)


@dataclass
class _FrictionView:
    """Các widget của màn hình đệm cần cập nhật khi Tầng 3 trả kết quả."""

    accent_bar: tk.Frame
    title: tk.Label
    bar: tk.Canvas
    bar_fill: int
    score: tk.Label
    tier: tk.Label
    reasons: tk.Frame
    advice_box: tk.Frame
    advice_text: tk.Label
    advice_title: tk.Label
    ui_font: str

    def render(self, result: Result, checking: bool) -> None:
        """Hiển thị ``result``; ``checking`` = Tầng 3 đang chạy nền."""
        accent = COLORS.get(result.level, COLORS["WARN"])
        self.accent_bar.config(bg=accent)
        title = UNPARSEABLE_TITLE if result.tier_reached == 0 else TITLES.get(result.level, TITLES["WARN"])
        self.title.config(text=title, fg=accent)
        self.bar.coords(self.bar_fill, 0, 0, _WRAP * max(0, min(100, result.score)) / 100, 8)
        self.bar.itemconfigure(self.bar_fill, fill=accent)
        self.score.config(text=f"Điểm rủi ro: {result.score}/100")
        self.tier.config(text=CHECKING_TEXT if checking else "Phát hiện ở: " + tier_text(result))
        for child in self.reasons.winfo_children():
            child.destroy()
        for reason in result.reasons[:4]:
            row = tk.Frame(self.reasons, bg=BG)
            row.pack(fill="x", pady=1)
            tk.Label(row, text="•", bg=BG, fg=FG, font=(self.ui_font, 11)).pack(side="left", anchor="n", padx=(0, 8))
            tk.Label(row, text=sanitize_for_display(reason), bg=BG, fg=FG, font=(self.ui_font, 11),
                     wraplength=_WRAP - 20, justify="left", anchor="w").pack(side="left", fill="x")
        if result.advice and not checking:
            self.advice_title.config(fg=accent)
            self.advice_text.config(text=result.advice)
            self.advice_box.pack(fill="x", pady=(12, 0))
        else:
            self.advice_box.pack_forget()


def show_friction(root: tk.Tk, result: Result, seconds_for: Callable[[str], int],
                  pending: Future[Result] | None = None) -> tuple[bool, int, Result]:
    """Hiển thị màn hình đệm và chờ người dùng quyết định.

    Args:
        root: Cửa sổ gốc Tk (có thể đang ẩn).
        result: Kết quả thẩm định (sơ bộ nếu ``pending`` khác ``None``).
        seconds_for: Thời gian khóa nút "vẫn mở" theo mức rủi ro.
        pending: Kết quả cuối của Tầng 3 đang chạy nền. Khi xong, màn hình được cập nhật tại chỗ;
            nếu mức rủi ro tăng, thời gian khóa được kéo dài tính từ lúc mở cửa sổ.

    Returns:
        (người dùng chọn mở, thời gian cân nhắc tính bằng ms, kết quả đang hiển thị lúc quyết định).

    Raises:
        tk.TclError: Không dựng được cửa sổ (người gọi phải xử lý theo chính sách fail-safe).
    """
    ui_font, mono_font = _fonts(root)
    top = tk.Toplevel(root)
    top.title("CHOTTO")
    top.configure(bg=BG)
    top.resizable(False, False)
    state: dict[str, Any] = {"open": False, "result": result, "pending": pending}
    started = time.monotonic()
    unlock = {"at": started + max(0, seconds_for(result.level))}

    accent_bar = tk.Frame(top, bg=BG, height=6)
    accent_bar.pack(fill="x")
    body = tk.Frame(top, bg=BG, padx=24, pady=18)
    body.pack(fill="both")
    title = tk.Label(body, text="", bg=BG, font=(ui_font, 15, "bold"), anchor="w")
    title.pack(fill="x")

    tk.Label(body, text=_domain_line(result), bg=BG, fg=FG, font=(ui_font, 12, "bold"), anchor="w",
             wraplength=_WRAP, justify="left").pack(fill="x", pady=(10, 0))
    box = tk.Frame(body, bg=PANEL, padx=12, pady=10)
    box.pack(fill="x", pady=(8, 8))
    shown_url = middle_truncate(sanitize_for_display(result.final_url), _URL_DISPLAY_LIMIT)
    tk.Label(box, text=shown_url, bg=PANEL, fg=FG, font=(mono_font, 10), wraplength=_WRAP, justify="left",
             anchor="w").pack(fill="x")

    bar = tk.Canvas(body, width=_WRAP, height=8, bg=PANEL, highlightthickness=0)
    bar.pack(pady=(0, 4))
    bar_fill = bar.create_rectangle(0, 0, 0, 8, fill=BG, width=0)
    score = tk.Label(body, text="", bg=BG, fg=MUTED, font=(ui_font, 9), anchor="w")
    score.pack(fill="x")
    tier = tk.Label(body, text="", bg=BG, fg=MUTED, font=(ui_font, 9), anchor="w")
    tier.pack(fill="x")

    tk.Label(body, text="Vì sao CHOTTO cảnh báo:", bg=BG, fg=FG, font=(ui_font, 11, "bold"),
             anchor="w").pack(fill="x", pady=(12, 4))
    reasons = tk.Frame(body, bg=BG)
    reasons.pack(fill="x")

    # Lời khuyên: chữ thường cỡ 11, màu sáng trên nền panel, có tiêu đề màu nhấn để dễ đọc với người lớn tuổi.
    advice_slot = tk.Frame(body, bg=BG)          # giữ chỗ cố định: hộp lời khuyên hiện/ẩn mà không đổi thứ tự
    advice_slot.pack(fill="x")
    advice_box = tk.Frame(advice_slot, bg=PANEL, padx=14, pady=12)
    advice_title = tk.Label(advice_box, text="Lời khuyên (AI chạy cục bộ)", bg=PANEL, font=(ui_font, 11, "bold"),
                            anchor="w")
    advice_title.pack(fill="x")
    advice_text = tk.Label(advice_box, text="", bg=PANEL, fg=ADVICE_FG, font=(ui_font, 11), wraplength=_WRAP - 28,
                           justify="left", anchor="w")
    advice_text.pack(fill="x", pady=(4, 0))

    buttons = tk.Frame(body, bg=BG)
    buttons.pack(fill="x", pady=(18, 0))

    view = _FrictionView(accent_bar, title, bar, bar_fill, score, tier, reasons, advice_box, advice_text,
                         advice_title, ui_font)
    view.render(result, checking=pending is not None)

    def finish(open_it: bool) -> None:
        state["open"] = open_it
        if top.winfo_exists():
            top.destroy()

    button_font = (ui_font, 11, "bold")
    FlatButton(buttons, "Đóng, không mở", lambda: finish(False), "#3ecf8e", button_font).pack(side="left")
    proceed = FlatButton(buttons, "", lambda: finish(True), "#d0d3dc", button_font)
    proceed.pack(side="right")

    def check_pending() -> None:
        future: Future[Result] | None = state["pending"]
        if future is None or not future.done():
            return
        state["pending"] = None
        try:
            final = future.result()
        except Exception:  # noqa: BLE001 - Tầng 3 lỗi: giữ nguyên kết quả đang hiển thị
            _LOG.exception("Tầng 3 nền lỗi, giữ kết quả sơ bộ")
            view.render(state["result"], checking=False)
            return
        state["result"] = final
        unlock["at"] = max(unlock["at"], started + max(0, seconds_for(final.level)))
        view.render(final, checking=False)

    def tick() -> None:
        if not top.winfo_exists():
            return
        check_pending()
        remaining = unlock["at"] - time.monotonic()
        if remaining > 0:
            proceed.set_enabled(False, f"Tôi hiểu rủi ro, vẫn mở ({math.ceil(remaining)})")
        else:
            proceed.set_enabled(True, "Tôi hiểu rủi ro, vẫn mở")
        if remaining > 0 or state["pending"] is not None:
            top.after(_TICK_MS, tick)

    tick()
    top.protocol("WM_DELETE_WINDOW", lambda: finish(False))
    top.bind("<Escape>", lambda _e: finish(False))
    top.update_idletasks()
    width, height = top.winfo_reqwidth(), top.winfo_reqheight()
    top.geometry(f"+{(top.winfo_screenwidth() - width) // 2}+{(top.winfo_screenheight() - height) // 3}")
    _set_dark_title_bar(top)
    _bring_to_front(top)
    root.wait_window(top)
    return bool(state["open"]), int((time.monotonic() - started) * 1000), state["result"]


@dataclass(frozen=True)
class SettingsActions:
    """Các tác vụ của cửa sổ cài đặt; mỗi hàm trả về thông báo tiếng Việt và có thể ném lỗi."""

    install: Callable[[], str]
    uninstall: Callable[[], str]
    update_blacklist: Callable[[], str]
    export_log: Callable[[str], str]


def show_settings(root: tk.Tk | tk.Toplevel, cfg: Mapping[str, Any], on_save: Callable[[dict[str, Any]], None],
                  actions: SettingsActions, on_close: Callable[[], None] | None = None) -> None:
    """Dựng cửa sổ cài đặt trên ``root``.

    Args:
        root: Cửa sổ chứa giao diện cài đặt (cửa sổ gốc ẩn hoặc một ``Toplevel``), sẽ được hiện ra.
        cfg: Cấu hình hiện tại.
        on_save: Hàm lưu cấu hình (nhận dict đầy đủ); có thể ném ``OSError``.
        actions: Các tác vụ nút bấm, chạy trên luồng nền.
        on_close: Gọi khi người dùng đóng cửa sổ; mặc định hủy ``root`` (thoát chương trình).
    """
    ui_font, _ = _fonts(root)
    working = dict(cfg)
    root.deiconify()
    root.title("CHOTTO – Cài đặt")
    root.configure(bg=BG)
    root.protocol("WM_DELETE_WINDOW", on_close or root.destroy)
    frame = tk.Frame(root, bg=BG, padx=24, pady=20)
    frame.pack()
    tk.Label(frame, text="CHOTTO", bg=BG, fg="#f5a623", font=(ui_font, 20, "bold")).pack(anchor="w")
    tk.Label(frame, text="Khoan đã! Kiểm tra link Zalo trước khi mở.", bg=BG, fg=MUTED,
             font=(ui_font, 10)).pack(anchor="w", pady=(0, 12))

    var_tier3 = tk.BooleanVar(value=bool(working["tier3_enabled"]))
    var_advice = tk.BooleanVar(value=bool(working["ai_advice"]))
    var_log = tk.BooleanVar(value=bool(working["log_decisions"]))
    var_unknown = tk.BooleanVar(value=working["unknown_caller_policy"] == "inspect")
    var_seconds = tk.IntVar(value=int(working["friction_seconds"]))

    def checkbox(text: str, variable: tk.BooleanVar) -> tk.Checkbutton:
        return tk.Checkbutton(frame, text=text, variable=variable, bg=BG, fg=FG, selectcolor=PANEL,
                              activebackground=BG, activeforeground=FG, anchor="w", font=(ui_font, 10))

    checkbox("Tra tuổi tên miền qua mạng (Tầng 3). Tắt = riêng tư 100%", var_tier3).pack(fill="x")
    checkbox("Hiện lời khuyên cục bộ (AI's Advices) khi không tra được tuổi tên miền", var_advice).pack(fill="x")
    checkbox("Kiểm tra cả link không xác định được nguồn gọi", var_unknown).pack(fill="x")
    checkbox("Ghi nhật ký cục bộ (chỉ lưu tên miền) để thống kê", var_log).pack(fill="x")
    row = tk.Frame(frame, bg=BG)
    row.pack(fill="x", pady=6)
    tk.Label(row, text="Thời gian khóa nút “vẫn mở” (giây):", bg=BG, fg=FG, font=(ui_font, 10)).pack(side="left")
    tk.Spinbox(row, from_=3, to=15, width=4, textvariable=var_seconds).pack(side="left", padx=8)

    status = tk.Label(frame, text="", bg=BG, fg=MUTED, wraplength=_WRAP, justify="left", font=(ui_font, 10))
    results: queue.Queue[tuple[str, str | None, Exception | None]] = queue.Queue()
    buttons: list[tk.Button] = []

    def set_busy(busy: bool) -> None:
        for button in buttons:
            button.config(state="disabled" if busy else "normal")

    def save() -> None:
        try:
            seconds = max(3, min(15, int(var_seconds.get())))
        except (tk.TclError, ValueError):
            status.config(text="Thời gian khóa phải là số nguyên từ 3 đến 15.")
            return
        var_seconds.set(seconds)
        working.update(tier3_enabled=var_tier3.get(), ai_advice=var_advice.get(), log_decisions=var_log.get(),
                       unknown_caller_policy="inspect" if var_unknown.get() else "forward",
                       friction_seconds=seconds)
        try:
            on_save(working)
        except OSError as exc:
            _LOG.exception("Không lưu được cấu hình")
            messagebox.showerror("CHOTTO", f"Không lưu được cài đặt: {exc}", parent=root)
            return
        status.config(text="Đã lưu cài đặt.")

    def poll() -> None:
        try:
            name, message, error = results.get_nowait()
        except queue.Empty:
            root.after(_POLL_MS, poll)
            return
        set_busy(False)
        if error is not None:
            messagebox.showerror("CHOTTO", f"{name}: {error}", parent=root)
            status.config(text="")
        else:
            status.config(text=message or "Xong.")

    def run_in_background(name: str, job: Callable[[], str]) -> None:
        def worker() -> None:
            try:
                results.put((name, job(), None))
            except Exception as exc:  # noqa: BLE001 - lỗi của tác vụ nền phải về được giao diện
                _LOG.exception("Tác vụ '%s' lỗi", name)
                results.put((name, None, exc))

        set_busy(True)
        status.config(text="Đang thực hiện…")
        threading.Thread(target=worker, name=f"chotto-settings-{name}", daemon=True).start()
        root.after(_POLL_MS, poll)

    def on_install() -> None:
        run_in_background("Cài đặt", actions.install)

    def on_uninstall() -> None:
        if messagebox.askyesno("CHOTTO", "Hủy đăng ký CHOTTO làm trình duyệt mặc định?\n\n"
                               "Sau đó bạn cần chọn lại trình duyệt mặc định trong Cài đặt của hệ thống.",
                               parent=root):
            run_in_background("Hủy đăng ký", actions.uninstall)

    def on_update() -> None:
        run_in_background("Cập nhật danh sách đen", actions.update_blacklist)

    def on_export() -> None:
        path = filedialog.asksaveasfilename(parent=root, title="Xuất nhật ký", defaultextension=".csv",
                                            initialfile="chotto_log.csv", filetypes=[("CSV", "*.csv")])
        if path:
            run_in_background("Xuất nhật ký", lambda: actions.export_log(path))

    bar = tk.Frame(frame, bg=BG)
    bar.pack(fill="x", pady=(10, 0))
    for label, command in (("Cài làm trình duyệt mặc định", on_install), ("Hủy đăng ký", on_uninstall),
                           ("Cập nhật danh sách đen", on_update), ("Xuất nhật ký CSV", on_export)):
        button = tk.Button(bar, text=label, command=command)
        button.pack(side="left", padx=(0, 6))
        buttons.append(button)
    save_button = tk.Button(frame, text="Lưu cài đặt", command=save)
    save_button.pack(anchor="e", pady=(12, 0))
    status.pack(fill="x", pady=(8, 0))
    _set_dark_title_bar(root)
