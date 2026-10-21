#!/usr/bin/env python3
"""CHOTTO Desktop – điểm vào.

  main.py <url>                  : chế độ Default URL Handler (hệ điều hành truyền link vào argv)
  main.py --force <url>          : như trên nhưng BỎ QUA bước "có từ Zalo không" (để thử giao diện)
  main.py                        : mở cửa sổ cài đặt
  main.py agent                  : chạy agent thường trú (tự khởi động cùng hệ thống sau khi cài)
  main.py agent-status | agent-stop : xem trạng thái / tắt agent
  main.py check <url>            : in kết quả thẩm định (JSON) - để kiểm thử
  main.py install | uninstall    : đăng ký / gỡ đăng ký handler (kèm tự khởi động agent)
  main.py log                    : in đường dẫn và 30 dòng cuối của chotto.log
  main.py update-blacklist       : nạp danh sách đen (ChongLuaDao, Phishing.Database, PhishTank)
  main.py export-log <file.csv>  : xuất nhật ký quyết định

Khi được gọi với một link, tiến trình này chỉ là launcher mỏng: đo nguồn gọi ngay lập tức, giao link
cho agent qua IPC rồi thoát. Agent chưa chạy thì launcher tự xử lý link (như bản 1.0) và khởi động agent
cho lần sau. Các module nặng (engine, giao diện) chỉ được import khi thật sự cần để launcher khởi động nhanh.
Chính sách an toàn khi xử lý link: xem ``chotto/service/handler.py``.
"""
from __future__ import annotations

import argparse
import io
import json
import logging
import logging.handlers
import sys
import time
from typing import Any, Final

from chotto import platform_setup
from chotto.caller import detect_caller
from chotto.config import data_dir, load_config, load_rules, save_config
from chotto.core.url import SUPPORTED_SCHEMES, URLParseError, get_scheme, parse_url

_LOG = logging.getLogger("chotto")
_LOG_MAX_BYTES: Final[int] = 1_000_000
_LOG_BACKUPS: Final[int] = 3
_MAC_EVENT_WAIT_MS: Final[int] = 2500
_IPC_TIMEOUT_S: Final[float] = 1.5


def setup_logging() -> None:
    """Ghi log UTF-8 xoay vòng (1 MB × 3) vào thư mục dữ liệu; lỗi mở file thì ghi ra stderr."""
    handler: logging.Handler
    try:
        handler = logging.handlers.RotatingFileHandler(
            data_dir() / "chotto.log", maxBytes=_LOG_MAX_BYTES, backupCount=_LOG_BACKUPS, encoding="utf-8"
        )
    except OSError:
        handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(process)d %(name)s: %(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(logging.INFO)


def host_for_log(url: str) -> str:
    """Chỉ ghi host vào log (không ghi đường dẫn/tham số có thể chứa dữ liệu cá nhân)."""
    try:
        return parse_url(url).host
    except URLParseError:
        return "<không phân tích được>"


def _is_mac_bundle() -> bool:
    """``True`` khi đang chạy dưới dạng CHOTTO.app (macOS tự bảo đảm chỉ có một bản đang chạy)."""
    return sys.platform == "darwin" and bool(getattr(sys, "frozen", False))


def launch(url: str, force: bool) -> int:
    """Launcher: đo nguồn gọi, giao link cho agent; agent không nhận thì tự xử lý.

    Returns:
        Mã thoát tiến trình.
    """
    started = time.perf_counter()
    cfg = load_config()
    caller = None if force else detect_caller(cfg)      # phải đo ngay, trước mọi việc khác
    if cfg["agent_enabled"]:
        try:
            from chotto.service.agent import send_open

            delivered = send_open(url, caller, force, _IPC_TIMEOUT_S)
        except Exception:  # noqa: BLE001 - mọi lỗi IPC ⇒ tự xử lý link, không bao giờ làm mất link
            _LOG.exception("Lỗi khi giao link cho agent")
            delivered = False
        if delivered:
            _LOG.info("Đã giao link cho agent sau %.0f ms", (time.perf_counter() - started) * 1000)
            return 0
        if not _is_mac_bundle():
            platform_setup.spawn_agent()                   # cho các link sau; link này tự xử lý ngay
    from chotto.service.app import run_once

    return run_once(url, force, caller=caller)


def _configure_streams() -> None:
    """Console Windows hay không in được tiếng Việt; với pythonw stream có thể là ``None``."""
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


def _build_parser() -> argparse.ArgumentParser:
    """Bộ phân tích tham số dòng lệnh."""
    parser = argparse.ArgumentParser(prog="chotto", description="CHOTTO – Khoan đã! Kiểm tra link Zalo.")
    parser.add_argument("target", nargs="?", help="URL, hoặc lệnh: check, install, uninstall, log, agent, "
                                                  "agent-status, agent-stop, update-blacklist, export-log")
    parser.add_argument("argument", nargs="?", help="URL cho 'check' hoặc file CSV cho 'export-log'")
    parser.add_argument("--force", action="store_true", help="bỏ qua bước nhận diện Zalo")
    parser.add_argument("--gui", action="store_true", help="mở cửa sổ cài đặt ngay (macOS)")
    return parser


def _run_command(target: str | None, argument: str | None, force: bool, gui: bool) -> int:
    """Thực thi một lệnh CLI; trả về mã thoát.

    Raises:
        OSError, BlacklistError, PlatformSetupError, ValueError: Lỗi của lệnh (``main`` xử lý).
    """
    if target and get_scheme(target) in SUPPORTED_SCHEMES:
        return launch(target, force)
    if target == "check" and argument:
        from chotto.engine import Engine

        print(json.dumps(Engine(load_config()).inspect(argument).to_dict(), ensure_ascii=False, indent=2))
    elif target == "install":
        cfg: dict[str, Any] = dict(load_config())
        print(platform_setup.install(cfg))
        save_config(cfg)
    elif target == "uninstall":
        from chotto.service.agent import stop_agent

        print(platform_setup.uninstall())
        stop_agent()
    elif target == "agent":
        from chotto.service.app import run_resident

        return run_resident(show_settings_now=gui)
    elif target == "agent-status":
        from chotto.service.agent import ping

        info = ping()
        print(f"Agent đang chạy: phiên bản {info.get('version')}, pid {info.get('pid')}" if info
              else "Agent không chạy.")
        return 0 if info else 1
    elif target == "agent-stop":
        from chotto.service.agent import stop_agent

        stopped = stop_agent()
        print("Đã yêu cầu agent tắt." if stopped else "Agent không chạy.")
    elif target == "log":
        path = data_dir() / "chotto.log"
        print(f"File nhật ký: {path}")
        if path.exists():
            print("\n".join(path.read_text("utf-8", "replace").splitlines()[-30:]))
        else:
            print("(chưa có dòng nào: nghĩa là CHOTTO chưa từng được gọi)")
    elif target == "update-blacklist":
        from chotto.tier1 import update_from_sources

        print("Đang cập nhật danh sách đen…")
        count = update_from_sources(load_rules())
        print(f"Tổng cộng {count} mục." if count else "Không cập nhật; danh sách cũ được giữ nguyên.")
        return 0 if count else 1
    elif target == "export-log" and argument:
        from chotto import logdb

        print(f"Đã xuất {logdb.export_csv(argument)} dòng.")
    elif target is None and _is_mac_bundle():
        # CHOTTO.app thường trú: mở bằng link thì không hiện cài đặt; người dùng tự mở app thì hiện.
        from chotto.service.app import run_resident

        if gui:
            return run_resident(show_settings_now=True)
        return run_resident(open_settings_after_ms=_MAC_EVENT_WAIT_MS)
    elif target is None:
        from chotto.service.app import run_once

        return run_once(None, False, gui)
    else:
        _build_parser().print_help()
        return 2
    return 0


def main(argv: list[str]) -> int:
    """Điểm vào; trả về mã thoát."""
    _configure_streams()
    setup_logging()
    args, unknown = _build_parser().parse_known_args(argv[1:])
    if unknown:
        _LOG.info("Bỏ qua tham số không biết: %s", [a for a in unknown if not a.lower().startswith("http")])
    target: str | None = args.target
    _LOG.info("KHOI DONG lệnh=%s", host_for_log(target) if target and get_scheme(target) else target)
    try:
        return _run_command(target, args.argument, args.force, args.gui)
    except Exception as exc:
        from chotto.tier1 import BlacklistError      # import muộn: launcher không cần nạp Tầng 1

        if not isinstance(exc, (OSError, BlacklistError, platform_setup.PlatformSetupError, ValueError)):
            raise
        _LOG.exception("Lệnh '%s' lỗi", target)
        print(f"Lỗi: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
