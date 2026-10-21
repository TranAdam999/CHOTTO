"""Giao thức giữa launcher và agent thường trú (phần không phụ thuộc giao diện, kiểm thử được).

Launcher (tiến trình mà hệ điều hành gọi cho mỗi link) chỉ nhận diện nguồn gọi rồi gửi
``{url, caller}`` cho agent và thoát. Agent giữ engine, Bloom, PSL và bộ luật trong RAM, xếp hàng các
link và hiển thị lần lượt từng màn hình đệm. Agent chạy phiên bản khác launcher thì tự tắt để lần
sau khởi động lại đúng bản mới.
"""
from __future__ import annotations

import logging
import os
import queue
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from .. import __version__
from ..caller import Caller
from ..core.url import MAX_URL_LENGTH
from . import ipc

__all__ = [
    "AgentCore",
    "LinkRequest",
    "caller_from_json",
    "caller_to_json",
    "ping",
    "send_open",
    "stop_agent",
]

_LOG = logging.getLogger(__name__)

_MAX_EVIDENCE: Final[int] = 300
_MAX_QUEUE: Final[int] = 32           # chống dồn cửa sổ khi bị spam link


@dataclass(frozen=True)
class LinkRequest:
    """Một link chờ agent xử lý."""

    url: str
    caller: Caller | None
    force: bool


def caller_to_json(caller: Caller | None) -> dict[str, Any] | None:
    """Tuần tự hóa ``Caller`` để gửi qua IPC."""
    if caller is None:
        return None
    return {"from_zalo": caller.from_zalo, "evidence": caller.evidence[:_MAX_EVIDENCE]}


def caller_from_json(value: object) -> Caller | None:
    """Đọc ``Caller`` từ JSON; dữ liệu sai kiểu cho ``Caller(None)`` (nguồn không xác định).

    ``None`` (không có trường) nghĩa là launcher chạy với ``--force``.
    """
    if value is None:
        return None
    if not isinstance(value, Mapping):
        return Caller(None, "dữ liệu nguồn gọi không hợp lệ")
    from_zalo = value.get("from_zalo")
    evidence = value.get("evidence")
    return Caller(
        from_zalo if isinstance(from_zalo, bool) else None,
        evidence[:_MAX_EVIDENCE] if isinstance(evidence, str) else "",
    )


class AgentCore:
    """Xử lý yêu cầu IPC (chạy trên luồng IPC) và chuyển link sang hàng đợi cho luồng giao diện."""

    def __init__(self, version: str = __version__, wake: Callable[[], None] | None = None) -> None:
        """Tạo lõi agent.

        Args:
            version: Phiên bản của agent (launcher khác phiên bản thì agent tự tắt).
            wake: Hàm báo cho luồng giao diện có việc mới (an toàn khi gọi từ luồng khác).
        """
        self.version = version
        self.links: queue.Queue[LinkRequest] = queue.Queue(maxsize=_MAX_QUEUE)
        self.quit_requested = threading.Event()
        self._wake = wake or (lambda: None)

    def submit(self, request: LinkRequest) -> bool:
        """Đưa link vào hàng đợi; ``False`` nếu hàng đợi đầy."""
        try:
            self.links.put_nowait(request)
        except queue.Full:
            _LOG.warning("Hàng đợi link của agent đầy, từ chối link mới")
            return False
        self._wake()
        return True

    def handle(self, message: dict[str, Any]) -> dict[str, Any]:
        """Trả lời một yêu cầu IPC đã xác thực. Không bao giờ ném lỗi.

        Yêu cầu: ``{"v": 1, "type": "ping" | "open" | "quit", ...}``. Với ``open``: ``url`` (str),
        ``caller`` (object hoặc null), ``force`` (bool), ``version`` (phiên bản launcher).
        """
        if message.get("v") != ipc.PROTOCOL_VERSION:
            return {"ok": False, "error": "protocol"}
        kind = message.get("type")
        if kind == "ping":
            return {"ok": True, "version": self.version, "pid": os.getpid()}
        if kind == "quit":
            _LOG.info("Agent nhận lệnh tắt")
            self.quit_requested.set()
            self._wake()
            return {"ok": True}
        if kind != "open":
            return {"ok": False, "error": "unknown_type"}
        if message.get("version") != self.version:
            # Launcher là bản mới hơn (vừa cập nhật): tắt để bản mới khởi động lại agent.
            _LOG.info("Launcher phiên bản %r khác agent %s, agent tự tắt", message.get("version"), self.version)
            self.quit_requested.set()
            self._wake()
            return {"ok": False, "error": "version"}
        url = message.get("url")
        if not isinstance(url, str) or not url or len(url) > MAX_URL_LENGTH:
            return {"ok": False, "error": "bad_url"}
        force = message.get("force") is True
        caller = None if force else caller_from_json(message.get("caller"))
        if not force and caller is None:
            caller = Caller(None, "launcher không gửi nguồn gọi")
        if self.quit_requested.is_set():
            return {"ok": False, "error": "stopping"}
        if not self.submit(LinkRequest(url, caller, force)):
            return {"ok": False, "error": "busy"}
        return {"ok": True}


def send_open(url: str, caller: Caller | None, force: bool, timeout: float = 1.5,
              directory: Path | None = None) -> bool:
    """Giao link cho agent đang chạy.

    Returns:
        ``True`` nếu agent đã nhận link (launcher có thể thoát); ``False`` nếu phải tự xử lý.
    """
    message = {
        "v": ipc.PROTOCOL_VERSION,
        "type": "open",
        "version": __version__,
        "url": url,
        "caller": None if force else caller_to_json(caller),
        "force": force,
    }
    try:
        response = ipc.request(message, timeout, directory)
    except ipc.IPCError as exc:
        _LOG.info("Không giao được link cho agent: %s", exc)
        return False
    if response.get("ok") is True:
        return True
    _LOG.info("Agent từ chối link: %s", response.get("error"))
    return False


def ping(timeout: float = 1.0, directory: Path | None = None) -> dict[str, Any] | None:
    """Thông tin agent đang chạy (``version``, ``pid``) hoặc ``None`` nếu không có agent."""
    try:
        response = ipc.request({"v": ipc.PROTOCOL_VERSION, "type": "ping"}, timeout, directory)
    except ipc.IPCError:
        return None
    return response if response.get("ok") is True else None


def stop_agent(timeout: float = 1.5, directory: Path | None = None) -> bool:
    """Yêu cầu agent tắt; ``True`` nếu agent xác nhận."""
    try:
        response = ipc.request({"v": ipc.PROTOCOL_VERSION, "type": "quit"}, timeout, directory)
    except ipc.IPCError:
        return False
    return response.get("ok") is True
