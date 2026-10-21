"""IPC cục bộ giữa launcher và agent thường trú.

Kênh truyền: Named Pipe trên Windows, Unix domain socket trên macOS/Linux (qua
``multiprocessing.connection``, chỉ dùng ``send_bytes``/``recv_bytes``, không bao giờ unpickle).

Xác thực hai chiều bằng HMAC-SHA256 với khóa ngẫu nhiên 32 byte trong thư mục dữ liệu của người dùng
(``agent.key``, quyền 0600 trên POSIX; ``%APPDATA%`` vốn chỉ người dùng hiện tại đọc được trên Windows):

    agent    → launcher : MAGIC ‖ n1
    launcher → agent    : HMAC(key, "C" ‖ n1 ‖ n2) ‖ n2
    agent    → launcher : HMAC(key, "S" ‖ n1 ‖ n2)
    launcher → agent    : yêu cầu JSON
    agent    → launcher : phản hồi JSON

Nhờ vậy tiến trình của người dùng khác không gửi được link vào agent, và launcher không bao giờ
giao link cho một tiến trình mạo danh đã chiếm trước tên pipe/socket. Mọi lần đọc đều có timeout
và giới hạn kích thước.
"""
from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import logging
import os
import secrets
import sys
import threading
from collections.abc import Callable
from multiprocessing.connection import Client, Listener
from pathlib import Path
from typing import Any, Final, Protocol

from ..config import data_dir

__all__ = [
    "MAX_MESSAGE_BYTES",
    "PROTOCOL_VERSION",
    "AgentAlreadyRunning",
    "IPCError",
    "IPCServer",
    "endpoint",
    "load_key",
    "request",
]

_LOG = logging.getLogger(__name__)

PROTOCOL_VERSION: Final[int] = 1
MAX_MESSAGE_BYTES: Final[int] = 64 * 1024
_MAGIC: Final[bytes] = b"CHOTTO-IPC1"
_NONCE_BYTES: Final[int] = 32
_KEY_BYTES: Final[int] = 32
_MAC_BYTES: Final[int] = 32
_KEY_FILE: Final[str] = "agent.key"
_SOCKET_FILE: Final[str] = "agent.sock"
_MAX_UNIX_PATH: Final[int] = 100        # sun_path: 104 byte trên macOS, 108 trên Linux (chừa byte NUL)
_SERVER_IO_TIMEOUT_S: Final[float] = 2.0

Handler = Callable[[dict[str, Any]], dict[str, Any]]


class Connection(Protocol):
    """Phần giao diện chung của ``Connection`` (socket) và ``PipeConnection`` (Windows) được dùng ở đây."""

    def poll(self, timeout: float | None = ...) -> bool:
        """Có dữ liệu để đọc trong ``timeout`` giây hay không."""

    def recv_bytes(self, maxlength: int | None = ...) -> bytes:
        """Đọc một thông điệp."""

    def send_bytes(self, buf: bytes, offset: int = ..., size: int | None = ...) -> None:
        """Gửi một thông điệp."""

    def close(self) -> None:
        """Đóng kết nối."""


class IPCError(RuntimeError):
    """Không liên lạc được với agent (chưa chạy, hết giờ, sai khóa, dữ liệu hỏng)."""


class AgentAlreadyRunning(IPCError):
    """Đã có agent khác đang giữ pipe/socket."""


def endpoint(directory: Path | None = None) -> tuple[str, str]:
    """Địa chỉ và họ kết nối của agent cho thư mục dữ liệu ``directory``.

    Returns:
        ``(địa chỉ, "AF_PIPE" | "AF_UNIX")``.

    Raises:
        IPCError: Đường dẫn socket quá dài cho ``sun_path``.
    """
    base = directory or data_dir()
    if sys.platform == "win32":
        tag = hashlib.sha256(str(base.resolve()).lower().encode("utf-8")).hexdigest()[:20]
        return rf"\\.\pipe\chotto-agent-{tag}", "AF_PIPE"
    path = base / _SOCKET_FILE
    if len(os.fsencode(path)) > _MAX_UNIX_PATH:
        raise IPCError(f"Đường dẫn socket quá dài: {path}")
    return str(path), "AF_UNIX"


def _create_key(path: Path) -> None:
    """Tạo file khóa nếu chưa có (``O_CREAT | O_EXCL``: hai agent khởi động cùng lúc không ghi đè nhau).

    Raises:
        IPCError: Không tạo được file.
    """
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    except FileExistsError:
        return
    except OSError as exc:
        raise IPCError(f"Không tạo được {path}: {exc}") from exc
    try:
        os.write(fd, secrets.token_bytes(_KEY_BYTES))
    finally:
        os.close(fd)


def load_key(directory: Path | None = None, create: bool = False) -> bytes:
    """Đọc khóa xác thực; ``create=True`` (chỉ agent dùng) tạo khóa mới nếu chưa có hoặc bị hỏng.

    Raises:
        IPCError: Không có khóa (agent chưa từng chạy), khóa hỏng hoặc không đọc/ghi được.
    """
    path = (directory or data_dir()) / _KEY_FILE
    for attempt in range(2):
        if create:
            _create_key(path)
        try:
            key = path.read_bytes()
        except FileNotFoundError as exc:
            raise IPCError("Chưa có khóa agent (agent chưa chạy lần nào)") from exc
        except OSError as exc:
            raise IPCError(f"Không đọc được {path}: {exc}") from exc
        if len(key) == _KEY_BYTES:
            return key
        if not create or attempt:
            break
        # File cụt (máy tắt giữa lúc ghi): chỉ agent được phép thay khóa.
        with contextlib.suppress(OSError):
            path.unlink()
    raise IPCError(f"Khóa agent hỏng: {path}")


def _mac(key: bytes, role: bytes, n1: bytes, n2: bytes) -> bytes:
    """HMAC-SHA256 có gắn vai trò để chống phản xạ (reflection)."""
    return hmac.new(key, role + n1 + n2, hashlib.sha256).digest()


def _recv(conn: Connection, timeout: float) -> bytes:
    """Đọc một thông điệp với timeout và giới hạn kích thước.

    Raises:
        IPCError: Hết giờ, kết nối đóng hoặc thông điệp quá lớn.
    """
    try:
        if not conn.poll(timeout):
            raise IPCError("Hết thời gian chờ dữ liệu")
        return conn.recv_bytes(MAX_MESSAGE_BYTES)
    except (OSError, EOFError) as exc:
        raise IPCError(f"Kết nối lỗi: {exc}") from exc


def _send(conn: Connection, payload: bytes) -> None:
    """Gửi một thông điệp.

    Raises:
        IPCError: Kết nối lỗi hoặc thông điệp quá lớn.
    """
    if len(payload) > MAX_MESSAGE_BYTES:
        raise IPCError("Thông điệp quá lớn")
    try:
        conn.send_bytes(payload)
    except (OSError, ValueError) as exc:
        raise IPCError(f"Kết nối lỗi: {exc}") from exc


def _decode(payload: bytes) -> dict[str, Any]:
    """Giải JSON object.

    Raises:
        IPCError: Không phải JSON object hợp lệ.
    """
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise IPCError("Dữ liệu IPC không phải JSON hợp lệ") from exc
    if not isinstance(value, dict):
        raise IPCError("Dữ liệu IPC phải là JSON object")
    return value


def _encode(value: dict[str, Any]) -> bytes:
    """Mã hóa JSON object (UTF-8)."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _client_exchange(conn: Connection, key: bytes, message: dict[str, Any], timeout: float) -> dict[str, Any]:
    """Phía launcher: xác thực hai chiều rồi gửi ``message``, trả về phản hồi.

    Raises:
        IPCError: Agent sai khóa, mạo danh, hết giờ hoặc trả dữ liệu hỏng.
    """
    hello = _recv(conn, timeout)
    if not hello.startswith(_MAGIC) or len(hello) != len(_MAGIC) + _NONCE_BYTES:
        raise IPCError("Bên kia không phải agent CHOTTO")
    n1 = hello[len(_MAGIC):]
    n2 = secrets.token_bytes(_NONCE_BYTES)
    _send(conn, _mac(key, b"C", n1, n2) + n2)
    proof = _recv(conn, timeout)
    if not hmac.compare_digest(proof, _mac(key, b"S", n1, n2)):
        raise IPCError("Agent không chứng minh được khóa (có thể là tiến trình mạo danh)")
    _send(conn, _encode(message))
    return _decode(_recv(conn, timeout))


def serve_connection(conn: Connection, key: bytes, handler: Handler,
                     timeout: float = _SERVER_IO_TIMEOUT_S) -> bool:
    """Phía agent: xác thực một kết nối và trả lời đúng một yêu cầu. Không bao giờ ném lỗi.

    Returns:
        ``True`` nếu đã xử lý một yêu cầu hợp lệ.
    """
    try:
        n1 = secrets.token_bytes(_NONCE_BYTES)
        _send(conn, _MAGIC + n1)
        answer = _recv(conn, timeout)
        mac, n2 = answer[:_MAC_BYTES], answer[_MAC_BYTES:]
        if len(n2) != _NONCE_BYTES or not hmac.compare_digest(mac, _mac(key, b"C", n1, n2)):
            _LOG.warning("Từ chối kết nối IPC: sai khóa xác thực")
            return False
        _send(conn, _mac(key, b"S", n1, n2))
        message = _decode(_recv(conn, timeout))
        try:
            response = handler(message)
        except Exception:  # noqa: BLE001 - lỗi xử lý phải về được launcher để nó tự xử lý link
            _LOG.exception("Agent xử lý yêu cầu lỗi")
            response = {"ok": False, "error": "internal"}
        _send(conn, _encode(response))
        return True
    except IPCError as exc:
        _LOG.info("Kết nối IPC bị bỏ: %s", exc)
        return False
    finally:
        with contextlib.suppress(OSError):
            conn.close()


def request(message: dict[str, Any], timeout: float = 1.5, directory: Path | None = None) -> dict[str, Any]:
    """Gửi một yêu cầu tới agent, có hạn chót tuyệt đối ``timeout`` giây (kể cả bước kết nối).

    Args:
        message: JSON object (``type``, ``v``...).
        timeout: Tổng thời gian tối đa.
        directory: Thư mục dữ liệu (mặc định ``data_dir()``).

    Returns:
        Phản hồi JSON của agent.

    Raises:
        IPCError: Agent không chạy, không trả lời kịp hoặc không xác thực được.
    """
    address, family = endpoint(directory)
    key = load_key(directory)
    outcome: dict[str, Any] = {}

    def worker() -> None:
        try:
            conn = Client(address, family)
        except (OSError, EOFError) as exc:
            outcome["error"] = IPCError(f"Agent không chạy: {exc}")
            return
        try:
            outcome["response"] = _client_exchange(conn, key, message, timeout)
        except IPCError as exc:
            outcome["error"] = exc
        finally:
            with contextlib.suppress(OSError):
                conn.close()

    # Kết nối Named Pipe có thể chờ tới 20 giây nếu pipe bận: chạy trên luồng daemon để giữ hạn chót.
    thread = threading.Thread(target=worker, name="chotto-ipc-client", daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        raise IPCError("Agent không trả lời kịp")
    if "error" in outcome:
        raise outcome["error"]
    response = outcome.get("response")
    if not isinstance(response, dict):
        raise IPCError("Agent không trả lời")
    return response


class IPCServer:
    """Máy chủ IPC của agent: mỗi kết nối được phục vụ trên một luồng riêng có timeout."""

    def __init__(self, handler: Handler, directory: Path | None = None) -> None:
        """Chuẩn bị máy chủ (chưa lắng nghe).

        Args:
            handler: Hàm xử lý yêu cầu đã xác thực; chạy trên luồng nền.
            directory: Thư mục dữ liệu (mặc định ``data_dir()``).
        """
        self._handler = handler
        self._directory = directory or data_dir()
        self._listener: Listener | None = None
        self._thread: threading.Thread | None = None
        self._stopping = threading.Event()
        self._key = b""
        self.address, self.family = endpoint(self._directory)

    def start(self) -> None:
        """Bắt đầu lắng nghe trên luồng nền.

        Raises:
            AgentAlreadyRunning: Agent khác đang chạy.
            IPCError: Không tạo được pipe/socket hoặc khóa.
        """
        self._key = load_key(self._directory, create=True)
        if self.family == "AF_UNIX":
            self._prepare_unix_socket()
        try:
            listener = Listener(self.address, self.family)
        except PermissionError as exc:
            # Windows: pipe đã tồn tại (FILE_FLAG_FIRST_PIPE_INSTANCE) nghĩa là đã có agent.
            raise AgentAlreadyRunning("Đã có agent đang chạy") from exc
        except OSError as exc:
            raise IPCError(f"Không lắng nghe được {self.address}: {exc}") from exc
        if self.family == "AF_UNIX":
            with contextlib.suppress(OSError):
                os.chmod(self.address, 0o600)
        self._listener = listener
        self._thread = threading.Thread(target=self._accept_loop, name="chotto-ipc-server", daemon=True)
        self._thread.start()
        _LOG.info("Agent lắng nghe tại %s", self.address)

    def _prepare_unix_socket(self) -> None:
        """Siết quyền thư mục và dọn socket cũ của agent đã chết.

        Raises:
            AgentAlreadyRunning: Socket còn sống (có agent khác trả lời).
        """
        with contextlib.suppress(OSError):
            os.chmod(self._directory, 0o700)
        if not os.path.exists(self.address):
            return
        try:
            probe = Client(self.address, self.family)
        except (OSError, EOFError):
            with contextlib.suppress(FileNotFoundError):
                os.unlink(self.address)          # socket mồ côi sau khi agent cũ bị tắt đột ngột
            return
        with contextlib.suppress(OSError):
            probe.close()
        raise AgentAlreadyRunning("Đã có agent đang chạy")

    def _accept_loop(self) -> None:
        """Vòng chấp nhận kết nối; dừng khi ``stop`` được gọi."""
        listener = self._listener
        while listener is not None and not self._stopping.is_set():
            try:
                conn = listener.accept()
            except (OSError, EOFError):
                if self._stopping.is_set():
                    break
                _LOG.warning("accept() lỗi", exc_info=True)
                continue
            if self._stopping.is_set():
                with contextlib.suppress(OSError):
                    conn.close()
                break
            threading.Thread(target=serve_connection, args=(conn, self._key, self._handler),
                             name="chotto-ipc-conn", daemon=True).start()

    def stop(self) -> None:
        """Dừng lắng nghe và dọn socket (an toàn khi gọi nhiều lần)."""
        if self._stopping.is_set():
            return
        self._stopping.set()
        # accept() không bị ngắt khi đóng listener từ luồng khác: tự kết nối một lần để đánh thức nó.
        with contextlib.suppress(OSError, EOFError):
            Client(self.address, self.family).close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        if self._listener is not None:
            with contextlib.suppress(OSError):
                self._listener.close()      # với AF_UNIX, Listener.close() tự xóa file socket
        self._listener = None
