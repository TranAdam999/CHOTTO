"""Tầng 1 – Danh sách đen offline: tập dấu vân tay 64-bit trong RAM, SQLite là nguồn gốc dữ liệu.

Tra cứu chỉ đụng tới RAM: mỗi khóa (``host`` hoặc ``host/path``) được băm BLAKE2b còn 64 bit, mảng đã
sắp xếp được tìm nhị phân. Với n mục, xác suất một tên miền sạch trùng dấu vân tay là n/2^64 (≈ 2·10⁻¹⁴ với
400.000 mục), nên không cần SQLite để xác nhận lại và không giữ file nào mở (Windows thay file thoải mái).

Độ bền:
- File dấu vân tay có header (magic, phiên bản, số mục, SHA-256 của tập khóa, SHA-256 của mảng) và được
  kiểm tra độ dài và toàn vẹn; file thiếu/hỏng/lệch với cơ sở dữ liệu được tự dựng lại từ SQLite.
- Mọi lần dựng lại chạy dưới khóa file liên tiến trình, ghi ra file tạm tên duy nhất rồi ``os.replace``.
- Một dòng dữ liệu hỏng không bao giờ làm hỏng cả lần cập nhật; nguồn trả về rỗng/lỗi không thay
  thế danh sách đang dùng; mục trùng tên miền tin cậy hoặc hậu tố công cộng bị loại (chống đầu độc).
- Cập nhật tăng dần: mỗi nguồn được nhớ ETag/Last-Modified và bản sao mục hợp lệ gần nhất; nguồn trả
  304 (không đổi) hoặc tạm lỗi thì dùng lại bản sao của chính nguồn đó.
"""
from __future__ import annotations

import array
import bisect
import contextlib
import csv
import hashlib
import io
import json
import logging
import os
import sqlite3
import struct
import sys
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from typing import Any, Final

from . import __version__
from .config import atomic_write_text, data_dir, resource_path
from .core.psl import default_psl
from .core.url import URLParseError, parse_url
from .util import in_domain, is_ip, normalize_host, parent_domains

__all__ = [
    "Blacklist",
    "BlacklistError",
    "Fingerprints",
    "entry_keys",
    "update_due",
    "update_from_sources",
]

_LOG = logging.getLogger(__name__)

_FP_MAGIC: Final[bytes] = b"CHFP"
_FP_VERSION: Final[int] = 1
_FP_HEADER: Final = struct.Struct(">4sBQ32s32s")   # magic, version, số mục, sha256(tập khóa), sha256(mảng)
_SCHEMA_VERSION: Final[str] = "2"
_SOURCES_DIR: Final[str] = "sources"
_UPDATE_STATE: Final[str] = "blacklist_update.json"
_USER_AGENT: Final[str] = f"CHOTTO/{__version__}"
_LOCK_TIMEOUT_S: Final[float] = 30.0
_REPLACE_RETRIES: Final[int] = 20
_DEFAULT_MAX_BYTES: Final[int] = 64 * 1024 * 1024
_DEFAULT_MIN_ENTRIES: Final[int] = 1
_SHRINK_GUARD_RATIO: Final[float] = 0.5
_SHRINK_GUARD_MIN_EXISTING: Final[int] = 1000

LogFn = Callable[[str], None]


class BlacklistError(RuntimeError):
    """Không mở hoặc không dựng được danh sách đen."""


class Fingerprints:
    """Tập dấu vân tay 64-bit đã sắp xếp (``array('Q')``), tra bằng tìm nhị phân."""

    def __init__(self, values: array.array[int], key_digest: bytes) -> None:
        """Tạo tập từ mảng ĐÃ sắp xếp tăng dần, không trùng.

        Raises:
            ValueError: ``key_digest`` không dài 32 byte.
        """
        if len(key_digest) != 32:
            raise ValueError("key_digest phải dài 32 byte")
        self.values = values
        self.key_digest = key_digest

    @staticmethod
    def fingerprint(key: str) -> int:
        """Dấu vân tay 64-bit của một khóa."""
        digest = hashlib.blake2b(key.encode("utf-8", "surrogatepass"), digest_size=8).digest()
        return int.from_bytes(digest, "little")

    @classmethod
    def from_keys(cls, keys: Iterable[str], key_digest: bytes) -> Fingerprints:
        """Dựng tập từ các khóa."""
        values = array.array("Q", sorted({cls.fingerprint(k) for k in keys}))
        return cls(values, key_digest)

    def __contains__(self, key: object) -> bool:
        """``True`` nếu dấu vân tay của ``key`` có trong tập."""
        if not isinstance(key, str):
            return False
        value = self.fingerprint(key)
        index = bisect.bisect_left(self.values, value)
        return index < len(self.values) and self.values[index] == value

    def __len__(self) -> int:
        """Số dấu vân tay."""
        return len(self.values)

    def _payload(self) -> bytes:
        """Mảng ở dạng little-endian (độc lập kiến trúc máy)."""
        values = self.values
        if sys.byteorder != "little":
            values = array.array("Q", values)
            values.byteswap()
        return values.tobytes()

    def dump(self) -> bytes:
        """Tuần tự hóa: header + mảng little-endian."""
        payload = self._payload()
        header = _FP_HEADER.pack(_FP_MAGIC, _FP_VERSION, len(self.values), self.key_digest,
                                 hashlib.sha256(payload).digest())
        return header + payload

    @classmethod
    def load(cls, raw: bytes) -> Fingerprints:
        """Đọc tập đã tuần tự hóa.

        Raises:
            ValueError: Dữ liệu cụt, sai magic/phiên bản, sai độ dài hoặc sai checksum.
        """
        if len(raw) < _FP_HEADER.size:
            raise ValueError("Dữ liệu dấu vân tay bị cụt")
        magic, version, count, key_digest, payload_digest = _FP_HEADER.unpack_from(raw)
        if magic != _FP_MAGIC or version != _FP_VERSION:
            raise ValueError("Sai định dạng file dấu vân tay")
        payload = raw[_FP_HEADER.size:]
        if len(payload) != count * 8:
            raise ValueError(f"File dấu vân tay dài {len(payload)} byte, cần {count * 8}")
        if hashlib.sha256(payload).digest() != payload_digest:
            raise ValueError("File dấu vân tay sai checksum")
        values = array.array("Q")
        if values.itemsize != 8:
            raise ValueError("Nền tảng không có kiểu số nguyên 64-bit cho array('Q')")
        values.frombytes(payload)
        if sys.byteorder != "little":
            values.byteswap()
        return cls(values, key_digest)


def entry_keys(entry: object) -> tuple[str, str | None] | None:
    """Chuẩn hóa một dòng danh sách đen thành ``(host, path|None)``; dòng không hợp lệ trả ``None``.

    Hỗ trợ: tên miền trần, URL đầy đủ, định dạng AdGuard ``||domain^``. Không bao giờ ném lỗi.
    """
    if not isinstance(entry, str):
        return None
    text = entry.strip()
    if not text or text.startswith(("#", "!", "//")):
        return None
    if text.startswith("||"):
        text = text[2:].split("^", 1)[0].split("$", 1)[0]
    if "://" not in text:
        text = "http://" + text
    try:
        parsed = parse_url(text)
    except URLParseError:
        return None
    host = parsed.host
    if not is_ip(host) and "." not in host:
        return None
    path = parsed.path.rstrip("/").lower()
    return host, (path or None)


def _entry_to_key(host: str, path: str | None) -> str:
    """Khóa lưu trong cơ sở dữ liệu: ``host`` hoặc ``host/path``."""
    return host if path is None else host + path


def _is_protected(host: str, protected: Iterable[str]) -> bool:
    """``True`` nếu ``host`` thuộc một tên miền được bảo vệ (tên miền tin cậy/chính thức)."""
    return any(in_domain(host, domain) for domain in protected)


def _keys_digest(keys: Iterable[str]) -> bytes:
    """SHA-256 của tập khóa đã sắp xếp (dùng để nhận ra Bloom lệch với cơ sở dữ liệu)."""
    digest = hashlib.sha256()
    for key in sorted(keys):
        digest.update(key.encode("utf-8", "surrogatepass"))
        digest.update(b"\n")
    return digest.digest()


@contextlib.contextmanager
def _file_lock(path: Path, timeout: float = _LOCK_TIMEOUT_S) -> Iterator[None]:
    """Khóa độc quyền liên tiến trình dựa trên file (``msvcrt`` trên Windows, ``fcntl`` trên POSIX).

    Raises:
        BlacklistError: Không lấy được khóa trong ``timeout`` giây.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(path, "a+b")  # noqa: SIM115 - đóng ở finally
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                if sys.platform == "win32":
                    import msvcrt

                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if time.monotonic() >= deadline:
                    raise BlacklistError(f"Không lấy được khóa {path}") from exc
                time.sleep(0.05)
        try:
            yield
        finally:
            if sys.platform == "win32":
                import msvcrt

                handle.seek(0)
                try:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                except OSError:
                    _LOG.warning("Không mở khóa được %s", path)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()


def _replace_with_retry(source: Path, target: Path) -> None:
    """``os.replace`` có thử lại (Windows từ chối thay file đang được tiến trình khác mở).

    Raises:
        BlacklistError: Vẫn thất bại sau khoảng 2 giây.
    """
    for attempt in range(_REPLACE_RETRIES):
        try:
            os.replace(source, target)
            return
        except PermissionError:
            if attempt == _REPLACE_RETRIES - 1:
                break
            time.sleep(0.1)
    raise BlacklistError(f"Không thay được {target} (file đang bị khóa)")


class Blacklist:
    """Danh sách đen cục bộ: tra cứu trong RAM (micro-giây), không giữ file nào mở giữa các lần tra."""

    def __init__(self) -> None:
        """Mở danh sách đen trong thư mục dữ liệu; dựng từ dữ liệu khởi tạo nếu chưa có.

        Raises:
            BlacklistError: Không dựng được danh sách lần đầu.
        """
        directory = data_dir()
        self.db_path = directory / "blacklist.db"
        self.fp_path = directory / "blacklist.fp"
        self.lock_path = directory / "blacklist.lock"
        self._fp: Fingerprints | None = None
        self._fp_stamp: tuple[int, int, int] | None = None
        self._checked = False
        if not self.db_path.exists():
            with _file_lock(self.lock_path):
                if not self.db_path.exists():
                    self._rebuild_locked(self.read_seed(), protected=())
        with contextlib.suppress(OSError):
            (directory / "blacklist.bloom").unlink()      # file của bản ≤ 1.2, không còn dùng

    # ---------- tra cứu ----------
    def _ensure_meta(self) -> str:
        """Bảo đảm bảng ``meta`` có ``keys_sha256`` (nâng cấp cơ sở dữ liệu đời cũ); trả về digest hex."""
        with contextlib.closing(sqlite3.connect(self.db_path, timeout=5.0)) as con, con:
            con.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            row = con.execute("SELECT value FROM meta WHERE key='keys_sha256'").fetchone()
            if row is not None:
                return str(row[0])
            keys = [str(r[0]) for r in con.execute("SELECT k FROM bl")]
            digest = _keys_digest(keys).hex()
            con.executemany(
                "REPLACE INTO meta (key, value) VALUES (?, ?)",
                [("keys_sha256", digest), ("schema_version", _SCHEMA_VERSION), ("entry_count", str(len(keys)))],
            )
            return digest

    def _stamp(self) -> tuple[int, int, int] | None:
        """(inode, mtime_ns, kích thước) của file dấu vân tay, ``None`` nếu chưa có."""
        try:
            info = os.stat(self.fp_path)
        except OSError:
            return None
        return info.st_ino, info.st_mtime_ns, info.st_size

    def _load_valid_fp(self, expected_digest: str) -> Fingerprints | None:
        """Đọc dấu vân tay từ đĩa; ``None`` nếu thiếu, hỏng hoặc lệch với cơ sở dữ liệu."""
        try:
            fingerprints = Fingerprints.load(self.fp_path.read_bytes())
        except FileNotFoundError:
            _LOG.warning("Thiếu %s, sẽ dựng lại từ cơ sở dữ liệu", self.fp_path)
            return None
        except (OSError, ValueError):
            _LOG.warning("File dấu vân tay hỏng, sẽ dựng lại từ cơ sở dữ liệu", exc_info=True)
            return None
        if fingerprints.key_digest.hex() != expected_digest:
            _LOG.warning("Dấu vân tay lệch với cơ sở dữ liệu, sẽ dựng lại")
            return None
        return fingerprints

    def _rebuild_fp_from_db(self) -> Fingerprints:
        """Dựng lại dấu vân tay từ khóa trong SQLite (dưới khóa file) và ghi nguyên tử ra đĩa."""
        with _file_lock(self.lock_path):
            digest_hex = self._ensure_meta()
            existing = self._load_valid_fp(digest_hex)
            if existing is not None:
                return existing
            with contextlib.closing(sqlite3.connect(self.db_path, timeout=5.0)) as con:
                keys = [str(r[0]) for r in con.execute("SELECT k FROM bl")]
            fingerprints = Fingerprints.from_keys(keys, bytes.fromhex(digest_hex))
            tmp = self.fp_path.with_name(f"{self.fp_path.name}.{uuid.uuid4().hex}.tmp")
            tmp.write_bytes(fingerprints.dump())
            _replace_with_retry(tmp, self.fp_path)
            return fingerprints

    def _open(self) -> Fingerprints:
        """Dấu vân tay hợp lệ trong RAM; chỉ đọc lại đĩa khi file đã bị thay (sau ``release``).

        Raises:
            BlacklistError: Cơ sở dữ liệu hỏng hoặc không mở được.
        """
        if self._fp is not None and self._checked:
            return self._fp
        stamp = self._stamp()
        if self._fp is not None and stamp is not None and stamp == self._fp_stamp:
            self._checked = True
            return self._fp                   # file không đổi: không đụng tới SQLite
        try:
            digest_hex = self._ensure_meta()
            cached = self._fp
            if cached is not None and cached.key_digest.hex() == digest_hex and stamp is not None:
                fingerprints = cached
            else:
                fingerprints = self._load_valid_fp(digest_hex) or self._rebuild_fp_from_db()
        except sqlite3.Error as exc:
            raise BlacklistError(f"Không mở được danh sách đen: {exc}") from exc
        except OSError as exc:
            raise BlacklistError(f"Không đọc được danh sách đen: {exc}") from exc
        self._fp, self._fp_stamp, self._checked = fingerprints, self._stamp(), True
        return fingerprints

    def release(self) -> None:
        """Đánh dấu cần kiểm tra lại file ở lần tra sau (an toàn khi gọi nhiều lần).

        Không file nào được giữ mở, nên tiến trình khác cập nhật được kể cả trên Windows. Lần tra sau chỉ
        ``stat`` file dấu vân tay; đọc lại khi file đã bị thay.
        """
        self._checked = False

    def close(self) -> None:
        """Bỏ dấu vân tay khỏi RAM (an toàn khi gọi nhiều lần)."""
        self._fp, self._fp_stamp, self._checked = None, None, False

    def lookup(self, host: str, path: str = "") -> str | None:
        """Tìm mục danh sách đen khớp với ``host`` (và các tên miền cha) hoặc ``host`` + tiền tố ``path``.

        Args:
            host: Host đã chuẩn hóa (ASCII chữ thường).
            path: Đường dẫn URL (so khớp theo tiền tố từng đoạn, không phân biệt hoa thường).

        Returns:
            Khóa danh sách đen đã khớp, hoặc ``None``.

        Raises:
            BlacklistError: Không đọc được danh sách.
        """
        host = normalize_host(host)
        if not host:
            return None
        fingerprints = self._open()
        candidates = list(parent_domains(host))
        segments = [s for s in (path or "").lower().split("/") if s]
        prefix = ""
        for segment in segments[:16]:
            prefix += "/" + segment
            candidates.append(host + prefix)
        for key in candidates:
            if key in fingerprints:
                return key
        return None

    def contains(self, host: str, path: str = "") -> bool:
        """``True`` nếu ``host``/``path`` nằm trong danh sách đen (xem ``lookup``)."""
        return self.lookup(host, path) is not None

    def count(self) -> int:
        """Số mục đang có trong danh sách đen; 0 nếu chưa đọc được."""
        try:
            return len(self._open())
        except BlacklistError:
            _LOG.exception("Không đếm được danh sách đen")
            return 0

    # ---------- xây dựng / cập nhật ----------
    @staticmethod
    def read_seed() -> list[str]:
        """Đọc danh sách đen khởi tạo đóng gói kèm; lỗi đọc trả về danh sách rỗng."""
        try:
            return resource_path("data", "blacklist.seed.txt").read_text("utf-8").splitlines()
        except OSError:
            _LOG.exception("Không đọc được blacklist.seed.txt")
            return []

    def rebuild(self, lines: Iterable[object], protected: Iterable[str] = ()) -> int:
        """Dựng lại toàn bộ danh sách đen từ các dòng dữ liệu.

        Args:
            lines: Các dòng (tên miền, URL, AdGuard). Dòng hỏng bị bỏ qua.
            protected: Tên miền tin cậy; mục thuộc các tên miền này bị loại để chống đầu độc dữ liệu.

        Returns:
            Số khóa đã ghi.

        Raises:
            BlacklistError: Không lấy được khóa file hoặc không ghi được.
        """
        with _file_lock(self.lock_path):
            return self._rebuild_locked(lines, protected)

    def _rebuild_locked(self, lines: Iterable[object], protected: Iterable[str]) -> int:
        """Thân của ``rebuild``; người gọi phải đang giữ khóa file."""
        protected_set = tuple(normalize_host(d) for d in protected if isinstance(d, str) and d)
        psl = default_psl()
        keys: set[str] = set()
        skipped = 0
        for line in lines:
            parsed = entry_keys(line)
            if parsed is None:
                continue
            host, path = parsed
            if not is_ip(host) and psl.lookup(host).registrable is None:
                skipped += 1           # mục là hậu tố công cộng (com.vn, web.app...): sẽ chặn cả nghìn trang
                continue
            if protected_set and _is_protected(host, protected_set):
                skipped += 1
                continue
            keys.add(_entry_to_key(host, path))
        if skipped:
            _LOG.warning("Đã loại %d mục danh sách đen trùng tên miền tin cậy/hậu tố công cộng", skipped)

        self.close()
        token = uuid.uuid4().hex
        tmp_db = self.db_path.with_name(f"{self.db_path.name}.{token}.tmp")
        tmp_fp = self.fp_path.with_name(f"{self.fp_path.name}.{token}.tmp")
        digest = _keys_digest(keys)
        try:
            with contextlib.closing(sqlite3.connect(tmp_db)) as con, con:
                con.execute("CREATE TABLE bl (k TEXT PRIMARY KEY) WITHOUT ROWID")
                con.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                con.executemany("INSERT INTO bl VALUES (?)", ((k,) for k in keys))
                con.executemany(
                    "INSERT INTO meta (key, value) VALUES (?, ?)",
                    [
                        ("keys_sha256", digest.hex()),
                        ("schema_version", _SCHEMA_VERSION),
                        ("entry_count", str(len(keys))),
                        ("built_at", str(int(time.time()))),
                    ],
                )
            tmp_fp.write_bytes(Fingerprints.from_keys(keys, digest).dump())
            # Thay cơ sở dữ liệu trước: tiến trình đọc giữa chừng thấy dấu vân tay cũ lệch digest và tự dựng lại.
            _replace_with_retry(tmp_db, self.db_path)
            _replace_with_retry(tmp_fp, self.fp_path)
        except (OSError, sqlite3.Error) as exc:
            raise BlacklistError(f"Không dựng được danh sách đen: {exc}") from exc
        finally:
            for leftover in (tmp_db, tmp_fp):
                with contextlib.suppress(OSError):
                    leftover.unlink()
        return len(keys)

    def existing_lines(self) -> list[str]:
        """Toàn bộ khóa hiện có (dùng để giữ dữ liệu của nguồn tạm thời lỗi khi cập nhật)."""
        try:
            with contextlib.closing(sqlite3.connect(self.db_path, timeout=5.0)) as con:
                return [str(r[0]) for r in con.execute("SELECT k FROM bl")]
        except sqlite3.Error:
            _LOG.exception("Không đọc được danh sách đen hiện có")
            return []


def _parse_source(raw: str) -> Iterator[str]:
    """Đọc nội dung một nguồn: JSON (list/dict), CSV PhishTank hoặc văn bản mỗi dòng một mục."""
    text = raw.strip().lstrip("﻿")
    if not text:
        return
    if text[0] in "[{":
        try:
            data: Any = json.loads(text)
        except ValueError:
            _LOG.warning("Nguồn trông như JSON nhưng không đọc được")
            return
        if isinstance(data, dict):
            data = next((v for v in data.values() if isinstance(v, list)), [])
        if not isinstance(data, list):
            return
        for item in data:
            if isinstance(item, str):
                yield item
            elif isinstance(item, dict):
                value = item.get("url") or item.get("domain") or item.get("host")
                if isinstance(value, str):
                    yield value
    elif text[:12].lower().startswith("phish_id"):
        for row in csv.DictReader(io.StringIO(text)):
            value = row.get("url")
            if value:
                yield value
    elif text[:15].lower().startswith(("<!doctype", "<html")):
        _LOG.warning("Nguồn trả về trang HTML thay vì danh sách")
        return
    else:
        yield from text.splitlines()


class _Fetched:
    """Kết quả tải một nguồn: nội dung mới, hoặc ``None`` khi máy chủ trả 304 (không đổi)."""

    def __init__(self, body: str | None, etag: str, last_modified: str) -> None:
        """Ghi lại nội dung và các trường xác thực bộ đệm HTTP."""
        self.body = body
        self.etag = etag
        self.last_modified = last_modified


def _download(url: str, timeout: float, max_bytes: int, etag: str = "", last_modified: str = "") -> _Fetched:
    """Tải nội dung qua HTTPS (giới hạn kích thước), gửi ``If-None-Match``/``If-Modified-Since`` nếu có.

    Raises:
        ValueError: URL không phải HTTPS hoặc dữ liệu vượt ``max_bytes``.
        OSError: Lỗi mạng/HTTP (trừ 304).
    """
    if not url.lower().startswith("https://"):
        raise ValueError("Chỉ chấp nhận nguồn HTTPS")
    headers = {"User-Agent": _USER_AGENT}
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - đã kiểm tra scheme
            body: bytes = response.read(max_bytes + 1)
            new_etag = str(response.headers.get("ETag") or "")
            new_modified = str(response.headers.get("Last-Modified") or "")
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return _Fetched(None, etag, last_modified)
        raise
    if len(body) > max_bytes:
        raise ValueError(f"Nguồn vượt quá {max_bytes} byte")
    return _Fetched(body.decode("utf-8", "replace"), new_etag, new_modified)


def _protected_domains(rules: dict[str, Any]) -> list[str]:
    """Tên miền tin cậy + tên miền chính thức của các thương hiệu."""
    domains = [d for d in rules.get("trusted_domains", []) if isinstance(d, str)]
    for brand in rules.get("brands", []):
        if isinstance(brand, dict):
            domains.extend(d for d in brand.get("domains", []) if isinstance(d, str))
    return domains


class _SourceCache:
    """Bản sao mục hợp lệ gần nhất và ETag/Last-Modified của từng nguồn (thư mục ``sources/``)."""

    def __init__(self, directory: Path) -> None:
        """Dùng ``directory`` để lưu."""
        self.directory = directory

    def _base(self, url: str) -> Path:
        """Tên file theo băm URL nguồn."""
        return self.directory / hashlib.sha256(url.encode("utf-8")).hexdigest()[:24]

    def validators(self, url: str) -> tuple[str, str]:
        """(ETag, Last-Modified) đã lưu; chỉ trả về khi bản sao mục còn nguyên."""
        try:
            meta = json.loads(self._base(url).with_suffix(".json").read_text("utf-8"))
            if not self._base(url).with_suffix(".txt").exists() or not isinstance(meta, dict):
                return "", ""
            return str(meta.get("etag", "")), str(meta.get("last_modified", ""))
        except (OSError, ValueError):
            return "", ""

    def entries(self, url: str) -> list[str] | None:
        """Bản sao mục của nguồn, ``None`` nếu chưa có hoặc không đọc được."""
        try:
            return self._base(url).with_suffix(".txt").read_text("utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            return None

    def store(self, url: str, entries: list[str], etag: str, last_modified: str) -> None:
        """Lưu bản sao (lỗi ghi chỉ làm mất khả năng cập nhật tăng dần lần sau)."""
        try:
            atomic_write_text(self._base(url).with_suffix(".txt"), "\n".join(entries) + "\n")
            atomic_write_text(self._base(url).with_suffix(".json"),
                              json.dumps({"url": url, "etag": etag, "last_modified": last_modified,
                                          "count": len(entries), "stored_at": int(time.time())}))
        except OSError:
            _LOG.warning("Không lưu được bản sao nguồn %s", url, exc_info=True)


def _record_update(succeeded: bool) -> None:
    """Ghi thời điểm cập nhật (thành công hoặc thử) vào ``blacklist_update.json``."""
    path = data_dir() / _UPDATE_STATE
    try:
        state = json.loads(path.read_text("utf-8"))
        if not isinstance(state, dict):
            state = {}
    except (OSError, ValueError):
        state = {}
    now = int(time.time())
    state["last_attempt"] = now
    if succeeded:
        state["last_success"] = now
    try:
        atomic_write_text(path, json.dumps(state))
    except OSError:
        _LOG.warning("Không ghi được %s", path, exc_info=True)


def update_due(interval_s: float = 86400.0, retry_s: float = 3600.0, now: float | None = None) -> bool:
    """``True`` nếu đã đến lúc tự cập nhật: lần thành công cuối quá ``interval_s`` và lần thử cuối quá ``retry_s``."""
    now = time.time() if now is None else now
    try:
        state = json.loads((data_dir() / _UPDATE_STATE).read_text("utf-8"))
    except (OSError, ValueError):
        return True
    if not isinstance(state, dict):
        return True
    success = state.get("last_success")
    attempt = state.get("last_attempt")
    if isinstance(attempt, (int, float)) and now - attempt < retry_s:
        return False
    return not (isinstance(success, (int, float)) and now - success < interval_s)


def update_from_sources(rules: dict[str, Any], timeout: float = 30.0, log: LogFn = print) -> int:
    """Tải các nguồn danh sách đen trong ``rules["blacklist_sources"]`` và dựng lại danh sách.

    Quy tắc an toàn:
    - Nguồn không phải HTTPS, vượt kích thước, trả HTML hoặc ít hơn ``min_entries`` mục bị coi là lỗi.
    - Nguồn trả 304 (không đổi) dùng lại bản sao của chính nó; nguồn lỗi dùng bản sao nếu có.
    - Không có nguồn nào cho dữ liệu mới ⇒ giữ nguyên danh sách hiện tại, trả về 0.
    - Có nguồn lỗi mà không có bản sao ⇒ gộp thêm danh sách hiện tại để không đánh mất dữ liệu.
    - Danh sách mới nhỏ hơn 50% danh sách cũ (≥ 1000 mục) ⇒ từ chối, trả về 0.

    Args:
        rules: Bộ luật đã nạp.
        timeout: Timeout mạng cho mỗi thao tác socket (giây).
        log: Hàm nhận thông báo tiến độ (tiếng Việt).

    Returns:
        Số mục trong danh sách mới, hoặc 0 nếu danh sách không được thay.

    Raises:
        BlacklistError: Không ghi được danh sách mới.
    """
    sources = [s for s in rules.get("blacklist_sources", []) if isinstance(s, dict)]
    max_bytes = int(rules.get("blacklist_max_bytes", _DEFAULT_MAX_BYTES))
    cache = _SourceCache(data_dir() / _SOURCES_DIR)
    collected: list[str] = []
    changed = 0
    unchanged = 0
    lost = 0
    for source in sources:
        name = str(source.get("name", "?"))
        url = str(source.get("url", ""))
        minimum = int(source.get("min_entries", _DEFAULT_MIN_ENTRIES))
        etag, modified = cache.validators(url)
        try:
            fetched = _download(url, timeout, max_bytes, etag, modified)
            if fetched.body is None:
                previous = cache.entries(url)
                if previous is None:
                    raise ValueError("máy chủ báo không đổi nhưng mất bản sao cục bộ")
                collected.extend(previous)
                unchanged += 1
                log(f"  [OK] {name}: không đổi ({len(previous)} mục)")
                continue
            entries = [e for e in _parse_source(fetched.body) if entry_keys(e) is not None]
            if len(entries) < minimum:
                raise ValueError(f"chỉ có {len(entries)} mục hợp lệ (cần ít nhất {minimum})")
        except (OSError, ValueError, urllib.error.URLError) as exc:
            log(f"  [LỖI] {name}: {exc}")
            previous = cache.entries(url)
            if previous is not None:
                collected.extend(previous)
                log(f"         dùng lại bản sao gần nhất ({len(previous)} mục)")
            else:
                lost += 1
            continue
        cache.store(url, entries, fetched.etag, fetched.last_modified)
        collected.extend(entries)
        changed += 1
        log(f"  [OK] {name}: {len(entries)} mục")
    _record_update(changed + unchanged > 0)
    if not changed:
        log("Không có dữ liệu mới, giữ nguyên danh sách hiện tại.")
        return 0

    blacklist = Blacklist()
    existing = blacklist.existing_lines()
    if lost:
        log("Có nguồn lỗi chưa có bản sao: giữ lại các mục cũ để không mất dữ liệu.")
        collected.extend(existing)
    elif (
        len(existing) >= _SHRINK_GUARD_MIN_EXISTING
        and len(set(collected)) < _SHRINK_GUARD_RATIO * len(existing)
    ):
        log(f"Danh sách mới ({len(set(collected))} mục) nhỏ bất thường so với hiện tại ({len(existing)}), "
            "giữ nguyên danh sách cũ.")
        return 0
    collected.extend(blacklist.read_seed())
    return blacklist.rebuild(collected, protected=_protected_domains(rules))
