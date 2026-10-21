"""Tầng 3 – Xác thực tuổi đời tên miền qua RDAP và WHOIS, có cache SQLite và deadline cứng.

- RDAP và WHOIS chạy **song song** trên luồng nền (daemon); kết quả đầu tiên có ngày đăng ký thắng.
- RDAP hỏi thẳng máy chủ của nhà đăng ký theo bảng IANA bootstrap (RFC 9224) lưu cục bộ, bớt một
  lượt chuyển hướng qua rdap.org; bảng được làm mới trên luồng nền mỗi 7 ngày, chưa có bảng hoặc TLD
  không có trong bảng thì dùng rdap.org.
- ``timeout`` là **tổng** thời gian chờ, kể cả phân giải DNS và chuyển hướng: hết hạn là trả ``None``
  ngay, luồng còn dở bị bỏ lại và không giữ tiến trình khi thoát.
- Lỗi cache (khóa, hỏng) chỉ làm mất cache, không làm mất Tầng 3; lỗi mạng trả ``None`` để
  engine quay về điểm Tầng 2.
"""
from __future__ import annotations

import contextlib
import json
import logging
import queue
import re
import socket
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final

from . import __version__
from .config import atomic_write_text, data_dir
from .core.psl import default_psl
from .util import is_ip

__all__ = ["AgeInfo", "RdapBootstrap", "lookup", "parse_bootstrap", "parse_registration_date", "rdap_url"]

_LOG = logging.getLogger(__name__)

_RDAP_URL: Final[str] = "https://rdap.org/domain/{domain}"
_BOOTSTRAP_URL: Final[str] = "https://data.iana.org/rdap/dns.json"
_BOOTSTRAP_FILE: Final[str] = "rdap_bootstrap.json"
_BOOTSTRAP_MAX_AGE_S: Final[float] = 7 * 86400
_BOOTSTRAP_RETRY_S: Final[float] = 6 * 3600
_MAX_BOOTSTRAP_BYTES: Final[int] = 2 << 20
_USER_AGENT: Final[str] = f"CHOTTO/{__version__}"
_MAX_RDAP_BYTES: Final[int] = 1 << 20
_MAX_WHOIS_BYTES: Final[int] = 64 * 1024
_FAILURE_TTL_S: Final[float] = 3600.0
_DATE_RE: Final = re.compile(
    r"^\s*(?:creation date|created on|created|registered on|registration time|registration date|"
    r"domain registration date|registered|domain create date)\s*:\s*(.+?)\s*$",
    re.I | re.M,
)
_REFER_RE: Final = re.compile(r"^(?:refer|whois):\s*(\S+)", re.I | re.M)
_DATE_FORMATS: Final[tuple[str, ...]] = (
    "%Y-%m-%d",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y.%m.%d",
    "%Y.%m.%d %H:%M:%S",
    "%Y/%m/%d",
    "%Y/%m/%d %H:%M:%S",
    "%d-%b-%Y",
    "%d-%b-%Y %H:%M:%S",
    "%d.%m.%Y",
    "%d.%m.%Y %H:%M:%S",
    "%Y%m%d",
    "%a %b %d %H:%M:%S %Z %Y",
)


@dataclass(frozen=True)
class AgeInfo:
    """Tuổi tên miền.

    Attributes:
        age_days: Số ngày kể từ khi đăng ký (không âm).
        org: Tổ chức đăng ký nếu có (chỉ để ghi nhận, không dùng để giảm điểm vì kẻ gian tự khai được).
        from_cache: ``True`` nếu lấy từ cache cục bộ.
    """

    age_days: float
    org: str = ""
    from_cache: bool = False


def parse_registration_date(text: str) -> datetime | None:
    """Đọc ngày đăng ký từ chuỗi RDAP/WHOIS (ISO 8601 và các định dạng WHOIS phổ biến); lỗi trả ``None``."""
    value = text.strip().split(" (", 1)[0].strip()
    if not value:
        return None
    iso = value.replace("Z", "+00:00") if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(iso)
    except ValueError:
        parsed = None
        for fmt in _DATE_FORMATS:
            try:
                parsed = datetime.strptime(value, fmt)
                break
            except ValueError:
                continue
    if parsed is None:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def parse_bootstrap(data: object) -> dict[str, str]:
    """Đọc bảng IANA RDAP bootstrap thành ``{tld: URL gốc https kết thúc bằng /}``.

    Chỉ nhận URL ``https://``; mục sai cấu trúc bị bỏ qua.

    Raises:
        ValueError: Dữ liệu không có danh sách ``services``.
    """
    if not isinstance(data, dict) or not isinstance(data.get("services"), list):
        raise ValueError("Bảng RDAP bootstrap thiếu 'services'")
    table: dict[str, str] = {}
    for service in data["services"]:
        if not (isinstance(service, list) and len(service) >= 2
                and isinstance(service[0], list) and isinstance(service[1], list)):
            continue
        base = next((u for u in service[1] if isinstance(u, str) and u.lower().startswith("https://")), None)
        if base is None:
            continue
        base = base if base.endswith("/") else base + "/"
        for tld in service[0]:
            if isinstance(tld, str) and tld:
                table[tld.lower().strip(".")] = base
    return table


class RdapBootstrap:
    """Bảng IANA RDAP bootstrap lưu ở thư mục dữ liệu, làm mới trên luồng nền (không chặn Tầng 3)."""

    def __init__(self, url: str = _BOOTSTRAP_URL, max_age_s: float = _BOOTSTRAP_MAX_AGE_S) -> None:
        """Tạo bộ quản lý bảng (chưa đọc đĩa, chưa gọi mạng)."""
        self.url = url
        self.max_age_s = max_age_s
        self._lock = threading.Lock()
        self._table: dict[str, str] | None = None
        self._loaded_mtime: float | None = None
        self._refreshing = False
        self._last_attempt = 0.0

    @property
    def path(self) -> Path:
        """File cache của bảng."""
        return data_dir() / _BOOTSTRAP_FILE

    def _read_disk(self) -> tuple[dict[str, str], float] | None:
        """(bảng, mtime) từ đĩa; ``None`` nếu thiếu hoặc hỏng."""
        try:
            mtime = self.path.stat().st_mtime
            if mtime == self._loaded_mtime and self._table is not None:
                return self._table, mtime
            table = parse_bootstrap(json.loads(self.path.read_text("utf-8")))
        except FileNotFoundError:
            return None
        except (OSError, ValueError):
            _LOG.warning("Bảng RDAP bootstrap hỏng, sẽ tải lại", exc_info=True)
            return None
        return table, mtime

    def refresh(self, timeout: float = 20.0) -> bool:
        """Tải bảng mới từ IANA và ghi nguyên tử ra đĩa. Không bao giờ ném lỗi.

        Returns:
            ``True`` nếu đã cập nhật.
        """
        try:
            request = urllib.request.Request(self.url, headers={"User-Agent": _USER_AGENT})
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - URL cố định https
                body = response.read(_MAX_BOOTSTRAP_BYTES + 1)
            if len(body) > _MAX_BOOTSTRAP_BYTES:
                raise ValueError("Bảng RDAP bootstrap quá lớn")
            raw = json.loads(body.decode("utf-8"))
            table = parse_bootstrap(raw)
            if not table:
                raise ValueError("Bảng RDAP bootstrap rỗng")
            atomic_write_text(self.path, json.dumps(raw, separators=(",", ":")))
        except (OSError, ValueError, urllib.error.URLError, UnicodeError) as exc:
            _LOG.info("Không làm mới được bảng RDAP bootstrap: %s", exc)
            return False
        with self._lock:
            self._table, self._loaded_mtime = table, None
        return True

    def _refresh_in_background(self) -> None:
        """Chạy ``refresh`` trên luồng daemon (tối đa một luồng, thử lại sau ``_BOOTSTRAP_RETRY_S``)."""
        with self._lock:
            now = time.monotonic()
            if self._refreshing or (self._last_attempt and now - self._last_attempt < _BOOTSTRAP_RETRY_S):
                return
            self._refreshing = True
            self._last_attempt = now

        def run() -> None:
            try:
                self.refresh()
            finally:
                with self._lock:
                    self._refreshing = False

        threading.Thread(target=run, name="chotto-rdap-bootstrap", daemon=True).start()

    def base_for(self, tld: str) -> str | None:
        """URL gốc RDAP của ``tld`` hoặc ``None`` (chưa có bảng / TLD không hỗ trợ RDAP).

        Bảng thiếu hoặc quá ``max_age_s`` thì kích hoạt làm mới nền; lần tra này vẫn dùng bảng cũ (nếu có).
        """
        loaded = self._read_disk()
        if loaded is None:
            self._refresh_in_background()
            return None
        table, mtime = loaded
        with self._lock:
            self._table, self._loaded_mtime = table, mtime
        if time.time() - mtime > self.max_age_s:
            self._refresh_in_background()
        return table.get(tld.lower())


_BOOTSTRAP: Final[RdapBootstrap] = RdapBootstrap()


def rdap_url(domain: str, bootstrap: RdapBootstrap | None = None) -> str:
    """URL RDAP cho ``domain``: máy chủ nhà đăng ký theo bảng IANA, hoặc rdap.org nếu không có."""
    base = (bootstrap or _BOOTSTRAP).base_for(domain.rsplit(".", 1)[-1])
    if base is None:
        return _RDAP_URL.format(domain=domain)
    return f"{base}domain/{domain}"


def _rdap(domain: str, deadline: float) -> tuple[datetime | None, str]:
    """Tra RDAP (máy chủ nhà đăng ký theo IANA bootstrap, dự phòng rdap.org). Trả về (ngày đăng ký, tổ chức)."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None, ""
    request = urllib.request.Request(
        rdap_url(domain),
        headers={"Accept": "application/rdap+json", "User-Agent": _USER_AGENT},
    )
    with urllib.request.urlopen(request, timeout=remaining) as response:  # noqa: S310 - URL cố định https
        body = response.read(_MAX_RDAP_BYTES + 1)
    if len(body) > _MAX_RDAP_BYTES:
        raise ValueError("Phản hồi RDAP quá lớn")
    data: Any = json.loads(body.decode("utf-8", "replace"))
    if not isinstance(data, dict):
        raise ValueError("Phản hồi RDAP không phải object")
    created: datetime | None = None
    for event in data.get("events") or []:
        if isinstance(event, dict) and event.get("eventAction") == "registration":
            candidate = parse_registration_date(str(event.get("eventDate", "")))
            if candidate is not None and (created is None or candidate < created):
                created = candidate
    org = ""
    for entity in data.get("entities") or []:
        if not isinstance(entity, dict) or "registrant" not in (entity.get("roles") or []):
            continue
        vcard = entity.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
            for item in vcard[1]:
                if isinstance(item, list) and len(item) > 3 and item[0] in ("fn", "org"):
                    value = item[3]
                    org = " ".join(map(str, value)) if isinstance(value, list) else str(value)
    return created, org


def _whois_query(server: str, query: str, deadline: float) -> str:
    """Một truy vấn WHOIS (cổng 43) với deadline tuyệt đối và giới hạn dung lượng.

    Raises:
        TimeoutError: Hết thời gian.
        OSError: Lỗi mạng.
    """
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Hết thời gian WHOIS")
    chunks: list[bytes] = []
    total = 0
    with socket.create_connection((server, 43), timeout=remaining) as sock:
        sock.sendall((query + "\r\n").encode("ascii", "replace"))
        while total < _MAX_WHOIS_BYTES:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Hết thời gian WHOIS")
            sock.settimeout(remaining)
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    return b"".join(chunks).decode("utf-8", "replace")


def _whois(domain: str, deadline: float) -> tuple[datetime | None, str]:
    """Tra WHOIS: hỏi IANA máy chủ của TLD rồi hỏi máy chủ đó. Trả về (ngày đăng ký, tổ chức)."""
    tld = domain.rsplit(".", 1)[-1]
    referral = _whois_query("whois.iana.org", tld, deadline)
    match = _REFER_RE.search(referral)
    if not match:
        return None, ""
    text = _whois_query(match.group(1), domain, deadline)
    date_match = _DATE_RE.search(text)
    org_match = re.search(r"^\s*registrant(?: organization| name)?\s*:\s*(.+?)\s*$", text, re.I | re.M)
    created = parse_registration_date(date_match.group(1)) if date_match else None
    return created, (org_match.group(1) if org_match else "")


Fetcher = Callable[[str, float], tuple[datetime | None, str]]


def _race(domain: str, deadline: float, fetchers: tuple[Fetcher, ...]) -> tuple[datetime | None, str]:
    """Chạy các nguồn song song trên luồng daemon; trả kết quả có ngày đăng ký đầu tiên trước ``deadline``."""
    results: queue.Queue[tuple[datetime | None, str] | None] = queue.Queue()

    def worker(fetch: Fetcher) -> None:
        try:
            results.put(fetch(domain, deadline))
        except (OSError, ValueError, urllib.error.URLError, TimeoutError, UnicodeError) as exc:
            _LOG.info("Tầng 3: nguồn %s lỗi cho %s: %s", getattr(fetch, "__name__", "?"), domain, exc)
            results.put(None)
        except Exception:  # noqa: BLE001 - luồng nền: mọi lỗi phải được ghi lại thay vì mất im lặng
            _LOG.exception("Tầng 3: lỗi không lường trước ở nguồn %s", getattr(fetch, "__name__", "?"))
            results.put(None)

    for fetch in fetchers:
        threading.Thread(target=worker, args=(fetch,), name=f"chotto-tier3-{fetch.__name__}", daemon=True).start()
    pending = len(fetchers)
    org_fallback = ""
    while pending:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            item = results.get(timeout=remaining)
        except queue.Empty:
            break
        pending -= 1
        if item is None:
            continue
        created, org = item
        if created is not None:
            return created, org
        org_fallback = org_fallback or org
    return None, org_fallback


@contextlib.contextmanager
def _cache() -> Iterator[sqlite3.Connection | None]:
    """Kết nối cache (``cache.db``); ``None`` nếu không mở được. Luôn đóng kết nối."""
    con: sqlite3.Connection | None = None
    try:
        con = sqlite3.connect(data_dir() / "cache.db", timeout=0.3)
        con.execute("PRAGMA journal_mode=WAL")
        con.execute(
            "CREATE TABLE IF NOT EXISTS age (d TEXT PRIMARY KEY, created REAL, org TEXT, fetched REAL, ok INT)"
        )
    except (sqlite3.Error, OSError):
        _LOG.warning("Không mở được cache Tầng 3, tra trực tiếp", exc_info=True)
        if con is not None:
            con.close()
        con = None
    try:
        yield con
    finally:
        if con is not None:
            con.close()


def _cache_get(con: sqlite3.Connection | None, domain: str, ttl_hours: float, now: float) -> tuple[bool, AgeInfo | None]:
    """Đọc cache. Trả về (có kết quả còn hạn, AgeInfo hoặc None nếu kết quả là "không tra được")."""
    if con is None:
        return False, None
    try:
        row = con.execute("SELECT created, org, fetched, ok FROM age WHERE d=?", (domain,)).fetchone()
    except sqlite3.Error:
        _LOG.warning("Đọc cache Tầng 3 lỗi", exc_info=True)
        return False, None
    if row is None:
        return False, None
    created, org, fetched, ok = row
    ttl = ttl_hours * 3600 if ok else _FAILURE_TTL_S
    if not isinstance(fetched, (int, float)) or now - fetched >= ttl:
        return False, None
    if ok and isinstance(created, (int, float)):
        return True, AgeInfo(max(0.0, (now - created) / 86400), str(org or ""), from_cache=True)
    return True, None


def _cache_put(con: sqlite3.Connection | None, domain: str, created: float | None, org: str, now: float) -> None:
    """Ghi cache; lỗi chỉ được ghi log."""
    if con is None:
        return
    try:
        with con:
            con.execute(
                "REPLACE INTO age (d, created, org, fetched, ok) VALUES (?, ?, ?, ?, ?)",
                (domain, created, org, now, 1 if created is not None else 0),
            )
    except sqlite3.Error:
        _LOG.warning("Ghi cache Tầng 3 lỗi", exc_info=True)


def lookup(
    host: str,
    timeout: float = 1.8,
    ttl_hours: float = 48,
    fetchers: tuple[Fetcher, ...] = (_rdap, _whois),
) -> AgeInfo | None:
    """Tra tuổi tên miền đăng ký được của ``host``.

    Args:
        host: Host ASCII chữ thường.
        timeout: Tổng thời gian tối đa (giây), kể cả DNS.
        ttl_hours: Thời hạn cache cho kết quả thành công.
        fetchers: Các nguồn tra cứu (thay được khi kiểm thử).

    Returns:
        ``AgeInfo``, hoặc ``None`` nếu host là IP/hậu tố công cộng, hết thời gian hay không tra được.
    """
    if not host or is_ip(host):
        return None
    domain = default_psl().lookup(host).registrable
    if domain is None:
        return None
    now = time.time()
    with _cache() as con:
        hit, info = _cache_get(con, domain, ttl_hours, now)
        if hit:
            return info
        deadline = time.monotonic() + max(0.1, timeout)
        created, org = _race(domain, deadline, fetchers)
        if created is None:
            # Chỉ nhớ thất bại khi các nguồn đã trả lời; hết giờ thì lần sau thử lại.
            if time.monotonic() < deadline:
                _cache_put(con, domain, None, org, now)
            return None
        _cache_put(con, domain, created.timestamp(), org, now)
        return AgeInfo(max(0.0, (now - created.timestamp()) / 86400), org)
