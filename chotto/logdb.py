"""Nhật ký quyết định cục bộ phục vụ đo kết quả nghiên cứu.

Chỉ lưu tên miền đăng ký được (không lưu đường dẫn/tham số), điểm, mức, mã tín hiệu, quyết định và
thời gian cân nhắc. ``record`` **không bao giờ ném lỗi**: ghi nhật ký thất bại không được phép ảnh
hưởng tới quyết định mở/đóng liên kết của người dùng.
"""
from __future__ import annotations

import contextlib
import csv
import logging
import sqlite3
import time
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Final

from .config import data_dir

if TYPE_CHECKING:
    from .engine import Result

__all__ = ["export_csv", "record"]

_LOG = logging.getLogger(__name__)
_SCHEMA_VERSION: Final[int] = 2
_COLUMNS: Final[tuple[str, ...]] = (
    "ts", "host", "score", "level", "tier", "decision", "dwell_ms", "source", "signals",
)


def _migrate(con: sqlite3.Connection) -> None:
    """Tạo bảng hoặc nâng cấp từ lược đồ cũ (8 cột, không có ``signals``)."""
    con.execute(
        "CREATE TABLE IF NOT EXISTS decisions (ts REAL, host TEXT, score INT, level TEXT, tier INT, "
        "decision TEXT, dwell_ms INT, source TEXT, signals TEXT DEFAULT '')"
    )
    columns = {str(row[1]) for row in con.execute("PRAGMA table_info(decisions)")}
    if "signals" not in columns:
        con.execute("ALTER TABLE decisions ADD COLUMN signals TEXT DEFAULT ''")
    con.execute("CREATE INDEX IF NOT EXISTS decisions_ts ON decisions(ts)")
    con.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")


@contextlib.contextmanager
def _connect(path: Path | None = None) -> Iterator[sqlite3.Connection]:
    """Mở ``decisions.db`` (WAL, timeout ngắn) và luôn đóng kết nối.

    Raises:
        sqlite3.Error: Không mở được cơ sở dữ liệu.
    """
    con = sqlite3.connect(path or (data_dir() / "decisions.db"), timeout=0.5)
    try:
        con.execute("PRAGMA journal_mode=WAL")
        with con:
            _migrate(con)
        yield con
    finally:
        con.close()


def record(result: Result, decision: str, dwell_ms: int, source: str, retention_days: int = 90) -> bool:
    """Ghi một quyết định; dọn bản ghi cũ hơn ``retention_days``.

    Args:
        result: Kết quả thẩm định.
        decision: ``auto_open`` | ``proceed`` | ``cancel`` | ``ui_failed``.
        dwell_ms: Thời gian người dùng cân nhắc (ms).
        source: ``desktop`` | ``extension``.
        retention_days: Số ngày lưu giữ.

    Returns:
        ``True`` nếu ghi thành công. Mọi lỗi được ghi vào log và trả ``False``.
    """
    try:
        now = time.time()
        codes = ",".join(sorted({str(s.get("code", "")) for s in result.signals if s.get("code")}))
        with _connect() as con, con:
            con.execute(
                "INSERT INTO decisions (ts, host, score, level, tier, decision, dwell_ms, source, signals) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (now, result.display_domain or result.host, int(result.score), str(result.level),
                 int(result.tier_reached), decision, int(dwell_ms), source, codes),
            )
            con.execute("DELETE FROM decisions WHERE ts < ?", (now - max(1, retention_days) * 86400,))
    except (sqlite3.Error, OSError, ValueError, TypeError):
        _LOG.exception("Không ghi được nhật ký quyết định")
        return False
    return True


def export_csv(path: str | Path) -> int:
    """Xuất nhật ký ra CSV (UTF-8 có BOM để Excel hiển thị đúng tiếng Việt, thời gian ISO 8601).

    Args:
        path: File CSV đích.

    Returns:
        Số dòng đã xuất.

    Raises:
        OSError: Không ghi được file đích.
        sqlite3.Error: Không đọc được nhật ký.
    """
    with _connect() as con:
        rows = con.execute(f"SELECT {', '.join(_COLUMNS)} FROM decisions ORDER BY ts").fetchall()
    with open(path, "w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle)
        writer.writerow(_COLUMNS)
        for row in rows:
            stamp = datetime.fromtimestamp(float(row[0]), tz=timezone.utc).isoformat(timespec="seconds")
            writer.writerow((stamp, *row[1:]))
    return len(rows)
