#!/usr/bin/env python3
"""Đồng bộ dữ liệu dùng chung từ ``chotto/data`` sang ``extension/data`` để Desktop và tiện ích cho cùng kết quả.

Sinh ra:
  - ``rules.json``: bản sao nguyên văn bộ luật (một nguồn sự thật cho cả hai nền tảng);
  - ``psl.json``: Public Suffix List đã tách sẵn thành ba bảng luật (thường, ``*.``, ``!``) với cờ PRIVATE,
    nhãn Unicode đã chuyển sang punycode bằng chính bộ phân tích của bản Desktop;
  - ``popular.json``: tên miền .vn phổ biến (CrUX) đã chuẩn hóa như ``config.load_popular_domains``;
  - ``advice.json``: lời khuyên cục bộ (``chotto.advisor``: TIPS, COMBOS, GENERAL);
  - ``confusables.json`` và ``blacklist.seed.txt``: bản sao nguyên văn;
  - ``sync.json``: SHA-256 của từng file nguồn, để ``--check`` (và CI) phát hiện dữ liệu tiện ích bị lệch.

Ví dụ:
  python tools/sync_extension_data.py           # ghi lại extension/data
  python tools/sync_extension_data.py --check   # chỉ kiểm tra, mã thoát 1 nếu lệch
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Final

ROOT: Final[Path] = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from chotto import __version__, advisor  # noqa: E402
from chotto.config import load_popular_domains, resource_path  # noqa: E402
from chotto.core.psl import PublicSuffixList  # noqa: E402

SOURCES: Final[tuple[str, ...]] = (
    "rules.json",
    "public_suffix_list.dat",
    "popular_vn.txt",
    "confusables_ascii.json",
    "blacklist.seed.txt",
)
DEFAULT_OUT: Final[Path] = ROOT / "extension" / "data"


def _sha256(path: Path) -> str:
    """SHA-256 dạng hex của một file.

    Raises:
        OSError: Không đọc được file.
    """
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _dump(data: Any) -> str:
    """JSON gọn, ổn định (khóa sắp xếp) và giữ nguyên tiếng Việt."""
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"


def advice_data() -> dict[str, Any]:
    """Lời khuyên cục bộ của ``chotto.advisor`` ở dạng JSON (nhóm mã dấu hiệu đã sắp xếp)."""
    return {
        "tips": dict(advisor.TIPS),
        "combos": [{"groups": [sorted(group) for group in groups], "text": text} for groups, text in advisor.COMBOS],
        "general": advisor.GENERAL,
    }


def build_outputs() -> dict[str, str]:
    """Nội dung từng file dữ liệu của tiện ích, sinh từ ``chotto/data``.

    Returns:
        ``{tên file: nội dung UTF-8}``.

    Raises:
        OSError: Thiếu file nguồn.
        ValueError: File nguồn hỏng (JSON sai, PSL rỗng).
    """
    data_dir = resource_path("data")
    rules_text = (data_dir / "rules.json").read_text("utf-8")
    rules = json.loads(rules_text)
    if not isinstance(rules, dict):
        raise ValueError("rules.json phải là JSON object")
    psl = PublicSuffixList((data_dir / "public_suffix_list.dat").read_text("utf-8"))
    tables = {
        "exact": {rule: int(private) for rule, private in psl._exact.items()},          # noqa: SLF001
        "wildcard": {rule: int(private) for rule, private in psl._wildcard.items()},    # noqa: SLF001
        "exception": {rule: int(private) for rule, private in psl._exception.items()},  # noqa: SLF001
    }
    confusables = json.loads((data_dir / "confusables_ascii.json").read_text("utf-8"))
    if not isinstance(confusables, dict):
        raise ValueError("confusables_ascii.json phải là JSON object")
    sync_info = {
        "chotto_version": __version__,
        "sources": {name: _sha256(data_dir / name) for name in SOURCES},
    }
    return {
        "rules.json": _dump(rules),
        "psl.json": _dump(tables),
        "popular.json": _dump(sorted(load_popular_domains())),
        "confusables.json": _dump(confusables),
        "advice.json": _dump(advice_data()),
        "blacklist.seed.txt": (data_dir / "blacklist.seed.txt").read_text("utf-8"),
        "sync.json": _dump(sync_info),
    }


def main(argv: list[str] | None = None) -> int:
    """Điểm vào dòng lệnh.

    Returns:
        0 nếu thành công (hoặc dữ liệu đã khớp khi ``--check``), 1 nếu lệch, 2 nếu lỗi đọc/ghi.
    """
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="Thư mục dữ liệu của tiện ích")
    parser.add_argument("--check", action="store_true", help="Chỉ kiểm tra dữ liệu tiện ích có khớp nguồn không")
    args = parser.parse_args(argv)
    try:
        outputs = build_outputs()
    except (OSError, ValueError) as exc:
        print(f"Lỗi đọc dữ liệu nguồn: {exc}", file=sys.stderr)
        return 2
    out_dir: Path = args.out
    if args.check:
        stale = []
        for name, content in outputs.items():
            path = out_dir / name
            try:
                current = path.read_text("utf-8")
            except OSError:
                current = None
            if current != content:
                stale.append(name)
        if stale:
            print("Dữ liệu tiện ích lệch với chotto/data: " + ", ".join(stale), file=sys.stderr)
            print("Chạy: python tools/sync_extension_data.py", file=sys.stderr)
            return 1
        print("Dữ liệu tiện ích khớp với chotto/data.")
        return 0
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        for name, content in outputs.items():
            (out_dir / name).write_text(content, "utf-8", newline="\n")
    except OSError as exc:
        print(f"Không ghi được {out_dir}: {exc}", file=sys.stderr)
        return 2
    print(f"Đã đồng bộ {len(outputs)} file vào {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
