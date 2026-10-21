#!/usr/bin/env python3
"""Sinh ``chotto/data/popular_vn.txt``: tên miền .vn phổ biến dùng để giảm báo nhầm ở Tầng 2.

Nguồn: Chrome UX Report (CrUX) top 1 triệu toàn cầu, CC BY 4.0, qua github.com/zakird/crux-top-lists.
Mỗi tên miền đăng ký (eTLD+1) đuôi .vn xuất hiện trong danh sách được giữ lại, TRỪ:
  - tên miền có bất kỳ host nào nằm trong danh sách lừa đảo (``--phish-domains``): thường là nền tảng
    cho người dùng tự tạo trang hoặc đã từng bị chiếm quyền, không được miễn kiểm tra;
  - dịch vụ rút gọn link trong ``rules.json``.

Ví dụ:
  python tools/build_popular.py --crux .eval-data/crux_global.csv.gz \
      --phish-domains .eval-data/phishing_domains.txt --out chotto/data/popular_vn.txt
"""
from __future__ import annotations

import argparse
import datetime
import gzip
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from chotto.config import load_rules  # noqa: E402
from chotto.core.url import URLParseError, parse_url  # noqa: E402
from chotto.util import registered_domain  # noqa: E402

HEADER = """\
# Tên miền .vn phổ biến (Chrome UX Report top 1M, CC BY 4.0, https://github.com/zakird/crux-top-lists).
# Dùng để giảm báo nhầm ở Tầng 2; KHÔNG miễn Tầng 1 (danh sách đen vẫn chặn được trang bị chiếm quyền).
# Sinh bởi tools/build_popular.py ngày {date}. Định dạng: tên_miền<TAB>hạng CrUX (1000, 5000, ..., 1000000).
"""


def popular_vn(crux: Path) -> dict[str, int]:
    """{tên miền đăng ký .vn: hạng CrUX tốt nhất}."""
    found: dict[str, int] = {}
    with gzip.open(crux, "rt", encoding="utf-8") as handle:
        next(handle, None)
        for line in handle:
            origin, _, rank = line.strip().rpartition(",")
            if not rank.isdigit():
                continue
            try:
                host = parse_url(origin).host
            except URLParseError:
                continue
            domain = registered_domain(host)
            if domain and domain.endswith(".vn"):
                found[domain] = min(found.get(domain, int(rank)), int(rank))
    return found


def tainted(phish_domains: Path, candidates: set[str]) -> set[str]:
    """Tên miền ứng viên có host nằm trong danh sách lừa đảo."""
    hit: set[str] = set()
    with open(phish_domains, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            host = line.strip().lower()
            if host.endswith(".vn"):
                domain = registered_domain(host)
                if domain in candidates:
                    hit.add(domain)
    return hit


def main(argv: list[str]) -> int:
    """Điểm vào."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--crux", type=Path, required=True)
    parser.add_argument("--phish-domains", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv[1:])
    try:
        domains = popular_vn(args.crux)
        excluded = tainted(args.phish_domains, set(domains))
    except OSError as exc:
        print(f"Lỗi đọc dữ liệu: {exc}", file=sys.stderr)
        return 1
    excluded |= {d for d in domains if d in set(load_rules()["shorteners"])}
    kept = sorted((d for d in domains if d not in excluded), key=lambda d: (domains[d], d))
    body = "".join(f"{domain}\t{domains[domain]}\n" for domain in kept)
    try:
        args.out.write_text(HEADER.format(date=datetime.datetime.now(datetime.timezone.utc).date().isoformat()) + body, "utf-8")
    except OSError as exc:
        print(f"Không ghi được {args.out}: {exc}", file=sys.stderr)
        return 1
    print(f"Ghi {len(kept)} tên miền, loại {len(excluded)}: {', '.join(sorted(excluded))}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
