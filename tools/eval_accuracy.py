#!/usr/bin/env python3
"""Đo độ chính xác của Tầng 2 (khả năng bắt link mới, chưa có trong danh sách đen) trên dữ liệu thật.

Dữ liệu (tải bằng ``--download`` vào ``--data``):
  - Âm tính: danh sách trang phổ biến Chrome UX Report (CrUX, CC BY 4.0) qua kho
    github.com/zakird/crux-top-lists. Lấy mọi tên miền .vn trong top 1 triệu, và top 10.000 toàn cầu.
  - Dương tính: Phishing.Database (MIT, github.com/mitchellkrogza/Phishing.Database), danh sách link
    lừa đảo đang hoạt động. Tách riêng tập "nhắm vào Việt Nam" (đuôi .vn hoặc chứa thương hiệu VN).

Tầng 1 và Tầng 3 bị tắt khi đo: con số phản ánh đúng năng lực với link zero-hour.

Danh sách tên miền phổ biến (``popular_vn.txt``) được sinh từ chính CrUX, nên đo trên tên miền đã có trong
danh sách thì báo nhầm bằng 0 theo định nghĩa. Để đo trung thực, ``--holdout`` tách ngẫu nhiên (theo băm
tên miền) một phần tên miền .vn ra khỏi danh sách và báo cáo riêng nhóm này: đó là ước lượng báo nhầm với
trang .vn hợp pháp chưa có trong danh sách (ví dụ trang mới nổi).

Ví dụ:
  python tools/eval_accuracy.py --download --data .eval-data
  python tools/eval_accuracy.py --data .eval-data --report report.md --json report.json
  python tools/eval_accuracy.py --data .eval-data --no-popular          # đo như bản 1.2 (không danh sách)
  python tools/eval_accuracy.py --data .eval-data --weights w.json      # thử bộ trọng số khác
"""
from __future__ import annotations

import argparse
import collections
import gzip
import hashlib
import json
import os
import random
import sys
import tempfile
import time
import urllib.request
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

os.environ.setdefault("CHOTTO_DATA_DIR", tempfile.mkdtemp(prefix="chotto-eval-"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from chotto.config import DEFAULTS, load_popular_domains, load_rules  # noqa: E402
from chotto.core.url import URLParseError, parse_url  # noqa: E402
from chotto.engine import Engine, Result  # noqa: E402
from chotto.tier1 import Blacklist  # noqa: E402
from chotto.util import registered_domain  # noqa: E402

SOURCES: Final[dict[str, str]] = {
    "crux_global.csv.gz": "https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/global/current.csv.gz",
    "phishing_links.txt": "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt",
}
_MAX_DOWNLOAD: Final[int] = 200 * 1024 * 1024


class NoBlacklist(Blacklist):
    """Tắt Tầng 1 khi đo (để đo năng lực với link chưa ai báo cáo)."""

    def __init__(self) -> None:
        """Không mở file nào."""
        self._fp = None
        self._fp_stamp = None
        self._checked = False

    def lookup(self, host: str, path: str = "") -> str | None:
        """Không bao giờ khớp."""
        return None


@dataclass
class Sample:
    """Một URL có nhãn."""

    url: str
    label: int          # 1 = lừa đảo, 0 = hợp pháp
    group: str


@dataclass
class GroupStats:
    """Thống kê của một nhóm mẫu."""

    total: int = 0
    flagged: int = 0
    high: int = 0
    signal_counts: collections.Counter[str] = field(default_factory=collections.Counter)
    examples: list[tuple[str, int, list[str]]] = field(default_factory=list)

    @property
    def rate(self) -> float:
        """Tỷ lệ bị cảnh báo (điểm ≥ ngưỡng friction)."""
        return self.flagged / self.total if self.total else 0.0


def download(data: Path) -> None:
    """Tải dữ liệu nguồn (có giới hạn kích thước).

    Raises:
        OSError: Lỗi mạng hoặc ghi file.
    """
    data.mkdir(parents=True, exist_ok=True)
    for name, url in SOURCES.items():
        target = data / name
        print(f"Tải {url}")
        request = urllib.request.Request(url, headers={"User-Agent": "CHOTTO-eval"})
        with urllib.request.urlopen(request, timeout=120) as response:
            payload = response.read(_MAX_DOWNLOAD + 1)
        if len(payload) > _MAX_DOWNLOAD:
            raise OSError(f"{url} vượt {_MAX_DOWNLOAD} byte")
        target.write_bytes(payload)


def crux_origins(path: Path) -> Iterator[tuple[str, int]]:
    """(origin, rank) từ file CrUX."""
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        next(handle, None)
        for line in handle:
            origin, _, rank = line.strip().rpartition(",")
            if origin.startswith("http") and rank.isdigit():
                yield origin, int(rank)


def in_holdout(domain: str, fraction: float) -> bool:
    """Tách tên miền vào tập giữ riêng theo băm (ổn định giữa các lần chạy và giữa các công cụ)."""
    bucket = int.from_bytes(hashlib.sha256(domain.encode("utf-8")).digest()[:4], "big") / 2**32
    return bucket < fraction


def build_negatives(path: Path, holdout: float = 0.0) -> tuple[list[Sample], set[str]]:
    """Trang hợp pháp: mọi tên miền .vn trong top 1 triệu + top 10.000 toàn cầu; mỗi tên miền đăng ký một mẫu.

    Tên miền .vn thuộc tập giữ riêng (``holdout``) vào nhóm ``vn_holdout``.
    """
    samples: list[Sample] = []
    seen: set[str] = set()
    for origin, rank in crux_origins(path):
        try:
            host = parse_url(origin).host
        except URLParseError:
            continue
        domain = registered_domain(host)
        if not domain or domain in seen:
            continue
        if domain.endswith(".vn"):
            group = "vn_holdout" if in_holdout(domain, holdout) else "vn_popular"
        elif rank <= 10_000:
            group = "global_top10k"
        else:
            continue
        seen.add(domain)
        samples.append(Sample(origin + "/", 0, group))
    return samples, seen


def _vn_targeted(host: str, url: str, brand_keywords: Iterable[str]) -> bool:
    """Tiêu chí độc lập với điểm số: đuôi .vn hoặc chứa tên một thương hiệu VN trong danh sách."""
    lowered = url.lower()
    return host.endswith(".vn") or any(keyword in lowered for keyword in brand_keywords)


def build_positives(path: Path, legit: set[str], rules: dict[str, Any], limit: int, seed: int) -> list[Sample]:
    """Link lừa đảo: toàn bộ tập nhắm VN + mẫu ngẫu nhiên ``limit`` link toàn cầu (mỗi tên miền một link)."""
    brand_keywords = sorted({str(k).lower() for brand in rules["brands"] for k in brand["keywords"]
                             if len(str(k)) >= 4})
    rng = random.Random(seed)
    vn: list[Sample] = []
    others: list[Sample] = []
    seen: set[str] = set()
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            url = line.strip()
            if not url.startswith(("http://", "https://")):
                continue
            try:
                host = parse_url(url).host
            except URLParseError:
                continue
            domain = registered_domain(host) or host
            if domain in legit or domain in seen:
                continue          # trang lừa đảo trên tên miền phổ biến (Google Forms...): ngoài phạm vi
            seen.add(domain)
            (vn if _vn_targeted(host, url, brand_keywords) else others).append(Sample(url, 1, ""))
    for sample in vn:
        sample.group = "phish_vn"
    picked = rng.sample(others, min(limit, len(others)))
    for sample in picked:
        sample.group = "phish_global"
    return vn + picked


def evaluate(samples: list[Sample], engine: Engine, threshold: float, high: float) -> dict[str, GroupStats]:
    """Chạy engine trên từng mẫu, gom thống kê theo nhóm."""
    stats: dict[str, GroupStats] = collections.defaultdict(GroupStats)
    for sample in samples:
        result: Result = engine.inspect(sample.url)
        group = stats[sample.group]
        group.total += 1
        codes = [str(s["code"]) for s in result.signals if int(s["points"]) > 0]
        group.signal_counts.update(set(codes))
        if result.score >= threshold:
            group.flagged += 1
            if sample.label == 0 and len(group.examples) < 40:
                group.examples.append((sample.url, result.score, codes))
        if result.score >= high:
            group.high += 1
    return stats


def render(stats: dict[str, GroupStats], elapsed: float, count: int) -> str:
    """Báo cáo Markdown."""
    names = {"vn_popular": "Trang .vn phổ biến (CrUX top 1M)",
             "vn_holdout": "Trang .vn phổ biến, giữ riêng (KHÔNG có trong danh sách)",
             "global_top10k": "Top 10.000 toàn cầu (CrUX)",
             "phish_vn": "Lừa đảo nhắm VN (đuôi .vn / thương hiệu VN)", "phish_global": "Lừa đảo toàn cầu (mẫu)"}
    lines = ["| Nhóm | Số mẫu | Bị cảnh báo (≥ 30) | Mức HIGH (≥ 60) |", "| --- | ---: | ---: | ---: |"]
    for key in ("vn_popular", "vn_holdout", "global_top10k", "phish_vn", "phish_global"):
        group = stats.get(key)
        if group is None:
            continue
        lines.append(f"| {names[key]} | {group.total} | {group.flagged} ({group.rate:.2%}) | "
                     f"{group.high} ({group.high / group.total:.2%}) |")
    lines.append("")
    lines.append(f"{count} URL trong {elapsed:.1f} giây ({elapsed / count * 1000:.2f} ms/URL).")
    for key in ("vn_popular", "vn_holdout", "global_top10k"):
        group = stats.get(key)
        if group and group.examples:
            lines += ["", f"### Báo nhầm – {names[key]}", "", "| URL | Điểm | Dấu hiệu |", "| --- | ---: | --- |"]
            lines += [f"| {url} | {score} | {', '.join(codes)} |" for url, score, codes in group.examples]
    for key in ("phish_vn", "phish_global"):
        group = stats.get(key)
        if group:
            top = ", ".join(f"{code} {n / group.total:.0%}" for code, n in group.signal_counts.most_common(8))
            lines += ["", f"Dấu hiệu hay gặp – {names[key]}: {top}"]
    return "\n".join(lines) + "\n"


def to_json(stats: dict[str, GroupStats]) -> dict[str, Any]:
    """Kết quả dạng JSON (để so sánh giữa các phiên bản luật)."""
    return {key: {"total": g.total, "flagged": g.flagged, "rate": round(g.rate, 5), "high": g.high,
                  "signals": dict(g.signal_counts.most_common())} for key, g in stats.items()}


def main(argv: list[str]) -> int:
    """Điểm vào."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data", type=Path, default=Path(".eval-data"))
    parser.add_argument("--download", action="store_true", help="tải dữ liệu nguồn trước khi đo")
    parser.add_argument("--rules", type=Path, help="đo với file rules.json khác (mặc định: bản đóng gói)")
    parser.add_argument("--weights", type=Path, help="file JSON {mã trọng số: điểm} ghi đè weights")
    parser.add_argument("--no-popular", action="store_true", help="không dùng danh sách tên miền phổ biến")
    parser.add_argument("--test-split", action="store_true",
                        help="chỉ đo trên mẫu thuộc tập giữ riêng (mọi nhóm), để so với trọng số học từ phần còn lại")
    parser.add_argument("--holdout", type=float, default=0.0,
                        help="tỷ lệ tên miền .vn tách khỏi danh sách phổ biến để đo báo nhầm trung thực (0–1)")
    parser.add_argument("--phish-sample", type=int, default=20_000)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args(argv[1:])
    try:
        if args.download:
            download(args.data)
        if args.rules:
            rules = json.loads(args.rules.read_text("utf-8"))
            rules["popular_domains"] = load_popular_domains()
        else:
            rules = load_rules()
        if args.weights:
            rules["weights"] = {**rules["weights"], **json.loads(args.weights.read_text("utf-8"))}
        if not 0.0 <= args.holdout < 1.0:
            raise ValueError("--holdout phải trong [0, 1)")
        negatives, legit = build_negatives(args.data / "crux_global.csv.gz", args.holdout)
        if args.no_popular:
            rules["popular_domains"] = frozenset()
        else:
            rules["popular_domains"] = frozenset(d for d in rules["popular_domains"]
                                                 if not in_holdout(d, args.holdout))
        positives = build_positives(args.data / "phishing_links.txt", legit, rules, args.phish_sample, args.seed)
    except (OSError, ValueError) as exc:
        print(f"Lỗi dữ liệu: {exc}", file=sys.stderr)
        return 1
    cfg = dict(DEFAULTS, tier3_enabled=False, ai_advice=False)
    engine = Engine(cfg, rules, blacklist=NoBlacklist(), age_lookup=lambda host: None)
    samples = negatives + positives
    if args.test_split:
        samples = [s for s in samples if in_holdout(registered_domain(parse_url(s.url).host) or parse_url(s.url).host,
                                                    args.holdout)]
    started = time.perf_counter()
    stats = evaluate(samples, engine, float(rules["thresholds"]["friction"]), float(rules["thresholds"]["high"]))
    report = render(stats, time.perf_counter() - started, len(samples))
    print(report)
    if args.report:
        args.report.write_text(report, "utf-8")
    if args.json:
        args.json.write_text(json.dumps(to_json(stats), ensure_ascii=False, indent=2), "utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
