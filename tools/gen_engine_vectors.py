#!/usr/bin/env python3
"""Sinh bộ test dùng chung ``tests/data/engine_vectors.json``: URL → kết quả của engine Python.

Bộ test này được chạy bởi cả ``tests/test_parity.py`` (Python) và ``extension/tests/parity.test.mjs``
(JavaScript) để bảo đảm bản Desktop và tiện ích trình duyệt cho CÙNG điểm, cùng mức, cùng dấu hiệu và
cùng lời khuyên trên mọi URL. Tầng 3 tắt (cần mạng); Tầng 1 dùng danh sách đen khởi tạo đóng gói kèm.

Nguồn URL: các ca biên viết tay trong file này, mọi URL xuất hiện trong ``tests/*.py``, và (tùy chọn) mẫu
ngẫu nhiên cố định từ danh sách lừa đảo và CrUX.

Ví dụ:
  python tools/gen_engine_vectors.py --phish .eval-data/phishing_links.txt \
      --crux .eval-data/crux_global.csv.gz --sample 1200
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import random
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Final

ROOT: Final[Path] = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

OUT: Final[Path] = ROOT / "tests" / "data" / "engine_vectors.json"
URL_IN_TESTS_RE: Final = re.compile(r"""["'](https?://[^"'\s]+)["']""")

EDGE_CASES: Final[tuple[str, ...]] = (
    "https://vietcombank.com.vn/",
    "https://www.vietcombank.com.vn/vi/KHCN",
    "https://vietcombank-xacthuc.top/login",
    "https://vcb-digibank-xacthuc.top/",
    "https://secure.vcb-digibank.com.vn/otp",
    "https://vcb-login.web.app/",
    "https://xn--vietcmbank-ilb.com/",
    "https://vietc0mbank.com.vn/",
    "https://vietcombsnk.com/",
    "https://mbbnak.com.vn/",
    "https://momo-hoantien.vip/",
    "https://evil.top\\@vietcombank.com.vn/",
    "https://vietcombank.com.vn@evil.top/",
    "http://192.168.1.10:8080/tra-cuu-phat-nguoi",
    "http://3232235777/",
    "https://bit.ly/3xYzAbC",
    "https://l.facebook.com/l.php?u=https%3A%2F%2Fvcb-xacnhan.xyz%2F",
    "https://www.google.com/url?q=https://momo-nhanqua.click/&sa=D",
    "https://zalo.me/redirect?url=aHR0cHM6Ly92Y2Itc2VjdXJlLnRvcC8",
    "https://phish-test.chotto.invalid/",
    "https://a.b.phish-test.chotto.invalid/x",
    "https://dichvucong.gov.vn/p/home/dvc-trang-chu.html",
    "https://thong-bao-phat-nguoi-csgt.com/tra-cuu",
    "https://hoan-thue-tncn.online/X%C3%A1c_Nh%E1%BA%ADn",
    "https://evil.top/vietcombank.com.vn/dang-nhap",
    "https://xk9q2v7z1p.xyz/",
    "https://a-b-c-d.example.com/",
    "https://shopee.vn/",
    "https://tiki.vn/khuyen-mai",
    "https://service.gov.uk/",
    "https://github.io/",
    "https://bidvonline.com/",
    "https://bidv-smartbanking.com/",
    "https://agribank-online24.com/",
    "https://xn--80ak6aa92e.com/",
    "https://xn--mmo-gna.vn/",
    "https://ví-điện-tử.vn/",
    "https://MOMO.vn./",
    "https://example.com:443/",
    "https://example.com:8443/",
    "https://[2001:db8::1]/",
    "https://example.com/?",
    "https://example.com/#",
    "https://t.co/abc?u=https://vcb.top",
    "https://www.facebook.com/l.php?u=https%253A%252F%252Fvcb-otp.top%252F",
    "javascript:alert(1)",
    "https://",
    "https://exa mple.com/",
    "https://xn--zz.com/",
    "https://example.com/" + "a" * 3000,
)


def collect_urls(phish: Path | None, crux: Path | None, sample: int, seed: int) -> list[str]:
    """Danh sách URL không trùng, thứ tự ổn định.

    Raises:
        OSError: Không đọc được file nguồn được chỉ định.
    """
    urls: list[str] = list(EDGE_CASES)
    for test_file in sorted((ROOT / "tests").glob("*.py")):
        urls.extend(URL_IN_TESTS_RE.findall(test_file.read_text("utf-8")))
    rng = random.Random(seed)
    if phish is not None:
        lines = [ln.strip() for ln in phish.read_text("utf-8", "replace").splitlines()]
        lines = [ln for ln in lines if ln.lower().startswith(("http://", "https://")) and len(ln) < 2000]
        urls.extend(rng.sample(lines, min(sample, len(lines))))
    if crux is not None:
        with gzip.open(crux, "rt", encoding="utf-8") as handle:
            next(handle, None)
            origins = [line.split(",", 1)[0] + "/" for line in handle if line.startswith("http")]
        urls.extend(rng.sample(origins, min(sample, len(origins))))
    return list(dict.fromkeys(urls))


def vector(engine: Any, url: str) -> dict[str, Any]:
    """Kết quả engine Python cho một URL (bỏ thời gian chạy)."""
    result = engine.inspect(url)
    return {
        "url": url,
        "score": result.score,
        "level": result.level,
        "tier": result.tier_reached,
        "host": result.host,
        "display_domain": result.display_domain,
        "reasons": result.reasons,
        "signals": [[s["code"], s["points"], s.get("brand", "")] for s in result.signals],
        "advice": result.advice,
    }


def main(argv: list[str] | None = None) -> int:
    """Điểm vào dòng lệnh. Trả về 0 nếu ghi thành công, 2 nếu lỗi đọc/ghi."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--phish", type=Path, help="Danh sách URL lừa đảo (mỗi dòng một URL)")
    parser.add_argument("--crux", type=Path, help="crux_global.csv.gz")
    parser.add_argument("--sample", type=int, default=1200, help="Số URL lấy mẫu từ mỗi nguồn")
    parser.add_argument("--seed", type=int, default=20261022)
    parser.add_argument("--out", type=Path, default=OUT)
    args = parser.parse_args(argv)
    with tempfile.TemporaryDirectory(prefix="chotto-vectors-") as data_dir:
        os.environ["CHOTTO_DATA_DIR"] = data_dir
        from chotto.config import DEFAULTS, load_rules
        from chotto.engine import Engine

        cfg = dict(DEFAULTS, tier3_enabled=False, ai_advice=True)
        engine = Engine(cfg, rules=load_rules())
        try:
            urls = collect_urls(args.phish, args.crux, args.sample, args.seed)
        except OSError as exc:
            print(f"Không đọc được nguồn URL: {exc}", file=sys.stderr)
            return 2
        vectors = [vector(engine, url) for url in urls]
        engine.release()
    payload = {
        "about": "Sinh bởi tools/gen_engine_vectors.py; Tầng 3 tắt, Tầng 1 = danh sách đen khởi tạo.",
        "vectors": vectors,
    }
    try:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(payload, ensure_ascii=False, indent=0) + "\n", "utf-8")
    except OSError as exc:
        print(f"Không ghi được {args.out}: {exc}", file=sys.stderr)
        return 2
    levels: dict[str, int] = {}
    for item in vectors:
        levels[item["level"]] = levels.get(item["level"], 0) + 1
    print(f"Đã ghi {len(vectors)} vector vào {args.out}: {levels}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
