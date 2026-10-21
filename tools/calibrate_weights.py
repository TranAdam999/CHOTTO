#!/usr/bin/env python3
"""Hiệu chỉnh trọng số Tầng 2 bằng hồi quy logistic trên dữ liệu thật, rồi quy đổi về thang điểm 0–100.

Quy trình (tách train/test theo băm tên miền, cùng hàm băm với ``eval_accuracy.py --holdout``):
  1. Mỗi URL thành véc-tơ đặc trưng: một cột 0/1 cho mỗi mã dấu hiệu, riêng ``lure`` là số từ khóa.
     Đặc trưng lấy từ chính ``tier2.analyze`` nên mỗi điểm số vẫn gắn với một lý do tiếng Việt.
  2. Hồi quy logistic có chuẩn hóa L2 trên tập train (gộp các véc-tơ trùng nhau nên chạy trong vài giây).
  3. Chọn ngưỡng logit τ lớn nhất-bắt-nhiều-nhất sao cho báo nhầm trên trang .vn phổ biến (train) ≤ mục tiêu.
  4. Quy đổi: điểm_i = hệ_số_i × 30 / τ (ngưỡng cảnh báo 30 giữ nguyên), kẹp trong [0, 60].
     Dấu hiệu có ít hơn ``--min-support`` lần xuất hiện ở tập train giữ trọng số viết tay (không đủ dữ liệu).

Kết quả: file JSON trọng số (dùng với ``eval_accuracy.py --weights``) và bảng so sánh Markdown.
Chỉ đưa trọng số mới vào ``rules.json`` khi chúng tốt hơn trên tập TEST.
"""
from __future__ import annotations

import argparse
import collections
import importlib.util
import json
import math
import sys
from pathlib import Path
from typing import Any, Final

_TOOLS = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("eval_accuracy", _TOOLS / "eval_accuracy.py")
if _spec is None or _spec.loader is None:
    raise ImportError("Không nạp được tools/eval_accuracy.py")
eval_accuracy = importlib.util.module_from_spec(_spec)
sys.modules["eval_accuracy"] = eval_accuracy        # dataclass cần module đã đăng ký
_spec.loader.exec_module(eval_accuracy)

from chotto import tier2  # noqa: E402
from chotto.config import load_rules  # noqa: E402
from chotto.core.url import URLParseError, parse_url  # noqa: E402
from chotto.util import registered_domain  # noqa: E402

# Mã dấu hiệu → khóa trọng số trong rules.json.
WEIGHT_KEY: Final[dict[str, str]] = {
    "typosquat": "typosquat", "homoglyph": "homoglyph", "combosquat": "combosquat", "lure": "lure_each",
    "tld": "high_risk_tld", "entropy": "entropy", "hyphens": "hyphens", "digits": "random_digits",
    "raw_ip": "raw_ip", "at_sign": "at_sign", "http": "http", "idn": "idn", "shortener": "shortener",
    "nested_redirect": "nested_redirect", "port": "port", "free_hosting": "free_hosting",
    "redirect_via_trusted": "redirect_via_trusted", "brand_in_path": "brand_in_path",
}
CODES: Final[tuple[str, ...]] = tuple(WEIGHT_KEY)
_MAX_POINTS: Final[int] = 60

Vector = tuple[int, ...]


def features(url: str, rules: dict[str, Any]) -> Vector | None:
    """Véc-tơ đặc trưng của ``url`` theo thứ tự ``CODES`` (``None`` nếu URL không phân tích được)."""
    try:
        result = tier2.analyze(parse_url(url), rules)
    except URLParseError:
        return None
    lure_each = max(1, int(rules["weights"]["lure_each"]))
    values = dict.fromkeys(CODES, 0)
    for signal in result.signals:
        if signal.code == "lure":
            values["lure"] = max(1, round(signal.points / lure_each))
        elif signal.code in values:
            values[signal.code] = 1
    return tuple(values[c] for c in CODES)


def fit_logistic(rows: dict[Vector, list[int]], l2: float, iterations: int = 3000,
                 rate: float = 0.5) -> tuple[float, list[float]]:
    """Hồi quy logistic (gradient descent toàn lô) trên dữ liệu đã gộp ``{véc-tơ: [số âm, số dương]}``.

    Mẫu dương và âm được cân bằng trọng lượng (mỗi lớp đóng góp như nhau) để hệ số không phụ thuộc tỷ lệ
    lớp của bộ dữ liệu; ngưỡng được chọn riêng ở bước sau.

    Returns:
        (hệ số chặn, các hệ số theo thứ tự ``CODES``).
    """
    total_neg = sum(c[0] for c in rows.values()) or 1
    total_pos = sum(c[1] for c in rows.values()) or 1
    width = len(CODES)
    bias = 0.0
    coef = [0.0] * width
    items = [(vector, counts[0] / total_neg, counts[1] / total_pos) for vector, counts in rows.items()]
    for _ in range(iterations):
        grad_b = 0.0
        grad = [0.0] * width
        for vector, w_neg, w_pos in items:
            z = bias + sum(c * x for c, x in zip(coef, vector))
            p = 1.0 / (1.0 + math.exp(-z)) if z > -60 else 0.0
            err = (w_neg + w_pos) * p - w_pos         # đạo hàm log-loss có trọng số theo z
            grad_b += err
            for i, x in enumerate(vector):
                if x:
                    grad[i] += err * x
        bias -= rate * grad_b
        coef = [c - rate * (g + l2 * c) for c, g in zip(coef, grad)]
    return bias, coef


def choose_threshold(rows: dict[Vector, list[int]], coef: list[float], target_fpr: float,
                     negatives_vn: dict[Vector, int]) -> float:
    """Ngưỡng τ (trên Σ hệ số × đặc trưng) nhỏ nhất mà báo nhầm trên trang .vn (train) ≤ ``target_fpr``."""
    total_vn = sum(negatives_vn.values()) or 1
    scores = sorted({sum(c * x for c, x in zip(coef, v)) for v in rows} | {0.0})
    for tau in scores:
        if tau <= 0:
            continue
        false_pos = sum(n for v, n in negatives_vn.items() if sum(c * x for c, x in zip(coef, v)) >= tau)
        if false_pos / total_vn <= target_fpr:
            return tau
    return max(scores) + 1.0


def main(argv: list[str]) -> int:
    """Điểm vào."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data", type=Path, default=Path(".eval-data"))
    parser.add_argument("--test-fraction", type=float, default=0.5)
    parser.add_argument("--target-fpr", type=float, default=0.005)
    parser.add_argument("--l2", type=float, default=0.001)
    parser.add_argument("--min-support", type=int, default=500)
    parser.add_argument("--phish-sample", type=int, default=20_000)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--out", type=Path, required=True, help="file JSON trọng số mới")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv[1:])

    rules = load_rules()
    rules["popular_domains"] = frozenset()        # học trên đặc trưng thô, không có danh sách phổ biến
    try:
        negatives, legit = eval_accuracy.build_negatives(args.data / "crux_global.csv.gz")
        positives = eval_accuracy.build_positives(args.data / "phishing_links.txt", legit, rules,
                                                  args.phish_sample, args.seed)
    except (OSError, ValueError) as exc:
        print(f"Lỗi dữ liệu: {exc}", file=sys.stderr)
        return 1

    train: dict[Vector, list[int]] = collections.defaultdict(lambda: [0, 0])
    train_vn: collections.Counter[Vector] = collections.Counter()
    support: collections.Counter[str] = collections.Counter()
    for sample in negatives + positives:
        host = parse_url(sample.url).host
        if eval_accuracy.in_holdout(registered_domain(host) or host, args.test_fraction):
            continue                                  # tập TEST: không được nhìn khi học
        vector = features(sample.url, rules)
        if vector is None:
            continue
        train[vector][sample.label] += 1
        if sample.group == "vn_popular":
            train_vn[vector] += 1
        support.update(code for code, x in zip(CODES, vector) if x)

    bias, coef = fit_logistic(train, args.l2)
    tau = choose_threshold(train, coef, args.target_fpr, train_vn)
    old = rules["weights"]
    new: dict[str, int] = {}
    lines = ["| Dấu hiệu | Số lần (train) | Hệ số LR | Trọng số cũ | Trọng số mới |",
             "| --- | ---: | ---: | ---: | ---: |"]
    for code, c in zip(CODES, coef):
        key = WEIGHT_KEY[code]
        if support[code] >= args.min_support:
            new[key] = max(0, min(_MAX_POINTS, round(c * 30 / tau)))
            shown = str(new[key])
        else:
            shown = f"{old[key]} (giữ, ít dữ liệu)"
        lines.append(f"| {code} | {support[code]} | {c:+.2f} | {old[key]} | {shown} |")
    summary = (f"Hệ số chặn {bias:+.2f}; ngưỡng τ = {tau:.2f} (báo nhầm .vn train ≤ {args.target_fpr:.2%}); "
               f"{sum(sum(v) for v in train.values())} mẫu train.")
    report = "\n".join(lines) + "\n\n" + summary + "\n"
    print(report)
    try:
        args.out.write_text(json.dumps(new, indent=2) + "\n", "utf-8")
        if args.report:
            args.report.write_text(report, "utf-8")
    except OSError as exc:
        print(f"Không ghi được kết quả: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
