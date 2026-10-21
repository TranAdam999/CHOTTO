"""Hàm tiện ích dùng chung: tên miền, khoảng cách chỉnh sửa, homoglyph, chuẩn hóa tiếng Việt, entropy."""
from __future__ import annotations

import functools
import ipaddress
import json
import logging
import math
import re
import unicodedata
from collections import Counter
from collections.abc import Iterator
from typing import Final
from urllib.parse import unquote

from .core.psl import default_psl
from .core.url import URLParseError, domain_to_ascii

__all__ = [
    "damerau_levenshtein",
    "fold_vietnamese",
    "homoglyph_normalize",
    "in_domain",
    "is_ip",
    "is_private_suffix_host",
    "levenshtein",
    "normalize_for_matching",
    "normalize_host",
    "parent_domains",
    "public_suffix",
    "registered_domain",
    "sanitize_for_display",
    "shannon_entropy",
    "skeleton",
    "tld_of",
]

_LOG = logging.getLogger(__name__)

# Thay thế nhiều ký tự trông giống một ký tự (áp dụng trước bảng một-ký-tự).
_MULTI_CHAR_HOMOGLYPHS: Final[tuple[tuple[str, str], ...]] = (("rn", "m"), ("vv", "w"), ("nn", "m"))
# Chữ số/ký hiệu thay chữ cái thường gặp trong tên miền giả mạo.
_ASCII_HOMOGLYPHS: Final[dict[str, str]] = {"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "7": "t", "8": "b"}
# Chỉ giữ các ánh xạ nhất quán với bản cũ cho homoglyph_normalize (tương thích ngược).
_LEGACY_HOMOGLYPHS: Final[tuple[tuple[str, str], ...]] = (("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"))
_BIDI_AND_INVISIBLE_CATEGORIES: Final[frozenset[str]] = frozenset({"Cc", "Cf", "Co", "Cs", "Zl", "Zp"})
_NON_ALNUM_RE: Final = re.compile(r"[^a-z0-9]+")


def normalize_host(host: str | None) -> str:
    """Chuẩn hóa host về ASCII chữ thường như trình duyệt; không bao giờ ném lỗi.

    Args:
        host: Host thô (có thể ``None``, chữ hoa, Unicode, dấu chấm cuối).

    Returns:
        Host đã chuẩn hóa; nếu không chuẩn hóa được thì trả về dạng chữ thường đã cắt khoảng trắng.
    """
    text = (host or "").strip()
    if not text:
        return ""
    if text.startswith("[") and text.endswith("]"):
        try:
            return f"[{ipaddress.IPv6Address(text[1:-1]).compressed}]"
        except ValueError:
            return text.lower()
    try:
        return domain_to_ascii(text)
    except URLParseError:
        return text.lower().rstrip(".")


def is_ip(host: str) -> bool:
    """``True`` nếu ``host`` là địa chỉ IPv4/IPv6 (chấp nhận IPv6 trong ngoặc vuông)."""
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def public_suffix(host: str) -> str:
    """Hậu tố công cộng của ``host`` theo PSL (``com.vn``, ``web.app``...)."""
    return default_psl().lookup(host).suffix


def registered_domain(host: str) -> str:
    """Tên miền đăng ký được của ``host`` theo PSL.

    Trả về chính ``host`` nếu host là IP hoặc bản thân là hậu tố công cộng (không có tên miền
    đăng ký được), để hàm gọi luôn nhận một chuỗi có nghĩa.
    """
    if not host or is_ip(host):
        return host
    return default_psl().lookup(host).registrable or host


def is_private_suffix_host(host: str) -> bool:
    """``True`` nếu host nằm dưới hậu tố PRIVATE (nền tảng hosting: ``web.app``, ``github.io``...).

    Với những host này, phần do kẻ gian kiểm soát là subdomain, còn tuổi của nền tảng không nói
    lên điều gì về trang đích.
    """
    if not host or is_ip(host):
        return False
    return default_psl().lookup(host).is_private


def tld_of(host: str) -> str:
    """Nhãn cuối cùng của host (TLD), chữ thường."""
    return host.rstrip(".").rsplit(".", 1)[-1].lower()


def in_domain(host: str, domain: str) -> bool:
    """``True`` nếu ``host`` bằng ``domain`` hoặc là subdomain của nó."""
    return host == domain or host.endswith("." + domain)


def parent_domains(host: str) -> Iterator[str]:
    """Sinh ``host`` và các tên miền cha, dừng ở tên miền đăng ký được (không bao giờ sinh ``com.vn``).

    Với IP hoặc host là hậu tố công cộng, chỉ sinh chính host.
    """
    if not host:
        return
    yield host
    if is_ip(host):
        return
    registrable = default_psl().lookup(host).registrable
    if registrable is None or registrable == host:
        return
    labels = host.split(".")
    stop = len(registrable.split("."))
    for index in range(1, len(labels) - stop + 1):
        yield ".".join(labels[index:])


@functools.lru_cache(maxsize=1)
def _confusables() -> dict[str, str]:
    """Bảng ký tự Unicode trông giống chữ/số ASCII (rút gọn từ Unicode TR39 confusables.txt)."""
    from .config import resource_path

    try:
        data = json.loads(resource_path("data", "confusables_ascii.json").read_text("utf-8"))
    except (OSError, ValueError):
        _LOG.exception("Không nạp được bảng confusables; dùng bảng rỗng")
        return {}
    if not isinstance(data, dict):
        _LOG.error("confusables_ascii.json không phải object; dùng bảng rỗng")
        return {}
    return {str(k): str(v) for k, v in data.items()}


def homoglyph_normalize(text: str) -> str:
    """Thay các cặp ký tự đánh lừa thị giác cơ bản (``rn→m``, ``vv→w``, ``0→o``, ``1→l``).

    Giữ hành vi cũ để tương thích; phân tích mới dùng ``skeleton``.
    """
    for source, target in _LEGACY_HOMOGLYPHS:
        text = text.replace(source, target)
    return text


def skeleton(text: str) -> str:
    """Dạng "khung xương" để so khớp mạo danh: mọi ký tự trông giống nhau quy về cùng một chữ ASCII.

    Gồm: NFKC, chữ thường, bảng confusables Unicode (Cyrillic ``а``→``a``...), bỏ dấu tiếng Việt,
    cặp nhiều ký tự (``rn``→``m``) và chữ số thay chữ (``0``→``o``, ``1``→``l``).
    """
    table = _confusables()
    lowered = unicodedata.normalize("NFKC", text).lower()
    mapped = "".join(table.get(ch, ch) for ch in lowered)
    mapped = fold_vietnamese(mapped)
    for source, target in _MULTI_CHAR_HOMOGLYPHS:
        mapped = mapped.replace(source, target)
    return "".join(_ASCII_HOMOGLYPHS.get(ch, ch) for ch in mapped)


def levenshtein(a: str, b: str) -> int:
    """Khoảng cách Levenshtein (chèn, xóa, thay thế)."""
    if a == b:
        return 0
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def damerau_levenshtein(a: str, b: str, max_distance: int | None = None) -> int:
    """Khoảng cách Damerau–Levenshtein dạng OSA (thêm phép đảo hai ký tự kề nhau).

    ``mbbnak`` so với ``mbbank`` có khoảng cách 1 (Levenshtein thường cho 2).

    Args:
        a: Chuỗi thứ nhất.
        b: Chuỗi thứ hai.
        max_distance: Nếu đặt, dừng sớm và trả về ``max_distance + 1`` khi chắc chắn vượt ngưỡng.

    Returns:
        Số phép biến đổi tối thiểu.
    """
    if a == b:
        return 0
    if max_distance is not None and abs(len(a) - len(b)) > max_distance:
        return max_distance + 1
    rows = len(a) + 1
    cols = len(b) + 1
    two_back: list[int] = []
    previous = list(range(cols))
    for i in range(1, rows):
        current = [i] + [0] * (cols - 1)
        for j in range(1, cols):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            value = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                value = min(value, two_back[j - 2] + 1)
            current[j] = value
        if max_distance is not None and min(current) > max_distance:
            return max_distance + 1
        two_back, previous = previous, current
    return previous[-1]


def fold_vietnamese(text: str) -> str:
    """Bỏ dấu tiếng Việt: ``xác nhận`` → ``xac nhan``, ``đ``/``Đ`` → ``d``/``D``."""
    decomposed = unicodedata.normalize("NFD", text.replace("đ", "d").replace("Đ", "D"))
    return unicodedata.normalize("NFC", "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn"))


def normalize_for_matching(text: str, max_unquote_rounds: int = 3) -> str:
    """Chuẩn hóa văn bản URL để so từ khóa tiếng Việt.

    Các bước: giải mã ``%XX`` lặp lại (tối đa ``max_unquote_rounds`` lớp), chuẩn NFC, chữ thường,
    bỏ dấu, rồi gộp mọi chuỗi ký tự không phải chữ/số thành một dấu ``-``.
    ``/X%C3%A1c_Nh%E1%BA%ADn`` → ``xac-nhan``.

    Args:
        text: Đường dẫn/truy vấn/host thô.
        max_unquote_rounds: Số lớp percent-encoding tối đa được giải.

    Returns:
        Chuỗi chỉ gồm ``[a-z0-9-]``, không có ``-`` ở đầu/cuối.
    """
    decoded = text
    for _ in range(max_unquote_rounds):
        nxt = unquote(decoded, errors="replace")
        if nxt == decoded:
            break
        decoded = nxt
    folded = fold_vietnamese(unicodedata.normalize("NFC", decoded).lower())
    return _NON_ALNUM_RE.sub("-", folded).strip("-")


def sanitize_for_display(text: str) -> str:
    """Bỏ ký tự điều khiển, ký tự vô hình và ký tự đảo chiều văn bản (U+202E...) trước khi hiển thị."""
    return "".join(
        "�" if unicodedata.category(ch) in _BIDI_AND_INVISIBLE_CATEGORIES else ch for ch in text
    )


def shannon_entropy(text: str) -> float:
    """Entropy Shannon (bit/ký tự) của chuỗi; chuỗi rỗng cho 0."""
    if not text:
        return 0.0
    length = len(text)
    return -sum(count / length * math.log2(count / length) for count in Counter(text).values())
