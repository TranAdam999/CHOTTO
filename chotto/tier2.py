"""Tầng 2 – Heuristics bản địa hóa tiếng Việt, chạy hoàn toàn trên máy.

Sáu nhóm đặc trưng theo đề án: (1) bóc link bọc trung gian, (2) mạo danh thương hiệu
(combosquat/typosquat/homoglyph), (3) từ khóa bẫy tâm lý tiếng Việt, (4) TLD rủi ro cao,
(5) entropy/gạch ngang/chữ số, (6) bất thường giao thức và mạng. Mọi phân tích làm trên
``ParsedURL`` (cách trình duyệt hiểu URL), và chỉ trên phần tên miền do kẻ gian kiểm soát
(bỏ hậu tố công cộng như ``com.vn`` hay ``web.app``).
"""
from __future__ import annotations

import base64
import binascii
import functools
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any, Final
from urllib.parse import parse_qsl, unquote

from .core.psl import default_psl
from .core.url import ParsedURL, URLParseError, domain_to_unicode, parse_url
from .util import (
    damerau_levenshtein,
    fold_vietnamese,
    in_domain,
    is_private_suffix_host,
    normalize_for_matching,
    registered_domain,
    shannon_entropy,
    skeleton,
    tld_of,
)

__all__ = [
    "Signal",
    "Tier2Result",
    "UnwrapResult",
    "analyze",
    "attacker_labels",
    "embedded_urls",
    "extract_url",
    "is_trusted",
    "unwrap",
]

_TOKEN_SPLIT_RE: Final = re.compile(r"[-_]+")
# Hậu tố PRIVATE của cơ quan nhà nước (service.gov.uk, gov.ru...) không phải nền tảng ai cũng lập trang được.
_GOVERNMENT_LABELS: Final[frozenset[str]] = frozenset({"gov", "govt", "gob", "gouv", "mil"})
_MAX_EMBEDDED: Final[int] = 5


@dataclass(frozen=True)
class Signal:
    """Một dấu hiệu rủi ro kèm điểm và lý do tiếng Việt hiển thị cho người dùng."""

    code: str
    points: int
    reason: str
    brand: str = ""


@dataclass(frozen=True)
class UnwrapResult:
    """Kết quả bóc link bọc.

    Attributes:
        final: URL đích cuối cùng sau khi bóc.
        chain: Toàn bộ chuỗi URL từ link gốc tới đích (gồm cả hai đầu).
        exhausted: ``True`` nếu đã bóc tới giới hạn mà đích vẫn còn là link bọc.
    """

    final: ParsedURL
    chain: tuple[ParsedURL, ...]
    exhausted: bool


@dataclass(frozen=True)
class Tier2Result:
    """Kết quả Tầng 2.

    Attributes:
        score: Tổng điểm 0–100.
        signals: Các dấu hiệu đã phát hiện.
        final: URL được chấm điểm (đích sau khi bóc, hoặc URL nhúng nếu đi qua tên miền tin cậy).
        chain: Chuỗi URL từ link gốc tới đích.
        trusted: ``True`` nếu đích thuộc tên miền tin cậy.
    """

    score: int
    signals: tuple[Signal, ...]
    final: ParsedURL
    chain: tuple[ParsedURL, ...]
    trusted: bool


def _try_parse(candidate: str) -> ParsedURL | None:
    """Phân tích ``candidate`` nếu là URL http(s) hợp lệ, ngược lại ``None``."""
    text = candidate.strip()
    if text.startswith("//"):
        text = "https:" + text
    if not text.lower().startswith(("http://", "https://")):
        return None
    try:
        return parse_url(text)
    except URLParseError:
        return None


def extract_url(value: str) -> ParsedURL | None:
    """Thử đọc ``value`` (tham số của link bọc) thành URL http(s).

    Chấp nhận: nguyên bản, mã hóa ``%`` một đến hai lớp nữa, base64 (chuẩn hoặc URL-safe),
    và dạng ``//host/path``.
    """
    candidates = [value]
    for _ in range(2):
        candidates.append(unquote(candidates[-1]))
    raw = value.strip()
    if raw and len(raw) <= 8192:
        padded = raw + "=" * (-len(raw) % 4)
        try:
            decoded = base64.b64decode(padded.replace("-", "+").replace("_", "/"), validate=True)
            candidates.append(decoded.decode("utf-8"))
        except (binascii.Error, ValueError):
            pass
    for candidate in candidates:
        parsed = _try_parse(candidate)
        if parsed is not None:
            return parsed
    return None


def _wrapper_matches(url: ParsedURL, wrapper: dict[str, Any]) -> bool:
    """``True`` nếu ``url`` khớp mô tả link bọc trong ``rules.json``."""
    host = str(wrapper["host"])
    host_ok = in_domain(url.host, host) if wrapper.get("match") == "suffix" else url.host == host
    return host_ok and url.path.startswith(str(wrapper["path"]))


def _wrapper_target(url: ParsedURL, rules: dict[str, Any]) -> tuple[bool, ParsedURL | None]:
    """Đích của link bọc. Trả về (url có phải link bọc không, URL đích nếu bóc được)."""
    query_pairs = parse_qsl(url.query or "", keep_blank_values=True)
    is_wrapper = False
    for wrapper in rules["wrappers"]:
        if not _wrapper_matches(url, wrapper):
            continue
        target_kind = wrapper.get("target", "params")
        if target_kind == "path":
            is_wrapper = True
            rest = url.path[len(str(wrapper["path"])):]
            scheme = str(wrapper.get("scheme", "https"))
            candidate = f"{scheme}://{rest}" + (f"?{url.query}" if url.query else "")
            parsed = _try_parse(candidate)
            if parsed is not None:
                return True, parsed
        elif target_kind == "query":
            is_wrapper = True
            parsed = extract_url(unquote(url.query or ""))
            if parsed is not None:
                return True, parsed
        else:
            names = [str(p) for p in wrapper.get("params", [])]
            wildcard = "*" in names
            ordered = [n for n in names if n != "*"]
            if wildcard:
                ordered += [k for k, _ in query_pairs if k not in ordered]
            for name in ordered:
                for key, value in query_pairs:
                    if key != name:
                        continue
                    if not wildcard:
                        is_wrapper = True
                    parsed = extract_url(value)
                    if parsed is not None:
                        return True, parsed
    return is_wrapper, None


def unwrap(url: str | ParsedURL, rules: dict[str, Any], depth: int | None = None) -> UnwrapResult:
    """Bóc các lớp link bọc trung gian (``l.messenger.com``, ``google.com/url``, ``zalo.me``...).

    Args:
        url: URL gốc (chuỗi hoặc đã phân tích).
        rules: Bộ luật chứa ``wrappers`` và ``thresholds.unwrap_depth``.
        depth: Số lớp tối đa; mặc định lấy từ bộ luật.

    Returns:
        ``UnwrapResult`` với đích cuối, chuỗi bóc và cờ "vẫn còn lớp bọc khi hết giới hạn".

    Raises:
        URLParseError: ``url`` là chuỗi không phân tích được.
    """
    current = url if isinstance(url, ParsedURL) else parse_url(url)
    limit = int(depth if depth is not None else rules["thresholds"]["unwrap_depth"])
    chain = [current]
    seen = {current.href}
    for _ in range(limit):
        _, target = _wrapper_target(current, rules)
        if target is None or target.href in seen:
            return UnwrapResult(current, tuple(chain), exhausted=False)
        current = target
        chain.append(current)
        seen.add(current.href)
    still_wrapped, _ = _wrapper_target(current, rules)
    return UnwrapResult(current, tuple(chain), exhausted=still_wrapped)


def embedded_urls(url: ParsedURL, limit: int = _MAX_EMBEDDED) -> list[ParsedURL]:
    """Các URL http(s) nhúng trong tham số truy vấn của ``url`` (khác tên miền đăng ký với ``url``)."""
    found: list[ParsedURL] = []
    own = registered_domain(url.host)
    for _, value in parse_qsl(url.query or "", keep_blank_values=False):
        parsed = extract_url(value)
        if parsed is not None and registered_domain(parsed.host) != own:
            found.append(parsed)
            if len(found) >= limit:
                break
    return found


def is_trusted(host: str, rules: dict[str, Any]) -> bool:
    """``True`` nếu host thuộc danh sách tin cậy, tên miền chính thức của một thương hiệu, hoặc tên miền
    .vn phổ biến (``rules["popular_domains"]``, từ CrUX).

    Tên miền tin cậy chỉ được miễn chấm điểm Tầng 2; Tầng 1 vẫn kiểm tra (trang bị chiếm quyền vẫn bị chặn)
    và URL nhúng trong tham số vẫn được chấm điểm (chống chuyển hướng mở).
    """
    if any(in_domain(host, d) for d in rules["trusted_domains"]):
        return True
    if any(in_domain(host, d) for brand in rules["brands"] for d in brand["domains"]):
        return True
    popular = rules.get("popular_domains")
    return isinstance(popular, frozenset) and registered_domain(host) in popular


def attacker_labels(host: str) -> list[str]:
    """Các nhãn tên miền do người đăng ký kiểm soát (bỏ hậu tố công cộng).

    ``secure.vcb-digibank.com.vn`` → ``["secure", "vcb-digibank"]``;
    ``vcb-login.web.app`` → ``["vcb-login"]``.
    """
    info = default_psl().lookup(host)
    labels = host.split(".")
    suffix_len = len(info.suffix.split(".")) if info.suffix else 0
    return labels[: len(labels) - suffix_len] if suffix_len < len(labels) else []


@functools.lru_cache(maxsize=64)
def _affix_set(affixes: tuple[str, ...]) -> frozenset[str]:
    """Tập phụ tố đã chuẩn hóa (cache theo nội dung bộ luật)."""
    return frozenset(a.lower() for a in affixes if a)


def _is_affix_sequence(text: str, affixes: frozenset[str]) -> bool:
    """``True`` nếu ``text`` ghép được hoàn toàn từ các phụ tố (``online``, ``smart``...) và cụm chữ số."""
    if not text:
        return True
    reachable = [False] * (len(text) + 1)
    reachable[0] = True
    for start in range(len(text)):
        if not reachable[start]:
            continue
        end = start
        while end < len(text) and text[end].isdigit():
            end += 1
            reachable[end] = True
        for affix in affixes:
            if text.startswith(affix, start):
                reachable[start + len(affix)] = True
    return reachable[len(text)]


def _short_keyword_match(token: str, keyword: str, affixes: frozenset[str]) -> bool:
    """Từ khóa thương hiệu ngắn (< 5 ký tự như ``vcb``, ``bidv``) chỉ khớp khi phần còn lại là phụ tố."""
    if token == keyword:
        return True
    if token.startswith(keyword):
        return _is_affix_sequence(token[len(keyword):], affixes)
    if token.endswith(keyword):
        return _is_affix_sequence(token[: -len(keyword)], affixes)
    return False


def _keyword_in(token: str, keyword: str, affixes: frozenset[str]) -> bool:
    """So khớp từ khóa thương hiệu trong một token theo độ dài từ khóa."""
    if len(keyword) >= 5:
        return keyword in token
    return _short_keyword_match(token, keyword, affixes)


def _brand_signal(labels: Sequence[str], rules: dict[str, Any]) -> Signal | None:
    """Tìm dấu hiệu mạo danh thương hiệu mạnh nhất trong các nhãn do kẻ gian kiểm soát."""
    weights = rules["weights"]
    affixes = _affix_set(tuple(str(a) for a in rules["brand_affixes"]))
    ascii_tokens: list[str] = []
    unicode_tokens: list[str] = []
    for label in labels:
        unicode_label = domain_to_unicode(label)
        ascii_tokens.extend(t for t in _TOKEN_SPLIT_RE.split(label) if t)
        ascii_tokens.append(label.replace("-", "").replace("_", ""))
        unicode_tokens.extend(t for t in _TOKEN_SPLIT_RE.split(unicode_label) if t)
        unicode_tokens.append(unicode_label.replace("-", "").replace("_", ""))

    best: Signal | None = None

    def consider(signal: Signal) -> None:
        nonlocal best
        if best is None or signal.points > best.points:
            best = signal

    for brand in rules["brands"]:
        name = str(brand["name"])
        for raw_keyword in brand["keywords"]:
            keyword = str(raw_keyword).lower()
            raw_hit = False
            for token in ascii_tokens:
                if not token.startswith("xn--") and _keyword_in(token, keyword, affixes):
                    raw_hit = True
                    consider(Signal("combosquat", int(weights["combosquat"]),
                                    f"Tên miền chứa tên “{name}” nhưng không phải trang chính thức", name))
                    break
            if raw_hit:
                continue
            for token in unicode_tokens:
                plain = fold_vietnamese(token.lower())
                shape = skeleton(token)
                if shape != plain and _keyword_in(shape, keyword, affixes):
                    consider(Signal("homoglyph", int(weights["homoglyph"]),
                                    f"Dùng ký tự đánh lừa thị giác (0/o, 1/l, rn/m, chữ Nga…) để mạo danh {name}",
                                    name))
                    break
            if len(keyword) < 5:
                continue
            threshold = 1 if len(keyword) < 8 else 2
            for token in ascii_tokens:
                if len(token) < 5 or abs(len(token) - len(keyword)) > 2:
                    continue
                distance = damerau_levenshtein(token, keyword, max_distance=threshold)
                if 0 < distance <= threshold:
                    consider(Signal("typosquat", int(weights["typosquat"]),
                                    f"Dấu hiệu mạo danh thương hiệu {name} (sai lệch {distance} ký tự)", name))
                    break
    return best


def _lure_signal(labels: Sequence[str], url: ParsedURL, rules: dict[str, Any]) -> Signal | None:
    """Từ khóa bẫy tâm lý tiếng Việt trong tên miền, đường dẫn và truy vấn (có dấu hoặc không dấu)."""
    weights = rules["weights"]
    host_text = normalize_for_matching("-".join(domain_to_unicode(label) for label in labels))
    host_flat = host_text.replace("-", "")
    path_text = normalize_for_matching(url.path_and_query)
    path_flat = path_text.replace("-", "")
    padded_host = f"-{host_text}-"
    padded_path = f"-{path_text}-"
    found: dict[str, str] = {}      # dạng so khớp → dạng hiển thị (tiếng Việt có dấu như trong rules.json)
    for raw_keyword in rules["lure_keywords"]:
        display = " ".join(str(raw_keyword).split())
        keyword = normalize_for_matching(display)
        if not keyword or keyword in found:
            continue
        flat = keyword.replace("-", "")
        if (
            f"-{keyword}-" in padded_host
            or f"-{keyword}-" in padded_path
            or (len(flat) >= 6 and flat in host_flat)
            or (len(flat) >= 7 and flat in path_flat)
        ):
            found[keyword] = display
    if not found:
        return None
    # Từ khóa dài hơn bao trùm từ khóa ngắn (tra-cuu-phat-nguoi ⊃ phat-nguoi): đếm một lần.
    distinct = [k for k in found if not any(k != other and k in other for other in found)]
    points = min(int(weights["lure_cap"]), int(weights["lure_each"]) * len(distinct))
    return Signal("lure", points, f"Chứa từ khóa gây hoang mang: “{found[distinct[0]]}”")


def _brand_domain_in_path(url: ParsedURL, rules: dict[str, Any]) -> Signal | None:
    """Tên miền chính thức của thương hiệu nằm trong đường dẫn/truy vấn (``evil.top/vietcombank.com.vn/``)."""
    text = unquote(url.path_and_query).lower()
    for brand in rules["brands"]:
        for domain in brand["domains"]:
            pattern = r"(?<![a-z0-9-])" + re.escape(str(domain).lower()) + r"(?![a-z0-9-])"
            if re.search(pattern, text):
                name = str(brand["name"])
                return Signal("brand_in_path", int(rules["weights"]["brand_in_path"]),
                              f"Đường dẫn chèn địa chỉ {domain} để giả làm trang của {name}", name)
    return None


def _lexical_signals(labels: Sequence[str], host: str, rules: dict[str, Any]) -> list[Signal]:
    """TLD rủi ro, IDN, entropy, gạch ngang, chữ số ngẫu nhiên, hosting miễn phí."""
    weights, thresholds = rules["weights"], rules["thresholds"]
    signals: list[Signal] = []
    tld = tld_of(host)
    if tld in rules["high_risk_tlds"]:
        signals.append(Signal("tld", int(weights["high_risk_tld"]), f"Đuôi .{tld} thường bị lạm dụng để lừa đảo"))
    if any(label.startswith("xn--") for label in labels):
        signals.append(Signal("idn", int(weights["idn"]), "Tên miền dùng ký tự Unicode dễ giả mạo"))
    joined = "".join(label.replace("-", "") for label in labels if not label.startswith("xn--"))
    if len(joined) >= 8 and shannon_entropy(joined) > float(thresholds["entropy"]):
        signals.append(Signal("entropy", int(weights["entropy"]), "Tên miền trông như chuỗi ký tự ngẫu nhiên"))
    hyphens = sum(label.count("-") for label in labels if not label.startswith("xn--"))
    if hyphens >= int(thresholds["hyphens"]):
        signals.append(Signal("hyphens", int(weights["hyphens"]), "Tên miền có nhiều dấu gạch ngang bất thường"))
    digits = sum(ch.isdigit() for ch in joined)
    if digits >= 3 and digits / max(len(joined), 1) > 0.3:
        signals.append(Signal("digits", int(weights["random_digits"]), "Tên miền chứa nhiều chữ số ngẫu nhiên"))
    if is_private_suffix_host(host) and not _GOVERNMENT_LABELS.intersection(default_psl().lookup(host).suffix.split(".")):
        signals.append(Signal("free_hosting", int(weights["free_hosting"]),
                              "Trang nằm trên nền tảng tạo web miễn phí, ai cũng lập được trong vài phút"))
    return signals


def _score_url(url: ParsedURL, chain: Iterable[ParsedURL], exhausted: bool, rules: dict[str, Any]) -> list[Signal]:
    """Chấm điểm một URL không thuộc tên miền tin cậy."""
    weights = rules["weights"]
    signals: list[Signal] = []
    if exhausted:
        signals.append(Signal("nested_redirect", int(weights["nested_redirect"]),
                              "Liên kết bị bọc qua quá nhiều lớp chuyển hướng để che đích thật"))
    if url.scheme == "http":
        signals.append(Signal("http", int(weights["http"]), "Liên kết không mã hóa (http://)"))
    if any(item.has_credentials for item in chain):
        signals.append(Signal("at_sign", int(weights["at_sign"]), "Chứa ký tự @ để che giấu tên miền thật"))
    if url.port is not None:
        signals.append(Signal("port", int(weights["port"]), f"Dùng cổng mạng bất thường (:{url.port})"))
    if registered_domain(url.host) in rules["shorteners"] or url.host in rules["shorteners"]:
        signals.append(Signal("shortener", int(weights["shortener"]), "Link rút gọn che giấu địa chỉ đích thật"))
    if url.is_ip:
        signals.append(Signal("raw_ip", int(weights["raw_ip"]), "Dùng địa chỉ IP thay cho tên miền"))
        labels: list[str] = []
    else:
        labels = attacker_labels(url.host)
        brand = _brand_signal(labels, rules)
        if brand is not None:
            signals.append(brand)
        signals.extend(_lexical_signals(labels, url.host, rules))
    lure = _lure_signal(labels, url, rules)
    if lure is not None:
        signals.append(lure)
    decoy = _brand_domain_in_path(url, rules)
    if decoy is not None:
        signals.append(decoy)
    return signals


def _total(signals: Iterable[Signal]) -> int:
    """Tổng điểm kẹp trong 0–100."""
    return max(0, min(100, sum(s.points for s in signals)))


def analyze(url: str | ParsedURL, rules: dict[str, Any], unwrapped: UnwrapResult | None = None) -> Tier2Result:
    """Chấm điểm rủi ro Tầng 2 cho một URL.

    Args:
        url: URL gốc.
        rules: Bộ luật.
        unwrapped: Kết quả ``unwrap`` đã tính sẵn (tránh bóc hai lần).

    Returns:
        ``Tier2Result``.

    Raises:
        URLParseError: ``url`` là chuỗi không phân tích được.
    """
    result = unwrapped or unwrap(url, rules)
    final, chain = result.final, result.chain
    credentials = any(item.has_credentials for item in chain)

    if not final.is_ip and is_trusted(final.host, rules):
        for embedded in embedded_urls(final):
            if embedded.is_ip or not is_trusted(embedded.host, rules):
                signals = _score_url(embedded, (*chain, embedded), False, rules)
                signals.append(Signal("redirect_via_trusted", int(rules["weights"]["redirect_via_trusted"]),
                                      f"Đi qua {final.host} để chuyển hướng sang {embedded.host}"))
                return Tier2Result(_total(signals), tuple(signals), embedded, (*chain, embedded), trusted=False)
        trusted_signals: list[Signal] = []
        if credentials:
            trusted_signals.append(Signal("at_sign", int(rules["weights"]["at_sign"]),
                                          "Chứa ký tự @ để che giấu tên miền thật"))
        if result.exhausted:
            trusted_signals.append(Signal("nested_redirect", int(rules["weights"]["nested_redirect"]),
                                          "Liên kết bị bọc qua quá nhiều lớp chuyển hướng để che đích thật"))
        return Tier2Result(_total(trusted_signals), tuple(trusted_signals), final, chain, trusted=True)

    signals = _score_url(final, chain, result.exhausted, rules)
    return Tier2Result(_total(signals), tuple(signals), final, chain, trusted=False)
