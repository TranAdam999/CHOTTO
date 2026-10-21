"""Phân tích URL http/https theo đúng cách trình duyệt hiểu (WHATWG URL Standard).

Lý do tồn tại: ``urllib.parse`` của Python và trình duyệt hiểu khác nhau cùng một chuỗi.
Ví dụ ``https://evil.top\\@vietcombank.com.vn/``: Python đọc host là ``vietcombank.com.vn``,
còn Chrome coi ``\\`` là ``/`` và mở ``evil.top``. Mọi tầng thẩm định của CHOTTO phải nhìn
URL giống hệt trình duyệt sẽ mở, nên toàn bộ dự án chỉ dùng ``parse_url`` trong file này.

Phạm vi: chỉ scheme đặc biệt ``http`` và ``https`` (đúng vai trò Default URL Handler).
Ánh xạ IDNA là xấp xỉ UTS #46 (NFKC + chữ thường + bỏ ký tự "ánh xạ thành rỗng"),
đủ để chuẩn hóa tên miền phục vụ chấm điểm rủi ro.
"""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from typing import Final, Literal

__all__ = [
    "MAX_URL_LENGTH",
    "SUPPORTED_SCHEMES",
    "HostKind",
    "ParsedURL",
    "URLParseError",
    "domain_to_ascii",
    "domain_to_unicode",
    "get_scheme",
    "parse_url",
]

MAX_URL_LENGTH: Final[int] = 32_768
SUPPORTED_SCHEMES: Final[frozenset[str]] = frozenset({"http", "https"})
_DEFAULT_PORTS: Final[dict[str, int]] = {"http": 80, "https": 443}

_SCHEME_RE: Final = re.compile(r"([A-Za-z][A-Za-z0-9+\-.]*):")
_TAB_NEWLINE: Final = str.maketrans("", "", "\t\n\r")
_IDEOGRAPHIC_DOTS: Final = str.maketrans({"。": ".", "．": ".", "｡": "."})
# Ký tự UTS #46 ánh xạ thành rỗng (bị trình duyệt bỏ đi im lặng).
_MAPPED_TO_NOTHING: Final = str.maketrans(
    "",
    "",
    "­͏᠋᠌᠍᠏​⁠﻿"
    + "".join(chr(c) for c in range(0xFE00, 0xFE10)),
)
# WHATWG "forbidden domain code point" (đã gồm C0, khoảng trắng, %, DEL).
_FORBIDDEN_DOMAIN: Final[frozenset[str]] = frozenset(
    "\x00\t\n\r #/:<>?@[\\]^|%\x7f" + "".join(chr(c) for c in range(0x20))
)

# Các tập percent-encode theo WHATWG (ngoài tập C0: < 0x20 hoặc > 0x7E).
_FRAGMENT_SET: Final[frozenset[str]] = frozenset(' "<>`')
_QUERY_SET: Final[frozenset[str]] = frozenset(" \"#<>'")  # special-query set (http/https)
_PATH_SET: Final[frozenset[str]] = frozenset(" \"#<>?`{}")
_USERINFO_SET: Final[frozenset[str]] = _PATH_SET | frozenset("/:;=@[\\]^|")

# Nhãn IDN giải mã ra ký tự điều khiển/chưa gán/riêng tư là không hợp lệ (trình duyệt từ chối).
_INVALID_LABEL_CATEGORIES: Final[frozenset[str]] = frozenset({"Cc", "Cs", "Co", "Cn"})

HostKind = Literal["domain", "ipv4", "ipv6"]


class URLParseError(ValueError):
    """URL không hợp lệ theo cách trình duyệt hiểu, hoặc không phải http/https."""


@dataclass(frozen=True)
class ParsedURL:
    """URL đã chuẩn hóa, mô tả đúng trang mà trình duyệt sẽ mở.

    Attributes:
        raw: Chuỗi đầu vào nguyên bản.
        scheme: ``"http"`` hoặc ``"https"``.
        username: Phần tên người dùng (đã percent-encode), rỗng nếu không có.
        password: Phần mật khẩu (đã percent-encode), rỗng nếu không có.
        host: Host dạng ASCII chữ thường (punycode cho IDN); IPv4 dạng chấm;
            IPv6 trong ngoặc vuông. Không có dấu chấm ở cuối.
        host_kind: ``"domain"``, ``"ipv4"`` hoặc ``"ipv6"``.
        port: Cổng nếu khác cổng mặc định của scheme, ngược lại ``None``.
        path: Đường dẫn đã chuẩn hóa, luôn bắt đầu bằng ``/``.
        query: Chuỗi truy vấn (không gồm ``?``), ``None`` nếu không có.
        fragment: Phân mảnh (không gồm ``#``), ``None`` nếu không có.
        unicode_host: Host ở dạng Unicode để hiển thị/so khớp homoglyph.
    """

    raw: str
    scheme: str
    username: str
    password: str
    host: str
    host_kind: HostKind
    port: int | None
    path: str
    query: str | None
    fragment: str | None
    unicode_host: str

    @property
    def has_credentials(self) -> bool:
        """``True`` nếu URL chứa phần ``user[:pass]@`` (thủ thuật che tên miền thật)."""
        return bool(self.username or self.password)

    @property
    def is_ip(self) -> bool:
        """``True`` nếu host là địa chỉ IP thay vì tên miền."""
        return self.host_kind != "domain"

    @property
    def href(self) -> str:
        """Chuỗi URL chuẩn hóa, an toàn để chuyển cho trình duyệt (không khoảng trắng/ngoặc kép)."""
        parts: list[str] = [self.scheme, "://"]
        if self.has_credentials:
            parts.append(self.username)
            if self.password:
                parts.extend((":", self.password))
            parts.append("@")
        parts.append(self.host)
        if self.port is not None:
            parts.extend((":", str(self.port)))
        parts.append(self.path)
        if self.query is not None:
            parts.extend(("?", self.query))
        if self.fragment is not None:
            parts.extend(("#", self.fragment))
        return "".join(parts)

    @property
    def path_and_query(self) -> str:
        """Đường dẫn kèm truy vấn, dùng cho phân tích từ khóa."""
        return self.path if self.query is None else f"{self.path}?{self.query}"


def _percent_encode(text: str, extra: frozenset[str]) -> str:
    """Percent-encode ``text`` theo một tập WHATWG; giữ nguyên ``%`` sẵn có như trình duyệt."""
    out: list[str] = []
    for ch in text:
        code = ord(ch)
        if code < 0x20 or code > 0x7E or ch in extra:
            out.append("".join(f"%{b:02X}" for b in ch.encode("utf-8", "surrogatepass")))
        else:
            out.append(ch)
    return "".join(out)


def _percent_decode(text: str) -> bytes:
    """Giải mã ``%XX`` thành byte; chuỗi ``%`` không hợp lệ được giữ nguyên như WHATWG."""
    raw = text.encode("utf-8", "surrogatepass")
    out = bytearray()
    i = 0
    hexdigits = b"0123456789abcdefABCDEF"
    while i < len(raw):
        byte = raw[i]
        if byte == 0x25 and i + 2 < len(raw) and raw[i + 1] in hexdigits and raw[i + 2] in hexdigits:
            out.append(int(raw[i + 1 : i + 3], 16))
            i += 3
        else:
            out.append(byte)
            i += 1
    return bytes(out)


def _label_to_ascii(label: str) -> str:
    """Chuyển một nhãn tên miền sang ASCII; nhãn ``xn--`` phải giải mã được."""
    if label.isascii():
        lowered = label.lower()
        if lowered.startswith("xn--"):
            try:
                decoded = lowered[4:].encode("ascii").decode("punycode")
            except (UnicodeError, ValueError) as exc:
                raise URLParseError(f"Nhãn punycode không hợp lệ: {label!r}") from exc
            if (
                not decoded
                or decoded.isascii()
                or any(unicodedata.category(ch) in _INVALID_LABEL_CATEGORIES for ch in decoded)
            ):
                raise URLParseError(f"Nhãn punycode không hợp lệ: {label!r}")
        return lowered
    try:
        return "xn--" + label.encode("punycode").decode("ascii")
    except UnicodeError as exc:
        raise URLParseError(f"Không mã hóa được nhãn IDN: {label!r}") from exc


def domain_to_ascii(domain: str) -> str:
    """Chuẩn hóa tên miền về dạng ASCII như trình duyệt (xấp xỉ UTS #46, chế độ không nghiêm ngặt).

    Args:
        domain: Tên miền có thể chứa Unicode, chữ hoa, dấu chấm kiểu Nhật/Trung, dấu chấm cuối.

    Returns:
        Tên miền ASCII chữ thường, nhãn Unicode chuyển sang punycode, đã bỏ dấu chấm cuối.

    Raises:
        URLParseError: Tên miền rỗng, chứa ký tự cấm, hoặc nhãn punycode hỏng.
    """
    mapped = unicodedata.normalize("NFKC", domain.translate(_MAPPED_TO_NOTHING).translate(_IDEOGRAPHIC_DOTS))
    mapped = mapped.translate(_IDEOGRAPHIC_DOTS).lower()
    if mapped.endswith("."):
        mapped = mapped[:-1]
    if not mapped:
        raise URLParseError("Tên miền rỗng")
    labels = [_label_to_ascii(label) for label in mapped.split(".")]
    result = ".".join(labels)
    bad = _FORBIDDEN_DOMAIN.intersection(result)
    if bad:
        raise URLParseError(f"Tên miền chứa ký tự cấm: {sorted(bad)!r}")
    return result


def domain_to_unicode(ascii_domain: str) -> str:
    """Giải mã các nhãn ``xn--`` để hiển thị; nhãn hỏng được giữ nguyên dạng ASCII."""
    labels: list[str] = []
    for label in ascii_domain.split("."):
        if label.startswith("xn--"):
            try:
                labels.append(label[4:].encode("ascii").decode("punycode"))
                continue
            except (UnicodeError, ValueError):
                pass
        labels.append(label)
    return ".".join(labels)


def _parse_ipv4_number(part: str) -> int:
    """Đọc một thành phần IPv4 kiểu trình duyệt: thập phân, ``0x`` hex hoặc bát phân có số 0 đầu."""
    if part == "":
        raise URLParseError("Thành phần IPv4 rỗng")
    base = 10
    digits = part
    if len(part) >= 2 and part[:2].lower() == "0x":
        base, digits = 16, part[2:]
    elif len(part) >= 2 and part[0] == "0":
        base, digits = 8, part[1:]
    if digits == "":
        return 0
    try:
        return int(digits, base)
    except ValueError as exc:
        raise URLParseError(f"Thành phần IPv4 không hợp lệ: {part!r}") from exc


def _ends_in_number(host: str) -> bool:
    """WHATWG "ends in a number": nhãn cuối là số thập phân hoặc ``0x`` hex ⇒ phải là IPv4."""
    labels = host.split(".")
    if labels[-1] == "":
        if len(labels) == 1:
            return False
        labels.pop()
    last = labels[-1]
    if last and all(c in "0123456789" for c in last):
        return True
    if len(last) >= 2 and last[:2].lower() == "0x":
        return all(c in "0123456789abcdefABCDEF" for c in last[2:])
    return False


def _parse_ipv4(host: str) -> str:
    """Phân tích IPv4 mọi dạng trình duyệt chấp nhận (``3232235777``, ``0xC0A80101``, ``192.168.1``)."""
    parts = host.split(".")
    if parts[-1] == "" and len(parts) > 1:
        parts.pop()
    if len(parts) > 4:
        raise URLParseError("IPv4 có quá 4 thành phần")
    numbers = [_parse_ipv4_number(p) for p in parts]
    if any(n > 255 for n in numbers[:-1]):
        raise URLParseError("Thành phần IPv4 vượt quá 255")
    if numbers[-1] >= 256 ** (5 - len(numbers)):
        raise URLParseError("Thành phần IPv4 cuối vượt giới hạn")
    value = numbers[-1]
    for index, number in enumerate(numbers[:-1]):
        value += number * 256 ** (3 - index)
    return str(ipaddress.IPv4Address(value))


def _parse_host(text: str) -> tuple[str, HostKind, str]:
    """Phân tích host của URL đặc biệt. Trả về (host ASCII, loại host, host Unicode)."""
    if text == "":
        raise URLParseError("URL http/https phải có host")
    if text.startswith("["):
        if not text.endswith("]"):
            raise URLParseError("IPv6 thiếu dấu ]")
        inner = text[1:-1]
        if "%" in inner:
            raise URLParseError("IPv6 không được chứa zone id")
        try:
            addr = ipaddress.IPv6Address(inner)
        except ValueError as exc:
            raise URLParseError(f"IPv6 không hợp lệ: {inner!r}") from exc
        host = f"[{addr.compressed}]"
        return host, "ipv6", host
    decoded = _percent_decode(text).decode("utf-8", "replace")
    ascii_domain = domain_to_ascii(decoded)
    if _ends_in_number(ascii_domain):
        ipv4 = _parse_ipv4(ascii_domain)
        return ipv4, "ipv4", ipv4
    return ascii_domain, "domain", domain_to_unicode(ascii_domain)


def _normalize_path(path_text: str) -> str:
    """Chuẩn hóa đường dẫn: ``\\`` thành ``/``, xử lý ``.``/``..`` (cả dạng ``%2e``), percent-encode."""
    text = path_text.replace("\\", "/")
    segments = text.split("/")[1:] if text else []
    out: list[str] = []
    for index, segment in enumerate(segments):
        is_last = index == len(segments) - 1
        lowered = segment.lower()
        if lowered in ("..", ".%2e", "%2e.", "%2e%2e"):
            if out:
                out.pop()
            if is_last:
                out.append("")
        elif lowered in (".", "%2e"):
            if is_last:
                out.append("")
        else:
            out.append(_percent_encode(segment, _PATH_SET))
    return "/" + "/".join(out)


def get_scheme(raw: str) -> str | None:
    """Trả về scheme (chữ thường) của chuỗi URL như trình duyệt đọc, hoặc ``None`` nếu không có."""
    cleaned = raw.strip("".join(chr(c) for c in range(0x21))).translate(_TAB_NEWLINE)
    match = _SCHEME_RE.match(cleaned)
    return match.group(1).lower() if match else None


def parse_url(raw: str) -> ParsedURL:
    """Phân tích một URL http/https đúng như trình duyệt.

    Args:
        raw: Chuỗi URL nhận từ hệ điều hành, tiện ích mở rộng hoặc tham số của link bọc.

    Returns:
        ``ParsedURL`` bất biến mô tả trang trình duyệt sẽ mở.

    Raises:
        URLParseError: URL quá dài, không phải http/https, hoặc trình duyệt sẽ từ chối nó.
    """
    if not isinstance(raw, str):
        raise URLParseError("URL phải là chuỗi")
    if len(raw) > MAX_URL_LENGTH:
        raise URLParseError(f"URL dài hơn {MAX_URL_LENGTH} ký tự")
    text = raw.strip("".join(chr(c) for c in range(0x21))).translate(_TAB_NEWLINE)
    match = _SCHEME_RE.match(text)
    if not match:
        raise URLParseError("URL không có scheme")
    scheme = match.group(1).lower()
    if scheme not in SUPPORTED_SCHEMES:
        raise URLParseError(f"Scheme không được hỗ trợ: {scheme}")
    rest = text[match.end():].lstrip("/\\")

    end = len(rest)
    for index, ch in enumerate(rest):
        if ch in "/\\?#":
            end = index
            break
    authority, tail = rest[:end], rest[end:]

    username = password = ""
    at = authority.rfind("@")
    if at != -1:
        userinfo, authority = authority[:at], authority[at + 1:]
        user, _, pwd = userinfo.partition(":")
        username = _percent_encode(user, _USERINFO_SET)
        password = _percent_encode(pwd, _USERINFO_SET)
        if authority == "":
            raise URLParseError("Có thông tin đăng nhập nhưng thiếu host")

    if authority.startswith("["):
        close = authority.find("]")
        if close == -1:
            raise URLParseError("IPv6 thiếu dấu ]")
        host_text, port_text = authority[: close + 1], authority[close + 1:]
        if port_text and not port_text.startswith(":"):
            raise URLParseError("Ký tự lạ sau địa chỉ IPv6")
        port_text = port_text[1:]
    else:
        host_text, _, port_text = authority.partition(":")

    port: int | None = None
    if port_text:
        if not port_text.isascii() or not port_text.isdigit():
            raise URLParseError(f"Cổng không hợp lệ: {port_text!r}")
        port = int(port_text)
        if port > 65535:
            raise URLParseError("Cổng lớn hơn 65535")
        if port == _DEFAULT_PORTS[scheme]:
            port = None

    host, host_kind, unicode_host = _parse_host(host_text)

    fragment: str | None = None
    if "#" in tail:
        tail, fragment_text = tail.split("#", 1)
        fragment = _percent_encode(fragment_text, _FRAGMENT_SET)
    query: str | None = None
    if "?" in tail:
        tail, query_text = tail.split("?", 1)
        query = _percent_encode(query_text, _QUERY_SET)
    path = _normalize_path(tail)

    return ParsedURL(
        raw=raw,
        scheme=scheme,
        username=username,
        password=password,
        host=host,
        host_kind=host_kind,
        port=port,
        path=path,
        query=query,
        fragment=fragment,
        unicode_host=unicode_host,
    )
