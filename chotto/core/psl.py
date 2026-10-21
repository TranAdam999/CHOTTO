"""Public Suffix List: xác định "tên miền đăng ký được" (registrable domain) đúng chuẩn.

Ví dụ: ``a.b.vietcombank.com.vn`` → ``vietcombank.com.vn``; ``vcb-secure.web.app`` →
``vcb-secure.web.app`` (vì ``web.app`` là hậu tố công cộng thuộc mục PRIVATE). Bản sao danh sách
được đóng gói kèm ứng dụng tại ``chotto/data/public_suffix_list.dat`` (giấy phép MPL-2.0) nên
hoạt động hoàn toàn offline.
"""
from __future__ import annotations

import functools
import logging
from dataclasses import dataclass
from typing import Final

from .url import URLParseError, domain_to_ascii

__all__ = ["PublicSuffixList", "SuffixInfo", "default_psl"]

_LOG = logging.getLogger(__name__)
_PRIVATE_MARKER: Final[str] = "===BEGIN PRIVATE DOMAINS==="


@dataclass(frozen=True)
class SuffixInfo:
    """Kết quả tra hậu tố công cộng của một host.

    Attributes:
        suffix: Hậu tố công cộng dài nhất khớp (ví dụ ``com.vn``, ``web.app``).
        is_private: ``True`` nếu luật khớp thuộc mục PRIVATE (nền tảng hosting/dịch vụ).
        registrable: Tên miền đăng ký được, ``None`` nếu host chính là một hậu tố công cộng.
    """

    suffix: str
    is_private: bool
    registrable: str | None


class PublicSuffixList:
    """Bộ tra cứu Public Suffix List theo thuật toán chuẩn (luật thường, ``*.`` và ``!``)."""

    def __init__(self, text: str) -> None:
        """Nạp danh sách từ nội dung file ``public_suffix_list.dat``.

        Args:
            text: Nội dung file PSL (UTF-8). Dòng chú thích ``//`` và dòng trống bị bỏ qua.

        Raises:
            ValueError: Danh sách không chứa luật nào (file hỏng hoặc rỗng).
        """
        self._exact: dict[str, bool] = {}
        self._wildcard: dict[str, bool] = {}
        self._exception: dict[str, bool] = {}
        private = False
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("//"):
                if _PRIVATE_MARKER in line:
                    private = True
                continue
            rule = line.split()[0]
            table = self._exact
            if rule.startswith("!"):
                table, rule = self._exception, rule[1:]
            elif rule.startswith("*."):
                table, rule = self._wildcard, rule[2:]
            try:
                table[rule.lower() if rule.isascii() else domain_to_ascii(rule)] = private
            except URLParseError:
                _LOG.warning("Bỏ qua luật PSL không hợp lệ: %r", line)
        if not (self._exact or self._wildcard):
            raise ValueError("Public Suffix List rỗng hoặc hỏng")

    def lookup(self, host: str) -> SuffixInfo:
        """Tra hậu tố công cộng của ``host``.

        Args:
            host: Tên miền dạng ASCII chữ thường (như ``ParsedURL.host``). Dấu chấm cuối được bỏ.

        Returns:
            ``SuffixInfo`` với hậu tố, cờ PRIVATE và tên miền đăng ký được.
        """
        labels = [label for label in host.lower().rstrip(".").split(".") if label]
        count = len(labels)
        if count == 0:
            return SuffixInfo(suffix="", is_private=False, registrable=None)

        for index in range(count):
            candidate = ".".join(labels[index:])
            if candidate in self._exception:
                suffix_len = count - index - 1
                return self._info(labels, suffix_len, self._exception[candidate])

        suffix_len, is_private = 1, False
        for index in range(count):
            candidate = ".".join(labels[index:])
            length = count - index
            if candidate in self._exact:
                suffix_len, is_private = length, self._exact[candidate]
                break
            parent = ".".join(labels[index + 1:])
            if index + 1 < count and parent in self._wildcard:
                suffix_len, is_private = length, self._wildcard[parent]
                break
        return self._info(labels, suffix_len, is_private)

    @staticmethod
    def _info(labels: list[str], suffix_len: int, is_private: bool) -> SuffixInfo:
        """Dựng ``SuffixInfo`` từ số nhãn của hậu tố."""
        suffix = ".".join(labels[len(labels) - suffix_len:]) if suffix_len else ""
        registrable = ".".join(labels[-(suffix_len + 1):]) if len(labels) > suffix_len else None
        return SuffixInfo(suffix=suffix, is_private=is_private, registrable=registrable)

    def registrable_domain(self, host: str) -> str | None:
        """Tên miền đăng ký được của ``host``, ``None`` nếu host là hậu tố công cộng."""
        return self.lookup(host).registrable


@functools.lru_cache(maxsize=1)
def default_psl() -> PublicSuffixList:
    """Nạp (một lần mỗi tiến trình) bản PSL đóng gói kèm ứng dụng.

    Raises:
        OSError: Không đọc được file dữ liệu đóng gói.
        ValueError: File dữ liệu hỏng.
    """
    from ..config import resource_path

    return PublicSuffixList(resource_path("data", "public_suffix_list.dat").read_text("utf-8"))
