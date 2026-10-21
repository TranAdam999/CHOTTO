"""AI's Advices (chế độ riêng tư 100%): lời khuyên sinh cục bộ từ các tín hiệu, KHÔNG gửi dữ liệu ra ngoài.

Hiện là bộ tư vấn dựa trên luật. Lời khuyên ưu tiên theo **tổ hợp** dấu hiệu (ví dụ mạo danh + hối thúc là
một kịch bản cụ thể, cần lời khuyên cụ thể), rồi mới đến từng dấu hiệu riêng lẻ. Có thể thay bằng mô hình
ngôn ngữ chạy cục bộ bằng cách giữ nguyên chữ ký ``advise(result) -> str``.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from .engine import Result

__all__ = ["COMBOS", "GENERAL", "TIPS", "advise", "advise_signals"]

_BRAND_PLACEHOLDER: Final[str] = "{brand}"
_DEFAULT_BRAND: Final[str] = "thương hiệu này"
_MAX_TIPS: Final[int] = 2

TIPS: Final[dict[str, str]] = {
    "blacklist": "Trang này đã bị cộng đồng báo cáo là lừa đảo. Đừng nhập bất kỳ thông tin nào và hãy báo cho người gửi biết.",
    "combosquat": "Đừng đăng nhập qua link trong tin nhắn. Hãy tự mở ứng dụng hoặc gõ địa chỉ chính thức của {brand}.",
    "homoglyph": "Địa chỉ này giả dạng {brand} bằng ký tự nhìn giống nhau. Hãy kiểm tra từng chữ cái trong tên miền.",
    "typosquat": "Tên miền gần giống {brand} nhưng sai vài ký tự, đây là chiêu giả mạo phổ biến.",
    "lure": "Các từ như “khóa tài khoản”, “phạt nguội”, “hoàn thuế” thường dùng để tạo cảm giác khẩn cấp. "
            "Hãy bình tĩnh và xác minh qua kênh chính thức.",
    "tld": "Đuôi tên miền giá rẻ thường được kẻ lừa đảo đăng ký hàng loạt.",
    "raw_ip": "Dịch vụ thật hiếm khi dùng địa chỉ IP trần. Không nhập thông tin cá nhân vào trang này.",
    "at_sign": "Phần đứng trước ký tự @ không phải trang đích thật. Đừng mở link này.",
    "shortener": "Link rút gọn che đích đến thật. Hãy hỏi người gửi địa chỉ đầy đủ.",
    "nested_redirect": "Liên kết được bọc nhiều lớp chuyển hướng để giấu trang đích. Đừng mở nếu không chắc chắn.",
    "redirect_via_trusted": "Liên kết mượn một trang uy tín để chuyển hướng bạn sang trang khác. Hãy xem kỹ trang đích.",
    "brand_in_path": "Tên ngân hàng/dịch vụ xuất hiện ở phần sau của địa chỉ chỉ để đánh lừa; trang thật nằm ở phần tên miền đứng trước.",
    "http": "Trang không mã hóa, thông tin nhập vào có thể bị đọc trộm.",
    "port": "Trang dùng cổng mạng lạ, dấu hiệu của máy chủ dựng tạm.",
    "idn": "Tên miền chứa ký tự Unicode có thể trông giống hệt chữ Latin. Hãy gõ tay địa chỉ chính thức.",
    "entropy": "Tên miền kiểu chuỗi ngẫu nhiên thường do công cụ tự sinh cho chiến dịch lừa đảo.",
    "hyphens": "Nhiều dấu gạch ngang là đặc điểm của tên miền ghép để giả mạo.",
    "digits": "Tên miền chứa nhiều chữ số ngẫu nhiên, thường thấy ở trang lừa đảo dựng hàng loạt.",
    "free_hosting": "Trang được dựng trên nền tảng miễn phí, ngân hàng và cơ quan nhà nước không dùng loại địa chỉ này.",
    "age": "Tên miền vừa được đăng ký gần đây; trang lừa đảo thường chỉ sống vài ngày.",
    "unparseable": "Liên kết có định dạng bất thường. Hãy hỏi lại người gửi trước khi mở.",
}
_IMPERSONATION: Final[frozenset[str]] = frozenset({"combosquat", "homoglyph", "typosquat"})
_REDIRECTS: Final[frozenset[str]] = frozenset({"redirect_via_trusted", "nested_redirect"})

# Tổ hợp theo thứ tự ưu tiên: (nhóm dấu hiệu phải có — mỗi nhóm cần ít nhất một mã —, lời khuyên).
COMBOS: Final[tuple[tuple[tuple[frozenset[str], ...], str], ...]] = (
    ((_IMPERSONATION, frozenset({"age"})),
     ("Trang giả {brand} trên một tên miền vừa đăng ký vài ngày: gần như chắc chắn là lừa đảo. "
      "Tuyệt đối không đăng nhập hay nhập mã OTP.")),
    ((_IMPERSONATION, frozenset({"lure"})),
     ("Đây là kịch bản quen thuộc: giả danh {brand} rồi hối thúc bạn xử lý gấp. {brand} không yêu cầu "
      "xác nhận hay mở khóa qua link; hãy gọi tổng đài in trên thẻ hoặc mở ứng dụng chính thức.")),
    ((_IMPERSONATION, frozenset({"free_hosting"})),
     "{brand} không bao giờ đặt trang đăng nhập trên nền tảng tạo web miễn phí. Đây là trang giả."),
    ((_IMPERSONATION, _REDIRECTS),
     "Liên kết đi vòng qua một trang uy tín rồi mới tới trang giả {brand}, để qua mặt bạn và bộ lọc."),
    ((frozenset({"shortener"}), frozenset({"lure"})),
     ("Link rút gọn đi kèm lời hối thúc: kẻ gian che địa chỉ thật để bạn không kịp nhận ra. "
      "Hãy hỏi người gửi địa chỉ đầy đủ qua một kênh khác.")),
    ((frozenset({"raw_ip", "port"}), frozenset({"lure", "http"})),
     "Trang đặt trên máy chủ dựng tạm (địa chỉ IP hoặc cổng lạ), không mã hóa. Không nhập bất kỳ thông tin nào."),
)

GENERAL: Final[str] = (
    "Ngân hàng, cơ quan nhà nước không yêu cầu cung cấp OTP, mật khẩu hay CCCD qua đường link trên Zalo. "
    "Nếu nghi ngờ, hãy gọi hotline chính thức hoặc hỏi người thân trước khi bấm."
)


def _brand_of(signals: list[Mapping[str, Any]], codes: frozenset[str]) -> str:
    """Tên thương hiệu của dấu hiệu mạnh nhất thuộc ``codes`` (hoặc chuỗi mặc định)."""
    for signal in signals:
        if str(signal.get("code", "")) in codes and signal.get("brand"):
            return str(signal["brand"])
    return _DEFAULT_BRAND


def advise_signals(signals: Iterable[Mapping[str, Any]]) -> str:
    """Ghép tối đa 2 lời khuyên: tổ hợp dấu hiệu khớp trước, rồi tới dấu hiệu riêng lẻ mạnh nhất.

    Args:
        signals: Các tín hiệu có ``code``, ``points`` và tùy chọn ``brand``.

    Returns:
        Đoạn lời khuyên tiếng Việt, luôn kết thúc bằng lời khuyên chung.
    """
    ordered = sorted((s for s in signals if int(s.get("points", 0)) > 0), key=lambda s: -int(s.get("points", 0)))
    present = {str(s.get("code", "")) for s in ordered}
    covered: set[str] = set()
    parts: list[str] = []
    for groups, text in COMBOS:
        if len(parts) == _MAX_TIPS:
            break
        if all(group & present for group in groups) and not all(group & present <= covered for group in groups):
            matched = frozenset().union(*(group & present for group in groups))
            parts.append(text.replace(_BRAND_PLACEHOLDER, _brand_of(ordered, matched)))
            covered |= matched
    for signal in ordered:
        if len(parts) == _MAX_TIPS:
            break
        code = str(signal.get("code", ""))
        tip = TIPS.get(code)
        if tip is None or code in covered:
            continue
        covered.add(code)
        brand = str(signal.get("brand") or "") or _DEFAULT_BRAND
        parts.append(tip.replace(_BRAND_PLACEHOLDER, brand))
    parts.append(GENERAL)
    return " ".join(parts)


def advise(result: Result) -> str:
    """Lời khuyên cục bộ cho một kết quả thẩm định."""
    return advise_signals(result.signals)
