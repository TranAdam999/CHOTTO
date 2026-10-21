"""Xử lý một liên kết từ đầu đến cuối (dùng chung cho agent thường trú và chế độ một tiến trình).

Chính sách an toàn:
  1. Lỗi khi phân tích ⇒ vẫn hiện màn hình đệm (fail-safe), không mở thẳng.
  2. Quyết định của người dùng là bất khả xâm phạm: lỗi ghi nhật ký/cache không bao giờ đổi kết quả,
     và không có đường mã nào mở link sau khi người dùng bấm "Đóng".
  3. Chỉ khi chính giao diện không dựng được VÀ liên kết không phân tích được thì mới mở thẳng;
     liên kết đã xác định nguy hiểm thì bị giữ lại và báo bằng hộp thoại hệ thống.
  4. Tầng 3 bất đồng bộ: nếu điểm Tầng 2 đã đủ để cảnh báo, màn hình đệm hiện ngay và tự cập nhật khi
     có tuổi tên miền. Màn hình đã hiện thì không bao giờ bị hạ xuống "an toàn".
"""
from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from concurrent.futures import Future
from dataclasses import dataclass, field, replace
from typing import Final

from ..caller import Caller
from ..config import Config, friction_seconds_for
from ..core.url import SUPPORTED_SCHEMES, URLParseError, get_scheme, parse_url
from ..engine import Engine, Level, Result, Tier3Job, analysis_failed_result, safe_open_url

__all__ = ["FrictionPresenter", "LinkHandler", "host_for_log", "merge_after_tier3"]

_LOG = logging.getLogger("chotto")

_SEVERITY: Final[dict[str, int]] = {"SAFE": 0, "WARN": 1, "HIGH": 2, "BLOCKED": 3}

SecondsFor = Callable[[str], int]
FrictionPresenter = Callable[[Result, SecondsFor, "Future[Result] | None"], tuple[bool, int, Result]]
Opener = Callable[[str], bool]
Alert = Callable[[str], None]
Recorder = Callable[[Result, str, int], bool]


def host_for_log(url: str) -> str:
    """Chỉ ghi host vào log (không ghi đường dẫn/tham số có thể chứa dữ liệu cá nhân)."""
    try:
        return parse_url(url).host
    except URLParseError:
        return "<không phân tích được>"


def merge_after_tier3(preliminary: Result, final: Result) -> Result:
    """Kết quả hiển thị sau khi Tầng 3 xong, khi màn hình đệm đã mở với kết quả sơ bộ.

    Mức rủi ro chỉ được tăng, không bao giờ giảm: người dùng đã thấy cảnh báo thì không được thấy nó
    biến thành "an toàn" (tên miền cũ bị mua lại vẫn có tuổi cao). Điểm và lý do lấy từ kết quả cuối.
    """
    if _SEVERITY.get(final.level, 1) >= _SEVERITY.get(preliminary.level, 1):
        return final
    return replace(final, level=preliminary.level)


@dataclass
class LinkHandler:
    """Xử lý một liên kết. Các phụ thuộc được tiêm vào để kiểm thử được."""

    cfg: Config
    engine_factory: Callable[[], Engine]
    present: FrictionPresenter
    open_url: Opener
    alert: Alert
    record: Recorder
    _engine: Engine | None = field(default=None, init=False, repr=False)

    def _get_engine(self) -> Engine:
        """Tạo engine ở lần dùng đầu (giữ trong RAM cho các lần sau)."""
        if self._engine is None:
            self._engine = self.engine_factory()
        return self._engine

    def _inspect_fast(self, url: str) -> tuple[Result, Tier3Job | None]:
        """Tầng 1 + 2; mọi lỗi (kể cả khi tạo engine) cho kết quả fail-safe."""
        try:
            return self._get_engine().inspect_fast(url)
        except Exception:  # noqa: BLE001 - ranh giới duy nhất: lỗi bất kỳ ⇒ màn hình đệm, không mở thẳng
            _LOG.exception("Thẩm định lỗi, chuyển sang màn hình đệm fail-safe")
            return analysis_failed_result(url), None
        finally:
            if self._engine is not None:
                self._engine.release()       # nhả file danh sách đen trong lúc người dùng cân nhắc

    def _complete(self, job: Tier3Job, fallback: Result) -> Result:
        """Tầng 3; lỗi bất ngờ trả về kết quả sơ bộ (``Engine.complete`` vốn không ném lỗi)."""
        try:
            return self._get_engine().complete(job)
        except Exception:  # noqa: BLE001 - Tầng 3 không bao giờ được làm hỏng quyết định
            _LOG.exception("Tầng 3 lỗi ngoài dự kiến")
            return fallback

    def _complete_in_background(self, job: Tier3Job, preliminary: Result) -> Future[Result]:
        """Chạy Tầng 3 trên luồng daemon; Future luôn hoàn tất bằng kết quả (không bằng ngoại lệ)."""
        future: Future[Result] = Future()

        def worker() -> None:
            final = self._complete(job, preliminary)
            future.set_result(merge_after_tier3(preliminary, final))

        threading.Thread(target=worker, name="chotto-tier3", daemon=True).start()
        return future

    def _safe_record(self, result: Result, decision: str, dwell_ms: int) -> None:
        """Ghi nhật ký nếu được bật; tuyệt đối không ném lỗi."""
        if not self.cfg["log_decisions"]:
            return
        try:
            self.record(result, decision, dwell_ms)
        except Exception:  # noqa: BLE001 - nhật ký không bao giờ được ảnh hưởng quyết định
            _LOG.exception("Ghi nhật ký lỗi (bỏ qua)")

    def _open(self, url: str) -> bool:
        """Mở bằng trình duyệt thật; thất bại thì báo người dùng."""
        try:
            opened = self.open_url(url)
        except Exception:  # noqa: BLE001 - báo lỗi thay vì im lặng
            _LOG.exception("Mở trình duyệt thật lỗi")
            opened = False
        if not opened:
            self.alert("CHOTTO không tìm thấy trình duyệt để mở liên kết. Hãy mở Cài đặt CHOTTO và bấm "
                       "\"Cài làm trình duyệt mặc định\" để chọn lại trình duyệt.")
        return opened

    def seconds_for(self, level: str) -> int:
        """Thời gian khóa nút "vẫn mở" theo mức rủi ro và cấu hình."""
        return friction_seconds_for(level, self.cfg["friction_seconds"])

    def handle(self, url: str, caller: Caller | None = None, force: bool = False) -> str:
        """Xử lý một liên kết.

        Args:
            url: Liên kết nhận được.
            caller: Kết quả nhận diện nguồn gọi (đo trước khi tạo cửa sổ); ``None`` khi ``force``.
            force: Bỏ qua bước nhận diện Zalo.

        Returns:
            Mã kết quả: ``rejected`` | ``forwarded`` | ``auto_open`` | ``proceed`` | ``cancel`` |
            ``ui_failed_open`` | ``ui_failed_blocked``.
        """
        _LOG.info("NHAN link host=%s force=%s", host_for_log(url), force)
        if get_scheme(url) not in SUPPORTED_SCHEMES:
            _LOG.warning("Bỏ qua liên kết không phải http/https")
            return "rejected"
        if not force and caller is not None:
            _LOG.info("CALLER from_zalo=%s (%s)", caller.from_zalo, caller.evidence)
            unknown_forward = caller.from_zalo is None and self.cfg["unknown_caller_policy"] == "forward"
            if caller.from_zalo is False or unknown_forward:
                _LOG.info("Không phải từ Zalo -> mở thẳng, KHÔNG kiểm tra")
                self._open(safe_open_url(url))
                return "forwarded"

        result, job = self._inspect_fast(url)
        pending: Future[Result] | None = None
        if job is not None:
            if result.level == Level.SAFE.value:
                # Tầng 3 có thể nâng điểm lên mức cảnh báo: phải chờ (tối đa tier3_timeout) trước khi mở.
                result = self._complete(job, result)
            else:
                pending = self._complete_in_background(job, result)
        _LOG.info("KET QUA score=%s level=%s tier=%s tín hiệu=%s ms=%s tầng3_nền=%s", result.score, result.level,
                  result.tier_reached, [s.get("code") for s in result.signals], result.elapsed_ms,
                  pending is not None)
        if result.level == Level.SAFE.value:
            self._open(result.open_url)
            self._safe_record(result, "auto_open", 0)
            return "auto_open"

        try:
            proceed, dwell_ms, shown = self.present(result, self.seconds_for, pending)
        except Exception:  # noqa: BLE001 - giao diện hỏng: áp dụng chính sách fail-safe ở dưới
            _LOG.exception("Không hiển thị được màn hình đệm")
            if result.tier_reached == 0:
                self._safe_record(result, "ui_failed_open", 0)
                self._open(result.open_url)
                return "ui_failed_open"
            self._safe_record(result, "ui_failed_blocked", 0)
            domain = result.display_domain or result.host or "không xác định"
            self.alert(f"CHOTTO đã giữ lại một liên kết nguy hiểm ({domain}). Không mở liên kết này.")
            return "ui_failed_blocked"

        _LOG.info("NGUOI DUNG chọn %s sau %sms (mức %s)", "MỞ" if proceed else "ĐÓNG", dwell_ms, shown.level)
        self._safe_record(shown, "proceed" if proceed else "cancel", dwell_ms)
        if not proceed:
            return "cancel"
        self._open(result.open_url)
        return "proceed"
