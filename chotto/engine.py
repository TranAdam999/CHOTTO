"""Pipeline thẩm định 3 tầng.

Thứ tự: phân tích URL như trình duyệt → bóc link bọc → Tầng 1 (mọi mắt xích và URL nhúng) →
Tầng 2 → Tầng 3 (chỉ vùng nghi vấn) → mức rủi ro, tối đa 4 lý do, lời khuyên cục bộ.

URL không phân tích được không bao giờ được coi là an toàn: kết quả là WARN kèm lý do
"không phân tích được" (fail-safe có friction).
"""
from __future__ import annotations

import itertools
import logging
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Final

from . import advisor, tier2, tier3
from .config import Config, load_config, load_rules, validate_config
from .core.url import ParsedURL, URLParseError, parse_url
from .tier1 import Blacklist, BlacklistError
from .util import is_private_suffix_host, registered_domain, sanitize_for_display

__all__ = ["Engine", "Level", "Result", "Tier3Job", "age_adjustment", "analysis_failed_result", "safe_open_url"]

_LOG = logging.getLogger(__name__)
_MAX_REASONS: Final[int] = 4
_UNSAFE_URL_CHARS: Final[dict[int, str]] = {ord(c): f"%{ord(c):02X}" for c in ' "<>`{}|\\^'}

AgeLookup = Callable[[str], "tier3.AgeInfo | None"]


class Level(str, Enum):
    """Mức rủi ro tổng hợp."""

    SAFE = "SAFE"
    WARN = "WARN"
    HIGH = "HIGH"
    BLOCKED = "BLOCKED"


@dataclass
class Result:
    """Kết quả thẩm định một liên kết.

    Attributes:
        url: Liên kết gốc nhận được.
        final_url: Đích đã chuẩn hóa sau khi bóc link bọc (dùng để hiển thị).
        host: Host của đích (ASCII).
        score: Điểm rủi ro 0–100.
        level: ``SAFE``/``WARN``/``HIGH``/``BLOCKED``.
        reasons: Tối đa 4 lý do tiếng Việt, xếp theo mức độ.
        signals: Toàn bộ dấu hiệu (``code``, ``points``, ``reason``, ``brand``).
        tier_reached: Tầng cuối cùng đã chạy (0 = không phân tích được).
        domain_age_days: Tuổi tên miền nếu Tầng 3 tra được.
        advice: Lời khuyên cục bộ (AI's Advices) khi Tầng 3 tắt/không tra được.
        elapsed_ms: Thời gian thẩm định.
        open_url: Chuỗi URL an toàn để chuyển cho trình duyệt (link gốc đã chuẩn hóa).
        display_domain: Tên miền thật (đăng ký được) để hiển thị nổi bật.
        degraded: Các thành phần bị bỏ qua do lỗi (ví dụ ``"tier1"``).
    """

    url: str
    final_url: str
    host: str
    score: int
    level: str
    reasons: list[str] = field(default_factory=list)
    signals: list[dict[str, Any]] = field(default_factory=list)
    tier_reached: int = 2
    domain_age_days: float | None = None
    advice: str = ""
    elapsed_ms: int = 0
    open_url: str = ""
    display_domain: str = ""
    degraded: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Dạng dict (JSON được) của kết quả."""
        return asdict(self)


def safe_open_url(raw: str) -> str:
    """Chuỗi URL an toàn để truyền cho trình duyệt: dạng chuẩn hóa nếu phân tích được,
    ngược lại bỏ ký tự điều khiển và percent-encode khoảng trắng/ngoặc kép (chống chèn tham số)."""
    try:
        return parse_url(raw).href
    except URLParseError:
        cleaned = "".join(ch for ch in raw.strip() if ch.isprintable())
        return cleaned.translate(_UNSAFE_URL_CHARS)


def analysis_failed_result(url: str, weights: Mapping[str, Any] | None = None, elapsed_ms: int = 0) -> Result:
    """Kết quả fail-safe khi không phân tích được liên kết: luôn hiện màn hình đệm mức WARN."""
    points = int((weights or {}).get("unparseable", 50))
    reason = "CHOTTO không phân tích được liên kết này, hãy kiểm tra kỹ trước khi mở"
    return Result(
        url=url,
        final_url=sanitize_for_display(url[:2048]),
        host="",
        score=points,
        level=Level.WARN.value,
        reasons=[reason],
        signals=[{"code": "unparseable", "points": points, "reason": reason, "brand": ""}],
        tier_reached=0,
        advice=advisor.GENERAL,
        elapsed_ms=elapsed_ms,
        open_url=safe_open_url(url),
        display_domain="",
    )


def age_adjustment(age_days: float, curve: Sequence[Sequence[float]], impersonates_brand: bool) -> tuple[int, str]:
    """Điểm cộng/trừ theo tuổi tên miền: nội suy tuyến tính trên các điểm ``[ngày, điểm]`` của ``age_curve``.

    Đường cong liên tục (không có bậc nhảy ở 7/30/90 ngày) nên tên miền 29 và 31 ngày tuổi được chấm gần
    như nhau. Sau điểm cuối, điểm giữ nguyên giá trị cuối. Tên miền mạo danh thương hiệu không bao giờ được
    trừ điểm vì tuổi (tên miền cũ hết hạn bị mua lại vẫn mang tuổi cũ).

    Args:
        age_days: Tuổi tên miền (ngày, âm được coi là 0).
        curve: Các điểm ``[ngày, điểm]``, số ngày tăng ngặt, bắt đầu từ 0 (đã kiểm tra khi nạp bộ luật).
        impersonates_brand: Có dấu hiệu mạo danh thương hiệu ở Tầng 2.

    Returns:
        (điểm điều chỉnh, lý do hiển thị hoặc chuỗi rỗng khi điểm không dương).
    """
    age = max(0.0, float(age_days))
    points = float(curve[-1][1])
    for (day0, value0), (day1, value1) in itertools.pairwise(curve):
        if age <= float(day1):
            span = float(day1) - float(day0)
            ratio = (age - float(day0)) / span if span > 0 else 1.0
            points = float(value0) + (float(value1) - float(value0)) * ratio
            break
    adjust = round(points)
    if adjust < 0 and impersonates_brand:
        adjust = 0
    if adjust > 0:
        return adjust, f"Tên miền mới đăng ký cách đây {int(age)} ngày"
    return adjust, ""


def _ms_since(started: float) -> int:
    """Số mili-giây kể từ mốc ``time.perf_counter()``."""
    return int((time.perf_counter() - started) * 1000)


@dataclass(frozen=True)
class Tier3Job:
    """Trạng thái sau Tầng 2, đủ để hoàn tất Tầng 3 trên luồng khác.

    Attributes:
        url: Liên kết gốc.
        open_url: URL chuẩn hóa để mở.
        scored: URL đích đã được chấm điểm.
        score: Điểm Tầng 2.
        signals: Dấu hiệu Tầng 2 (bản sao chỉ đọc).
        degraded: Thành phần đã bị bỏ qua do lỗi.
        started: Mốc ``time.perf_counter()`` lúc bắt đầu thẩm định.
    """

    url: str
    open_url: str
    scored: ParsedURL
    score: int
    signals: tuple[dict[str, Any], ...]
    degraded: tuple[str, ...]
    started: float

    @property
    def host(self) -> str:
        """Host sẽ được tra tuổi."""
        return self.scored.host


def _signal_dict(signal: tier2.Signal) -> dict[str, Any]:
    """Chuyển ``Signal`` sang dict (giữ định dạng cũ cho nhật ký và giao diện)."""
    return {"code": signal.code, "points": signal.points, "reason": signal.reason, "brand": signal.brand}


class Engine:
    """Bộ thẩm định 3 tầng. Một đối tượng dùng được cho nhiều lần ``inspect``."""

    def __init__(
        self,
        cfg: Mapping[str, Any] | None = None,
        rules: dict[str, Any] | None = None,
        blacklist: Blacklist | None = None,
        age_lookup: AgeLookup | None = None,
    ) -> None:
        """Khởi tạo engine.

        Args:
            cfg: Cấu hình (được kiểm tra lại); ``None`` để đọc ``config.json``.
            rules: Bộ luật; ``None`` để đọc ``rules.json`` đóng gói kèm.
            blacklist: Danh sách đen; ``None`` để mở lười ở lần dùng đầu.
            age_lookup: Hàm tra tuổi tên miền (thay được khi kiểm thử).

        Raises:
            RulesError: ``rules.json`` hỏng.
        """
        self.cfg: Config = validate_config(cfg) if cfg is not None else load_config()
        self.rules: dict[str, Any] = rules if rules is not None else load_rules()
        self._blacklist = blacklist
        self.age_lookup: AgeLookup = age_lookup or self._default_age_lookup

    def _default_age_lookup(self, host: str) -> tier3.AgeInfo | None:
        """Tra tuổi tên miền với timeout/TTL theo cấu hình."""
        return tier3.lookup(host, self.cfg["tier3_timeout"], self.cfg["cache_ttl_hours"])

    def _get_blacklist(self) -> Blacklist:
        """Mở danh sách đen ở lần dùng đầu.

        Raises:
            BlacklistError: Không mở/dựng được.
        """
        if self._blacklist is None:
            self._blacklist = Blacklist()
        return self._blacklist

    def _tier1(self, urls: list[ParsedURL]) -> str | None:
        """Tra danh sách đen cho mọi URL; trả về host khớp đầu tiên.

        Raises:
            BlacklistError: Danh sách đen không dùng được.
        """
        blacklist = self._get_blacklist()
        for item in urls:
            if blacklist.lookup(item.host, item.path) is not None:
                return item.host
        return None

    def release(self) -> None:
        """Nhả file danh sách đen (giữ Bloom trong RAM) để tiến trình khác cập nhật được trên Windows.

        Gọi sau mỗi lần thẩm định ở agent thường trú; lần tra kế tiếp tự mở lại. Không bao giờ ném lỗi.
        """
        if self._blacklist is not None:
            try:
                self._blacklist.release()
            except Exception:  # noqa: BLE001 - nhả tài nguyên không được làm hỏng luồng xử lý link
                _LOG.exception("Không nhả được danh sách đen")

    def inspect(self, url: str) -> Result:
        """Thẩm định một liên kết (chạy cả Tầng 3 nếu cần, chặn tối đa ``tier3_timeout`` giây).

        Args:
            url: Liên kết nhận từ hệ điều hành hoặc tiện ích.

        Returns:
            ``Result``. Liên kết không phân tích được cho kết quả WARN (không bao giờ SAFE).
        """
        preliminary, job = self.inspect_fast(url)
        return preliminary if job is None else self.complete(job)

    def inspect_fast(self, url: str) -> tuple[Result, Tier3Job | None]:
        """Chạy phần cục bộ (phân tích, Tầng 1, Tầng 2) trong vài mili-giây.

        Args:
            url: Liên kết cần thẩm định.

        Returns:
            ``(kết quả sơ bộ, việc Tầng 3)``. Việc Tầng 3 là ``None`` khi không cần tra tuổi tên miền,
            lúc đó kết quả sơ bộ chính là kết quả cuối. Ngược lại, kết quả sơ bộ là điểm Tầng 2 và
            người gọi chạy ``complete(job)`` (có thể trên luồng nền) để có kết quả cuối.
        """
        started = time.perf_counter()
        thresholds, weights = self.rules["thresholds"], self.rules["weights"]
        try:
            original = parse_url(url)
            unwrapped = tier2.unwrap(original, self.rules)
        except URLParseError as exc:
            _LOG.info("Không phân tích được liên kết: %s", exc)
            return analysis_failed_result(url, weights, _ms_since(started)), None

        degraded: list[str] = []
        final = unwrapped.final

        # --- Tầng 1: mọi mắt xích + URL nhúng ---
        to_check = list(unwrapped.chain)
        for item in unwrapped.chain:
            to_check.extend(tier2.embedded_urls(item))
        try:
            hit_host = self._tier1(to_check)
        except BlacklistError:
            _LOG.exception("Tầng 1 không dùng được, tiếp tục với Tầng 2")
            degraded.append("tier1")
            hit_host = None
        if hit_host is not None:
            reason = "Tên miền nằm trong danh sách lừa đảo đã được cộng đồng báo cáo"
            return Result(
                url=url,
                final_url=final.href,
                host=hit_host,
                score=100,
                level=Level.BLOCKED.value,
                reasons=[reason],
                signals=[{"code": "blacklist", "points": 100, "reason": reason, "brand": ""}],
                tier_reached=1,
                advice=advisor.advise_signals([{"code": "blacklist", "points": 100}]) if self.cfg["ai_advice"] else "",
                elapsed_ms=_ms_since(started),
                open_url=original.href,
                display_domain=registered_domain(hit_host),
                degraded=degraded,
            ), None

        # --- Tầng 2 ---
        t2 = tier2.analyze(original, self.rules, unwrapped)
        job = Tier3Job(
            url=url,
            open_url=original.href,
            scored=t2.final,
            score=t2.score,
            signals=tuple(_signal_dict(s) for s in t2.signals),
            degraded=tuple(degraded),
            started=started,
        )
        eligible = (
            self.cfg["tier3_enabled"]
            and not t2.trusted
            and not t2.final.is_ip
            and not is_private_suffix_host(t2.final.host)
            and not any(s.code == "shortener" for s in t2.signals)
            and float(thresholds["tier3_low"]) <= t2.score <= float(thresholds["tier3_high"])
        )
        preliminary = self._finalize(job, tier=2, extra=None, age_days=None, degraded=list(degraded))
        return preliminary, (job if eligible else None)

    def complete(self, job: Tier3Job) -> Result:
        """Chạy Tầng 3 cho ``job`` và trả về kết quả cuối. Không bao giờ ném lỗi.

        Args:
            job: Việc Tầng 3 do ``inspect_fast`` trả về.

        Returns:
            Kết quả cuối; nếu tra không được thì là điểm Tầng 2 kèm lời khuyên cục bộ.
        """
        degraded = list(job.degraded)
        try:
            info = self.age_lookup(job.scored.host)
        except Exception:  # noqa: BLE001 - Tầng 3 không bao giờ được làm hỏng thẩm định
            _LOG.exception("Tầng 3 lỗi, quay về điểm Tầng 2")
            degraded.append("tier3")
            info = None
        if info is None:
            return self._finalize(job, tier=3, extra=None, age_days=None, degraded=degraded)
        impersonates = any(s["code"] in ("combosquat", "homoglyph", "typosquat") for s in job.signals)
        adjust, why = age_adjustment(info.age_days, self.rules["age_curve"], impersonates)
        extra = {"code": "age", "points": adjust, "reason": why, "brand": ""} if adjust else None
        return self._finalize(job, tier=3, extra=extra, age_days=info.age_days, degraded=degraded)

    def _finalize(self, job: Tier3Job, tier: int, extra: dict[str, Any] | None, age_days: float | None,
                  degraded: list[str]) -> Result:
        """Tính mức rủi ro, lý do và lời khuyên từ điểm Tầng 2 (và điều chỉnh Tầng 3 nếu có)."""
        thresholds = self.rules["thresholds"]
        signals = [dict(signal) for signal in job.signals]
        score = job.score
        if extra is not None:
            signals.append(extra)
            score = max(0, min(100, score + int(extra["points"])))
        if score >= float(thresholds["high"]):
            level = Level.HIGH
        elif score >= float(thresholds["friction"]):
            level = Level.WARN
        else:
            level = Level.SAFE
        signals.sort(key=lambda s: -int(s["points"]))
        reasons = [str(s["reason"]) for s in signals if int(s["points"]) > 0 and s["reason"]][:_MAX_REASONS]
        result = Result(
            url=job.url,
            final_url=job.scored.href,
            host=job.scored.host,
            score=score,
            level=level.value,
            reasons=reasons,
            signals=signals,
            tier_reached=tier,
            domain_age_days=age_days,
            open_url=job.open_url,
            display_domain=registered_domain(job.scored.host),
            degraded=degraded,
        )
        if level is not Level.SAFE and self.cfg["ai_advice"] and age_days is None:
            result.advice = advisor.advise(result)
        result.elapsed_ms = _ms_since(job.started)
        return result
