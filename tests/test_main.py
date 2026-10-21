"""Kiểm thử bất biến an toàn của luồng xử lý link (LinkHandler), không cần Tk."""
import logging
import os
import sys
import tempfile
import unittest
from collections.abc import Callable
from concurrent.futures import Future
from pathlib import Path

os.environ.setdefault("CHOTTO_DATA_DIR", tempfile.mkdtemp(prefix="chotto-test-"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from chotto.caller import Caller  # noqa: E402
from chotto.config import DEFAULTS, load_rules, validate_config  # noqa: E402
from chotto.engine import Engine, Result  # noqa: E402
from chotto.service.handler import LinkHandler, merge_after_tier3  # noqa: E402
from chotto.tier3 import AgeInfo  # noqa: E402

DANGEROUS = "https://vcb-digibanks.top/xac-nhan"
SAFE = "https://vietcombank.com.vn/"


class Harness:
    """Bộ giả lập các phụ thuộc của LinkHandler, ghi lại mọi lần gọi."""

    def __init__(self, *, proceed: bool = False, present_error: bool = False, record_error: bool = False,
                 open_ok: bool = True, engine_error: bool = False, policy: str = "inspect",
                 age: Callable[[str], AgeInfo | None] | None = None) -> None:
        self.opened: list[str] = []
        self.alerts: list[str] = []
        self.presented: list[tuple[Result, int]] = []
        self.had_pending: list[bool] = []
        self.age = age or (lambda h: None)
        self.recorded: list[str] = []
        self.recorded_levels: list[str] = []
        self.proceed = proceed
        self.present_error = present_error
        self.record_error = record_error
        self.open_ok = open_ok
        self.engine_error = engine_error
        cfg = validate_config(dict(DEFAULTS, unknown_caller_policy=policy))
        rules = load_rules()
        self.handler = LinkHandler(
            cfg=cfg,
            engine_factory=self.make_engine(cfg, rules),
            present=self.present,
            open_url=self.open_url,
            alert=self.alerts.append,
            record=self.record,
        )

    def make_engine(self, cfg: object, rules: dict[str, object]):  # type: ignore[no-untyped-def]
        def factory() -> Engine:
            if self.engine_error:
                raise RuntimeError("engine hỏng")
            return Engine(cfg, rules, age_lookup=self.age)  # type: ignore[arg-type]
        return factory

    def present(self, result: Result, seconds_for: Callable[[str], int],
                pending: Future[Result] | None) -> tuple[bool, int, Result]:
        if self.present_error:
            raise RuntimeError("Tk hỏng")
        self.had_pending.append(pending is not None)
        shown = pending.result(timeout=5) if pending is not None else result
        self.presented.append((shown, seconds_for(shown.level)))
        return self.proceed, 1234, shown

    def open_url(self, url: str) -> bool:
        self.opened.append(url)
        return self.open_ok

    def record(self, result: Result, decision: str, dwell_ms: int) -> bool:
        self.recorded.append(decision)
        self.recorded_levels.append(result.level)
        if self.record_error:
            raise OSError("database is locked")
        return True


class LinkHandlerTests(unittest.TestCase):
    def setUp(self) -> None:
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)

    def test_cancel_never_opens_even_if_logging_fails(self) -> None:
        harness = Harness(proceed=False, record_error=True)
        self.assertEqual(harness.handler.handle(DANGEROUS, Caller(True)), "cancel")
        self.assertEqual(harness.opened, [])

    def test_safe_link_opens_exactly_once_even_if_logging_fails(self) -> None:
        harness = Harness(record_error=True)
        self.assertEqual(harness.handler.handle(SAFE, Caller(True)), "auto_open")
        self.assertEqual(harness.opened, [SAFE])

    def test_proceed_opens_original_link(self) -> None:
        harness = Harness(proceed=True)
        self.assertEqual(harness.handler.handle(DANGEROUS, Caller(True)), "proceed")
        self.assertEqual(harness.opened, [DANGEROUS])
        self.assertEqual(harness.recorded, ["proceed"])

    def test_engine_failure_shows_friction_instead_of_opening(self) -> None:
        harness = Harness(engine_error=True, proceed=False)
        self.assertEqual(harness.handler.handle(DANGEROUS, Caller(True)), "cancel")
        self.assertEqual(harness.opened, [])
        self.assertEqual(harness.presented[0][0].tier_reached, 0)

    def test_ui_failure_keeps_dangerous_link_blocked(self) -> None:
        harness = Harness(present_error=True)
        self.assertEqual(harness.handler.handle(DANGEROUS, Caller(True)), "ui_failed_blocked")
        self.assertEqual(harness.opened, [])
        self.assertEqual(len(harness.alerts), 1)

    def test_ui_failure_on_unparseable_link_opens(self) -> None:
        harness = Harness(present_error=True)
        self.assertEqual(harness.handler.handle("https://[evil.top/", Caller(True)), "ui_failed_open")
        self.assertEqual(len(harness.opened), 1)

    def test_friction_seconds_scale_with_level(self) -> None:
        harness = Harness()
        harness.handler.handle("https://sub.phish-test.chotto.invalid/", Caller(True))
        harness.handler.handle(DANGEROUS, Caller(True))
        levels = {result.level: seconds for result, seconds in harness.presented}
        self.assertEqual(levels["BLOCKED"], 10)
        self.assertEqual(levels["HIGH"], 8)

    def test_non_zalo_caller_is_forwarded_without_inspection(self) -> None:
        harness = Harness()
        self.assertEqual(harness.handler.handle(DANGEROUS, Caller(False, "winword.exe")), "forwarded")
        self.assertEqual(harness.presented, [])
        self.assertEqual(harness.opened, [DANGEROUS])

    def test_unknown_caller_follows_policy(self) -> None:
        self.assertEqual(Harness().handler.handle(DANGEROUS, Caller(None)), "cancel")
        self.assertEqual(Harness(policy="forward").handler.handle(DANGEROUS, Caller(None)), "forwarded")

    def test_non_http_is_rejected(self) -> None:
        harness = Harness()
        self.assertEqual(harness.handler.handle("file:///C:/Windows/System32/calc.exe", Caller(True)), "rejected")
        self.assertEqual(harness.opened, [])

    def test_browser_failure_is_reported(self) -> None:
        harness = Harness(open_ok=False)
        harness.handler.handle(SAFE, Caller(True))
        self.assertEqual(len(harness.alerts), 1)

    def test_forwarded_url_is_sanitised(self) -> None:
        harness = Harness()
        harness.handler.handle('https://example.com/a b" --flag', Caller(False))
        self.assertNotIn(" ", harness.opened[0])
        self.assertNotIn('"', harness.opened[0])



class AsyncTier3Tests(unittest.TestCase):
    """Giai đoạn 1: màn hình đệm hiện ngay, Tầng 3 chạy nền và chỉ được nâng mức rủi ro."""

    def setUp(self) -> None:
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)

    def test_warning_is_shown_immediately_and_escalates(self) -> None:
        harness = Harness(age=lambda h: AgeInfo(2))
        self.assertEqual(harness.handler.handle("https://vcb-digibank.com/", Caller(True)), "cancel")
        self.assertEqual(harness.had_pending, [True])
        shown, seconds = harness.presented[0]
        self.assertEqual((shown.level, shown.tier_reached, seconds), ("HIGH", 3, 8))
        self.assertEqual(harness.recorded_levels, ["HIGH"])

    def test_old_domain_never_downgrades_a_shown_warning(self) -> None:
        harness = Harness(age=lambda h: AgeInfo(5000))
        harness.handler.handle("https://shopsale.top/xac-nhan", Caller(True))      # Tầng 2: 30 điểm
        shown, _ = harness.presented[0]
        self.assertEqual(shown.level, "WARN")
        self.assertLess(shown.score, 30)

    def test_safe_by_tier2_waits_for_tier3_before_opening(self) -> None:
        harness = Harness(age=lambda h: AgeInfo(1))
        self.assertEqual(harness.handler.handle("https://shopsale.top/", Caller(True)), "cancel")   # Tầng 2: 18
        self.assertEqual(harness.opened, [])
        self.assertEqual(harness.had_pending, [False])
        self.assertEqual(harness.presented[0][0].level, "HIGH")

    def test_tier3_crash_in_background_keeps_warning(self) -> None:
        def explode(host: str) -> AgeInfo | None:
            raise RuntimeError("mạng hỏng")

        harness = Harness(age=explode)
        harness.handler.handle("https://vcb-digibank.com/", Caller(True))
        shown, _ = harness.presented[0]
        self.assertEqual(shown.level, "WARN")
        self.assertIn("tier3", shown.degraded)
        self.assertTrue(shown.advice)

    def test_merge_rule(self) -> None:
        base = Result(url="u", final_url="u", host="h", score=40, level="WARN")
        self.assertEqual(merge_after_tier3(base, Result(url="u", final_url="u", host="h", score=20,
                                                        level="SAFE")).level, "WARN")
        self.assertEqual(merge_after_tier3(base, Result(url="u", final_url="u", host="h", score=90,
                                                        level="HIGH")).level, "HIGH")


if __name__ == "__main__":
    unittest.main()
