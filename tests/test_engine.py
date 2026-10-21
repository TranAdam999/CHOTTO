"""Kiểm thử engine 3 tầng, gồm toàn bộ ca tấn công nêu trong bản audit (kiểm thử hồi quy)."""
import logging
import os
import sys
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path

os.environ.setdefault("CHOTTO_DATA_DIR", tempfile.mkdtemp(prefix="chotto-test-"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from chotto.config import DEFAULTS, load_rules  # noqa: E402
from chotto.engine import Engine, age_adjustment  # noqa: E402
from chotto.tier1 import Blacklist, BlacklistError  # noqa: E402
from chotto.tier3 import AgeInfo  # noqa: E402

RULES = load_rules()


def setUpModule() -> None:
    logging.disable(logging.CRITICAL)


def tearDownModule() -> None:
    logging.disable(logging.NOTSET)


def engine(age: Callable[[str], AgeInfo | None] | None = None, tier3: bool = True,
           blacklist: Blacklist | None = None) -> Engine:
    cfg = dict(DEFAULTS, tier3_enabled=tier3)
    return Engine(cfg, RULES, blacklist=blacklist, age_lookup=age or (lambda h: None))


class BrokenBlacklist(Blacklist):
    def __init__(self) -> None:  # noqa: D107 - không mở file thật
        pass

    def lookup(self, host: str, path: str = "") -> str | None:
        raise BlacklistError("hỏng")


class OriginalBehaviourTests(unittest.TestCase):
    def test_official_and_trusted_safe(self) -> None:
        for url in ("https://vietcombank.com.vn/", "https://online.mbbank.com.vn/x", "https://google.com/",
                    "https://dichvucong.gov.vn/p/home", "https://example.com/", "https://viettelstore.vn/",
                    "https://shopeefood.vn/", "https://acbs.com.vn/", "https://tcbs.com.vn/"):
            with self.subTest(url=url):
                self.assertEqual(engine().inspect(url).level, "SAFE")

    def test_tier1_blacklist(self) -> None:
        result = engine().inspect("https://sub.phish-test.chotto.invalid/login")
        self.assertEqual((result.level, result.score, result.tier_reached), ("BLOCKED", 100, 1))

    def test_combosquat_with_lure(self) -> None:
        result = engine().inspect("https://vcb-digibanks.com/xac-nhan")
        self.assertGreaterEqual(result.score, 50)
        self.assertTrue(any("Vietcombank" in reason for reason in result.reasons))

    def test_homoglyph(self) -> None:
        self.assertEqual(engine().inspect("https://vietcornbank.top/").level, "HIGH")

    def test_typosquat(self) -> None:
        result = engine().inspect("https://vietcombamk.vn/")
        self.assertTrue(any(s["code"] == "typosquat" for s in result.signals))

    def test_unwrap(self) -> None:
        result = engine().inspect("https://l.messenger.com/l.php?u=https%3A%2F%2Fmbbank-khoa-tai-khoan.xyz%2F")
        self.assertEqual(result.host, "mbbank-khoa-tai-khoan.xyz")
        self.assertEqual(result.level, "HIGH")
        self.assertTrue(result.open_url.startswith("https://l.messenger.com/"))

    def test_tld_alone_is_not_enough(self) -> None:
        self.assertEqual(engine().inspect("https://abc.xyz/").level, "SAFE")

    def test_raw_ip_http(self) -> None:
        self.assertEqual(engine().inspect("http://192.168.1.5/login").score, RULES["weights"]["raw_ip"] + RULES["weights"]["http"])

    def test_tier3_new_domain_escalates(self) -> None:
        result = engine(lambda h: AgeInfo(2)).inspect("https://vcb-digibank.com/")
        self.assertEqual(result.tier_reached, 3)
        self.assertEqual(result.level, "HIGH")
        self.assertTrue(any("2 ngày" in reason for reason in result.reasons))

    def test_tier3_old_domain_reduces_when_not_impersonating(self) -> None:
        result = engine(lambda h: AgeInfo(2000)).inspect("https://shop-sale-x.top/")
        self.assertEqual(result.score, RULES["weights"]["high_risk_tld"] + RULES["weights"]["hyphens"] + int(RULES["age_curve"][-1][1]))

    def test_tier3_timeout_falls_back(self) -> None:
        result = engine(lambda h: None).inspect("https://vcb-digibank.com/")
        self.assertEqual(result.score, RULES["weights"]["combosquat"])
        self.assertTrue(result.advice)

    def test_ai_advice_when_tier3_off(self) -> None:
        result = engine(tier3=False).inspect("http://vcb-digibank.com/")
        self.assertEqual(result.tier_reached, 2)
        self.assertIn("Vietcombank", result.advice)

    def test_bypass_suffix_trick(self) -> None:
        self.assertNotEqual(engine().inspect("https://vietcombank.com.vn.secure-login.top/").level, "SAFE")

    def test_reasons_max_4(self) -> None:
        self.assertLessEqual(len(engine().inspect("http://vcb-xac-nhan-khoa-tai-khoan.top/").reasons), 4)

    def test_zalo_wrapped_link_is_unwrapped(self) -> None:
        bad = "https%3A%2F%2Fvcb-digibanks.top%2Fxac-nhan"
        for url in (f"https://zalo.me/redirect?url={bad}", f"https://l.zalo.me/?u={bad}",
                    f"https://link.zaloapp.com/x?target={bad}"):
            with self.subTest(url=url):
                result = engine().inspect(url)
                self.assertEqual(result.host, "vcb-digibanks.top")
                self.assertNotEqual(result.level, "SAFE")

    def test_plain_zalo_links_stay_safe(self) -> None:
        for url in ("https://zalo.me/g/abc123", "https://zalo.me/s/12349955"):
            with self.subTest(url=url):
                self.assertEqual(engine().inspect(url).level, "SAFE")


class AuditRegressionTests(unittest.TestCase):
    """Mỗi test ứng với một lỗi đã kiểm chứng trong bản audit."""

    def test_backslash_parser_differential(self) -> None:
        calls: list[str] = []
        result = engine(lambda h: calls.append(h) or AgeInfo(1)).inspect(
            "https://evil-login.top\\@vietcombank.com.vn/")
        self.assertEqual(result.host, "evil-login.top")
        self.assertNotEqual(result.level, "SAFE")
        self.assertTrue(any(s["code"] == "brand_in_path" for s in result.signals))

    def test_unparseable_url_is_never_safe(self) -> None:
        for url in ("https://[evil.top/", "https://vcb.top]/", "https://evil.top:80x/"):
            with self.subTest(url=url):
                result = engine().inspect(url)
                self.assertEqual(result.level, "WARN")
                self.assertEqual(result.tier_reached, 0)

    def test_hosting_platform_age_is_not_used(self) -> None:
        calls: list[str] = []
        result = engine(lambda h: calls.append(h) or AgeInfo(5000)).inspect("https://vcb-secure.web.app/")
        self.assertEqual(calls, [])
        self.assertGreaterEqual(result.score, 50)
        self.assertTrue(any(s["code"] == "free_hosting" for s in result.signals))

    def test_whois_org_cannot_whitewash(self) -> None:
        result = engine(lambda h: AgeInfo(800, org="Vietcombank JSC")).inspect("http://vcb-digibank.com/")
        self.assertGreaterEqual(result.score, 50)

    def test_nested_wrappers_beyond_depth(self) -> None:
        url = "https://vcb-xacnhan.top/"
        for _ in range(12):
            url = "https://www.google.com/url?q=" + url
        result = engine().inspect(url)
        self.assertNotEqual(result.level, "SAFE")
        self.assertTrue(any(s["code"] == "nested_redirect" for s in result.signals))

    def test_four_google_layers_are_unwrapped(self) -> None:
        url = "https://vcb-xacnhan.top/"
        for _ in range(4):
            url = "https://www.google.com/url?q=" + url
        self.assertEqual(engine().inspect(url).host, "vcb-xacnhan.top")

    def test_open_redirect_on_trusted_domain(self) -> None:
        result = engine().inspect("https://www.google.com/amp/s/vcb-xacnhan.top/")
        self.assertEqual(result.host, "vcb-xacnhan.top")
        self.assertEqual(result.level, "HIGH")

    def test_vietnamese_lures_with_diacritics_and_underscores(self) -> None:
        for url in ("https://abc.top/x%C3%A1c-nh%E1%BA%ADn", "https://abc.top/xac_nhan_tai_khoan",
                    "https://abc.top/Kh%C3%B3a%20t%C3%A0i%20kho%E1%BA%A3n"):
            with self.subTest(url=url):
                self.assertTrue(any(s["code"] == "lure" for s in engine().inspect(url).signals))

    def test_numeric_ip_forms(self) -> None:
        for url in ("http://3232235777/login", "http://0xC0A80101/login"):
            with self.subTest(url=url):
                result = engine().inspect(url)
                self.assertTrue(any(s["code"] == "raw_ip" for s in result.signals))
                self.assertNotEqual(result.level, "SAFE")

    def test_short_brand_keywords_and_transposition(self) -> None:
        for url, code in (("https://vcbonline.top/", "combosquat"), ("https://bidvsmart.xyz/", "combosquat"),
                          ("https://mbbnak.com/", "typosquat")):
            with self.subTest(url=url):
                self.assertTrue(any(s["code"] == code for s in engine().inspect(url).signals))

    def test_cyrillic_homoglyph(self) -> None:
        result = engine().inspect("https://viеtcombank.com/")
        self.assertTrue(any(s["code"] == "homoglyph" for s in result.signals))
        self.assertEqual(result.level, "HIGH")

    def test_shortener_always_triggers_friction(self) -> None:
        calls: list[str] = []
        result = engine(lambda h: calls.append(h) or AgeInfo(5000)).inspect("https://bit.ly/3xyzAbc")
        self.assertEqual(calls, [])
        self.assertEqual(result.level, "WARN")

    def test_broken_blacklist_degrades_instead_of_crashing(self) -> None:
        result = engine(blacklist=BrokenBlacklist()).inspect("https://vcb-digibanks.top/xac-nhan")
        self.assertIn("tier1", result.degraded)
        self.assertEqual(result.level, "HIGH")

    def test_tier3_exception_falls_back(self) -> None:
        def explode(host: str) -> AgeInfo | None:
            raise RuntimeError("mạng hỏng")

        result = engine(explode).inspect("https://vcb-digibank.com/")
        self.assertEqual(result.score, RULES["weights"]["combosquat"])
        self.assertIn("tier3", result.degraded)

    def test_lure_reason_shows_vietnamese_with_diacritics(self) -> None:
        result = engine().inspect("https://vcb-digibanks.top/xac-nhan")
        self.assertIn("Chứa từ khóa gây hoang mang: “xác nhận”", result.reasons)

    def test_inspect_fast_defers_tier3(self) -> None:
        calls: list[str] = []
        preliminary, job = engine(lambda h: calls.append(h) or AgeInfo(2)).inspect_fast("https://vcb-digibank.com/")
        self.assertEqual((preliminary.tier_reached, calls), (2, []))
        assert job is not None
        self.assertEqual(job.host, "vcb-digibank.com")
        self.assertIsNone(engine().inspect_fast("https://vcb-digibanks.top/xac-nhan")[1])

    def test_age_adjustment_follows_curve(self) -> None:
        curve = RULES["age_curve"]
        self.assertEqual(age_adjustment(0, curve, False), (50, "Tên miền mới đăng ký cách đây 0 ngày"))
        self.assertEqual(age_adjustment(7, curve, False)[0], 40)
        self.assertEqual(age_adjustment(30, curve, False)[0], 22)
        self.assertEqual(age_adjustment(90, curve, False)[0], 10)
        self.assertEqual(age_adjustment(200, curve, False), (0, ""))
        self.assertEqual(age_adjustment(2000, curve, False), (-10, ""))
        self.assertEqual(age_adjustment(2000, curve, True), (0, ""))
        self.assertEqual(age_adjustment(-5, curve, False)[0], 50)

    def test_age_curve_has_no_jumps(self) -> None:
        curve = RULES["age_curve"]
        scores = [age_adjustment(day, curve, False)[0] for day in range(0, 800)]
        self.assertTrue(all(abs(a - b) <= 2 for a, b in zip(scores, scores[1:])))
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_bad_age_curve_is_rejected(self) -> None:
        from chotto import config

        for bad in ([[0, 50]], [[1, 50], [7, 40]], [[0, 50], [0, 40]], [[0, "x"], [7, 40]], [[0, True], [7, 1]]):
            self.assertFalse(config._valid_age_curve(bad), bad)

if __name__ == "__main__":
    unittest.main()
