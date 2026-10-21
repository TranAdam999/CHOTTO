"""Kiểm thử Giai đoạn 2: danh sách tên miền phổ biến, lời khuyên theo tổ hợp, RDAP bootstrap, tự cập nhật."""
import json
import logging
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

os.environ.setdefault("CHOTTO_DATA_DIR", tempfile.mkdtemp(prefix="chotto-test-"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from chotto import advisor, tier2, tier3  # noqa: E402
from chotto.config import DEFAULTS, load_popular_domains, load_rules  # noqa: E402
from chotto.engine import Engine  # noqa: E402
from chotto.service.app import AutoUpdater  # noqa: E402

RULES = load_rules()

BOOTSTRAP = {
    "services": [
        [["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
        [["top"], ["http://insecure.example/", "https://rdap.nic.top"]],
        [["bad"], ["http://only-http.example/"]],
        "rác",
        [["xyz"]],
    ]
}


def setUpModule() -> None:
    logging.disable(logging.CRITICAL)


def tearDownModule() -> None:
    logging.disable(logging.NOTSET)


class PopularDomainTests(unittest.TestCase):
    def test_bundled_list_is_loaded(self) -> None:
        popular = load_popular_domains()
        self.assertGreater(len(popular), 3000)
        self.assertIn("24h.com.vn", popular)
        self.assertTrue(all(d.endswith(".vn") for d in popular))
        self.assertIs(type(RULES["popular_domains"]), frozenset)

    def test_tainted_platforms_are_not_listed(self) -> None:
        popular = load_popular_domains()
        for domain in ("pancake.vn", "zing.vn", "go.vn"):
            self.assertNotIn(domain, popular)

    def test_popular_domain_is_not_scored_but_blacklist_still_applies(self) -> None:
        engine = Engine(dict(DEFAULTS, tier3_enabled=False), RULES, age_lookup=lambda h: None)
        result = engine.inspect("https://viettelpost.vn/")
        self.assertEqual((result.level, result.score), ("SAFE", 0))
        rules = dict(RULES, popular_domains=frozenset())
        self.assertEqual(tier2.analyze("https://viettelpost.vn/", rules).signals[0].code, "combosquat")

    def test_popular_domain_still_checks_embedded_redirect(self) -> None:
        domain = min(RULES["popular_domains"])
        result = tier2.analyze(f"https://{domain}/r?u=https://vcb-digibank.top/login", RULES)
        self.assertIn("redirect_via_trusted", [s.code for s in result.signals])
        self.assertFalse(result.trusted)

    def test_government_private_suffix_is_not_free_hosting(self) -> None:
        codes = [s.code for s in tier2.analyze("https://www.tax.service.gov.uk/", RULES).signals]
        self.assertNotIn("free_hosting", codes)
        codes = [s.code for s in tier2.analyze("https://vcb-login.web.app/", RULES).signals]
        self.assertIn("free_hosting", codes)

    def test_missing_list_degrades_to_empty(self) -> None:
        with patch("chotto.config.resource_path", return_value=Path("/khong/ton/tai.txt")):
            self.assertEqual(load_popular_domains(), frozenset())

    def test_comments_and_ranks_are_parsed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "popular.txt"
            path.write_text("# chú thích\nA.vn\t1000\n\nb.com.vn\nkhongcodau\n", "utf-8")
            with patch("chotto.config.resource_path", return_value=path):
                self.assertEqual(load_popular_domains(), frozenset({"a.vn", "b.com.vn"}))


class ComboAdviceTests(unittest.TestCase):
    def test_brand_plus_lure_gives_scenario_advice(self) -> None:
        text = advisor.advise_signals([
            {"code": "combosquat", "points": 40, "brand": "Vietcombank"},
            {"code": "lure", "points": 12},
            {"code": "tld", "points": 15},
        ])
        self.assertIn("giả danh Vietcombank rồi hối thúc", text)
        self.assertNotIn("Các từ như", text)                      # mẹo riêng lẻ của "lure" không lặp lại
        self.assertIn("Đuôi tên miền giá rẻ", text)
        self.assertTrue(text.endswith(advisor.GENERAL))

    def test_young_impersonation_beats_lure_combo(self) -> None:
        text = advisor.advise_signals([
            {"code": "typosquat", "points": 45, "brand": "MBBank"},
            {"code": "age", "points": 40},
            {"code": "lure", "points": 12},
        ])
        self.assertTrue(text.startswith("Trang giả MBBank trên một tên miền vừa đăng ký"))
        self.assertIn("giả danh MBBank rồi hối thúc", text)

    def test_at_most_two_tips(self) -> None:
        text = advisor.advise_signals([
            {"code": "combosquat", "points": 40, "brand": "VCB"}, {"code": "lure", "points": 12},
            {"code": "free_hosting", "points": 10}, {"code": "shortener", "points": 30},
        ])
        self.assertEqual(text.count(advisor.GENERAL), 1)
        body = text.replace(advisor.GENERAL, "")
        tips = sum(1 for combo in advisor.COMBOS if combo[1].split("{brand}")[0][:25] in body)
        tips += sum(1 for tip in advisor.TIPS.values() if tip.split("{brand}")[0][:25] in body)
        self.assertLessEqual(tips, 2)

    def test_shortener_with_lure(self) -> None:
        text = advisor.advise_signals([{"code": "shortener", "points": 30}, {"code": "lure", "points": 12}])
        self.assertTrue(text.startswith("Link rút gọn đi kèm lời hối thúc"))

    def test_single_signal_falls_back_to_tip(self) -> None:
        text = advisor.advise_signals([{"code": "raw_ip", "points": 35}])
        self.assertTrue(text.startswith(advisor.TIPS["raw_ip"]))

    def test_no_brand_name_uses_default(self) -> None:
        text = advisor.advise_signals([{"code": "homoglyph", "points": 45}, {"code": "free_hosting", "points": 10}])
        self.assertIn("thương hiệu này không bao giờ", text.lower())

    def test_negative_and_garbage_signals_are_ignored(self) -> None:
        text = advisor.advise_signals([{"code": "age", "points": -10}, {"code": "khong-ro", "points": 5}])
        self.assertEqual(text, advisor.GENERAL)


class RdapBootstrapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        env = patch.dict(os.environ, {"CHOTTO_DATA_DIR": self.tmp.name})
        env.start()
        self.addCleanup(env.stop)

    def test_parse_keeps_only_https(self) -> None:
        table = tier3.parse_bootstrap(BOOTSTRAP)
        self.assertEqual(table, {"com": "https://rdap.verisign.com/com/v1/", "net": "https://rdap.verisign.com/com/v1/",
                                 "top": "https://rdap.nic.top/"})
        with self.assertRaises(ValueError):
            tier3.parse_bootstrap({"services": "x"})

    def test_url_uses_registry_then_falls_back(self) -> None:
        bootstrap = tier3.RdapBootstrap()
        bootstrap.path.write_text(json.dumps(BOOTSTRAP), "utf-8")
        self.assertEqual(tier3.rdap_url("vcb-digibank.com", bootstrap),
                         "https://rdap.verisign.com/com/v1/domain/vcb-digibank.com")
        self.assertEqual(tier3.rdap_url("abc.vn", bootstrap), "https://rdap.org/domain/abc.vn")

    def test_missing_table_falls_back_and_refreshes_in_background(self) -> None:
        bootstrap = tier3.RdapBootstrap()
        started = threading.Event()

        def fake_refresh(timeout: float = 20.0) -> bool:
            started.set()
            return False

        with patch.object(bootstrap, "refresh", side_effect=fake_refresh):
            self.assertEqual(tier3.rdap_url("a.com", bootstrap), "https://rdap.org/domain/a.com")
            self.assertTrue(started.wait(2))
            started.clear()
            tier3.rdap_url("b.com", bootstrap)          # vừa thử: không tải lại ngay
            self.assertFalse(started.wait(0.2))

    def test_refresh_writes_table_and_rejects_garbage(self) -> None:
        bootstrap = tier3.RdapBootstrap()
        response = MagicMock()
        response.read.return_value = json.dumps(BOOTSTRAP).encode()
        with patch("chotto.tier3.urllib.request.urlopen") as urlopen:
            urlopen.return_value.__enter__.return_value = response
            self.assertTrue(bootstrap.refresh())
            self.assertEqual(bootstrap.base_for("com"), "https://rdap.verisign.com/com/v1/")
            response.read.return_value = b"<html>"
            self.assertFalse(bootstrap.refresh())
        self.assertEqual(bootstrap.base_for("net"), "https://rdap.verisign.com/com/v1/")   # bảng cũ còn nguyên

    def test_stale_table_is_used_while_refreshing(self) -> None:
        bootstrap = tier3.RdapBootstrap(max_age_s=10)
        bootstrap.path.write_text(json.dumps(BOOTSTRAP), "utf-8")
        old = time.time() - 3600
        os.utime(bootstrap.path, (old, old))
        with patch.object(bootstrap, "_refresh_in_background") as refresh:
            self.assertEqual(bootstrap.base_for("top"), "https://rdap.nic.top/")
        refresh.assert_called_once()


class AutoUpdaterTests(unittest.TestCase):
    def test_runs_only_when_enabled_and_due(self) -> None:
        calls: list[int] = []
        updater = AutoUpdater(enabled=lambda: False, due=lambda: True, run=lambda: calls.append(1) or 5)
        self.assertFalse(updater.tick())
        updater = AutoUpdater(enabled=lambda: True, due=lambda: False, run=lambda: calls.append(1) or 5)
        self.assertFalse(updater.tick())
        updater = AutoUpdater(enabled=lambda: True, due=lambda: True, run=lambda: calls.append(1) or 5)
        self.assertTrue(updater.tick())
        updater.join(2)
        self.assertEqual(calls, [1])

    def test_never_overlaps_and_survives_errors(self) -> None:
        gate = threading.Event()

        def slow() -> int:
            gate.wait(2)
            raise RuntimeError("mạng hỏng")

        updater = AutoUpdater(enabled=lambda: True, due=lambda: True, run=slow)
        self.assertTrue(updater.tick())
        self.assertFalse(updater.tick())
        gate.set()
        updater.join(2)
        self.assertTrue(updater.tick())
        updater.join(2)

    def test_bad_config_skips_tick(self) -> None:
        def broken() -> bool:
            raise KeyError("auto_update")

        self.assertFalse(AutoUpdater(enabled=broken, due=lambda: True, run=lambda: 0).tick())


if __name__ == "__main__":
    unittest.main()
