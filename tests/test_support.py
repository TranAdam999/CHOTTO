"""Kiểm thử Tầng 3, cấu hình, nhật ký, chuyển tiếp trình duyệt và nhận diện nguồn gọi."""
import contextlib
import logging
import os
import sqlite3
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("CHOTTO_DATA_DIR", tempfile.mkdtemp(prefix="chotto-test-"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from chotto import config, logdb, tier3  # noqa: E402
from chotto.caller import decide_from_evidence  # noqa: E402
from chotto.engine import Result  # noqa: E402
from chotto.platform_setup import build_browser_argv, split_windows_command  # noqa: E402


class IsolatedDataDir(unittest.TestCase):
    def setUp(self) -> None:
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        env = patch.dict(os.environ, {"CHOTTO_DATA_DIR": self.tmp.name})
        env.start()
        self.addCleanup(env.stop)
        self.dir = Path(self.tmp.name)


class Tier3Tests(IsolatedDataDir):
    def test_parse_dates(self) -> None:
        expected = datetime(2024, 1, 15, tzinfo=timezone.utc)
        for text in ("2024-01-15T00:00:00Z", "2024-01-15", "15-Jan-2024", "2024.01.15", "20240115",
                     "2024-01-15 00:00:00 (YYYY-MM-DD)"):
            with self.subTest(text=text):
                self.assertEqual(tier3.parse_registration_date(text), expected)
        self.assertIsNone(tier3.parse_registration_date("không phải ngày"))

    def test_deadline_is_hard(self) -> None:
        def slow(domain: str, deadline: float) -> tuple[datetime | None, str]:
            time.sleep(3)
            return datetime(2020, 1, 1, tzinfo=timezone.utc), ""

        started = time.monotonic()
        self.assertIsNone(tier3.lookup("example-slow.com", timeout=0.3, fetchers=(slow,)))
        self.assertLess(time.monotonic() - started, 1.0)

    def test_fast_source_wins_and_is_cached(self) -> None:
        calls: list[str] = []
        created = datetime.now(timezone.utc).replace(microsecond=0)

        def fast(domain: str, deadline: float) -> tuple[datetime | None, str]:
            calls.append(domain)
            return created, ""

        def slow(domain: str, deadline: float) -> tuple[datetime | None, str]:
            time.sleep(2)
            return None, ""

        info = tier3.lookup("a.b.example-new.com", timeout=1.0, fetchers=(slow, fast))
        assert info is not None
        self.assertLess(info.age_days, 1)
        cached = tier3.lookup("x.example-new.com", timeout=1.0, fetchers=(fast,))
        assert cached is not None
        self.assertTrue(cached.from_cache)
        self.assertEqual(calls, ["example-new.com"])

    def test_ip_and_public_suffix_are_skipped(self) -> None:
        def boom(domain: str, deadline: float) -> tuple[datetime | None, str]:
            raise AssertionError("không được gọi")

        self.assertIsNone(tier3.lookup("192.168.1.5", fetchers=(boom,)))
        self.assertIsNone(tier3.lookup("com.vn", fetchers=(boom,)))

    def test_corrupt_cache_does_not_disable_lookup(self) -> None:
        (self.dir / "cache.db").write_bytes(b"day khong phai sqlite" * 100)

        def fast(domain: str, deadline: float) -> tuple[datetime | None, str]:
            return datetime(2020, 1, 1, tzinfo=timezone.utc), ""

        self.assertIsNotNone(tier3.lookup("example.org", timeout=1.0, fetchers=(fast,)))


class ConfigTests(IsolatedDataDir):
    def test_non_object_json_falls_back_to_defaults(self) -> None:
        (self.dir / "config.json").write_text("[1, 2]", "utf-8")
        self.assertEqual(config.load_config(), config.validate_config({}))

    def test_wrong_types_and_ranges(self) -> None:
        cfg = config.validate_config({"friction_seconds": 99, "tier3_timeout": "2", "tier3_enabled": "yes",
                                      "unknown_caller_policy": "random", "zalo_processes": [], "lạ": 1})
        self.assertEqual(cfg["friction_seconds"], 15)
        self.assertEqual(cfg["tier3_timeout"], config.DEFAULTS["tier3_timeout"])
        self.assertIs(cfg["tier3_enabled"], True)
        self.assertEqual(cfg["unknown_caller_policy"], "inspect")
        self.assertEqual(cfg["zalo_processes"], ["zalo.exe"])
        self.assertNotIn("lạ", cfg)

    def test_save_is_atomic_and_round_trips(self) -> None:
        cfg = dict(config.load_config(), browser_progid="ChromeHTML", friction_seconds=7)
        config.save_config(cfg)
        self.assertEqual(config.load_config()["browser_progid"], "ChromeHTML")
        self.assertEqual([p.name for p in self.dir.iterdir() if p.suffix == ".tmp"], [])

    def test_friction_by_level(self) -> None:
        self.assertEqual([config.friction_seconds_for(level, 5) for level in ("WARN", "HIGH", "BLOCKED")],
                         [5, 8, 10])

    def test_rules_validate(self) -> None:
        self.assertIn("weights", config.load_rules())


class LogDbTests(IsolatedDataDir):
    def result(self) -> Result:
        return Result(url="https://x.top/a?otp=1", final_url="https://x.top/a", host="x.top", score=55,
                      level="WARN", signals=[{"code": "tld", "points": 15}], display_domain="x.top")

    def test_record_and_export_utf8_bom(self) -> None:
        self.assertTrue(logdb.record(self.result(), "cancel", 1500, "desktop"))
        out = self.dir / "log.csv"
        self.assertEqual(logdb.export_csv(out), 1)
        raw = out.read_bytes()
        self.assertTrue(raw.startswith(b"\xef\xbb\xbf"))
        self.assertNotIn(b"otp", raw)

    def test_record_never_raises_on_corrupt_db(self) -> None:
        (self.dir / "decisions.db").write_bytes(b"hong" * 1000)
        self.assertFalse(logdb.record(self.result(), "cancel", 1, "desktop"))

    def test_migrates_old_schema(self) -> None:
        with contextlib.closing(sqlite3.connect(self.dir / "decisions.db")) as con, con:
            con.execute("CREATE TABLE decisions (ts REAL, host TEXT, score INT, level TEXT, tier INT, "
                        "decision TEXT, dwell_ms INT, source TEXT)")
            con.execute("INSERT INTO decisions VALUES (?, 'old.vn', 10, 'SAFE', 2, 'auto_open', 0, 'desktop')",
                        (time.time(),))
        self.assertTrue(logdb.record(self.result(), "proceed", 10, "desktop"))
        self.assertEqual(logdb.export_csv(self.dir / "x.csv"), 2)


class BrowserCommandTests(unittest.TestCase):
    def test_split_windows_command(self) -> None:
        cases = {
            r'"C:\Program Files\Mozilla Firefox\firefox.exe" -osint -url "%1"':
                [r"C:\Program Files\Mozilla Firefox\firefox.exe", "-osint", "-url", "%1"],
            r'"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --single-argument %1':
                [r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", "--single-argument", "%1"],
            r'C:\b\browser.exe "a \"q\" b" c\\"d"': [r"C:\b\browser.exe", 'a "q" b', "c\\d"],
        }
        for command, expected in cases.items():
            with self.subTest(command=command):
                self.assertEqual(split_windows_command(command), expected)

    def test_url_is_a_single_argument(self) -> None:
        argv = build_browser_argv(["firefox.exe", "-osint", "-url", "%1"], "https://evil.top/%22%20-profile")
        self.assertEqual(argv, ["firefox.exe", "-osint", "-url", "https://evil.top/%22%20-profile"])
        self.assertEqual(build_browser_argv(["chrome.exe"], "https://a.vn/"), ["chrome.exe", "https://a.vn/"])
        self.assertEqual(build_browser_argv(["x.exe", "%1", "%*"], "https://a.vn/"), ["x.exe", "https://a.vn/"])


class CallerTests(unittest.TestCase):
    zalo = {"zalo.exe"}
    own = {"chotto.exe", "pythonw.exe"}

    def test_decisions(self) -> None:
        self.assertIs(decide_from_evidence(["chotto.exe", "zalo.exe"], None, self.zalo, self.own).from_zalo, True)
        self.assertIs(decide_from_evidence(["explorer.exe"], "zalo.exe", self.zalo, self.own).from_zalo, True)
        self.assertIs(decide_from_evidence(["explorer.exe"], "winword.exe", self.zalo, self.own).from_zalo, False)
        self.assertIsNone(decide_from_evidence(["explorer.exe"], "chotto.exe", self.zalo, self.own).from_zalo)
        self.assertIsNone(decide_from_evidence([], "explorer.exe", self.zalo, self.own).from_zalo)
        self.assertIsNone(decide_from_evidence([], None, self.zalo, self.own).from_zalo)


if __name__ == "__main__":
    unittest.main()
