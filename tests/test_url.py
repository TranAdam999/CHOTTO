"""Kiểm thử parser URL: phải hiểu URL giống hệt trình duyệt (vector sinh bằng Node.js/WHATWG)."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("CHOTTO_DATA_DIR", tempfile.mkdtemp(prefix="chotto-test-"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from chotto.core.url import MAX_URL_LENGTH, URLParseError, get_scheme, parse_url  # noqa: E402

VECTORS = json.loads((Path(__file__).parent / "data" / "url_vectors.json").read_text("utf-8"))["vectors"]


class WhatwgParityTests(unittest.TestCase):
    def test_vectors_match_browser(self) -> None:
        for vector in VECTORS:
            with self.subTest(url=vector["input"]):
                if not vector["valid"]:
                    with self.assertRaises(URLParseError):
                        parse_url(vector["input"])
                    continue
                parsed = parse_url(vector["input"])
                self.assertEqual(parsed.host, vector["host"])
                self.assertEqual(parsed.href, vector["href"])


class ParserBehaviourTests(unittest.TestCase):
    def test_backslash_userinfo_trick_resolves_to_attacker_host(self) -> None:
        parsed = parse_url("https://evil-login.top\\@vietcombank.com.vn/")
        self.assertEqual(parsed.host, "evil-login.top")
        self.assertFalse(parsed.has_credentials)

    def test_credentials_are_detected(self) -> None:
        parsed = parse_url("https://vietcombank.com.vn@evil.top/")
        self.assertEqual(parsed.host, "evil.top")
        self.assertTrue(parsed.has_credentials)

    def test_numeric_ipv4_forms(self) -> None:
        for raw in ("http://3232235777/", "http://0xC0A80101/", "http://0300.0250.1.1/", "http://192.168.257/"):
            with self.subTest(raw=raw):
                parsed = parse_url(raw)
                self.assertEqual(parsed.host_kind, "ipv4")
                self.assertTrue(parsed.is_ip)

    def test_href_is_safe_for_command_line(self) -> None:
        href = parse_url('https://example.com/a b"c?x=" --flag').href
        self.assertNotIn(" ", href)
        self.assertNotIn('"', href)

    def test_unicode_host_kept_for_display(self) -> None:
        parsed = parse_url("https://viеtcombank.com/")      # chữ "е" Cyrillic
        self.assertTrue(parsed.host.startswith("xn--"))
        self.assertEqual(parsed.unicode_host, "viеtcombank.com")

    def test_rejects_non_http_and_oversized(self) -> None:
        for raw in ("javascript:alert(1)", "file:///C:/x", "mailto:a@b.c", "https://"):
            with self.subTest(raw=raw), self.assertRaises(URLParseError):
                parse_url(raw)
        with self.assertRaises(URLParseError):
            parse_url("https://a.com/" + "a" * MAX_URL_LENGTH)

    def test_get_scheme(self) -> None:
        self.assertEqual(get_scheme("  HTTPS://x"), "https")
        self.assertEqual(get_scheme("ht\ttp://x"), "http")
        self.assertIsNone(get_scheme("no scheme here"))


if __name__ == "__main__":
    unittest.main()
