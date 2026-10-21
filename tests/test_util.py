"""Kiểm thử Public Suffix List và các hàm tiện ích."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("CHOTTO_DATA_DIR", tempfile.mkdtemp(prefix="chotto-test-"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from chotto import util  # noqa: E402
from chotto.core.psl import PublicSuffixList, default_psl  # noqa: E402


class PublicSuffixTests(unittest.TestCase):
    def test_bundled_list(self) -> None:
        psl = default_psl()
        cases = {
            "a.b.vietcombank.com.vn": ("com.vn", False, "vietcombank.com.vn"),
            "vcb-secure.web.app": ("web.app", True, "vcb-secure.web.app"),
            "momo-qua.github.io": ("github.io", True, "momo-qua.github.io"),
            "com.vn": ("com.vn", False, None),
            "www.city.kawasaki.jp": ("kawasaki.jp", False, "city.kawasaki.jp"),
            "bbc.co.uk": ("co.uk", False, "bbc.co.uk"),
            "localhost": ("localhost", False, None),
        }
        for host, (suffix, private, registrable) in cases.items():
            with self.subTest(host=host):
                info = psl.lookup(host)
                self.assertEqual((info.suffix, info.is_private, info.registrable), (suffix, private, registrable))

    def test_rules_wildcard_and_exception(self) -> None:
        psl = PublicSuffixList("com\n*.ck\n!www.ck\n// ===BEGIN PRIVATE DOMAINS===\nweb.app\n")
        self.assertEqual(psl.registrable_domain("a.b.ck"), "a.b.ck")
        self.assertIsNone(psl.registrable_domain("b.ck"))
        self.assertEqual(psl.registrable_domain("www.ck"), "www.ck")
        self.assertTrue(psl.lookup("x.web.app").is_private)

    def test_empty_list_rejected(self) -> None:
        with self.assertRaises(ValueError):
            PublicSuffixList("// chỉ có chú thích\n")


class UtilTests(unittest.TestCase):
    def test_legacy_helpers(self) -> None:
        self.assertEqual(util.levenshtein("vietcombank", "vietcombamk"), 1)
        self.assertEqual(util.registered_domain("a.b.vietcombank.com.vn"), "vietcombank.com.vn")
        self.assertEqual(util.homoglyph_normalize("vietcornbank"), "vietcombank")

    def test_damerau_counts_transposition_as_one(self) -> None:
        self.assertEqual(util.damerau_levenshtein("mbbnak", "mbbank"), 1)
        self.assertEqual(util.damerau_levenshtein("abc", "xyz", max_distance=1), 2)

    def test_skeleton_maps_confusables(self) -> None:
        self.assertEqual(util.skeleton("viеtc0mbаnk"), "vietcombank")   # е, а Cyrillic + số 0
        self.assertEqual(util.skeleton("vietcornbank"), "vietcombank")

    def test_vietnamese_normalisation(self) -> None:
        self.assertEqual(util.normalize_for_matching("/X%C3%A1c_Nh%E1%BA%ADn"), "xac-nhan")
        self.assertEqual(util.normalize_for_matching("Đóng%2520băng"), "dong-bang")
        self.assertEqual(util.fold_vietnamese("Khóa tài khoản"), "Khoa tai khoan")

    def test_parent_domains_stop_at_registrable(self) -> None:
        self.assertEqual(list(util.parent_domains("a.b.vietcombank.com.vn")),
                         ["a.b.vietcombank.com.vn", "b.vietcombank.com.vn", "vietcombank.com.vn"])
        self.assertEqual(list(util.parent_domains("x.web.app")), ["x.web.app"])
        self.assertEqual(list(util.parent_domains("1.2.3.4")), ["1.2.3.4"])

    def test_sanitize_removes_bidi_override(self) -> None:
        self.assertNotIn("‮", util.sanitize_for_display("abc‮gnp.exe"))

    def test_normalize_host_never_raises(self) -> None:
        self.assertEqual(util.normalize_host(None), "")
        self.assertEqual(util.normalize_host("ExAmple.COM."), "example.com")
        self.assertEqual(util.normalize_host("bad host%"), "bad host%")


if __name__ == "__main__":
    unittest.main()
