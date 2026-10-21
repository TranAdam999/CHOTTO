import contextlib
import email.message
import logging
import sqlite3
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

from chotto.tier1 import Blacklist, Fingerprints, entry_keys, update_due, update_from_sources


class Tier1Tests(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.data_path = Path(self.temp_dir.name)
        self.data_patch = patch("chotto.tier1.data_dir", return_value=self.data_path)
        self.config_patch = patch.dict("os.environ", {"CHOTTO_DATA_DIR": str(self.data_path)})
        self.config_patch.start()
        self.addCleanup(self.config_patch.stop)
        self.data_patch.start()
        self.addCleanup(self.data_patch.stop)

    def test_missing_fingerprints_are_rebuilt_from_database(self):
        blacklist = Blacklist()
        blacklist.rebuild(["phish.example/login"])
        blacklist.fp_path.unlink()

        restored = Blacklist()
        self.assertTrue(restored.contains("phish.example", "/login"))
        self.assertTrue(restored.fp_path.exists())

    def test_corrupt_fingerprints_are_rebuilt_from_database(self):
        blacklist = Blacklist()
        blacklist.rebuild(["phish.example"])
        blacklist.fp_path.write_bytes(b"invalid")

        restored = Blacklist()
        self.assertTrue(restored.contains("phish.example"))

    def test_legacy_database_gets_fingerprints_and_metadata(self):
        database = self.data_path / "blacklist.db"
        with contextlib.closing(sqlite3.connect(database)) as con, con:
            con.execute("CREATE TABLE bl (k TEXT PRIMARY KEY) WITHOUT ROWID")
            con.execute("INSERT INTO bl VALUES (?)", ("phish.example",))

        blacklist = Blacklist()
        self.assertTrue(blacklist.contains("phish.example"))
        with contextlib.closing(sqlite3.connect(database)) as con, con:
            self.assertIsNotNone(
                con.execute("SELECT value FROM meta WHERE key='keys_sha256'").fetchone()
            )

    def test_rebuild_refreshes_an_already_open_instance(self):
        blacklist = Blacklist()
        self.assertTrue(blacklist.contains("phish-test.chotto.invalid"))

        blacklist.rebuild(["other.example"])
        self.assertTrue(blacklist.contains("other.example"))
        self.assertFalse(blacklist.contains("phish-test.chotto.invalid"))

    def test_invalid_entries_do_not_abort_input_processing(self):
        self.assertIsNone(entry_keys("http://[invalid"))
        self.assertIsNone(entry_keys(None))
        self.assertEqual(entry_keys("valid.example/login"), ("valid.example", "/login"))

    def test_empty_successful_source_does_not_replace_existing_list(self):
        blacklist = Blacklist()
        blacklist.rebuild(["existing.example"])
        response = MagicMock()
        response.read.return_value = b" \n"

        with patch("chotto.tier1.urllib.request.urlopen") as urlopen:
            urlopen.return_value.__enter__.return_value = response
            count = update_from_sources(
                {"blacklist_sources": [{"name": "empty", "url": "https://example.test/list"}]},
                log=lambda *_: None,
            )

        self.assertEqual(count, 0)
        self.assertTrue(Blacklist().contains("existing.example"))

    def test_fingerprints_reject_corrupt_or_truncated_data(self):
        dumped = Fingerprints.from_keys(["a.example", "b.example"], bytes(32)).dump()
        self.assertIn("a.example", Fingerprints.load(dumped))
        with self.assertRaises(ValueError):
            Fingerprints.load(dumped[:-1])
        with self.assertRaises(ValueError):
            Fingerprints.load(b"")
        flipped = bytearray(dumped)
        flipped[-1] ^= 1
        with self.assertRaises(ValueError):
            Fingerprints.load(bytes(flipped))

    def test_fingerprints_membership_is_exact_for_listed_keys(self):
        keys = [f"phish{i}.example" for i in range(5000)]
        fingerprints = Fingerprints.from_keys(keys, bytes(32))
        self.assertTrue(all(k in fingerprints for k in keys))
        self.assertFalse(any(f"clean{i}.example" in fingerprints for i in range(5000)))
        self.assertNotIn(None, fingerprints)

    def test_lookup_does_not_touch_database_after_open(self):
        blacklist = Blacklist()
        blacklist.rebuild(["phish.example"])
        self.assertTrue(blacklist.contains("phish.example"))
        with patch("chotto.tier1.sqlite3.connect", side_effect=AssertionError("không được mở SQLite")):
            self.assertTrue(blacklist.contains("www.phish.example"))
            blacklist.release()
            self.assertFalse(blacklist.contains("clean.example"))

    def test_rebuild_by_other_instance_is_seen_after_release(self):
        reader = Blacklist()
        reader.rebuild(["old.example"])
        self.assertTrue(reader.contains("old.example"))
        reader.release()
        Blacklist().rebuild(["new.example"])
        self.assertTrue(reader.contains("new.example"))
        self.assertFalse(reader.contains("old.example"))

    def _fake_urlopen(self, responses):
        """urlopen giả: lần lượt trả (status, body, headers); ghi lại header của từng request."""
        sent = []

        def urlopen(request, timeout):
            sent.append(dict(request.header_items()))
            status, body, headers = responses.pop(0)
            if status == 304:
                raise urllib.error.HTTPError(request.full_url, 304, "Not Modified", email.message.Message(), None)
            if status != 200:
                raise urllib.error.URLError("mất mạng")
            response = MagicMock()
            response.read.return_value = body
            response.headers = headers
            context = MagicMock()
            context.__enter__.return_value = response
            return context

        return urlopen, sent

    def test_incremental_update_uses_etag_and_cached_copy(self):
        rules = {"blacklist_sources": [{"name": "A", "url": "https://a.test/list"},
                                       {"name": "B", "url": "https://b.test/list"}]}
        urlopen, sent = self._fake_urlopen([
            (200, b"a1.example\na2.example\n", {"ETag": '"v1"'}),
            (200, b"b1.example\n", {"Last-Modified": "Tue, 20 Oct 2026 00:00:00 GMT"}),
            (304, b"", {}),
            (200, b"b2.example\n", {}),
        ])
        with patch("chotto.tier1.urllib.request.urlopen", side_effect=urlopen):
            self.assertGreaterEqual(update_from_sources(rules, log=lambda *_: None), 3)
            update_from_sources(rules, log=lambda *_: None)
        self.assertEqual(sent[2].get("If-none-match"), '"v1"')
        self.assertEqual(sent[3].get("If-modified-since"), "Tue, 20 Oct 2026 00:00:00 GMT")
        blacklist = Blacklist()
        self.assertTrue(blacklist.contains("a1.example"))      # nguồn A không đổi: dùng lại bản sao
        self.assertTrue(blacklist.contains("b2.example"))
        self.assertFalse(blacklist.contains("b1.example"))

    def test_failed_source_falls_back_to_its_own_copy(self):
        rules = {"blacklist_sources": [{"name": "A", "url": "https://a.test/list"},
                                       {"name": "B", "url": "https://b.test/list"}]}
        urlopen, _ = self._fake_urlopen([
            (200, b"a1.example\n", {}), (200, b"b1.example\n", {}),
            (500, b"", {}), (200, b"b2.example\n", {}),
        ])
        with patch("chotto.tier1.urllib.request.urlopen", side_effect=urlopen):
            update_from_sources(rules, log=lambda *_: None)
            update_from_sources(rules, log=lambda *_: None)
        blacklist = Blacklist()
        self.assertTrue(blacklist.contains("a1.example"))
        self.assertTrue(blacklist.contains("b2.example"))
        self.assertFalse(blacklist.contains("b1.example"))

    def test_update_due_schedule(self):
        self.assertTrue(update_due(now=1_000_000))
        rules = {"blacklist_sources": [{"name": "A", "url": "https://a.test/list"}]}
        urlopen, _ = self._fake_urlopen([(200, b"a1.example\n", {})])
        with patch("chotto.tier1.urllib.request.urlopen", side_effect=urlopen), \
                patch("chotto.tier1.time.time", return_value=1_000_000):
            update_from_sources(rules, log=lambda *_: None)
        self.assertFalse(update_due(now=1_000_000 + 3600 * 5))
        self.assertTrue(update_due(now=1_000_000 + 86400 + 1))
        (self.data_path / "blacklist_update.json").write_text("rác", "utf-8")
        self.assertTrue(update_due(now=1_000_000))

if __name__ == "__main__":
    unittest.main()
