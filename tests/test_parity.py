"""Kiểm thử Giai đoạn 3: bản Desktop và tiện ích trình duyệt dùng chung dữ liệu và cho cùng kết quả.

- ``extension/data`` phải khớp ``chotto/data`` (``tools/sync_extension_data.py --check``).
- Engine Python phải tái tạo đúng ``tests/data/engine_vectors.json``; engine JavaScript được kiểm tra
  trên CÙNG file bởi ``extension/tests/parity.test.mjs``. Hai phía cùng đúng ⇒ hai bản cho cùng kết quả.
"""
import json
import logging
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("CHOTTO_DATA_DIR", tempfile.mkdtemp(prefix="chotto-test-"))
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import gen_engine_vectors  # noqa: E402
import sync_extension_data  # noqa: E402
from chotto.config import DEFAULTS, load_rules  # noqa: E402
from chotto.engine import Engine  # noqa: E402

VECTORS = ROOT / "tests" / "data" / "engine_vectors.json"


def setUpModule() -> None:
    logging.disable(logging.CRITICAL)


def tearDownModule() -> None:
    logging.disable(logging.NOTSET)


class ExtensionDataSyncTest(unittest.TestCase):
    def test_extension_data_matches_desktop_data(self) -> None:
        outputs = sync_extension_data.build_outputs()
        out_dir = ROOT / "extension" / "data"
        for name, content in outputs.items():
            with self.subTest(file=name):
                self.assertEqual((out_dir / name).read_text("utf-8"), content,
                                 "Chạy: python tools/sync_extension_data.py")

    def test_advice_export_round_trips(self) -> None:
        data = sync_extension_data.advice_data()
        self.assertTrue(data["general"])
        self.assertIn("combosquat", data["tips"])
        self.assertTrue(all(isinstance(group, list) for combo in data["combos"] for group in combo["groups"]))


class SharedVectorsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.payload = json.loads(VECTORS.read_text("utf-8"))
        cfg = dict(DEFAULTS, tier3_enabled=False, ai_advice=True)
        cls.engine = Engine(cfg, rules=load_rules())

    @classmethod
    def tearDownClass(cls) -> None:
        cls.engine.release()

    def test_vectors_cover_every_level_and_signal_family(self) -> None:
        vectors = self.payload["vectors"]
        self.assertGreater(len(vectors), 100)
        levels = {v["level"] for v in vectors}
        self.assertEqual(levels, {"SAFE", "WARN", "HIGH", "BLOCKED"})
        codes = {s[0] for v in vectors for s in v["signals"]}
        for code in ("combosquat", "homoglyph", "typosquat", "lure", "tld", "raw_ip", "at_sign", "shortener",
                     "free_hosting", "redirect_via_trusted", "brand_in_path", "unparseable", "blacklist"):
            self.assertIn(code, codes)

    def test_python_engine_reproduces_shared_vectors(self) -> None:
        mismatched = []
        for expected in self.payload["vectors"]:
            actual = gen_engine_vectors.vector(self.engine, expected["url"])
            if actual != expected:
                mismatched.append(expected["url"])
        self.assertEqual(mismatched[:10], [], f"{len(mismatched)} vector lệch; chạy tools/gen_engine_vectors.py")


if __name__ == "__main__":
    unittest.main()
