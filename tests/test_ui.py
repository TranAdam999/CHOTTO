"""Kiểm thử giao diện Tk thật (tự bỏ qua khi máy không có Tk hoặc không có màn hình)."""
import logging
import os
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import Future
from pathlib import Path

os.environ.setdefault("CHOTTO_DATA_DIR", tempfile.mkdtemp(prefix="chotto-test-"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from chotto.config import DEFAULTS, friction_seconds_for, load_rules  # noqa: E402
from chotto.engine import Engine, Result  # noqa: E402
from chotto.service.handler import merge_after_tier3  # noqa: E402
from chotto.tier3 import AgeInfo  # noqa: E402

try:
    import tkinter as tk

    from chotto import ui
except ImportError:  # máy không cài Tk
    tk = None  # type: ignore[assignment]


def seconds_for(level: str) -> int:
    return friction_seconds_for(level, 5)


@unittest.skipIf(tk is None, "không có tkinter")
class FrictionWindowTests(unittest.TestCase):
    def setUp(self) -> None:
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)
        try:
            self.root = tk.Tk()
        except tk.TclError:
            self.skipTest("không có màn hình")
        self.root.withdraw()
        self.addCleanup(self.root.destroy)

    def close_window_after(self, ms: int) -> None:
        def close() -> None:
            for child in self.root.winfo_children():
                child.destroy()
        self.root.after(ms, close)

    def test_updates_in_place_when_tier3_finishes(self) -> None:
        engine = Engine(dict(DEFAULTS), load_rules(), age_lookup=lambda h: (time.sleep(0.3), AgeInfo(2))[1])
        preliminary, job = engine.inspect_fast("https://vcb-digibank.com/")
        assert job is not None
        self.assertEqual(preliminary.level, "WARN")
        future: Future[Result] = Future()
        threading.Thread(target=lambda: future.set_result(merge_after_tier3(preliminary, engine.complete(job))),
                         daemon=True).start()
        texts: list[str] = []

        def collect(widget: tk.Misc) -> None:
            for child in widget.winfo_children():
                if isinstance(child, tk.Label):
                    texts.append(str(child.cget("text")))
                collect(child)

        self.root.after(150, lambda: collect(self.root))
        self.close_window_after(1200)
        proceed, _, shown = ui.show_friction(self.root, preliminary, seconds_for, future)
        self.assertFalse(proceed)
        self.assertEqual(shown.level, "HIGH")
        self.assertIn(ui.CHECKING_TEXT, texts)

    def test_proceed_button_is_locked(self) -> None:
        result = Engine(dict(DEFAULTS), load_rules(), age_lookup=lambda h: None).inspect(
            "https://vcb-digibanks.top/xac-nhan")
        self.close_window_after(300)
        started = time.monotonic()
        proceed, dwell_ms, shown = ui.show_friction(self.root, result, seconds_for, None)
        self.assertFalse(proceed)
        self.assertLess(time.monotonic() - started, 3)
        self.assertIs(shown, result)
        self.assertGreater(dwell_ms, 0)


if __name__ == "__main__":
    unittest.main()
