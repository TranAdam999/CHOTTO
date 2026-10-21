"""Kiểm thử Giai đoạn 1: IPC có xác thực, lõi agent, launcher và việc nhả file danh sách đen."""
import logging
import os
import sys
import tempfile
import threading
import time
import unittest
from multiprocessing.connection import Listener
from pathlib import Path
from typing import Any
from unittest.mock import patch

os.environ.setdefault("CHOTTO_DATA_DIR", tempfile.mkdtemp(prefix="chotto-test-"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import main  # noqa: E402
from chotto import __version__  # noqa: E402
from chotto.caller import Caller  # noqa: E402
from chotto.config import DEFAULTS, load_rules  # noqa: E402
from chotto.engine import Engine  # noqa: E402
from chotto.service import agent, ipc  # noqa: E402
from chotto.tier1 import Blacklist  # noqa: E402


class IsolatedDataDir(unittest.TestCase):
    def setUp(self) -> None:
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)
        # Thư mục ngắn để đường dẫn socket không vượt giới hạn sun_path.
        self.tmp = tempfile.TemporaryDirectory(prefix="ch", dir="/tmp" if sys.platform != "win32" else None)
        self.addCleanup(self.tmp.cleanup)
        env = patch.dict(os.environ, {"CHOTTO_DATA_DIR": self.tmp.name})
        env.start()
        self.addCleanup(env.stop)
        self.dir = Path(self.tmp.name)

    def start_server(self, handler: ipc.Handler) -> ipc.IPCServer:
        server = ipc.IPCServer(handler, self.dir)
        server.start()
        self.addCleanup(server.stop)
        return server


class IPCTests(IsolatedDataDir):
    def test_round_trip_is_fast(self) -> None:
        self.start_server(lambda message: {"ok": True, "echo": message})
        started = time.monotonic()
        self.assertEqual(ipc.request({"type": "x", "text": "Khóa tài khoản"}, directory=self.dir),
                         {"ok": True, "echo": {"type": "x", "text": "Khóa tài khoản"}})
        self.assertLess(time.monotonic() - started, 0.5)

    def test_second_agent_is_refused(self) -> None:
        self.start_server(lambda message: {"ok": True})
        with self.assertRaises(ipc.AgentAlreadyRunning):
            ipc.IPCServer(lambda message: {}, self.dir).start()

    def test_wrong_key_is_rejected_both_ways(self) -> None:
        calls: list[dict[str, Any]] = []
        self.start_server(lambda message: calls.append(message) or {"ok": True})
        key_file = self.dir / "agent.key"
        good = key_file.read_bytes()
        key_file.write_bytes(bytes(32))
        with self.assertRaises(ipc.IPCError):
            ipc.request({"type": "ping"}, directory=self.dir)
        self.assertEqual(calls, [])
        key_file.write_bytes(good)
        self.assertTrue(ipc.request({"type": "ping"}, directory=self.dir)["ok"])

    def test_no_agent_fails_fast(self) -> None:
        ipc.load_key(self.dir, create=True)
        started = time.monotonic()
        with self.assertRaises(ipc.IPCError):
            ipc.request({"type": "ping"}, directory=self.dir)
        self.assertLess(time.monotonic() - started, 0.5)

    def test_missing_key_means_no_agent(self) -> None:
        with self.assertRaises(ipc.IPCError):
            ipc.request({"type": "ping"}, directory=self.dir)

    def test_silent_impostor_hits_deadline(self) -> None:
        if sys.platform == "win32":
            self.skipTest("kiểm thử socket Unix")
        ipc.load_key(self.dir, create=True)
        address, family = ipc.endpoint(self.dir)
        impostor = Listener(address, family)
        self.addCleanup(impostor.close)
        threading.Thread(target=lambda: impostor.accept(), daemon=True).start()
        started = time.monotonic()
        with self.assertRaises(ipc.IPCError):
            ipc.request({"type": "ping"}, timeout=0.4, directory=self.dir)
        self.assertLess(time.monotonic() - started, 1.5)

    def test_stale_socket_is_cleaned(self) -> None:
        if sys.platform == "win32":
            self.skipTest("kiểm thử socket Unix")
        address, _ = ipc.endpoint(self.dir)
        Path(address).write_bytes(b"")          # socket mồ côi của agent bị tắt đột ngột
        self.start_server(lambda message: {"ok": True})
        self.assertTrue(ipc.request({}, directory=self.dir)["ok"])

    def test_oversized_message_is_refused(self) -> None:
        self.start_server(lambda message: {"ok": True})
        with self.assertRaises(ipc.IPCError):
            ipc.request({"pad": "x" * (ipc.MAX_MESSAGE_BYTES + 1)}, directory=self.dir)

    def test_handler_crash_returns_error_instead_of_hanging(self) -> None:
        def crash(message: dict[str, Any]) -> dict[str, Any]:
            raise RuntimeError("lỗi")

        self.start_server(crash)
        self.assertEqual(ipc.request({}, directory=self.dir), {"ok": False, "error": "internal"})

    def test_corrupt_key_is_replaced_by_agent_only(self) -> None:
        (self.dir / "agent.key").write_bytes(b"cut")
        with self.assertRaises(ipc.IPCError):
            ipc.load_key(self.dir)
        self.assertEqual(len(ipc.load_key(self.dir, create=True)), 32)


def open_message(**overrides: Any) -> dict[str, Any]:
    message: dict[str, Any] = {"v": ipc.PROTOCOL_VERSION, "type": "open", "version": __version__,
                               "url": "https://a.vn/", "caller": {"from_zalo": True, "evidence": "zalo.exe"},
                               "force": False}
    message.update(overrides)
    return message


class AgentCoreTests(unittest.TestCase):
    def setUp(self) -> None:
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)

    def test_open_is_queued_with_caller(self) -> None:
        woken: list[int] = []
        core = agent.AgentCore(wake=lambda: woken.append(1))
        self.assertEqual(core.handle(open_message()), {"ok": True})
        request = core.links.get_nowait()
        self.assertEqual((request.url, request.caller, request.force), ("https://a.vn/", Caller(True, "zalo.exe"), False))
        self.assertEqual(woken, [1])

    def test_rejects_bad_requests(self) -> None:
        core = agent.AgentCore()
        self.assertEqual(core.handle(open_message(v=99))["error"], "protocol")
        self.assertEqual(core.handle(open_message(type="rm"))["error"], "unknown_type")
        self.assertEqual(core.handle(open_message(url=123))["error"], "bad_url")
        self.assertEqual(core.handle(open_message(url="https://a.vn/" + "x" * 40000))["error"], "bad_url")
        self.assertTrue(core.links.empty())

    def test_garbage_caller_becomes_unknown(self) -> None:
        core = agent.AgentCore()
        core.handle(open_message(caller="zalo"))
        core.handle(open_message(caller={"from_zalo": "yes"}))
        core.handle(open_message(caller=None))
        callers = [core.links.get_nowait().caller for _ in range(3)]
        self.assertTrue(all(c is not None and c.from_zalo is None for c in callers))

    def test_force_has_no_caller(self) -> None:
        core = agent.AgentCore()
        core.handle(open_message(force=True))
        self.assertIsNone(core.links.get_nowait().caller)

    def test_version_mismatch_stops_agent(self) -> None:
        core = agent.AgentCore()
        self.assertEqual(core.handle(open_message(version="0.0.1"))["error"], "version")
        self.assertTrue(core.quit_requested.is_set())
        self.assertTrue(core.links.empty())
        self.assertEqual(core.handle(open_message())["error"], "stopping")

    def test_queue_is_bounded(self) -> None:
        core = agent.AgentCore()
        answers = [core.handle(open_message())["ok"] for _ in range(40)]
        self.assertIn(False, answers)
        self.assertLessEqual(core.links.qsize(), 32)

    def test_ping_and_quit(self) -> None:
        core = agent.AgentCore()
        self.assertEqual(core.handle({"v": 1, "type": "ping"})["version"], __version__)
        self.assertTrue(core.handle({"v": 1, "type": "quit"})["ok"])
        self.assertTrue(core.quit_requested.is_set())


class LauncherTests(IsolatedDataDir):
    def test_launcher_hands_link_to_running_agent(self) -> None:
        core = agent.AgentCore()
        self.start_server(core.handle)
        with patch.object(main, "detect_caller", return_value=Caller(True, "zalo.exe")), \
                patch("chotto.service.app.run_once") as run_once:
            self.assertEqual(main.launch("https://vcb-digibanks.top/xac-nhan", force=False), 0)
        run_once.assert_not_called()
        request = core.links.get_nowait()
        self.assertEqual((request.url, request.caller), ("https://vcb-digibanks.top/xac-nhan", Caller(True, "zalo.exe")))
        self.assertEqual(agent.ping(directory=self.dir)["version"], __version__)
        self.assertTrue(agent.stop_agent(directory=self.dir))

    def test_launcher_falls_back_and_starts_agent(self) -> None:
        with patch.object(main, "detect_caller", return_value=Caller(True, "zalo.exe")), \
                patch.object(main.platform_setup, "spawn_agent", return_value=True) as spawn, \
                patch("chotto.service.app.run_once", return_value=0) as run_once:
            self.assertEqual(main.launch("https://a.vn/", force=False), 0)
        spawn.assert_called_once()
        run_once.assert_called_once_with("https://a.vn/", False, caller=Caller(True, "zalo.exe"))

    def test_agent_disabled_skips_ipc(self) -> None:
        (self.dir / "config.json").write_text('{"agent_enabled": false}', "utf-8")
        with patch.object(main, "detect_caller", return_value=Caller(False, "winword.exe")), \
                patch.object(main.platform_setup, "spawn_agent") as spawn, \
                patch("chotto.service.agent.send_open") as send, \
                patch("chotto.service.app.run_once", return_value=0):
            main.launch("https://a.vn/", force=False)
        send.assert_not_called()
        spawn.assert_not_called()

    def test_ipc_crash_never_loses_the_link(self) -> None:
        with patch.object(main, "detect_caller", return_value=Caller(True)), \
                patch("chotto.service.agent.send_open", side_effect=ValueError("hỏng")), \
                patch.object(main.platform_setup, "spawn_agent", return_value=False), \
                patch("chotto.service.app.run_once", return_value=0) as run_once:
            main.launch("https://a.vn/", force=False)
        run_once.assert_called_once()


class ReleaseTests(IsolatedDataDir):
    def test_release_keeps_fingerprints_when_file_unchanged(self) -> None:
        blacklist = Blacklist()
        self.addCleanup(blacklist.close)
        self.assertIsNotNone(blacklist.lookup("phish-test.chotto.invalid"))
        fingerprints = blacklist._fp
        blacklist.release()
        self.assertIsNotNone(blacklist.lookup("phish-test.chotto.invalid"))
        self.assertIs(blacklist._fp, fingerprints)

    def test_release_then_rebuild_reloads_fingerprints(self) -> None:
        blacklist = Blacklist()
        self.addCleanup(blacklist.close)
        blacklist.lookup("a.vn")
        blacklist.release()
        writer = Blacklist()
        self.addCleanup(writer.close)
        writer.rebuild(["moi-lua-dao.top"])
        self.assertEqual(blacklist.lookup("moi-lua-dao.top"), "moi-lua-dao.top")

    def test_engine_release_is_safe_before_use(self) -> None:
        engine = Engine(dict(DEFAULTS), load_rules(), age_lookup=lambda h: None)
        engine.release()
        self.assertEqual(engine.inspect("https://sub.phish-test.chotto.invalid/").level, "BLOCKED")
        engine.release()


if __name__ == "__main__":
    unittest.main()
