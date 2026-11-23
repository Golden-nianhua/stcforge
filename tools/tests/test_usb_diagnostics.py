"""诊断通道的关键回归：跨超时保留读取、底层错误码及失败日志。"""
import ctypes as C
from ctypes import wintypes as W
import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from stcforge.transport import TransportTimeout
from stcforge.ice import encode_request, DataResponse

spec = importlib.util.spec_from_file_location(
    "usb_diagnostics", Path(__file__).resolve().parents[2] / "tools/diagnostics/diagnose_usb_ice.py")
diagnostics = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnostics)


class TraceTests(unittest.TestCase):
    def test_read_failure_preserves_windows_error_code(self):
        failure = OSError("设备没有连接")
        failure.winerror = 1167
        transport = Mock()
        transport.read_report.side_effect = failure
        output = io.StringIO()
        with self.assertRaises(OSError) as caught:
            diagnostics.Trace(transport, output).read_report(1000)
        self.assertIs(caught.exception, failure)
        row = json.loads(output.getvalue())
        self.assertEqual((row["operation"], row["winerror"]), ("READ_ERROR", 1167))

    def test_idle_poll_timeouts_do_not_fill_trace(self):
        transport = Mock()
        transport.read_report.side_effect = TransportTimeout("empty")
        output = io.StringIO()
        trace = diagnostics.Trace(transport, output)
        with self.assertRaises(TransportTimeout):
            trace.read_report(0)
        self.assertEqual(output.getvalue(), "")
        with self.assertRaises(TransportTimeout):
            trace.read_report(1000)
        self.assertEqual(json.loads(output.getvalue())["operation"], "TIMEOUT")


class StartupSafetyTests(unittest.TestCase):
    def diagnose(self, pc):
        transport, session = Mock(), Mock()
        transport.device_path = None
        session.version.return_value = "V4.0"
        session.read_state.return_value = SimpleNamespace(pc=pc, raw=b"state")
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(diagnostics, "HidTransport", return_value=transport), \
             patch.object(diagnostics, "IceSession", return_value=session), \
             patch.object(diagnostics.time, "sleep") as sleep, \
             patch.object(diagnostics.faulthandler, "dump_traceback_later"), \
             patch.object(diagnostics.faulthandler, "cancel_dump_traceback_later"), \
             contextlib.redirect_stderr(io.StringIO()):
            output = Path(folder) / "trace.jsonl"
            result = diagnostics.main(["--official-start", "--output", str(output)])
            rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
        transport.close.assert_called_once()
        return result, session, sleep, rows

    def test_startup_refuses_to_relocate_a_different_pc(self):
        result, session, sleep, _ = self.diagnose(0xFF0481)
        self.assertEqual(result, 1)
        session._event_exchange.assert_not_called()
        session.resume.assert_not_called()
        sleep.assert_not_called()

    def test_startup_matches_official_frame_and_waits_before_second_snapshot(self):
        result, session, sleep, rows = self.diagnose(0xFF0000)
        self.assertEqual(result, 0)
        command, payload = session._event_exchange.call_args.args
        self.assertEqual(encode_request(command, payload)[:11].hex(), "ff5a08020000ff0000009e")
        sleep.assert_called_once_with(2)
        self.assertEqual(session.read_state.call_count, 2)
        self.assertIn("STARTUP_STATE", [row["operation"] for row in rows])
        session.resume.assert_not_called()  # 启动对照不隐式运行用户程序。


class VerifyImageTests(unittest.TestCase):
    def test_reads_device_space_five_and_does_not_read_hex_gaps(self):
        image = {0xFF0000 + i: value for i, value in enumerate(b"\x9a\xff\x00\x1f")}
        image[0xFF0200] = 0xAA
        session = Mock()
        session._data_exchange.side_effect = [DataResponse(b"\x9a\xff\x00\x1f", b""),
                                             DataResponse(b"\xaa", b"")]
        trace = diagnostics.Trace(None, io.StringIO())
        diagnostics.verify_image(session, image, trace)
        first, second = session._data_exchange.call_args_list
        self.assertEqual(encode_request(*first.args)[:11].hex(), "ff5a08040500ff00000493")
        self.assertEqual(second.args, (4, b"\x05\0\xff\x02\0\x01"))
        session.write_memory.assert_not_called()
        session.resume.assert_not_called()

    def test_mismatch_stops_before_reading_later_chunks(self):
        session = Mock()
        session._data_exchange.return_value = DataResponse(b"\x08\0\0\0", b"")
        trace = diagnostics.Trace(None, io.StringIO())
        image = {0xFF0000 + i: value for i, value in enumerate(b"\x9a\xff\x00\x1f")}
        image[0xFF0200] = 0xAA
        with self.assertRaisesRegex(RuntimeError, "0xFF0000.*9A.*08"):
            diagnostics.verify_image(session, image, trace)
        session._data_exchange.assert_called_once()
        self.assertIn('"operation": "VERIFY_MISMATCH"', trace.output.getvalue())

    def test_wrong_address_space_is_rejected_before_any_request(self):
        session = Mock()
        with self.assertRaises(ValueError):
            diagnostics.verify_image(session, {0: 0x9A}, Mock())
        session._data_exchange.assert_not_called()


@unittest.skipUnless(os.name == "nt", "Win32 native 通道")
class NativeReadTests(unittest.TestCase):
    def transport(self):
        class Overlapped(C.Structure):
            _fields_ = [("hEvent", W.HANDLE)]
        transport = diagnostics.WindowsHid.__new__(diagnostics.WindowsHid)
        transport.k = Mock()
        transport.k.ReadFile.return_value = False
        transport.k.GetOverlappedResult.return_value = False
        transport.read = Overlapped(1)
        transport.buffer = C.create_string_buffer(65)
        transport.handle = 42
        transport.pending = False
        return transport

    def test_timeout_reuses_same_pending_read_then_delivers_report(self):
        transport = self.transport()
        # 第一次 ReadFile=IO_PENDING，后续 GetOverlappedResult=IO_INCOMPLETE。
        with patch.object(diagnostics.C, "get_last_error", side_effect=[997, 996, 996]):
            for _ in range(2):
                with self.assertRaises(TransportTimeout):
                    transport.read_report(0)
        self.assertTrue(transport.pending)
        self.assertEqual(transport.k.ReadFile.call_count, 1)
        transport.buffer.raw = b"\0" + b"\x07\x06\0\0\0\0\0\x04".ljust(64, b"\0")
        def completed(handle, ov, count, wait):
            self.assertFalse(wait)
            count._obj.value = 65
            return True
        transport.k.GetOverlappedResult.side_effect = completed
        self.assertEqual(transport.read_report(0), transport.buffer.raw[1:])
        self.assertFalse(transport.pending)
        self.assertEqual(transport.k.ReadFile.call_count, 1)

    def test_removed_device_error_is_not_converted_to_timeout(self):
        transport = self.transport()
        transport.pending = True
        with patch.object(diagnostics.C, "get_last_error", return_value=1167):
            with self.assertRaises(OSError) as caught:
                transport.read_report(1000)
        self.assertEqual(caught.exception.winerror, 1167)
        self.assertFalse(transport.pending)


if __name__ == "__main__":
    unittest.main()
