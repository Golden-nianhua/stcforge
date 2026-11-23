"""STC USB-ICE 编解码、同步会话和 HID 传输边界测试。

阶段说明
--------
所有测试使用注入的 Fake 传输或真实抓包十六进制，不打开、不枚举也不写入
任何硬件。真实抓包样例来自：
``STC32K144G246_32BIT_SDCC_Template/Misc/Reference/usb-ice-analysis/reports.json``。

测试固定了当前阶段的关键限制：严格按 LEN/固定事件长度解析、校验零填充、
IN 数据最大 61 字节、单包写数据最大 53 字节、resume 后续事件进入队列，
以及零内容 06 确认/停止无法仅凭内容区分。硬件时序仍待真实设备验收。
"""

from __future__ import annotations

import importlib
import os
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from stcforge.ice import (  # noqa: E402
    CMD_CONTROL,
    CMD_QUERY,
    CMD_READ,
    CMD_WRITE,
    MAX_DRAIN_EVENTS,
    DataResponse,
    Event,
    IceDisconnectedError,
    IceSession,
    IceTimeoutError,
    ProtocolError,
    State,
    UnsupportedOperationError,
    decode_data_response,
    decode_event,
    decode_request,
    decode_response,
    encode_request,
)
from stcforge.transport import (  # noqa: E402
    STC_PID,
    STC_VID,
    HidTransport,
    TransportDisconnected,
    TransportError,
    TransportTimeout,
)


def report(hex_text: str) -> bytes:
    data = bytes.fromhex(hex_text.replace(" ", "").replace("\n", ""))
    if len(data) > 64:
        raise ValueError(f"测试样例超过 64 字节：{len(data)}")
    return data.ljust(64, b"\x00")


def data_response(payload: bytes) -> bytes:
    length = 2 + len(payload)
    checksum = (-(0x02 + sum(payload))) & 0xFF
    effective = bytes((length, 0x02)) + payload + bytes((checksum,))
    return effective.ljust(64, b"\x00")


ZERO_EVENT = report("0706000000000004")
EVENT_WITH_PC = report("07060000FF048304")
VERSION_EVENT = report("07060056342E3004")

# 抓包 frame 33：执行前 CPU 状态，PC=0x00FF0481。
STATE_FRAME_33 = report(
    "300200001D4C007EF7A000000001000000000000000000000000000000000000"
    "00000001000000000037414000FF048142"
)


class ScriptedTransport:
    """按脚本返回报告的可注入传输；同时记录所有写请求。

    ``stale`` 模拟命令发送前已经到达的事件，``responses`` 模拟发送后返回的
    回复。这样测试不会把本应属于当前命令的回复误当成旧事件。
    """

    def __init__(self, responses=(), *, stale=(), write_error=None, read_error=None):
        self.responses = list(responses)
        self.stale = list(stale)
        self.writes: list[bytes] = []
        self.read_timeouts: list[int] = []
        self.write_error = write_error
        self.read_error = read_error

    def write_report(self, report_bytes: bytes, *, timeout_ms=None) -> None:
        self.writes.append(bytes(report_bytes))
        if self.write_error is not None:
            raise self.write_error

    def read_report(self, timeout_ms: int) -> bytes:
        self.read_timeouts.append(timeout_ms)
        if self.read_error is not None:
            raise self.read_error
        queue = self.stale if not self.writes else self.responses
        if not queue:
            raise TransportTimeout("脚本没有更多回复")
        return queue.pop(0)


class CodecTests(unittest.TestCase):
    def test_encode_matches_real_version_request(self):
        self.assertEqual(encode_request(CMD_QUERY, b"\x00"), report("FF5A030000A4"))

    def test_encode_matches_real_state_request(self):
        self.assertEqual(encode_request(CMD_QUERY, b"\x01"), report("FF5A030001A3"))

    def test_encode_matches_real_pc_read(self):
        encoded = encode_request(CMD_READ, b"\x00" + bytes(4) + b"\x04")
        self.assertEqual(encoded, report("FF5A080400000000000497"))

    def test_encode_matches_real_step_request(self):
        encoded = encode_request(CMD_CONTROL, b"\x01\xC2\xAF\x7E\x1F\x00")
        self.assertEqual(encoded, report("FF5A080801C2AF7E1F0088"))

    def test_encode_matches_real_code_write(self):
        encoded = encode_request(
            CMD_WRITE, b"\x05\x00\xFF\x04\x98\x01\xB9"
        )
        self.assertEqual(encoded, report("FF5A09020500FF049801B942"))

    def test_decode_request_uses_len_not_trailing_zero_removal(self):
        raw = encode_request(CMD_QUERY, b"\x00\x00")
        request = decode_request(raw)
        self.assertEqual(request.payload, b"\x00\x00")
        self.assertEqual(len(request.raw), 64)

    def test_bad_request_magic(self):
        bad = bytearray(report("FF5A030000A4"))
        bad[0] = 0xFE
        with self.assertRaises(ProtocolError):
            decode_request(bad)

    def test_bad_request_length(self):
        bad = bytearray(report("FF5A030000A4"))
        bad[2] = 0x01
        with self.assertRaises(ProtocolError):
            decode_request(bad)
        too_long = bytearray(report("FF5A030000A4"))
        too_long[2] = 0x3E
        with self.assertRaises(ProtocolError):
            decode_request(too_long)

    def test_bad_request_checksum(self):
        bad = bytearray(report("FF5A030000A4"))
        bad[5] ^= 0x01
        with self.assertRaisesRegex(ProtocolError, "sum8"):
            decode_request(bad)

    def test_bad_request_padding(self):
        bad = bytearray(report("FF5A030000A4"))
        bad[6] = 1
        with self.assertRaisesRegex(ProtocolError, "填充"):
            decode_request(bad)

    def test_request_wrong_report_size(self):
        with self.assertRaises(ProtocolError):
            decode_request(report("FF5A030000A4")[:-1])

    def test_payload_limit_59(self):
        encoded = encode_request(0x55, bytes(59))
        self.assertEqual(encoded[2], 61)
        self.assertEqual(len(encoded), 64)
        with self.assertRaises(ValueError):
            encode_request(0x55, bytes(60))

    def test_real_version_event(self):
        event = decode_event(VERSION_EVENT)
        self.assertEqual(event.content, b"\x00V4.0")
        self.assertEqual(event.version_text, "V4.0")
        self.assertIsNone(event.pc)

    def test_real_data_response(self):
        response = decode_data_response(report("060200FF04817A"), expected_data_length=4)
        self.assertEqual(response.data, bytes.fromhex("00FF0481"))

    def test_bad_in_checksum(self):
        bad = bytearray(report("060200FF04817A"))
        bad[6] ^= 0x01
        with self.assertRaisesRegex(ProtocolError, "sum8"):
            decode_data_response(bad)

    def test_bad_in_length_below_minimum(self):
        bad = bytearray(report("060200FF04817A"))
        bad[0] = 2
        with self.assertRaises(ProtocolError):
            decode_response(bad)

    def test_bad_in_length_beyond_report(self):
        bad = bytearray(report("060200FF04817A"))
        bad[0] = 64
        with self.assertRaises(ProtocolError):
            decode_response(bad)

    def test_bad_in_padding(self):
        bad = bytearray(report("060200FF04817A"))
        bad[7] = 0x00
        bad[64 - 1] = 1
        with self.assertRaisesRegex(ProtocolError, "填充"):
            decode_response(bad)

    def test_bad_event_length(self):
        bad = bytearray(VERSION_EVENT)
        bad[0] = 6
        with self.assertRaises(ProtocolError):
            decode_event(bad)

    def test_bad_event_terminator(self):
        bad = bytearray(VERSION_EVENT)
        bad[7] = 0x05
        with self.assertRaisesRegex(ProtocolError, "04"):
            decode_event(bad)

    def test_bad_event_padding(self):
        bad = bytearray(VERSION_EVENT)
        bad[8] = 1
        with self.assertRaisesRegex(ProtocolError, "填充"):
            decode_event(bad)

    def test_unknown_response_type(self):
        bad = bytearray(report("060200FF04817A"))
        bad[1] = 0x05
        bad[6] = (-(0x05 + 0x00 + 0xFF + 0x04 + 0x81)) & 0xFF
        with self.assertRaisesRegex(ProtocolError, "未知"):
            decode_response(bad)

    def test_expected_data_length_mismatch(self):
        with self.assertRaisesRegex(ProtocolError, "长度"):
            decode_data_response(report("060200FF04817A"), expected_data_length=3)

    def test_data_parser_rejects_event(self):
        with self.assertRaises(ProtocolError):
            decode_data_response(ZERO_EVENT)

    def test_event_parser_rejects_data(self):
        with self.assertRaises(ProtocolError):
            decode_event(report("060200FF04817A"))

    def test_zero_byte_data_is_not_stripped(self):
        response = decode_data_response(data_response(b"\x00\x00\x12\x00"))
        self.assertEqual(response.data, b"\x00\x00\x12\x00")


class GeneratedTransport:
    """根据最近一次写请求即时生成回复，模拟真实设备的请求-回复关系。

    这比预排队列更接近真实链路：下一条命令尚未发送时，不会提前出现它的
    数据回复；测试分块时因此能可靠检查地址和数量。
    """

    def __init__(self, responder):
        self.responder = responder
        self.writes: list[bytes] = []
        self.pending: list[bytes] = []
        self.last_write: bytes | None = None

    def write_report(self, report_bytes: bytes, *, timeout_ms=None) -> None:
        self.last_write = bytes(report_bytes)
        self.writes.append(self.last_write)
        self.pending = list(self.responder(self.last_write))

    def read_report(self, timeout_ms: int) -> bytes:
        if not self.pending:
            raise TransportTimeout("没有当前请求对应的回复")
        return self.pending.pop(0)


class StateTests(unittest.TestCase):
    def test_real_state_frame_33(self):
        state = State(decode_data_response(STATE_FRAME_33, expected_data_length=46).data)
        self.assertEqual(len(state.raw), 46)
        self.assertEqual(state.heap, state.raw[:32])
        self.assertEqual(state.heap[:8], bytes.fromhex("00001D4C007EF7A0"))
        self.assertEqual(state.dpx, 0x00010000)
        self.assertEqual(state.spx, 0x37)
        self.assertEqual(state.psw, 0x41)
        self.assertEqual(state.psw1, 0x40)
        self.assertEqual(state.pc, 0x00FF0481)

    def test_state_requires_exactly_46_bytes(self):
        with self.assertRaises(ValueError):
            State(bytes(45))
        with self.assertRaises(ValueError):
            State(bytes(47))


class InitializeDebugTests(unittest.TestCase):
    """启动请求使用抓包原始字节，所有回复只在对应请求发送后出现。"""

    VERSION_REQUEST = report("FF5A030000A4")
    START_REQUEST = report("FF5A08020000FF0000009E")
    STATE_REQUEST = report("FF5A030001A3")
    SNAPSHOT = decode_data_response(STATE_FRAME_33).data[:42] + bytes.fromhex("00FF0000")

    def make_transport(self, replies, timeline):
        class StartupTransport(GeneratedTransport):
            def write_report(self, report_bytes, *, timeout_ms=None):
                timeline.append(("write", bytes(report_bytes)))
                super().write_report(report_bytes, timeout_ms=timeout_ms)

            def read_report(self, timeout_ms):
                reply = super().read_report(timeout_ms)
                if isinstance(reply, Exception):
                    timeline.append(("read_error", type(reply)))
                    raise reply
                timeline.append(("read", reply))
                return reply

        def respond(write):
            return [replies[len(transport.writes) - 1]]

        transport = StartupTransport(respond)
        return transport

    def test_default_startup_matches_capture_and_waits_after_ack_before_state(self):
        timeline = []
        snapshot_report = data_response(self.SNAPSHOT)
        transport = self.make_transport([VERSION_EVENT, ZERO_EVENT, snapshot_report], timeline)
        session = IceSession(transport)
        with mock.patch("time.sleep", side_effect=lambda seconds: timeline.append(("sleep", seconds))) as sleep, \
             mock.patch.object(session, "halt") as halt, \
             mock.patch.object(session, "resume") as resume:
            version, state = session.initialize_debug()
        self.assertEqual(version, "V4.0")
        self.assertIsInstance(state, State)
        self.assertEqual(state.raw, self.SNAPSHOT)
        self.assertEqual(len(state.raw), 46)
        self.assertEqual(state.pc, 0xFF0000)
        self.assertEqual(timeline, [
            ("write", self.VERSION_REQUEST), ("read", VERSION_EVENT),
            ("write", self.START_REQUEST), ("read", ZERO_EVENT),
            ("sleep", 2.0),
            ("write", self.STATE_REQUEST), ("read", snapshot_report),
        ])
        self.assertEqual(transport.pending, [])
        sleep.assert_called_once_with(2.0)
        halt.assert_not_called()
        resume.assert_not_called()

    def test_explicit_startup_wait_is_used_before_state_request(self):
        timeline = []
        transport = self.make_transport(
            [VERSION_EVENT, ZERO_EVENT, data_response(self.SNAPSHOT)], timeline
        )
        with mock.patch("time.sleep", side_effect=lambda seconds: timeline.append(("sleep", seconds))) as sleep:
            IceSession(transport).initialize_debug(entry_pc=0xFF0000, settle_seconds=2.5)
        sleep.assert_called_once_with(2.5)
        self.assertEqual(timeline[3:6], [
            ("read", ZERO_EVENT), ("sleep", 2.5), ("write", self.STATE_REQUEST),
        ])
        self.assertEqual(transport.writes, [
            self.VERSION_REQUEST, self.START_REQUEST, self.STATE_REQUEST,
        ])

    def test_version_failure_never_sends_startup_or_waits(self):
        cases = (
            (ZERO_EVENT, ProtocolError),
            (TransportTimeout("version timeout"), IceTimeoutError),
            (TransportDisconnected("version disconnected"), IceDisconnectedError),
        )
        for reply, error in cases:
            with self.subTest(reply=reply):
                transport = self.make_transport([reply], [])
                with mock.patch("time.sleep") as sleep:
                    with self.assertRaises(error):
                        IceSession(transport).initialize_debug()
                self.assertEqual(transport.writes, [self.VERSION_REQUEST])
                sleep.assert_not_called()

    def test_startup_requires_ack_before_wait_or_state_query(self):
        bad_terminator = bytearray(ZERO_EVENT)
        bad_terminator[7] = 5
        cases = (
            (data_response(bytes(4)), ProtocolError),
            (VERSION_EVENT, ProtocolError),
            (EVENT_WITH_PC, ProtocolError),
            (bytes(bad_terminator), ProtocolError),
            (TransportTimeout("startup ACK timeout"), IceTimeoutError),
            (TransportDisconnected("startup disconnected"), IceDisconnectedError),
        )
        for reply, error in cases:
            with self.subTest(reply=reply):
                transport = self.make_transport([VERSION_EVENT, reply], [])
                with mock.patch("time.sleep") as sleep:
                    with self.assertRaises(error):
                        IceSession(transport).initialize_debug()
                self.assertEqual(transport.writes, [self.VERSION_REQUEST, self.START_REQUEST])
                sleep.assert_not_called()

    def test_state_failure_does_not_retry_halt_or_run(self):
        bad_checksum = bytearray(data_response(self.SNAPSHOT))
        bad_checksum[48] ^= 1
        cases = (
            (data_response(self.SNAPSHOT[:-1]), ProtocolError),
            (data_response(self.SNAPSHOT + b"\x00"), ProtocolError),
            (bytes(bad_checksum), ProtocolError),
            (ZERO_EVENT, ProtocolError),
            (TransportTimeout("state timeout"), IceTimeoutError),
            (TransportDisconnected("state disconnected"), IceDisconnectedError),
        )
        for reply, error in cases:
            with self.subTest(reply=reply):
                transport = self.make_transport([VERSION_EVENT, ZERO_EVENT, reply], [])
                session = IceSession(transport)
                with mock.patch("time.sleep") as sleep, \
                     mock.patch.object(session, "halt") as halt, \
                     mock.patch.object(session, "resume") as resume:
                    with self.assertRaises(error):
                        session.initialize_debug()
                self.assertEqual(transport.writes, [
                    self.VERSION_REQUEST, self.START_REQUEST, self.STATE_REQUEST,
                ])
                sleep.assert_called_once_with(2.0)
                halt.assert_not_called()
                resume.assert_not_called()

    def test_interrupted_settle_does_not_query_state(self):
        transport = self.make_transport([VERSION_EVENT, ZERO_EVENT], [])
        with mock.patch("time.sleep", side_effect=KeyboardInterrupt) as sleep:
            with self.assertRaises(KeyboardInterrupt):
                IceSession(transport).initialize_debug()
        sleep.assert_called_once_with(2.0)
        self.assertEqual(transport.writes, [self.VERSION_REQUEST, self.START_REQUEST])

    def test_write_failure_at_each_stage_stops_remaining_startup(self):
        requests = [self.VERSION_REQUEST, self.START_REQUEST, self.STATE_REQUEST]
        for failed_request in requests:
            for transport_error, session_error in (
                (TransportTimeout, IceTimeoutError),
                (TransportDisconnected, IceDisconnectedError),
            ):
                with self.subTest(request=failed_request[:11].hex(), error=transport_error.__name__):
                    transport = self.make_transport(
                        [VERSION_EVENT, ZERO_EVENT, data_response(self.SNAPSHOT)], []
                    )
                    write = transport.write_report
                    attempts = []

                    def fail_write(report_bytes, *, timeout_ms=None):
                        attempts.append(report_bytes)
                        if report_bytes == failed_request:
                            raise transport_error("startup write failed")
                        write(report_bytes, timeout_ms=timeout_ms)

                    session = IceSession(transport)
                    with mock.patch.object(transport, "write_report", side_effect=fail_write), \
                         mock.patch("time.sleep") as sleep, \
                         mock.patch.object(session, "halt") as halt, \
                         mock.patch.object(session, "resume") as resume:
                        with self.assertRaises(session_error):
                            session.initialize_debug()
                    self.assertEqual(attempts, requests[:requests.index(failed_request) + 1])
                    if failed_request == self.STATE_REQUEST:
                        sleep.assert_called_once_with(2.0)
                    else:
                        sleep.assert_not_called()
                    halt.assert_not_called()
                    resume.assert_not_called()

    def test_invalid_startup_arguments_fail_before_any_io_or_wait(self):
        invalid = [
            {"entry_pc": value}
            for value in (0, 0xFF0001, -1, 0x100000000, True, 0xFF0000 * 1.0, "FF0000", None)
        ] + [
            {"settle_seconds": value}
            for value in (True, False, None, "2", -1, 0, 1.999, 60.001,
                          float("nan"), float("inf"), float("-inf"))
        ]
        for kwargs in invalid:
            with self.subTest(**kwargs):
                transport = self.make_transport([], [])
                with mock.patch("time.sleep") as sleep:
                    with self.assertRaises(ValueError):
                        IceSession(transport).initialize_debug(**kwargs)
                self.assertEqual(transport.writes, [])
                sleep.assert_not_called()

    def test_settle_accepts_integer_lower_and_upper_boundaries(self):
        for seconds in (2, 60):
            with self.subTest(seconds=seconds):
                transport = self.make_transport(
                    [VERSION_EVENT, ZERO_EVENT, data_response(self.SNAPSHOT)], []
                )
                with mock.patch("time.sleep") as sleep:
                    version, state = IceSession(transport).initialize_debug(settle_seconds=seconds)
                sleep.assert_called_once_with(seconds)
                self.assertEqual((version, state.raw), ("V4.0", self.SNAPSHOT))
                self.assertEqual(transport.writes, [
                    self.VERSION_REQUEST, self.START_REQUEST, self.STATE_REQUEST,
                ])

    def test_unsupported_version_stops_before_startup_request(self):
        transport = self.make_transport([report("07060056332E3004")], [])
        with mock.patch("time.sleep") as sleep:
            with self.assertRaises(ProtocolError):
                IceSession(transport).initialize_debug()
        self.assertEqual(transport.writes, [self.VERSION_REQUEST])
        sleep.assert_not_called()

    def test_nonzero_ack_without_pc_is_also_rejected(self):
        transport = self.make_transport([VERSION_EVENT, report("0706010000000004")], [])
        with mock.patch("time.sleep") as sleep:
            with self.assertRaises(ProtocolError):
                IceSession(transport).initialize_debug()
        self.assertEqual(transport.writes, [self.VERSION_REQUEST, self.START_REQUEST])
        sleep.assert_not_called()

    def test_snapshot_pc_mismatch_does_not_attempt_to_halt_or_run(self):
        for pc in (0, 0xFF001F, 0xFF0481, 0x01FF0000):
            with self.subTest(pc=hex(pc)):
                snapshot = self.SNAPSHOT[:42] + pc.to_bytes(4, "big")
                transport = self.make_transport(
                    [VERSION_EVENT, ZERO_EVENT, data_response(snapshot)], []
                )
                session = IceSession(transport)
                with mock.patch("time.sleep") as sleep, \
                     mock.patch.object(session, "halt") as halt, \
                     mock.patch.object(session, "resume") as resume:
                    with self.assertRaises(ProtocolError):
                        session.initialize_debug()
                sleep.assert_called_once_with(2.0)
                self.assertEqual(transport.writes, [
                    self.VERSION_REQUEST, self.START_REQUEST, self.STATE_REQUEST,
                ])
                halt.assert_not_called()
                resume.assert_not_called()


class SessionTests(unittest.TestCase):
    def test_version_real_capture(self):
        transport = ScriptedTransport([VERSION_EVENT])
        session = IceSession(transport)
        self.assertEqual(session.version(), "V4.0")
        self.assertEqual(transport.writes[0], report("FF5A030000A4"))

    def test_read_state_real_capture(self):
        transport = ScriptedTransport([STATE_FRAME_33])
        state = IceSession(transport).read_state()
        self.assertEqual(state.pc, 0x00FF0481)
        self.assertEqual(transport.writes[0], report("FF5A030001A3"))

    def test_read_pc_real_capture(self):
        transport = ScriptedTransport([report("060200FF04817A")])
        result = IceSession(transport).read_memory(0, 0, 4)
        self.assertEqual(result, bytes.fromhex("00FF0481"))
        self.assertEqual(transport.writes[0], report("FF5A080400000000000497"))

    def test_read_sfr_real_capture(self):
        transport = ScriptedTransport([report("03028876")])
        result = IceSession(transport).read_memory(4, 0xA8, 1)
        self.assertEqual(result, b"\x88")
        self.assertEqual(transport.writes[0], report("FF5A080404000000A801EE"))

    def test_step_real_capture_returns_stop_pc(self):
        transport = ScriptedTransport([EVENT_WITH_PC])
        event = IceSession(transport).step(bytes.fromhex("C2AF7E1F"))
        self.assertEqual(event.pc, 0x00FF0483)
        self.assertEqual(transport.writes[0], report("FF5A080801C2AF7E1F0088"))

    def test_step_rejects_non_4_byte_window(self):
        session = IceSession(ScriptedTransport())
        with self.assertRaises(ValueError):
            session.step(b"\x00")
        with self.assertRaises(TypeError):
            session.step(0x00FF0481)  # 地址不是指令窗口

    def test_resume_keeps_second_event_for_poll(self):
        transport = ScriptedTransport([ZERO_EVENT, ZERO_EVENT])
        session = IceSession(transport)
        session.resume()
        self.assertEqual(len(transport.writes), 1)
        event = session.poll_event(0)
        self.assertIsNotNone(event)
        self.assertEqual(event.content, bytes(5))
        self.assertIsNone(session.poll_event(0))

    def test_resume_first_reply_is_attributed_to_resume(self):
        transport = ScriptedTransport([ZERO_EVENT])
        session = IceSession(transport)
        session.resume()
        self.assertIsNone(session.poll_event(0))

    def test_resume_rejects_data_reply(self):
        transport = ScriptedTransport([report("060200FF04817A")])
        with self.assertRaises(ProtocolError):
            IceSession(transport).resume()

    def test_halt_real_capture(self):
        transport = ScriptedTransport([ZERO_EVENT])
        IceSession(transport).halt()
        self.assertEqual(transport.writes[0], report("FF5A030002A2"))

    def test_running_halt_timeout_does_not_issue_unconfirmed_state_query(self):
        transport = GeneratedTransport(lambda request: [])
        session = IceSession(transport, timeout_ms=25)
        with mock.patch.object(session, "read_state") as state:
            with self.assertRaisesRegex(IceTimeoutError, "未收到停止确认") as caught:
                session.halt(expect_running=True)
        self.assertIsInstance(caught.exception.__cause__, IceTimeoutError)
        state.assert_not_called()
        self.assertEqual(transport.writes, [report("FF5A030002A2")])

    def test_halt_rejects_unknown_running_flag_before_usb_io(self):
        for value in (None, 0, 1, "true"):
            with self.subTest(value=value):
                transport = ScriptedTransport()
                with self.assertRaises(TypeError):
                    IceSession(transport).halt(expect_running=value)
                self.assertEqual(transport.writes, [])

    def test_halt_drains_stale_event_before_ack(self):
        transport = ScriptedTransport([ZERO_EVENT], stale=[ZERO_EVENT])
        session = IceSession(transport)
        session.halt()
        # 第一条是发送前清理到的旧事件，第二条才是本次 ACK；旧事件仍可读取。
        self.assertEqual(len(transport.writes), 1)
        self.assertEqual(session.poll_event(0).content, bytes(5))
        self.assertIsNone(session.poll_event(0))

    def test_halt_preserves_pc_stop_event(self):
        transport = ScriptedTransport([EVENT_WITH_PC, ZERO_EVENT])
        session = IceSession(transport)
        session.halt()
        event = session.poll_event(0)
        self.assertEqual(event.pc, 0x00FF0483)
        self.assertIsNone(session.poll_event(0))

    def test_halt_pc_event_without_following_ack(self):
        transport = ScriptedTransport([EVENT_WITH_PC])
        session = IceSession(transport)
        session.halt()
        self.assertEqual(session.poll_event(0).pc, 0x00FF0483)

    def _halt_without_ack_transport(self, snapshot_responses):
        halt_request = report("FF5A030002A2")
        state_request = report("FF5A030001A3")

        def respond(write):
            if write == halt_request:
                self.assertEqual(transport.writes, [halt_request])
                return []
            self.assertEqual(write, state_request)
            self.assertEqual(transport.writes, [halt_request, state_request])
            # Publish the snapshot only after its request, so the stale-event
            # drain before read_state() cannot consume the future response.
            return snapshot_responses

        transport = GeneratedTransport(respond)
        return transport

    def test_halt_without_ack_requires_validated_cpu_snapshot(self):
        captured = decode_data_response(STATE_FRAME_33, expected_data_length=46).data
        for pc in (0x00FF0000, 0x00FF001F):
            with self.subTest(pc=hex(pc)):
                snapshot = captured[:42] + pc.to_bytes(4, "big")
                transport = self._halt_without_ack_transport([data_response(snapshot)])
                session = IceSession(transport, timeout_ms=25)
                with mock.patch.object(session, "read_state", wraps=session.read_state) as read_state:
                    self.assertIsNone(session.halt())
                    read_state.assert_called_once_with()
                self.assertEqual(
                    transport.writes,
                    [report("FF5A030002A2"), report("FF5A030001A3")],
                )
                self.assertEqual(transport.pending, [])
                self.assertIsNone(session.poll_event(0))

    def test_halt_without_ack_and_snapshot_response_still_times_out(self):
        transport = self._halt_without_ack_transport([])
        session = IceSession(transport, timeout_ms=25)
        with self.assertRaisesRegex(IceTimeoutError, "25 ms"):
            session.halt()
        self.assertEqual(
            transport.writes,
            [report("FF5A030002A2"), report("FF5A030001A3")],
        )

    def test_halt_without_ack_rejects_wrong_snapshot_length(self):
        for size in (45, 47):
            with self.subTest(size=size):
                transport = self._halt_without_ack_transport([data_response(bytes(size))])
                with self.assertRaises(ProtocolError):
                    IceSession(transport, timeout_ms=25).halt()
                self.assertEqual(
                    transport.writes,
                    [report("FF5A030002A2"), report("FF5A030001A3")],
                )

    def test_halt_without_ack_rejects_bad_snapshot_checksum(self):
        bad_snapshot = bytearray(STATE_FRAME_33)
        bad_snapshot[48] ^= 1  # Type + 46-byte data is followed by sum8.
        transport = self._halt_without_ack_transport([bytes(bad_snapshot)])
        with self.assertRaises(ProtocolError):
            IceSession(transport, timeout_ms=25).halt()
        self.assertEqual(
            transport.writes,
            [report("FF5A030002A2"), report("FF5A030001A3")],
        )

    def test_halt_without_ack_rejects_event_in_place_of_snapshot(self):
        for event in (ZERO_EVENT, EVENT_WITH_PC, VERSION_EVENT):
            with self.subTest(event=event[:8].hex()):
                transport = self._halt_without_ack_transport([event])
                with self.assertRaises(ProtocolError):
                    IceSession(transport, timeout_ms=25).halt()
                self.assertEqual(
                    transport.writes,
                    [report("FF5A030002A2"), report("FF5A030001A3")],
                )

    def test_write_memory_real_capture(self):
        transport = ScriptedTransport([ZERO_EVENT])
        IceSession(transport).write_memory(5, 0x00FF0498, b"\xB9")
        self.assertEqual(transport.writes[0], report("FF5A09020500FF049801B942"))

    def test_write_rejects_space_above_5(self):
        with self.assertRaises(ValueError):
            IceSession(ScriptedTransport()).write_memory(6, 0, b"\x00")

    def test_read_space_5_is_explicitly_unsupported(self):
        with self.assertRaises(UnsupportedOperationError):
            IceSession(ScriptedTransport()).read_memory(5, 0, 1)

    def test_read_rejects_zero_and_oversize_count(self):
        session = IceSession(ScriptedTransport())
        with self.assertRaises(ValueError):
            session.read_memory(0, 0, 0)
        with self.assertRaises(ValueError):
            session.read_memory(0, 0, 256)

    def test_read_61_byte_boundary(self):
        payload = bytes(range(61))
        def responder(write):
            self.assertEqual(write[9], 61)
            return [data_response(payload)]
        transport = GeneratedTransport(responder)
        result = IceSession(transport).read_memory(4, 0x20, 61)
        self.assertEqual(result, payload)
        self.assertEqual(transport.writes[0][2], 8)
        self.assertEqual(transport.writes[0][9], 61)

    def test_read_62_bytes_splits_into_61_and_1(self):
        def responder(write):
            count = write[9]
            return [data_response(bytes([0xAA]) * count if count == 61 else b"\xBB")]
        transport = GeneratedTransport(responder)
        result = IceSession(transport).read_memory(4, 0x20, 62)
        self.assertEqual(result, bytes([0xAA]) * 61 + b"\xBB")
        self.assertEqual(len(transport.writes), 2)
        self.assertEqual(transport.writes[0][5:9], (0x20).to_bytes(4, "big"))
        self.assertEqual(transport.writes[1][5:9], (0x20 + 61).to_bytes(4, "big"))

    def test_write_53_byte_boundary(self):
        transport = GeneratedTransport(lambda write: [ZERO_EVENT])
        IceSession(transport).write_memory(5, 0x00FF0000, bytes(53))
        self.assertEqual(len(transport.writes[0]), 64)
        self.assertEqual(transport.writes[0][2], 0x3D)
        self.assertEqual(transport.writes[0][9], 53)
        effective_length = 3 + transport.writes[0][2]
        self.assertEqual(sum(transport.writes[0][:effective_length]) & 0xFF, 0)

    def test_write_54_bytes_splits_into_53_and_1(self):
        transport = GeneratedTransport(lambda write: [ZERO_EVENT])
        IceSession(transport).write_memory(5, 0x00FF0000, bytes(54))
        self.assertEqual(len(transport.writes), 2)
        self.assertEqual(transport.writes[0][9], 53)
        self.assertEqual(transport.writes[1][5:9], (0x00FF0000 + 53).to_bytes(4, "big"))
        self.assertEqual(transport.writes[1][9], 1)

    def test_write_255_bytes_chunks(self):
        transport = GeneratedTransport(lambda write: [ZERO_EVENT])
        IceSession(transport).write_memory(5, 0x1000, bytes(255))
        self.assertEqual([write[9] for write in transport.writes], [53, 53, 53, 53, 43])

    def test_read_wrong_reply_length_is_protocol_error(self):
        transport = ScriptedTransport([report("060200FF04817A")])
        with self.assertRaisesRegex(ProtocolError, "长度"):
            IceSession(transport).read_memory(0, 0, 3)

    def test_data_command_rejects_event(self):
        transport = ScriptedTransport([ZERO_EVENT])
        with self.assertRaises(ProtocolError):
            IceSession(transport).read_state()

    def test_timeout_is_bounded_and_readable(self):
        session = IceSession(ScriptedTransport(), timeout_ms=25)
        with self.assertRaisesRegex(IceTimeoutError, "25 ms"):
            session.read_state()

    def test_transport_timeout_is_wrapped(self):
        transport = ScriptedTransport(read_error=TransportTimeout("device timeout"))
        with self.assertRaises(IceTimeoutError):
            IceSession(transport).version()

    def test_disconnect_is_wrapped(self):
        transport = ScriptedTransport(write_error=OSError("unplugged"))
        with self.assertRaises(IceDisconnectedError):
            IceSession(transport).version()

    def test_invalid_report_size_from_transport(self):
        transport = ScriptedTransport([b"\x00"])
        with self.assertRaises(ProtocolError):
            IceSession(transport).version()

    def test_set_pc_is_explicitly_unsupported(self):
        with self.assertRaises(UnsupportedOperationError):
            IceSession(ScriptedTransport()).set_pc(0xFF0000)

    def test_timeout_validation(self):
        with self.assertRaises(ValueError):
            IceSession(ScriptedTransport(), timeout_ms=0)
        with self.assertRaises(ValueError):
            IceSession(ScriptedTransport(), timeout_ms=60_001)

    def test_stale_event_drain_is_bounded(self):
        transport = ScriptedTransport(
            [VERSION_EVENT], stale=[ZERO_EVENT] * (MAX_DRAIN_EVENTS + 1)
        )
        with self.assertRaisesRegex(ProtocolError, "拒绝无限读取"):
            IceSession(transport).version()
        self.assertEqual(transport.writes, [])


class FakeHidDevice:
    def __init__(self):
        self.opened = []
        self.writes = []
        self.closed = 0
        self.nonblocking = False
        self.nonblocking_calls = []
        self.nonblocking_result = 0
        self.read_calls = []
        self.read_data = b"\x00" + report("07060056342E3004")

    def open_path(self, path):
        self.opened.append(path)

    def set_nonblocking(self, value):
        assert self.opened, "set_nonblocking must follow open_path"
        self.nonblocking_calls.append(value)
        if self.nonblocking_result == 0:
            self.nonblocking = bool(value)
        return self.nonblocking_result

    def write(self, data):
        self.writes.append(bytes(data))
        return len(data)

    def read(self, size, timeout):
        self.read_calls.append((size, timeout))
        if timeout == 0 and not self.nonblocking:
            raise AssertionError("read(size, 0) would block without set_nonblocking(1)")
        return self.read_data

    def close(self):
        self.closed += 1


class FakeHidModule:
    def __init__(self):
        self.device_obj = FakeHidDevice()
        self.enumerations = []

    def enumerate(self, *, vendor_id, product_id):
        self.enumerations.append((vendor_id, product_id))
        return [{"path": b"fake-stc-path", "vendor_id": vendor_id, "product_id": product_id}]

    def device(self):
        return self.device_obj


class TransportTests(unittest.TestCase):
    def test_construction_does_not_load_hidapi(self):
        with mock.patch.dict(sys.modules, {"hid": None}):
            transport = HidTransport()
            self.assertFalse(transport.is_open)

    def test_module_import_is_lazy(self):
        # 当前解释器中即使没有 hidapi，导入 transport 本身也必须成功。
        module = importlib.import_module("stcforge.transport")
        self.assertTrue(hasattr(module, "HidTransport"))

    def test_identity_constants(self):
        self.assertEqual((STC_VID, STC_PID), (0x34BF, 0x1002))

    def test_open_uses_vid_pid_and_explicit_path(self):
        fake = FakeHidModule()
        transport = HidTransport(module_factory=lambda: fake)
        transport.open()
        self.assertTrue(transport.is_open)
        self.assertEqual(fake.enumerations, [(0x34BF, 0x1002)])
        self.assertEqual(fake.device_obj.opened, [b"fake-stc-path"])
        self.assertEqual(fake.device_obj.nonblocking_calls, [1])
        self.assertTrue(fake.device_obj.nonblocking)

    def test_nonblocking_configuration_failure_closes_device(self):
        for result in (-1, 1):
            with self.subTest(result=result):
                fake = FakeHidModule()
                fake.device_obj.nonblocking_result = result
                transport = HidTransport(module_factory=lambda: fake)
                with self.assertRaises(TransportDisconnected):
                    transport.open()
                self.assertEqual(fake.device_obj.opened, [b"fake-stc-path"])
                self.assertEqual(fake.device_obj.nonblocking_calls, [1])
                self.assertEqual(fake.device_obj.closed, 1)
                self.assertFalse(transport.is_open)
                with self.assertRaises(TransportDisconnected):
                    transport.read_report(0)
                self.assertEqual(fake.device_obj.read_calls, [])
                transport.close()
                self.assertEqual(fake.device_obj.closed, 1)

    def test_fake_zero_timeout_read_rejects_blocking_mode(self):
        device = FakeHidDevice()
        device.open_path(b"fake-stc-path")
        device.read_data = b""
        with self.assertRaisesRegex(AssertionError, "would block"):
            device.read(65, 0)

    def test_zero_timeout_without_data_is_immediate_transport_timeout(self):
        fake = FakeHidModule()
        fake.device_obj.read_data = b""
        transport = HidTransport(module_factory=lambda: fake)
        transport.open()
        with self.assertRaises(TransportTimeout):
            transport.read_report(0)
        self.assertEqual(fake.device_obj.nonblocking_calls, [1])
        self.assertEqual(fake.device_obj.read_calls, [(65, 0)])

    def test_zero_timeout_returns_data_arriving_after_empty_poll(self):
        fake = FakeHidModule()
        fake.device_obj.read_data = b""
        transport = HidTransport(module_factory=lambda: fake)
        transport.open()
        with self.assertRaises(TransportTimeout):
            transport.read_report(0)
        fake.device_obj.read_data = b"\x00" + VERSION_EVENT
        self.assertEqual(transport.read_report(0), VERSION_EVENT)
        self.assertEqual(fake.device_obj.read_calls, [(65, 0), (65, 0)])

    def test_positive_read_timeouts_are_passed_through_unchanged(self):
        fake = FakeHidModule()
        transport = HidTransport(module_factory=lambda: fake, read_timeout_ms=321)
        transport.open()
        for timeout in (1, 10, 1000, 60_000):
            with self.subTest(timeout=timeout):
                self.assertEqual(transport.read_report(timeout), VERSION_EVENT)
                self.assertEqual(fake.device_obj.read_calls[-1], (65, timeout))
        self.assertEqual(transport.read_report(), VERSION_EVENT)
        self.assertEqual(fake.device_obj.read_calls[-1], (65, 321))

    def test_write_windows_prepends_report_id_zero(self):
        fake = FakeHidModule()
        transport = HidTransport(module_factory=lambda: fake)
        transport.open()
        with mock.patch("stcforge.transport.os.name", "nt"):
            transport.write_report(report("FF5A030000A4"))
        self.assertEqual(len(fake.device_obj.writes[0]), 65)
        self.assertEqual(fake.device_obj.writes[0][0], 0)
        self.assertEqual(fake.device_obj.writes[0][1:], report("FF5A030000A4"))

    def test_write_non_windows_also_prepends_report_id(self):
        fake = FakeHidModule()
        transport = HidTransport(module_factory=lambda: fake)
        transport.open()
        with mock.patch("stcforge.transport.os.name", "posix"):
            transport.write_report(report("FF5A030000A4"))
        self.assertEqual(fake.device_obj.writes[0], b"\0" + report("FF5A030000A4"))

    def test_short_write_is_rejected(self):
        fake = FakeHidModule()
        fake.device_obj.write = lambda data: 64
        transport = HidTransport(module_factory=lambda: fake)
        transport.open()
        with self.assertRaises(TransportDisconnected):
            transport.write_report(report("FF5A030000A4"))

    def test_multiple_devices_require_explicit_path(self):
        fake = FakeHidModule()
        fake.enumerate = lambda **kw: [{"path": b"one"}, {"path": b"two"}]
        transport = HidTransport(module_factory=lambda: fake)
        with self.assertRaisesRegex(TransportDisconnected, "多个"):
            transport.open()

    def test_read_strips_leading_report_id_zero(self):
        fake = FakeHidModule()
        transport = HidTransport(module_factory=lambda: fake)
        transport.open()
        self.assertEqual(transport.read_report(10), report("07060056342E3004"))

    def test_read_timeout_is_transport_timeout(self):
        fake = FakeHidModule()
        fake.device_obj.read_data = b""
        transport = HidTransport(module_factory=lambda: fake)
        transport.open()
        with self.assertRaises(TransportTimeout):
            transport.read_report(1)

    def test_close_is_idempotent(self):
        fake = FakeHidModule()
        transport = HidTransport(module_factory=lambda: fake)
        transport.open()
        transport.close()
        transport.close()
        self.assertEqual(fake.device_obj.closed, 1)
        self.assertFalse(transport.is_open)

    def test_write_before_open_is_disconnected(self):
        transport = HidTransport(module_factory=lambda: FakeHidModule())
        with self.assertRaises(TransportDisconnected):
            transport.write_report(report("FF5A030000A4"))

    def test_missing_device_is_readable(self):
        class EmptyHid:
            def enumerate(self, *, vendor_id, product_id):
                return []

            def device(self):
                raise AssertionError("不应创建设备对象")

        transport = HidTransport(module_factory=EmptyHid)
        with self.assertRaisesRegex(TransportDisconnected, "34BF"):
            transport.open()

    def test_write_requires_64_bytes(self):
        fake = FakeHidModule()
        transport = HidTransport(module_factory=lambda: fake)
        transport.open()
        with self.assertRaises(ValueError):
            transport.write_report(b"\x00")

    def test_transport_protocol_is_runtime_checkable(self):
        from stcforge.transport import Transport

        self.assertIsInstance(ScriptedTransport(), Transport)


if __name__ == "__main__":
    unittest.main()

