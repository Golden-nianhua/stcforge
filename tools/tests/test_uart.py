import collections
import unittest
from unittest.mock import patch

from stcforge.ice import IceTimeoutError, ProtocolError
from stcforge.target import IceTarget
from stcforge.uart import SerialIceSession

HELLO = bytes.fromhex("ff 5a 03 00 00 a4")
REGS = bytes.fromhex("ff 5a 03 00 01 a3")
RUN = bytes.fromhex("ff 5a 03 08 00 9c")
READ_4 = bytes.fromhex("ff 5a 08 04 00 00 00 00 00 04 97")
WRITE_1 = bytes.fromhex("ff 5a 09 02 04 00 00 00 a8 01 80 6f")
STEP = bytes.fromhex("ff 5a 08 08 01 7e 34 f7 a0 00 4d")
ACK = bytes.fromhex("06 00 00 00 00 00 04")
VERSION = b"\x06\x00V4.0\x04"


def data_reply(data):
    body = b"\x02" + data
    return body + bytes((-sum(body) & 0xff,))


def snapshot(pc):
    return data_reply(bytes(42) + pc.to_bytes(4, "big"))


class ScriptedLink:
    def __init__(self, exchanges):
        self.exchanges = collections.deque(exchanges)
        self.pending = bytearray()
        self.purges = 0

    def write(self, data, timeout_ms):
        expected, reply = self.exchanges.popleft()
        if data != expected or self.pending:
            raise AssertionError((expected, data, self.pending))
        self.pending.extend(reply)

    def read(self, size, timeout_ms):
        size = min(size, 3)  # Multiple reads even for one protocol reply.
        data = self.pending[:size]
        del self.pending[:size]
        return bytes(data)

    def discard_input(self):
        self.purges += 1
        self.pending.clear()

    def close(self):
        pass


@patch("stcforge.uart.sleep", return_value=None)
class UartMonitorTests(unittest.TestCase):
    def test_init_and_memory_without_hid_padding(self, _):
        link = ScriptedLink([(b"\x80", b"\x80"), (b"\x80", b"\x00"), (b"\x80", b"\xff"),
                             (HELLO, VERSION), (REGS, snapshot(0xff0172)),
                             (READ_4, data_reply(b"\x00\xff\x01\x72"))])
        session = SerialIceSession(link)
        version, state = session.initialize_debug()
        self.assertEqual((version, state.pc), ("V4.0", 0xff0172))
        self.assertEqual(session.read_memory(0, 0, 4), bytes.fromhex("00 ff 01 72"))
        self.assertFalse(link.exchanges)

    def test_pause_requires_rehandshake_and_snapshot(self, _):
        link = ScriptedLink([(RUN, ACK), (b"\xff", b"\x06\x00\x00"),
                             (b"\x80", b"\xff"), (b"\x80", b"\x00"),
                             (REGS, snapshot(0xff0176))])
        target = IceTarget(SerialIceSession(link), {})
        target.resume()
        self.assertTrue(target.running)
        target.halt()
        self.assertFalse(target.running)
        self.assertEqual(link.purges, 1)
        self.assertFalse(link.exchanges)

    def test_breakpoint_stop_marker_is_confirmed(self, _):
        link = ScriptedLink([(RUN, ACK), (b"\x80", b"\x00"), (b"\x80", b"\xff"),
                             (REGS, snapshot(0xff0176))])
        target = IceTarget(SerialIceSession(link), {})
        target.resume()
        self.assertFalse(target.poll_stop())
        link.pending.extend(b"\x06\x00\x00")
        self.assertTrue(target.poll_stop())
        self.assertFalse(target.running)
        self.assertFalse(link.exchanges)

    def test_single_step_uses_instruction_bytes(self, _):
        link = ScriptedLink([(STEP, bytes.fromhex("06 00 00 ff 01 76 04"))])
        self.assertEqual(SerialIceSession(link).step(bytes.fromhex("7e 34 f7 a0")).pc, 0xff0176)

    def test_write_requires_monitor_acknowledgement(self, _):
        link = ScriptedLink([(WRITE_1, ACK)])
        SerialIceSession(link).write_memory(4, 0xa8, b"\x80")
        self.assertFalse(link.exchanges)

    def test_corrupt_data_and_timeout_are_not_accepted(self, _):
        corrupt = data_reply(b"\x00" * 4)[:-1] + b"\x01"
        for reply, error in [(corrupt, ProtocolError), (corrupt[:3], IceTimeoutError)]:
            with self.subTest(reply=reply), self.assertRaises(error):
                SerialIceSession(ScriptedLink([(READ_4, reply)])).read_memory(0, 0, 4)

    def test_pause_marker_alone_does_not_mark_target_stopped(self, _):
        link = ScriptedLink([(RUN, ACK), (b"\xff", b"\x06"), (b"\x80", b"\xff"),
                             (b"\x80", b"\xff")])
        target = IceTarget(SerialIceSession(link), {})
        target.resume()
        with self.assertRaisesRegex(ProtocolError, "Invalid UART monitor handshake"):
            target.halt()
        self.assertTrue(target.running)
