"""来自官方网站 WASM 的向量、模拟 Link1D 及真 GDB 客户端。"""
import contextlib
import io
import os
import queue
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from stcforge.cli import main
from stcforge.ice import IceError, IceTimeoutError, ProtocolError
from stcforge.server import Client, memory_xml, serve
from stcforge.swd import (FlashLoad, Link1DHidTransport, Link1DSession, Link1DTarget,
                          decode_snapshot, pack_command, plan_code_pages, unpack_reply)
from stcforge.symbols import _ElfSymbol, _build_elf
from stcforge.transport import TransportDisconnected, TransportTimeout


def reply(data=b"", status=0):
    prefix = (bytes((0xa5, status, len(data))) + data).ljust(63, b"\0")
    return prefix + bytes((-sum(prefix) & 255,))


class FakeProbe:
    """探针模型，只响应本后端使用的命令；不存在擦写 Flash 的实现。"""
    def __init__(self, flash=None):
        self.requests = []
        self.pc = 0xff0000
        self.running = True
        self.slots = {}
        self.pending = None
        self.closed = False
        self.error = None
        self.flash = flash
        self.ignore_code_writes = False
        self.xfr = {}
        self.ie = 0
        self.ie_at_step = []
        self.spx = 0x106
        self.edata = {}

    def write_report(self, packet, *, timeout_ms):
        assert self.pending is None
        assert len(packet) == 64 and packet[0] == 0x5a and sum(packet) % 256 == 0
        cmd, address, size = packet[1], int.from_bytes(packet[2:6], "big"), packet[6]
        self.requests.append((cmd, address, size, packet[7:7 + size]))
        data = b""
        if cmd == 0x80:
            assert (address, size) == (0, 1)
            assert 0 <= packet[7] <= 3
            data = bytes.fromhex("011900065545")
        elif cmd == 0x81:
            pass
        elif cmd == 0x82:
            assert not self.running
            data = (bytes(range(32)) + bytes.fromhex("00012345")
                    + self.spx.to_bytes(2, "big") + bytes.fromhex("c1e000") + self.pc.to_bytes(3, "big"))
        elif cmd == 0x83:
            if self.running and self.slots:
                self.running = False
                self.pc = next(iter(self.slots.values()))
                data = b"\2"
            else:
                data = bytes([int(self.running)])
        elif cmd == 0x84:
            self.running = True
        elif cmd == 0x85:
            assert not self.running
            self.ie_at_step.append(self.ie)
            self.pc += 1
        elif cmd == 0x86:
            self.running = False
        elif cmd == 0x87:
            data = self.pc.to_bytes(4, "big")
        elif cmd == 0x8d:
            assert not self.running and size == 0
            self.pc = address
        elif self.flash is not None and cmd in (0x8c, 0x92, 0x93):
            if cmd == 0x8c:
                assert 0xfc2800 <= address <= 0x1000000 - size
                data = bytes(self.flash.get(address + offset, 0xff) for offset in range(size))
            elif cmd == 0x93:
                assert not self.running and 0xff0000 <= address < 0x1000000
                assert size == 0 and address % 512 == 0
                for offset in range(512):
                    self.flash.pop(address + offset, None)
            else:
                assert not self.running and 0xff0000 <= address < 0x1000000
                assert 1 <= size <= 40 and address % 512 + size <= 512
                if not self.ignore_code_writes:
                    for offset, value in enumerate(packet[7:7 + size]):
                        prev = self.flash.get(address + offset, 0xff)
                        assert prev & value == value
                        self.flash[address + offset] = value
        elif cmd == 0x89 and 0x7ef300 <= address <= 0x7efeff:
            assert not self.running
            data = bytes(self.xfr.get(address + offset, 0x5a) for offset in range(size))
        elif cmd == 0x8f and 0x7ef300 <= address <= 0x7efeff:
            assert not self.running
            self.xfr.update((address + offset, packet[7 + offset]) for offset in range(size))
        elif cmd == 0x8b and (address, size) == (0xa8, 1):
            assert not self.running
            data = bytes([self.ie])
        elif cmd == 0x91 and (address, size) == (0xa8, 1):
            assert not self.running
            self.ie = packet[7]
        elif cmd == 0x88:
            data = bytes(self.edata.get(address + offset, 0) for offset in range(size))
        elif cmd in (0x88, 0x89, 0x8b, 0x8c):
            assert not self.running
            data = bytes([0x5a if cmd == 0x89 else 0]) * size
        elif cmd in (0x8e, 0x8f, 0x91):
            assert not self.running
        elif cmd == 0x94:
            assert not self.running and size == 1
            slot, enabled = divmod(packet[7], 16)
            if enabled:
                self.slots[slot] = address
            else:
                self.slots.pop(slot, None)
        else:
            raise AssertionError(f"unexpected probe command {cmd:02x}")
        self.pending = reply(data)

    def read_report(self, timeout_ms):
        if self.error:
            raise self.error
        result, self.pending = self.pending, None
        assert result is not None
        return result

    def close(self):
        self.closed = True


class Link1DTests(unittest.TestCase):
    def test_flash_only_changed_image_pages_and_verify(self):
        image = {0xff0000: 2, 0xff0001: 0, 0xff0002: 0x1f, 0xff0200: 0x42}
        wire = FakeProbe({0xff0000: 0, 0xff0004: 0, 0xff0200: 0x42, 0xff0400: 0x66})
        session = Link1DSession(wire)
        session.initialize_debug()
        reports = []
        self.assertEqual(session.program_code(image, lambda *args: reports.append(args)), (2, 1))
        self.assertEqual(reports, [(1, 2, 1), (2, 2, 1)])
        writes = [row for row in wire.requests if row[0] in (0x92, 0x93)]
        self.assertEqual(writes, [
            (0x93, 0xff0000, 0, b""),
            (0x92, 0xff0000, 40, b"\x02\x00\x1f" + b"\xff" * 37),
        ])
        self.assertEqual(wire.flash[0xff0400], 0x66)
        self.assertEqual(wire.flash[0xff0004], 0xff)
        self.assertEqual(session.program_code(image), (2, 0))
        session.close()

    def test_flash_bad_readback_stops_before_next_erase(self):
        wire = FakeProbe({})
        wire.ignore_code_writes = True
        session = Link1DSession(wire)
        session.initialize_debug()
        with self.assertRaisesRegex(ProtocolError, "FF0000"):
            session.program_code({0xff0000: 2, 0xff0001: 0, 0xff0002: 0x1f, 0xff0200: 0x42})
        session.close()
        self.assertEqual([r[1] for r in wire.requests if r[0] == 0x93], [0xff0000])
        self.assertNotIn(0x81, [r[0] for r in wire.requests])

    def test_debug_download_validates_image_before_touching_hardware(self):
        image = {0xff0000: 2, 0xff0001: 0, 0xff0002: 0x1f}
        session = mock.Mock()
        load = FlashLoad(session, image, None)
        with self.assertRaisesRegex(ValueError, "erase range"):
            load.erase(0xff0200, 512)
        load.erase(0xff0000, 512)
        load.write(0xff0000, b"\x02\x00")
        with self.assertRaisesRegex(ValueError, "does not match"):
            load.write(0xff0002, b"\x00")
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            load.finish()
        session.program_code.assert_not_called()

    @unittest.skipUnless(os.environ.get("STCFORGE_GDB"), "真实 GDB 需要 STCFORGE_GDB")
    def test_real_gdb_loads_verified_image_over_swd(self):
        code = b"\x02\x00\x00$#}*"
        image = dict(enumerate(code, 0xff0000))
        wire = FakeProbe({0xff0000: 0x00, 0xff0200: 0x42})
        wire.pc = 0xff0003
        session = Link1DSession(wire)
        session.initialize_debug()
        ready, errors = queue.Queue(), []

        def worker():
            try:
                serve(Link1DTarget(session), port=0, once=True, ready=ready.put,
                      flash=FlashLoad(session, image, None))
            except Exception as exc:
                errors.append(exc)

        with tempfile.TemporaryDirectory() as folder:
            elf = Path(folder) / "firmware.elf"
            elf.write_bytes(_build_elf(code, 0xff0000, b"", b"", b"", [], 1))
            thread = threading.Thread(target=worker, daemon=True)
            thread.start()
            host, port = ready.get(timeout=5)
            command = [os.environ["STCFORGE_GDB"], "-nx", "-q", "--batch", elf.as_posix()]
            for item in ("set architecture mcs251", "set endian big", f"target remote {host}:{port}",
                         "load", 'printf "ENTRY=%#x\\n", $pc', "detach"):
                command += ["-ex", item]
            done = subprocess.run(command, capture_output=True, text=True, timeout=20)
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertFalse(errors, errors)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("ENTRY=0xff0000", done.stdout)
        self.assertEqual(bytes(wire.flash[address] for address in image), code)
        self.assertEqual(wire.flash[0xff0200], 0x42)
        self.assertEqual([r[1] for r in wire.requests if r[0] == 0x93], [0xff0000])

    def test_flash_plan_requires_absolute_reset_and_disallows_eeprom(self):
        image = {0xff0000: 2, 0xff0001: 0, 0xff0002: 0x1f}
        for invalid in ({0: 2, 1: 0, 2: 0x1f}, {**image, 0xfc2800: 0},
                        {**image, 0x1000000: 0}, {**image, 0xff0000: 0xff}):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                plan_code_pages(invalid)

    def test_official_web_vectors(self):
        for report, prefix, checksum in (
            (pack_command(0x80, count=1, data=b"\x0c"), "5a8000000000010c", 0x19),
            (pack_command(0x85), "5a85", 0x21),
            (pack_command(0x89, address=0x10203, count=4), "5a890001020304", 0x13),
            (pack_command(0x91, address=0x10203, count=3, data=bytes.fromhex("123456")),
             "5a910001020303123456", 0x70),
            (pack_command(0x94, address=0xff0123, count=1, data=b"\x71"),
             "5a9400ff01230171", 0x7d),
        ):
            self.assertEqual(report, bytes.fromhex(prefix).ljust(63, b"\0") + bytes([checksum]))
        with self.assertRaises(ValueError):
            pack_command(0x89, count=57)

    def test_reply_and_snapshot_validation(self):
        self.assertEqual(unpack_reply(reply(b"\x00\x01")), b"\x00\x01")
        # 官方网页校验整个报告，包含有效负载之后的填充。
        padded_reply = bytearray(reply(b"\x02"))
        padded_reply[30] = 5
        padded_reply[63] = 83
        self.assertEqual(unpack_reply(bytes(padded_reply)), b"\x02")
        for packet in (b"\0" * 64, reply(b"X")[:-1] + b"\0", reply(status=3), reply(bytes(61))):
            with self.assertRaises(ProtocolError):
                unpack_reply(packet)
        data = bytes(range(32)) + bytes.fromhex("ff0123450106c1e0aaff0123")
        state = decode_snapshot(data, 0xff0123)
        self.assertEqual(state.raw, bytes(range(32)) + bytes.fromhex("0001234500000106c1e000ff0123"))
        self.assertEqual(decode_snapshot(state.raw, 0xff0123), state)
        with self.assertRaisesRegex(ProtocolError, "独立 PC"):
            decode_snapshot(data, 0xff0124)

    def test_attach_pause_step_and_real_memory_reads(self):
        wire = FakeProbe()
        session = Link1DSession(wire)
        _, state = session.initialize_debug()
        self.assertEqual(state.pc, 0xff0000)
        self.assertEqual([r[0] for r in wire.requests], [0x80, 0x83, 0x86, 0x83, 0x82, 0x87])
        self.assertEqual(wire.requests[0], (0x80, 0, 1, b"\x01"))
        target = Link1DTarget(session)
        self.assertEqual(target.read_memory(0x10000, 64), bytes([0x5a]) * 64)
        self.assertEqual([(r[1], r[2]) for r in wire.requests[-2:]], [(0x10000, 56), (0x10038, 8)])
        self.assertEqual(target.read_memory(0xff0000, 2), b"\0\0")
        self.assertEqual(wire.requests[-1][:3], (0x8c, 0xff0000, 2))
        target.step()
        self.assertEqual(target.pc, 0xff0001)
        target.write_memory(0x100000a8, b"\x80")
        self.assertEqual(wire.requests[-1], (0x91, 0xa8, 1, b"\x80"))
        with self.assertRaises(ValueError):
            target.write_memory(0xff0000, b"\x80")
        target.close()
        self.assertEqual(wire.requests[-1][0], 0x81)
        self.assertTrue(wire.closed)

    def test_xfr_reads_and_writes_keep_full_far_address(self):
        wire = FakeProbe()
        session = Link1DSession(wire)
        session.initialize_debug()
        target = Link1DTarget(session)
        self.assertEqual(target.read_memory(0x7ef7a0, 1), b"\x5a")
        self.assertEqual(wire.requests[-1][:3], (0x89, 0x7ef7a0, 1))
        target.write_memory(0x7ef701, b"\x08")
        self.assertEqual(wire.requests[-1], (0x8f, 0x7ef701, 1, b"\x08"))
        self.assertEqual(target.read_memory(0x7ef701, 1), b"\x08")
        sent = len(wire.requests)
        with self.assertRaises(ValueError):
            target.write_memory(0x7efeff, b"\x00\x00")
        with self.assertRaises(ValueError):
            target.read_memory(0x7efeff, 2)
        self.assertEqual(len(wire.requests), sent)
        self.assertNotIn(b'0x7ef300', memory_xml())
        self.assertIn(b'<memory type="ram" start="0x7ef300" length="0xc00"/>',
                      memory_xml(regions=target.regions))
        target.resume()
        sent = len(wire.requests)
        with self.assertRaises(RuntimeError):
            target.write_memory(0x7ef701, b"\x00")
        self.assertEqual(len(wire.requests), sent)
        target.close()

    def test_step_temporarily_masks_ea_but_preserves_ie_instructions(self):
        for code, initial_ie, expected_ie_at_step in (
            ("9aff1c2b", 0x88, 0x08),  # ECALL
            ("d2af", 0x88, 0x88),     # SETB EA
            ("c2af", 0x88, 0x88),     # CLR EA
            ("30af10", 0x88, 0x88),   # JNB EA
            ("e5a8", 0x88, 0x88),     # MOV A,IE
            ("85a0a8", 0x88, 0x88),   # MOV IE,other
            ("a58fa8", 0x88, 0x88),   # MOV IE,R7 (legacy escape)
            ("74a8", 0x88, 0x08),    # MOV A,#0xa8 is not an IE read
            ("00", 0x08, 0x08),      # already disabled
        ):
            with self.subTest(code=code, ie=initial_ie):
                wire = FakeProbe(dict(enumerate(bytes.fromhex(code), 0xff0000)))
                wire.ie = initial_ie
                session = Link1DSession(wire)
                session.initialize_debug()
                target = Link1DTarget(session)
                target.step()
                self.assertEqual(wire.ie_at_step, [expected_ie_at_step])
                self.assertEqual(wire.ie, initial_ie)
                expected_writes = [] if initial_ie == expected_ie_at_step else [
                    bytes([expected_ie_at_step]), bytes([initial_ie])]
                self.assertEqual([r[3] for r in wire.requests if r[:3] == (0x91, 0xa8, 1)],
                                 expected_writes)
                target.close()

    def test_step_does_not_restore_ie_if_stop_was_not_confirmed(self):
        wire = FakeProbe({0xff0000: 0})
        wire.ie = 0x88
        session = Link1DSession(wire)
        session.initialize_debug()
        original_read = wire.read_report

        def read_report(timeout_ms):
            if wire.ie_at_step and wire.requests[-1][0] == 0x83:
                raise TransportTimeout("lost stop reply")
            return original_read(timeout_ms)

        wire.read_report = read_report
        target = Link1DTarget(session)
        with self.assertRaises(IceTimeoutError):
            target.step()
        self.assertEqual(wire.ie, 0x08)
        sent = list(wire.requests)
        target.close()
        self.assertEqual(wire.requests, sent)

    def test_connect_encodes_keil_speed_selection(self):
        for speed_khz, index in ((1000, 0), (600, 1), (300, 2), (100, 3)):
            with self.subTest(speed_khz=speed_khz):
                wire = FakeProbe()
                session = Link1DSession(wire, speed_khz=speed_khz)
                session.connect()
                self.assertEqual(wire.requests, [(0x80, 0, 1, bytes((index,)))])
                session.close()
        with self.assertRaises(ValueError):
            Link1DSession(FakeProbe(), speed_khz=500)

    def test_hardware_breakpoint_status_cleanup_and_limits(self):
        wire = FakeProbe()
        session = Link1DSession(wire)
        session.initialize_debug()
        target = Link1DTarget(session)
        for offset in range(8):
            target.insert_breakpoint(0xff0002 + offset)
        with self.assertRaisesRegex(ValueError, "8 个"):
            target.insert_breakpoint(0xff000a)
        target.resume()
        self.assertTrue(target.poll_stop())
        self.assertTrue(target.last_hardware_break)
        self.assertEqual(target.pc, 0xff0002)
        target.close()
        self.assertEqual(wire.slots, {})
        self.assertNotIn(0x92, [r[0] for r in wire.requests])

    def test_timeout_never_retries_or_clears_breakpoints_on_bad_session(self):
        wire = FakeProbe()
        session = Link1DSession(wire)
        session.initialize_debug()
        target = Link1DTarget(session)
        target.insert_breakpoint(0xff0001)
        wire.error = TransportTimeout("fixture timeout")
        with self.assertRaises(IceTimeoutError):
            target.read_memory(0x10000, 2)
        emitted = list(wire.requests)
        with self.assertRaises(IceError):
            target.read_registers()
        with self.assertLogs(level="WARNING"):
            target.close()
        self.assertEqual(wire.requests, emitted)
        self.assertTrue(wire.closed)

    def test_invalid_target_handshake_stops_attach_before_status(self):
        wire = FakeProbe()
        wire.read_report = mock.Mock(return_value=reply(bytes.fromhex("011900757575")))
        session = Link1DSession(wire)
        with self.assertRaisesRegex(ProtocolError, "未收到有效的 SWD 目标握手"):
            session.initialize_debug()
        session.close()
        self.assertEqual([r[0] for r in wire.requests], [0x80])
        self.assertTrue(wire.closed)

    def test_invalid_target_status_stops_attach_before_halt(self):
        for status in (0x75, 0xff):
            with self.subTest(status=status):
                wire = FakeProbe()
                read_report = wire.read_report

                def bad_status(timeout_ms):
                    data = read_report(timeout_ms)
                    return reply(bytes([status])) if wire.requests[-1][0] == 0x83 else data

                wire.read_report = bad_status
                session = Link1DSession(wire)
                with self.assertRaisesRegex(ProtocolError, f"0x{status:02X}"):
                    session.initialize_debug()
                session.close()
                self.assertEqual([r[0] for r in wire.requests], [0x80, 0x83])
                self.assertTrue(wire.closed)

    def test_detect_only_link1d_and_validate_explicit_path(self):
        module = mock.Mock()
        module.enumerate.side_effect = lambda vendor_id, product_id: (
            [{"path": b"link"}] if (vendor_id, product_id) == (0x34bf, 0x1005) else [])
        module.device.return_value.set_nonblocking.return_value = 0
        transport = Link1DHidTransport(module_factory=lambda: module)
        with transport:
            module.device.return_value.open_path.assert_called_once_with(b"link")
        self.assertEqual(module.enumerate.call_args_list, [mock.call(vendor_id=0x34bf, product_id=p)
                                                          for p in (0x1004, 0x1005)])
        module.device.reset_mock()
        with self.assertRaises(TransportDisconnected):
            Link1DHidTransport(b"usb-ice", module_factory=lambda: module).open()
        module.device.assert_not_called()

    def test_rsp_advertises_hardware_not_software(self):
        wire = FakeProbe()
        session = Link1DSession(wire)
        session.initialize_debug()
        target = Link1DTarget(session)
        with mock.patch("stcforge.server.GDBServerPacketIOThread"):
            client = Client(mock.sentinel.socket, target)
        self.assertIn(b"hwbreak+", client.dispatch(b"qSupported:hwbreak+"))
        self.assertIn(b'<memory type="rom"', client.dispatch(b"qXfer:memory-map:read::0,fff"))
        self.assertEqual(client.dispatch(b"Z0,ff0002,1"), b"")
        self.assertEqual(client.dispatch(b"Z1,ff0002,1"), b"OK")
        client.dispatch(b"c")
        self.assertTrue(target.poll_stop())
        self.assertIn(b"hwbreak:;", client.stop_reply())
        self.assertEqual(client.dispatch(b"z1,ff0002,1"), b"OK")

    def test_cli_initializes_swd_before_serving_without_hex(self):
        wire = FakeProbe()
        wire.open = mock.Mock()
        with mock.patch("stcforge.swd.Link1DHidTransport", return_value=wire), \
             mock.patch("stcforge.server.serve") as serve_mock, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["gdbserver", "--swd", "--once"]), 0)
        wire.open.assert_called_once_with()
        target = serve_mock.call_args.args[0]
        self.assertIsInstance(target, Link1DTarget)
        self.assertFalse(target.running)
        target.close()

    @unittest.skipUnless(os.environ.get("STCFORGE_GDB"), "真实 GDB 需要 STCFORGE_GDB")
    def test_real_gdb_hardware_breakpoint_and_step(self):
        wire = FakeProbe()
        session = Link1DSession(wire)
        session.initialize_debug()
        ready, errors = queue.Queue(), []

        def worker():
            try:
                serve(Link1DTarget(session), port=0, once=True, ready=ready.put)
            except Exception as exc:
                errors.append(exc)

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        host, port = ready.get(timeout=5)
        command = [os.environ["STCFORGE_GDB"], "-nx", "-q", "--batch"]
        for instruction in ("set architecture mcs251", "set endian big", f"target remote {host}:{port}",
                            "x/bx 0x10000", "x/bx 0x100000a8", "x/bx 0x7ef7a0",
                            "set {unsigned char}0x7ef701 = 8",
                            'printf "P9OUT_HIGH=%u\\n", {unsigned char}0x7ef701',
                            "set {unsigned char}0x7ef701 = 0",
                            'printf "P9OUT_LOW=%u\\n", {unsigned char}0x7ef701',
                            "stepi", "break *0xff0002", "continue",
                            'printf "SWD_PC=%#x\\n", $pc', "delete breakpoints", "detach"):
            command += ["-ex", instruction]
        done = subprocess.run(command, capture_output=True, text=True, timeout=20)
        thread.join(5)
        self.assertFalse(errors, errors)
        self.assertFalse(thread.is_alive())
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("SWD_PC=0xff0002", done.stdout)
        self.assertIn("0x5a", done.stdout)
        self.assertIn("P9OUT_HIGH=8", done.stdout)
        self.assertIn("P9OUT_LOW=0", done.stdout)
        self.assertEqual([row[3] for row in wire.requests if row[:3] == (0x8f, 0x7ef701, 1)],
                         [b"\x08", b"\x00"])
        self.assertIn((0x8b, 0xa8, 1), [row[:3] for row in wire.requests])
        self.assertIn((0x89, 0x7ef7a0, 1), [row[:3] for row in wire.requests])
        self.assertTrue(any(row[0:3] == (0x94, 0xff0002, 1) for row in wire.requests))
        self.assertNotIn(0x92, [r[0] for r in wire.requests])
        self.assertEqual(wire.slots, {})

    @unittest.skipUnless(os.environ.get("STCFORGE_GDB"), "真实 GDB 需要 STCFORGE_GDB")
    def test_real_gdb_nexti_uses_call_return_hardware_breakpoint(self):
        base, callee = 0xff0000, 0xff0008
        code = b"\x9a\xff\x00\x08\x80\xfe\xff\xff\x00\xaa\x22"

        class CallProbe(FakeProbe):
            def write_report(self, packet, *, timeout_ms):
                pc = self.pc
                super().write_report(packet, timeout_ms=timeout_ms)
                if packet[1] == 0x85 and pc == base:
                    self.pc = callee
                    for byte in (base + 4).to_bytes(3, "big"):
                        self.spx += 1
                        self.edata[self.spx] = byte
                if packet[1] == 0x83 and pc == callee and self.pc == base + 4:
                    self.spx -= 3

        wire = CallProbe(dict(enumerate(code, base)))
        session = Link1DSession(wire)
        session.initialize_debug()
        ready = queue.Queue()
        thread = threading.Thread(target=serve, args=(Link1DTarget(session),),
                                  kwargs={"port": 0, "once": True, "ready": ready.put},
                                  daemon=True)
        with tempfile.TemporaryDirectory() as folder:
            elf = Path(folder) / "calls.elf"
            symbols = [_ElfSymbol("", 0, 0, 0, 0, 0),
                       _ElfSymbol("caller", base, 6, 1, 2, 1),
                       _ElfSymbol("callee", callee, 3, 1, 2, 1)]
            elf.write_bytes(_build_elf(code, base, b"", b"", b"", symbols, 1))
            thread.start()
            host, port = ready.get(timeout=5)
            command = [os.environ["STCFORGE_GDB"], "-nx", "-q", "--batch", elf.as_posix()]
            for item in (f"target remote {host}:{port}", "nexti",
                         'printf "NEXT_PC=%#x\\n", $pc', "detach"):
                command += ["-ex", item]
            done = subprocess.run(command, capture_output=True, text=True, timeout=20)
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("NEXT_PC=0xff0004", done.stdout)
        self.assertTrue(any(row[:3] == (0x94, base + 4, 1) and row[3][0] & 1
                            for row in wire.requests))
        self.assertEqual(wire.slots, {})


if __name__ == "__main__":
    unittest.main()
