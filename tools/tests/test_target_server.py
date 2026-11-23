"""服务端真实套接字协议测试，以及可选的真实 GDB 联调。"""
import os
import queue
import socket
import subprocess
import threading
import unittest
from unittest import mock

from stcforge.server import Client, serve
from stcforge.target import MockTarget, IceTarget
from stcforge.ice import State, Event, IceError, IceDisconnectedError, IceTimeoutError, ProtocolError

class TargetTests(unittest.TestCase):
    def test_sfr_is_separate_from_edata(self):
        target = MockTarget()
        target.write_memory(0xa8, b"\x12")
        self.assertEqual(target.read_memory(0xa8, 1), b"\x12")
        self.assertEqual(target.read_memory(0x100000a8, 1), b"\x80")

    def test_code_protection_and_breakpoint_restore(self):
        target = MockTarget()
        with self.assertRaises(ValueError): target.write_memory(0xff0000, b"\xff")
        target.insert_breakpoint(0xff0000)
        self.assertEqual(target.memory[0xff0000], 0xb9)
        self.assertEqual(target.read_memory(0xff0000, 1), b"\0")
        target.restore_breakpoints()
        self.assertEqual(target.memory[0xff0000], 0)
        self.assertFalse(target.breakpoints)

    def test_region_boundaries(self):
        target = MockTarget()
        for address, size in ((0x3fff, 2), (0xffffffff, 2), (-1, 1), (0, 4097)):
            with self.assertRaises(ValueError): target.read_memory(address, size)

    def test_reg_width_and_endian(self):
        target = MockTarget()
        self.assertEqual(len(target.read_registers()), 46)
        self.assertEqual(target.read_register(16), b"\x12\x34")
        self.assertEqual(target.pc, 0xff0000)

    def test_ice_code_is_local_and_step_preserves_clr_ea(self):
        class Session:
            def __init__(self): self.writes = []
            def read_state(self):
                return State(bytes(42) + (0xff0000).to_bytes(4, "big"))
            def read_memory(self, space, address, count):
                # 禁止误发尚未验证的 space 5 读命令。
                assert (space, address, count) == (4, 0xa8, 1)
                return b"\x88"
            def write_memory(self, space, address, data): self.writes.append((space, address, data))
            def step(self, window):
                self.window = window
                return Event(b"\0" + (0xff0002).to_bytes(4, "big"))
        session = Session()
        target = IceTarget(session, dict(zip(range(0xff0000, 0xff0004), b"\xc2\xaf\0\0")))
        target.step()
        self.assertEqual(session.window, b"\xc2\xaf\0\0")
        self.assertEqual(session.writes, [(4, 0xa8, b"\x08")])

    def test_ice_step_restores_only_ea_bit(self):
        class Session:
            def __init__(self): self.writes = []; self.ie = iter((b"\x88", b"\x0b"))
            def read_state(self): return State(bytes(42) + (0xff0000).to_bytes(4, "big"))
            def read_memory(self, *args): return next(self.ie)
            def write_memory(self, space, address, data): self.writes.append(data)
            def step(self, window): return Event(b"\0" + (0xff0001).to_bytes(4, "big"))
        session = Session()
        target = IceTarget(session, {i: 0 for i in range(0xff0000, 0xff0004)})
        target.step()
        self.assertEqual(session.writes, [b"\x08", b"\x8b"])

class ClientFailureTests(unittest.TestCase):
    def test_memory_failure_closes_client_without_gdb_split_retries(self):
        for error in (IceTimeoutError('first XDATA timeout'), ProtocolError('unexpected reply length')):
            with self.subTest(error=type(error).__name__):
                session = mock.Mock()
                session.read_memory.side_effect = error
                target = IceTarget(session, {0xff0000: 0})
                target.breakpoints[0xff0000] = 0
                io = mock.Mock()
                io.receive.side_effect = [b'$m10001,4#00', b'$m10001,1#00']
                with mock.patch('stcforge.server.GDBServerPacketIOThread', return_value=io):
                    client = Client(mock.sentinel.socket, target)
                with self.assertLogs(level='ERROR') as logs:
                    with self.assertRaises(type(error)) as caught:
                        client.run()
                    target.close()
                self.assertIs(caught.exception, error)
                self.assertIs(target._communication_failure, error)
                session.read_memory.assert_called_once_with(2, 0x10001, 4)
                session.write_memory.assert_not_called()
                session.read_state.assert_not_called()
                session.transport.close.assert_called_once_with()
                io.receive.assert_called_once_with(block=False)
                io.send.assert_not_called()
                io.stop.assert_called_once_with()
                self.assertEqual(target.breakpoints, {0xff0000: 0})
                self.assertIn("b'm10001,4'", '\n'.join(logs.output))
                self.assertIn('尚未恢复', '\n'.join(logs.output))

    def test_failed_session_refuses_followup_device_operations(self):
        session = mock.Mock()
        first = IceTimeoutError('XDATA read did not complete')
        session.read_memory.side_effect = first
        target = IceTarget(session, {0xff0000: 0})
        with self.assertRaises(IceTimeoutError):
            target.read_memory(0x10001, 4)
        for operation in (lambda: target.read_memory(0x10001, 1),
                          target.read_registers, target.resume,
                          lambda: target.write_memory(0x10001, b'\x00')):
            with self.assertRaises(IceError) as caught:
                operation()
            self.assertIs(caught.exception.__cause__, first)
        session.read_memory.assert_called_once_with(2, 0x10001, 4)
        session.read_state.assert_not_called()
        session.poll_event.assert_not_called()
        session.resume.assert_not_called()
        session.write_memory.assert_not_called()

    def test_ctrl_c_failure_is_not_retried_during_breakpoint_cleanup(self):
        session = mock.Mock()
        error = IceTimeoutError("pause confirmation missing")
        session.halt.side_effect = error
        target = IceTarget(session, {0xff0000: 0})
        target.running = True
        target.breakpoints[0xff0000] = 0
        io = mock.Mock()
        io.receive.return_value = None
        io.interrupt_event.is_set.return_value = True
        with mock.patch("stcforge.server.GDBServerPacketIOThread", return_value=io):
            client = Client(mock.sentinel.socket, target)
        with self.assertLogs(level="ERROR") as logs:
            with self.assertRaises(IceTimeoutError) as caught:
                client.run()
            target.close()
        self.assertIs(caught.exception, error)
        session.halt.assert_called_once_with(expect_running=True)
        session.read_state.assert_not_called()
        session.write_memory.assert_not_called()
        session.transport.close.assert_called_once_with()
        self.assertTrue(target.running)  # 未收到停止确认，不能宣称已暂停。
        self.assertEqual(target.breakpoints, {0xff0000: 0})
        self.assertIn("请求暂停", "\n".join(logs.output))
        self.assertIn("b'\\x03'", "\n".join(logs.output))
        self.assertIn("尚未恢复", "\n".join(logs.output))
        io.send.assert_not_called()  # 不给 GDB 伪造 T02 停止回复。

    def test_cleanup_failure_preserves_first_communication_exception(self):
        target = MockTarget()
        target.running = True
        first = IceDisconnectedError("first USB read failed")
        io = mock.Mock()
        io.receive.return_value = None
        io.interrupt_event.is_set.return_value = False
        with mock.patch("stcforge.server.GDBServerPacketIOThread", return_value=io):
            client = Client(mock.sentinel.socket, target)
        client.waiting = True
        with mock.patch.object(target, "poll_stop", side_effect=first), \
             mock.patch.object(target, "restore_breakpoints", side_effect=RuntimeError("cleanup failed")), \
             self.assertLogs("stcforge.server", level="ERROR") as logs:
            with self.assertRaises(IceDisconnectedError) as caught:
                client.run()
        self.assertIs(caught.exception, first)
        self.assertIn("保留首个通信错误", "\n".join(logs.output))
        self.assertIn("等待停止事件", "\n".join(logs.output))

    def test_target_close_failure_preserves_server_exception(self):
        target = mock.Mock()
        target.close.side_effect = RuntimeError("close failed")
        first = IceTimeoutError("initial pause failed")
        with mock.patch("stcforge.server.socket.socket") as socket_factory, \
             mock.patch("stcforge.server.Client") as client_factory:
            listener = socket_factory.return_value.__enter__.return_value
            listener.accept.return_value = (mock.MagicMock(), ("127.0.0.1", 1))
            client_factory.return_value.run.side_effect = first
            with self.assertLogs("stcforge.server", level="ERROR") as logs:
                with self.assertRaises(IceTimeoutError) as caught:
                    serve(target, once=True)
        self.assertIs(caught.exception, first)
        target.close.assert_called_once_with()
        self.assertIn("保留首个通信错误", "\n".join(logs.output))

    def test_continue_poll_disconnect_logs_context_and_cleans_up(self):
        target = MockTarget()
        address = 0xff0001
        original = target.memory[address]
        target.insert_breakpoint(address)
        self.assertEqual(target.memory[address], 0xb9)

        io = mock.Mock()
        io.receive.side_effect = [b"$c#63", None]
        io.interrupt_event.is_set.return_value = False
        # Replacing the packet IO constructor avoids sockets and reader threads.
        with mock.patch("stcforge.server.GDBServerPacketIOThread", return_value=io):
            client = Client(mock.sentinel.socket, target)

        error = IceDisconnectedError("read error")

        def fail_poll():
            self.assertTrue(target.running)
            self.assertTrue(client.waiting)
            self.assertEqual(client.last_request, b"c")
            raise error

        with mock.patch.object(target, "poll_stop", side_effect=fail_poll) as poll_stop, \
             mock.patch.object(target, "restore_breakpoints", wraps=target.restore_breakpoints) as restore:
            with self.assertLogs("stcforge.server", level="ERROR") as logs:
                with self.assertRaises(IceDisconnectedError) as raised:
                    client.run()
            poll_stop.assert_called_once_with()
            restore.assert_called_once_with()

        self.assertIs(raised.exception, error)
        log_text = "\n".join(logs.output)
        self.assertIn("运行中", log_text)
        self.assertIn("最近 GDB 请求=b'c'", log_text)
        self.assertIn("read error", log_text)
        self.assertEqual(io.receive.call_args_list, [mock.call(block=False)] * 2)
        io.send.assert_not_called()
        io.stop.assert_called_once_with()
        self.assertEqual(target.memory[address], original)
        self.assertFalse(target.breakpoints)
        self.assertFalse(target.running)


class WireTests(unittest.TestCase):
    def setUp(self):
        self.sock, peer = socket.socketpair()
        self.sock.settimeout(3)
        self.target = MockTarget()
        self.client = Client(peer, self.target)
        self.thread = threading.Thread(target=self.client.run, daemon=True)
        self.thread.start()
        self.peer = peer

    def tearDown(self):
        self.sock.close()
        self.thread.join(3)
        self.peer.close()
        self.assertFalse(self.thread.is_alive())

    def request(self, command):
        data = command.encode()
        self.sock.sendall(b"$" + data + b"#" + f"{sum(data) & 255:02x}".encode())
        reply = b""
        while b"#" not in reply or len(reply.split(b"#")[-1]) < 2:
            reply += self.sock.recv(4096)
        self.sock.sendall(b"+")
        return reply[reply.index(b"$")+1:reply.index(b"#")]

    def test_registers_memory_and_step(self):
        self.assertEqual(len(self.request("g")), 92)
        self.assertEqual(self.request("p10"), b"1234")
        self.assertEqual(self.request("m30,2"), b"1234")
        self.assertEqual(self.request("M30,2:aabb"), b"OK")
        self.assertEqual(self.request("m30,2"), b"aabb")
        self.assertIn(b"1c:00ff0001", self.request("s"))

    def test_unsupported_and_invalid_requests(self):
        self.assertEqual(self.request("P0=11"), b"E01")
        self.assertEqual(self.request("qUnknown"), b"")
        with self.assertLogs('stcforge.server', level='WARNING'):
            self.assertEqual(self.request("Mff0000,1:ff"), b"E01")
            self.assertEqual(self.request("m3fff,2"), b"E01")
        self.assertEqual(self.request("Z1,ff0000,1"), b"")

    def test_disconnect_restores_code(self):
        self.assertEqual(self.request("Z0,ff0001,1"), b"OK")
        self.assertEqual(self.target.memory[0xff0001], 0xb9)
        self.assertEqual(self.request("D"), b"OK")
        self.thread.join(3)
        self.assertEqual(self.target.memory[0xff0001], 0)

    def test_ctrl_c_interrupts_running_target(self):
        self.sock.sendall(b"$c#63")
        self.assertEqual(self.sock.recv(1), b"+")
        self.sock.sendall(b"\x03")
        reply = b""
        while b"#" not in reply or len(reply.split(b"#")[-1]) < 2:
            reply += self.sock.recv(4096)
        self.sock.sendall(b"+")
        self.assertIn(b"$T02thread:1;", reply)
        self.assertFalse(self.target.running)

    def test_bad_checksum_is_nacked_without_execution(self):
        self.sock.sendall(b"$s#00")
        self.assertEqual(self.sock.recv(1), b"-")
        self.assertEqual(self.target.pc, 0xff0000)
        self.assertEqual(self.request("p1c"), b"00ff0000")

@unittest.skipUnless(os.environ.get("STCFORGE_GDB"), "设置 STCFORGE_GDB 后运行真实 GDB 联调")
class RealGdbTests(unittest.TestCase):
    def test_real_gdb(self):
        ready = queue.Queue()
        errors = []
        def worker():
            try: serve(MockTarget(), port=0, once=True, ready=ready.put)
            except BaseException as exc: errors.append(exc)
        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        host, port = ready.get(timeout=5)
        args = [os.environ["STCFORGE_GDB"], "-nx", "-q", "--batch"]
        commands = ["set architecture mcs251", "set endian big", f"target remote {host}:{port}",
                    "show architecture", "p/x $r0", "p/x $wr16", "p sizeof(int)",
                    "p sizeof(void*)", "x/2bx 0x30", "stepi", "p/x $pc",
                    "break *0xff0002", "continue", 'printf "STCFORGE_PC=%#x\\n", $pc',
                    'printf "STCFORGE_INT=%u PTR=%u\\n", sizeof(int), sizeof(void*)',
                    "delete breakpoints", "detach"]
        for command in commands: args.extend(("-ex", command))
        result = subprocess.run(args, capture_output=True, text=True, timeout=25)
        thread.join(5)
        self.assertFalse(errors, errors)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        output = result.stdout
        for value in ("mcs251", "0x2a", "0x1234", "0xff0001", "0xff0002"):
            self.assertIn(value, output)
        self.assertNotIn("Truncated register", result.stderr)
        self.assertNotIn("not supported", result.stderr)
        self.assertNotIn("Cannot insert", result.stderr)
        self.assertIn("STCFORGE_PC=0xff0002", output)
        self.assertIn("STCFORGE_INT=2 PTR=3", output)
        self.assertFalse(thread.is_alive(), result.stdout + result.stderr)

if __name__ == "__main__": unittest.main()
