"""真实 GDB 默认 MI2 异步中断回归；只连接回环地址的 MockTarget。

不设置 mi-async on，验收发行版的默认值。同步 MI 的旧二进制应在有限
时间内失败；即使 continue 后不再接受 MI 命令，也必须回收进程和服务。
STCFORGE_GDB 可指定待验收二进制，默认 dist/windows/stc-gdb.exe。
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import queue
import re
import socket
import subprocess
import threading
import time
import unittest

from stcforge.server import Client
from stcforge.target import MockTarget


ROOT = Path(__file__).resolve().parents[2]
STC_GDB = Path(os.environ.get("STCFORGE_GDB", str(ROOT / "dist/windows/stc-gdb.exe")))
RESULT = re.compile(r"^(\d+)\^([a-z-]+)(?:,|$)")
ASYNC = re.compile(r"^(?:\d+)?(\*[a-z-]+)(?:,|$)")


def _mi_string(record: str, field: str) -> str:
    match = re.search(r'(?:^|,)' + re.escape(field) + r'=("(?:[^"\\]|\\.)*")', record)
    if match is None:
        raise AssertionError(f"MI record has no {field!r}: {record}")
    return json.loads(match.group(1))


class _MiSession:
    """Token results and untagged execution events have separate mailboxes.

    Reader threads only drain pipes. The test thread consumes their queue with
    absolute deadlines; prompts are never treated as command completion.
    """

    def __init__(self, executable: Path):
        env = os.environ.copy()
        for key in ("PYTHONHOME", "PYTHONPATH"):
            env.pop(key, None)
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        self.process = subprocess.Popen(
            [str(executable), "-nx", "-nh", "-q", "--interpreter=mi2"],
            cwd=ROOT, env=env, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace", bufsize=1,
        )
        self.queue: queue.Queue[tuple[str, str | None]] = queue.Queue()
        self.results: dict[str, str] = {}
        self.events: list[tuple[int, str]] = []
        self.transcript: list[str] = []
        self.sequence = 0
        self.token = 0
        self.readers = []
        for name, stream in (("stdout", self.process.stdout), ("stderr", self.process.stderr)):
            reader = threading.Thread(
                target=self._drain, args=(name, stream),
                name=f"stc-gdb-mi-{name}", daemon=True,
            )
            reader.start()
            self.readers.append(reader)

    def _drain(self, name, stream):
        try:
            for line in stream:
                self.queue.put((name, line.rstrip("\r\n")))
        finally:
            self.queue.put((name, None))

    def details(self):
        return f"GDB return code: {self.process.poll()}\n" + "\n".join(self.transcript[-160:])

    def send(self, command: str) -> str:
        if self.process.poll() is not None:
            raise AssertionError(f"GDB exited before {command!r}\n{self.details()}")
        self.token += 1
        token = str(self.token)
        self.transcript.append(f"> {token}{command}")
        try:
            self.process.stdin.write(f"{token}{command}\n")
            self.process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise AssertionError(f"Could not send {command!r}\n{self.details()}") from exc
        return token

    def _pump(self, deadline: float):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError(f"MI deadline expired\n{self.details()}")
        try:
            source, line = self.queue.get(timeout=remaining)
        except queue.Empty as exc:
            raise AssertionError(f"MI deadline expired\n{self.details()}") from exc
        if line is None:
            if source == "stdout":
                raise AssertionError(f"GDB closed stdout before expected record\n{self.details()}")
            return
        self.transcript.append(f"{source}: {line}")
        if source != "stdout":
            return
        self.sequence += 1
        result = RESULT.match(line)
        if result:
            token = result.group(1)
            if token in self.results:
                raise AssertionError(f"Duplicate MI result token {token}\n{self.details()}")
            self.results[token] = line
        elif ASYNC.match(line):
            self.events.append((self.sequence, line))

    def result(self, token: str, expected: str = "done", *, deadline: float) -> str:
        while token not in self.results:
            self._pump(deadline)
        record = self.results.pop(token)
        if RESULT.match(record).group(2) != expected:
            raise AssertionError(f"Expected {token}^{expected}, got {record}\n{self.details()}")
        return record

    def command(self, command: str, expected: str = "done", timeout: float = 10.0) -> str:
        deadline = time.monotonic() + timeout
        return self.result(self.send(command), expected, deadline=deadline)

    def event(self, kind: str, *, after: int, deadline: float) -> tuple[int, str]:
        while True:
            for index, (sequence, record) in enumerate(self.events):
                if sequence > after and ASYNC.match(record).group(1) == kind:
                    return self.events.pop(index)
            self._pump(deadline)

    def close(self):
        # A synchronous MI process may ignore gdb-exit as well as interrupt.
        # Never let cleanup depend on another MI result or a prompt.
        try:
            if self.process.poll() is None:
                try:
                    self.send("-gdb-exit")
                except (AssertionError, OSError):
                    pass
                try:
                    self.process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=3)
        finally:
            for reader in self.readers:
                reader.join(timeout=2)
            # Do not block closing a TextIOWrapper still held by a reader.
            for stream, reader in zip((self.process.stdout, self.process.stderr), self.readers):
                if not reader.is_alive():
                    stream.close()
            try:
                self.process.stdin.close()
            except (BrokenPipeError, OSError):
                pass
        if any(reader.is_alive() for reader in self.readers):
            raise AssertionError(f"GDB pipe reader did not exit\n{self.details()}")


class _MockServer:
    """Production RSP Client with a cancellable loopback accept and MockTarget.

    Own the listener so a failed GDB launch/connection cannot leave serve()
    blocked in accept(). Close the accepted socket to unblock packet I/O.
    """

    def __init__(self):
        self.target = MockTarget()
        self.errors: list[BaseException] = []
        self.stopping = threading.Event()
        self.lock = threading.Lock()
        self.connection = None
        self.client = None
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.listener.bind(("127.0.0.1", 0))
            self.listener.listen(1)
            self.listener.settimeout(0.1)
            self.address = self.listener.getsockname()
        except BaseException:
            self.listener.close()
            raise
        self.thread = threading.Thread(target=self._run, name="stc-gdb-mock-server", daemon=True)
        self.thread.start()

    def _run(self):
        try:
            while not self.stopping.is_set():
                try:
                    connection, _ = self.listener.accept()
                except socket.timeout:
                    continue
                with self.lock:
                    if self.stopping.is_set():
                        connection.close()
                        return
                    self.connection = connection
                    self.client = Client(connection, self.target)
                with connection:
                    self.client.run()
                return
        except OSError as exc:
            if not self.stopping.is_set():
                self.errors.append(exc)
        except BaseException as exc:
            self.errors.append(exc)
        finally:
            self.target.close()

    def close(self):
        self.stopping.set()
        self.listener.close()
        with self.lock:
            if self.client is not None:
                # Also stop Client.run if a socket closed during packet-thread
                # startup produces OSError instead of a clean EOF notification.
                self.client.detached = True
            if self.connection is not None:
                try:
                    self.connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                self.connection.close()
        self.thread.join(timeout=3)
        if self.thread.is_alive():
            raise AssertionError("Mock RSP server did not exit")
        if self.errors:
            raise AssertionError(f"Mock RSP server failed: {self.errors!r}")


@unittest.skipUnless(STC_GDB.is_file(), f"STCForge GDB is not available at {STC_GDB}")
class GdbAsyncTests(unittest.TestCase):
    def session(self):
        mi = _MiSession(STC_GDB)
        self.addCleanup(mi.close)
        return mi

    def test_default_mi2_continue_interrupt_twice_and_read_pc(self):
        server = _MockServer()
        self.addCleanup(server.close)
        mi = self.session()
        # Query only: enabling async here would hide the shipping-default bug.
        self.assertEqual(_mi_string(mi.command("-gdb-show mi-async"), "value"), "on", mi.details())
        mi.command("-gdb-set architecture mcs251")
        mi.command("-gdb-set endian big")
        mi.command("-gdb-set remotetimeout 3")
        host, port = server.address
        mi.command(f"-target-select remote {host}:{port}", expected="connected")

        for round_index in range(2):
            with self.subTest(round=round_index + 1):
                marker = mi.sequence
                deadline = time.monotonic() + 10
                continue_token = mi.send("-exec-continue")
                mi.result(continue_token, "running", deadline=deadline)
                running_sequence, _ = mi.event("*running", after=marker, deadline=deadline)

                # The result and *stopped can arrive in either order. Keep the
                # stop event buffered while matching this exact command token.
                deadline = time.monotonic() + 10
                interrupt_token = mi.send("-exec-interrupt --all")
                self.assertNotEqual(continue_token, interrupt_token)
                mi.result(interrupt_token, deadline=deadline)
                _, stopped = mi.event("*stopped", after=running_sequence, deadline=deadline)
                self.assertEqual(_mi_string(stopped, "reason"), "signal-received", mi.details())
                self.assertEqual(_mi_string(stopped, "signal-name"), "SIGINT", mi.details())
                self.assertFalse(server.target.running, mi.details())
                self.assertFalse(server.errors, repr(server.errors))

                # A separate token proves MI remains usable after each stop.
                pc_reply = mi.command('-data-evaluate-expression "$pc"')
                pc = int(_mi_string(pc_reply, "value").split()[0], 0)
                self.assertEqual(pc, 0xFF0000, mi.details())

        mi.command("-target-detach")

    def test_explicit_mi_async_off_overrides_default(self):
        mi = self.session()
        self.assertEqual(_mi_string(mi.command("-gdb-show mi-async"), "value"), "on", mi.details())
        mi.command('-interpreter-exec console "set mi-async off"')
        self.assertEqual(_mi_string(mi.command("-gdb-show mi-async"), "value"), "off", mi.details())


if __name__ == "__main__":
    unittest.main()
