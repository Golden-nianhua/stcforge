"""Validate that the packaged STCForge GDB has the Python surface CLion needs."""

from __future__ import annotations

import json
import os
from pathlib import Path
import queue
import re
import subprocess
import tempfile
import threading
import time
import unittest


ROOT = Path(__file__).resolve().parents[2]
STC_GDB = Path(os.environ.get("STCFORGE_GDB", str(ROOT / "dist/windows/stc-gdb.exe")))

_GDB_VERSION_RE = re.compile(r"^\d+(?:\.\d+)+(?:[-+][0-9A-Za-z.-]+)?$")
_PYTHON_INFO_PREFIX = "STC_GDB_PYTHON_INFO="


def _clean_gdb_env() -> dict[str, str]:
    """Keep acceptance independent from an installed or development Python."""
    env = os.environ.copy()
    env.pop("PYTHONHOME", None)
    env.pop("PYTHONPATH", None)
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def _result_text(result: subprocess.CompletedProcess[str]) -> str:
    return f"return code: {result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"


def _assert_version(test: unittest.TestCase, version: object, context: str) -> None:
    test.assertIsInstance(version, str, context)
    test.assertRegex(version, _GDB_VERSION_RE, context)
    test.assertGreaterEqual(int(version.split(".", 1)[0]), 16, context)


class _MiSession:
    """Synchronous MI2 client with independent stdout/stderr drain threads."""

    def __init__(self, executable: Path, cwd: Path, env: dict[str, str]):
        self.process = subprocess.Popen(
            [str(executable), "--interpreter=mi2", "-nx", "-q"],
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        self._lines: list[str] = []
        self._stderr_lines: list[str] = []
        self._stdout_queue: queue.Queue[str | None] = queue.Queue()
        self._stderr_lock = threading.Lock()
        self._stdout_thread = threading.Thread(target=self._drain_stdout, daemon=True)
        self._stderr_thread = threading.Thread(target=self._drain_stderr, daemon=True)
        self._stdout_thread.start()
        self._stderr_thread.start()

    def _drain_stdout(self) -> None:
        try:
            assert self.process.stdout is not None
            for line in self.process.stdout:
                self._stdout_queue.put(line)
        finally:
            self._stdout_queue.put(None)

    def _drain_stderr(self) -> None:
        assert self.process.stderr is not None
        for line in self.process.stderr:
            with self._stderr_lock:
                self._stderr_lines.append(line)

    def wait_for_prompt(self, timeout: float = 15.0) -> list[str]:
        received: list[str] = []
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(
                    f"GDB MI2 did not return a prompt.\nstdout:\n{''.join(self._lines)}"
                    f"\nstderr:\n{self.stderr_text()}"
                )
            try:
                line = self._stdout_queue.get(timeout=min(remaining, 0.25))
            except queue.Empty:
                continue
            if line is None:
                raise AssertionError(
                    f"GDB MI2 exited before returning a prompt.\nstdout:\n{''.join(self._lines)}"
                    f"\nstderr:\n{self.stderr_text()}"
                )
            self._lines.append(line)
            received.append(line)
            if line.strip() == "(gdb)":
                return received

    def command(self, command: str, timeout: float = 15.0) -> list[str]:
        if self.process.poll() is not None:
            raise AssertionError(
                f"GDB MI2 exited before command {command!r}.\nstdout:\n{self.stdout_text()}"
                f"\nstderr:\n{self.stderr_text()}"
            )
        assert self.process.stdin is not None
        self.process.stdin.write(command + "\n")
        self.process.stdin.flush()
        return self.wait_for_prompt(timeout)

    def close(self, timeout: float = 10.0) -> int | None:
        if self.process.poll() is None:
            try:
                assert self.process.stdin is not None
                self.process.stdin.write("-gdb-exit\n")
                self.process.stdin.flush()
                self.process.stdin.close()
            except (BrokenPipeError, OSError, ValueError):
                pass
            try:
                self.process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self._stdout_thread.join(timeout=5)
        self._stderr_thread.join(timeout=5)
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            if stream is not None:
                stream.close()
        return self.process.returncode

    def stdout_text(self) -> str:
        return "".join(self._lines)

    def stderr_text(self) -> str:
        with self._stderr_lock:
            return "".join(self._stderr_lines)


@unittest.skipUnless(
    STC_GDB.is_file(),
    f"STC MCS-251 GDB is not available at {STC_GDB}",
)
class GdbPythonTests(unittest.TestCase):
    """A present executable must prove its Python capability; only a missing binary skips."""

    def test_batch_python_runtime_and_gdb_modules(self):
        with tempfile.TemporaryDirectory(prefix="stcforge-gdb-python-") as folder:
            work = Path(folder)
            script = work / "check-python.gdb"
            script.write_text(
                """set pagination off
set architecture mcs251
python
import gdb
import gdb.command
import gdb.command.pretty_printers
import gdb.disassembler
import gdb.frames
import gdb.FrameDecorator
import gdb.FrameIterator
import gdb.function
import gdb.printing
import gdb.types
import gdb.unwinder
import gdb.xmethod
import ctypes
import json
import os
import re
import socket
import ssl
import sys

version = gdb.VERSION
if not isinstance(version, str) or not re.fullmatch(
    r"\\d+(?:\\.\\d+)+(?:[-+][0-9A-Za-z.-]+)?", version
):
    raise AssertionError("unexpected gdb.VERSION: %r" % (version,))
if int(version.split(".", 1)[0]) < 16:
    raise AssertionError("GDB is too old for the expected Python API: %s" % version)
if sys.version_info < (3, 11):
    raise AssertionError("GDB CPython must be 3.11 or newer: %r" % (sys.version_info,))
if sys.maxsize <= 0x7FFFFFFF:
    raise AssertionError("GDB CPython does not expose a 64-bit integer ABI")

target_int_size = gdb.lookup_type("int").sizeof
target_pointer_size = gdb.lookup_type("void").pointer().sizeof
if target_int_size != 2:
    raise AssertionError("mcs251 int must be 2 bytes, got %r" % (target_int_size,))
if target_pointer_size != 3:
    raise AssertionError("mcs251 void* must be 3 bytes, got %r" % (target_pointer_size,))

modules = [
    "gdb.command",
    "gdb.command.pretty_printers",
    "gdb.disassembler",
    "gdb.frames",
    "gdb.FrameDecorator",
    "gdb.FrameIterator",
    "gdb.function",
    "gdb.printing",
    "gdb.types",
    "gdb.unwinder",
    "gdb.xmethod",
    "ctypes",
    "socket",
    "ssl",
]
payload = {
    "cwd": os.getcwd(),
    "gdb_version": version,
    "maxsize": sys.maxsize,
    "modules": modules,
    "python_version": list(sys.version_info[:3]),
    "sys_executable": sys.executable,
    "target_int_size": target_int_size,
    "target_pointer_size": target_pointer_size,
}
print("STC_GDB_PYTHON_INFO=" + json.dumps(payload, sort_keys=True))
print("STC_GDB_PYTHON_BATCH_OK")
end
info pretty-printer
echo STC_GDB_PRETTY_PRINTER_BATCH_OK\\n
""",
                encoding="utf-8",
            )
            result = subprocess.run(
                [str(STC_GDB), "--batch", "-nx", "-x", str(script)],
                cwd=work,
                env=_clean_gdb_env(),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )

        details = _result_text(result)
        combined = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, details)
        self.assertNotIn("Python scripting is not supported", combined, details)
        self.assertNotIn("Traceback (most recent call last)", combined, details)
        self.assertNotIn("Undefined info command", combined, details)
        self.assertIn("STC_GDB_PYTHON_BATCH_OK", result.stdout, details)
        self.assertIn("STC_GDB_PRETTY_PRINTER_BATCH_OK", result.stdout, details)

        info_lines = [
            line.split(_PYTHON_INFO_PREFIX, 1)[1]
            for line in result.stdout.splitlines()
            if _PYTHON_INFO_PREFIX in line
        ]
        self.assertEqual(len(info_lines), 1, details)
        payload = json.loads(info_lines[0])
        _assert_version(self, payload.get("gdb_version"), details)
        python_version = tuple(payload.get("python_version", ()))
        self.assertGreaterEqual(python_version, (3, 11), details)
        self.assertGreater(payload.get("maxsize", 0), 0x7FFFFFFF, details)
        self.assertEqual(payload.get("target_int_size"), 2, details)
        self.assertEqual(payload.get("target_pointer_size"), 3, details)
        self.assertEqual(
            sorted(payload.get("modules", [])),
            [
                "ctypes",
                "gdb.FrameDecorator",
                "gdb.FrameIterator",
                "gdb.command",
                "gdb.command.pretty_printers",
                "gdb.disassembler",
                "gdb.frames",
                "gdb.function",
                "gdb.printing",
                "gdb.types",
                "gdb.unwinder",
                "gdb.xmethod",
                "socket",
                "ssl",
            ],
            details,
        )

    def test_mi2_clion_python_commands_have_no_error(self):
        with tempfile.TemporaryDirectory(prefix="stcforge-gdb-mi-") as folder:
            work = Path(folder)
            session = _MiSession(STC_GDB, work, _clean_gdb_env())
            try:
                session.wait_for_prompt()
                version_lines = session.command("python import gdb; print(gdb.VERSION)")
                pretty_printer_lines = session.command("info pretty-printer")
            finally:
                exit_code = session.close()
            stdout = session.stdout_text()
            stderr = session.stderr_text()

        details = (
            f"exit code: {exit_code}\nstdout:\n{stdout}\nstderr:\n{stderr}\n"
            f"version response:\n{''.join(version_lines)}\n"
            f"pretty-printer response:\n{''.join(pretty_printer_lines)}"
        )
        self.assertEqual(exit_code, 0, details)
        response_text = "\n".join(version_lines + pretty_printer_lines)
        self.assertNotIn("^error", response_text.lower(), details)
        self.assertNotIn("Python scripting is not supported", details, details)
        self.assertNotIn("Undefined info command", details)
        version_text = "\n".join(version_lines)
        version_match = re.search(r"\d+(?:\.\d+)+", version_text)
        self.assertIsNotNone(version_match, details)
        _assert_version(self, version_match.group(0), details)


if __name__ == "__main__":
    unittest.main()
