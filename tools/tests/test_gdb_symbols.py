"""真实 SDCC -> CDB/HEX -> ELF -> GDB 的整条链路；全程无硬件。"""
import os
from pathlib import Path
import queue
import subprocess
import tempfile
import threading
import unittest

from stcforge.server import serve
from stcforge.symbols import convert
from stcforge.target import MockTarget

ROOT = Path(__file__).resolve().parents[2]

@unittest.skipUnless(os.environ.get("STCFORGE_GDB") and os.environ.get("STCFORGE_SDCC"),
                     "设置 STCFORGE_GDB 和 STCFORGE_SDCC 后运行编译器/调试器联调")
class CompilerGdbTests(unittest.TestCase):
    def test_compiler_symbols_and_live_globals(self):
        with tempfile.TemporaryDirectory(prefix="stcforge-symbols-") as folder:
            work = Path(folder)
            source = ROOT / "docs/examples/firmware/main.c"
            ihx = work / "fixture.ihx"
            compile_result = subprocess.run([
                os.environ["STCFORGE_SDCC"], "-mmcs251", "--model-small", "--debug",
                "--code-loc", "0xff0000", "--xram-loc", "0x10000",
                str(source), "-o", str(ihx),
            ], capture_output=True, text=True, timeout=30)
            self.assertEqual(compile_result.returncode, 0, compile_result.stdout + compile_result.stderr)
            elf = work / "fixture.debug.elf"
            summary = convert(work / "fixture.cdb", ihx, elf, ROOT / "docs/examples/firmware")
            self.assertGreaterEqual(summary["functions"], 2)
            target = MockTarget()
            # 独立于转换器填入编译器指定的 XDATA 起始数据。
            target.write_memory(0x10000, b"\x12\x34\x89\xab\xcd\xef")
            ready = queue.Queue()
            errors = []
            def worker():
                try: serve(target, port=0, once=True, ready=ready.put)
                except BaseException as exc: errors.append(exc)
            thread = threading.Thread(target=worker, daemon=True)
            thread.start()
            host, port = ready.get(timeout=5)
            args = [os.environ["STCFORGE_GDB"], "-nx", "-q", "--batch"]
            commands = ["set architecture mcs251", "set endian big", "set host-charset UTF-8",
                        f'file "{elf.as_posix()}"', "info line probe", "info address counter",
                        f"target remote {host}:{port}",
                        'printf "COUNTER=%#x TICKS=%#lx IE=%#x\\n", counter, ticks, IE',
                        "set var counter = 0x5678", 'printf "UPDATED=%#x\\n", counter',
                        "detach"]
            for command in commands: args.extend(("-ex", command))
            result = subprocess.run(args, capture_output=True, text=True, timeout=25)
            thread.join(5)
            self.assertFalse(errors, errors)
            self.assertFalse(thread.is_alive())
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('of "main.c"', result.stdout)
            self.assertIn("COUNTER=0x1234 TICKS=0x89abcdef IE=0x80", result.stdout)
            self.assertIn("UPDATED=0x5678", result.stdout)
            self.assertNotIn("Dwarf Error", result.stderr)

if __name__ == "__main__": unittest.main()
