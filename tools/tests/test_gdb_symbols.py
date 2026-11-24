"""真实 SDCC -> CDB/HEX -> ELF -> GDB 的整条链路；全程无硬件。"""
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

from stcforge.server import serve
from stcforge.stack_symbols import read_listing
from stcforge.symbols import convert, read_hex
from stcforge.target import MockTarget
from test_gdb_async import _MiSession, _MockServer, _mi_string

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

    def test_compiler_locals_at_branches_loop_and_calls(self):
        temp = tempfile.TemporaryDirectory(prefix="stcforge-locals-")
        self.addCleanup(temp.cleanup)
        work = Path(temp.name)
        source = ROOT / "tools/tests/fixtures/gdb-locals/locals_fixture.c"
        image = work / "locals_fixture.ihx"
        result = subprocess.run([
            os.environ["STCFORGE_SDCC"], "-mmcs251", "--model-large", "--stack-auto",
            "--int-long-reent", "--std-c11", "--debug", "--code-loc", "0xff0000",
            "--xram-loc", "0x10000", str(source), "-o", str(image),
        ], cwd=work, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        elf = image.with_suffix(".debug.elf")
        convert(image.with_suffix(".cdb"), image, elf, source.parent)
        rows = read_listing(image.with_suffix(".rst"))
        lines = source.read_text(encoding="ascii").splitlines()

        def pc_for(statement):
            line, = [n for n, text in enumerate(lines, 1) if text.strip() == statement]
            return min(pc for pc, row in rows.items() if row.source_line == line)

        call_return, = [row.end for row in rows.values() if row.op == "ecall"
                        and row.source and "unsigned int inner =" in row.source[2]]
        unavailable = "<optimized out>"
        checkpoints = [
            (pc_for("unsigned int value = read_sample();"), {"value": unavailable}),
            (pc_for("marker = 11;"), {"value": "4660"}),
            (pc_for("choice = read_sample();"), {"choice": unavailable}),
            (pc_for("choice = read_alternate();"), {"choice": unavailable}),
            (pc_for("marker = 12;"), {"choice": "4660"}),
            (pc_for("marker = 13;"), {"pending": unavailable}),
            (pc_for("marker = 14;"), {"pending": "4660"}),
            (pc_for("outer = read_sample();"), {"outer": unavailable, "inner": unavailable}),
            (call_return, {"outer": "22136", "inner": unavailable}),
            (pc_for("marker = 15;"), {"outer": "4660", "inner": "39612"}),
            (pc_for("outer = read_sample();"), {"outer": unavailable, "inner": unavailable}),
            (pc_for("marker = 17;"), {"bounded": "4660"}),
            (pc_for("marker = 18;"), {"bounded": unavailable}),
            # SDCC records both declarations, but gives no location for the
            # inner one. Never let GDB read the outer one inside its shadow.
            (pc_for("unsigned int duplicate = read_alternate();"), {"duplicate": None}),
        ]
        server = _MockServer()
        self.addCleanup(server.close)
        server.target.memory.update(read_hex(image))
        mi = _MiSession(Path(os.environ["STCFORGE_GDB"]).resolve())
        self.addCleanup(mi.close)
        mi.command("-gdb-set architecture mcs251")
        mi.command("-gdb-set endian big")
        mi.command("-file-exec-and-symbols " + json.dumps(elf.as_posix()))
        host, port = server.address
        mi.command(f"-target-select remote {host}:{port}", expected="connected")
        for pc, expected in checkpoints:
            with self.subTest(pc=hex(pc), expected=expected):
                # Model the SDCC allocation at these stops; MockTarget does
                # not execute the fixture's instructions.
                regs = server.target.registers
                regs[4:8] = bytes.fromhex("9abc1234" if pc != call_return else "9abcdead")
                regs[36:40] = (0x102 if pc == call_return else 0x100).to_bytes(4, "big")
                server.target.write_memory(0x101, b"\x78\x56")
                mi.command(f"-break-insert -t *{pc:#x}")
                seq = mi.sequence
                mi.command("-exec-continue", expected="running")
                mi.event("*stopped", after=seq, deadline=time.monotonic() + 5)
                self.assertEqual(int(_mi_string(mi.command('-data-evaluate-expression "$pc"'),
                                                "value"), 0), pc)
                locals_ = mi.command("-stack-list-variables --all-values")
                for name, value in expected.items():
                    if value is None:
                        self.assertNotIn(f'name="{name}"', locals_)
                        mi.command(f"-data-evaluate-expression {name}", expected="error")
                    else:
                        self.assertRegex(locals_, rf'name="{name}"[^}}]*value="{re.escape(value)}"')
                        checked = mi.command(f"-data-evaluate-expression {name}")
                        self.assertEqual(_mi_string(checked, "value"), value)
        mi.command("-target-detach")

if __name__ == "__main__": unittest.main()
