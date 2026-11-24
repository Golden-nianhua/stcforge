"""真实 SDCC -> CDB/HEX -> ELF -> GDB 的整条链路；全程无硬件。"""
from contextlib import ExitStack
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

    def test_compiler_complex_types_and_pointer_address_spaces(self):
        with ExitStack() as cleanup:
            work = Path(cleanup.enter_context(tempfile.TemporaryDirectory(prefix="stcforge-types-")))
            source = ROOT / "tools/tests/fixtures/gdb-locals/types_fixture.c"
            image = work / "types_fixture.ihx"
            result = subprocess.run([
                os.environ["STCFORGE_SDCC"], "-mmcs251", "--model-large", "--stack-auto",
                "--int-long-reent", "--std-c11", "--debug", "--code-loc", "0xff0000",
                "--xram-loc", "0x10000", str(source), "-o", str(image),
            ], cwd=work, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            cdb = image.with_suffix(".cdb")
            elf = image.with_suffix(".debug.elf")
            summary = convert(cdb, image, elf, source.parent)
            self.assertEqual(summary["skipped"]["unknown_types"], 0, summary)
            self.assertGreaterEqual(summary["stack_locals"], 5, summary)
            cdb_text = cdb.read_text(encoding="utf-8")
            globals_ = {name: int(raw, 16) for name, raw in re.findall(
                r"^L:(?:G|Ftypes_fixture)\$([^$]+)\$[^:]+:([0-9A-F]+)$", cdb_text, re.M)}
            initializers = {name: int(raw, 16) for name, raw in re.findall(
                r"^L:Ftypes_fixture\$__xinit_([^$]+)\$[^:]+:([0-9A-F]+)$", cdb_text, re.M)}
            slots = {name: int(offset) for name, offset in re.findall(
                r"^S:Ltypes_fixture\.main\$([^$]+)\$[^,]+\([^)]*\),B,1,(\d+)$",
                cdb_text, re.M)}
            rows = read_listing(image.with_suffix(".rst"))
            main_pc = next(pc for pc, row in sorted(rows.items()) if row.source
                           and row.source[2].startswith("sink = get_value() + local."))
            # The probe double supplies snapshots; actual CDB, HEX and GDB
            # drive every type, address and debugger expression below.
            server = _MockServer()
            cleanup.callback(server.close)
            target = server.target
            memory = read_hex(image)
            target.memory.update(memory)
            values = {
                "nodes": (bytes.fromhex("0711223344") + (globals_["nodes"] + 8).to_bytes(3, "big")
                          + bytes.fromhex("0966778899000000")),
                "word": bytes.fromhex("3fc00000"),
                "flags": b"\xdd",
                "matrix": bytes.fromhex("000100020003000400050006"),
                "volts": bytes.fromhex("c0200000"),
                "wide": bytes.fromhex("fedcba9876543210"),
                "hidden": b"\x12" + bytes(7),
                "near_value": b"\x42",
            }
            widths = {"far_value": 2, "far_ptr": 3, "near_ptr": 1, "code_ptr": 3, "callback": 3,
                      "generic_code": 3, "generic_near": 3, "generic_far": 3}
            for name, size in widths.items():
                values[name] = bytes(memory[initializers[name] + i] for i in range(size))
            for name, data in values.items():
                target.write_memory(globals_[name], data)
            for name, data in {"local": bytes.fromhex("3fc00000"),
                               "samples": bytes.fromhex("11223344"),
                               "measured": bytes.fromhex("0009bfc00000"),
                               "reading": bytes.fromhex("40200000"),
                               "ptr": values["far_ptr"]}.items():
                target.write_memory(0x100 + slots[name], data)
            target.registers[36:40] = (0x100 + max(slots[name] + size - 1 for name, size in
                                                   (("local", 4), ("samples", 4), ("measured", 6), ("reading", 4),
                                                    ("ptr", 3)))).to_bytes(4, "big")
            target._set_pc(main_pc)
            mi = _MiSession(Path(os.environ["STCFORGE_GDB"]).resolve())
            cleanup.callback(mi.close)
            mi.command("-gdb-set architecture mcs251")
            mi.command("-gdb-set endian big")
            mi.command("-file-exec-and-symbols " + json.dumps(elf.as_posix()))
            host, port = server.address
            mi.command(f"-target-select remote {host}:{port}", expected="connected")
            expected = {
                "sizeof(nodes)": 16, "nodes[0].payload[1]": 0x3344,
                "nodes[0].next->payload[0]": 0x6677, "matrix[1][2]": 6,
                "word.raw": 0x3fc00000, "word.real": 1.5, "word.bytes[0]": 0x3f,
                "flags.mode": 5, "flags.ready": 1, "flags.delta": -3,
                "volts": -2.5, "wide": 0xfedcba9876543210, "hidden.id": 0x12,
                "sizeof(near_ptr)": 1, "*near_ptr": 0x42, "sizeof(code_ptr)": 3,
                "*code_ptr": 0xb2, "sizeof(far_ptr)": 3, "*far_ptr": 0x3456,
                "generic_code[2]": 0xc3, "*generic_near": 0x42, "*generic_far": 0x3456,
                "(unsigned long)callback": globals_["get_value"],
                "local.real": 1.5, "samples[1]": 0x3344, "measured.channel": 9,
                "measured.value": -1.5, "reading": 2.5, "*ptr": 0x3456,
            }
            for expression, value in expected.items():
                with self.subTest(expression=expression):
                    record = mi.command("-data-evaluate-expression " + json.dumps(expression))
                    rendered = _mi_string(record, "value").split()[0]
                    actual = float(rendered) if isinstance(value, float) else int(rendered, 0)
                    self.assertEqual(actual, value, mi.details())
            record = mi.command("-var-create aggregate * nodes")
            self.assertEqual(_mi_string(record, "numchild"), "2")
            self.assertIn('exp="0"', mi.command("-var-list-children --all-values aggregate"))
            record = mi.command("-var-create aggregate_local * local")
            self.assertEqual(_mi_string(record, "numchild"), "3")
            self.assertIn('exp="real"', mi.command("-var-list-children --all-values aggregate_local"))
            mi.command("-target-detach")

if __name__ == "__main__": unittest.main()
