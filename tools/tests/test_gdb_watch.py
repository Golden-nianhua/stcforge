"""Real packaged GDB/MI variable-object regression; loopback MockTarget only.

No compiler, USB transport, native target, or firmware writes are involved.
The real ELF supplies symbols/types; MockTarget supplies deterministic values
and NOP stepping (it does not execute the firmware).
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import re
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
GDB = Path(os.environ.get("STCFORGE_GDB", str(ROOT / "dist/windows/stc-gdb.exe")))
ELF = Path(os.environ.get("STCFORGE_WATCH_ELF", (
    "D:/Code/CLionProjects/STC/STC32K144G246_32BIT_SDCC_Template/Misc/"
    "SDCC Simulation Test/build/Debug/firmware/"
    "STC32G144K246_Simulation_Test.debug.elf"
)))

# Reuse the bounded MI reader and cancellable loopback server from the existing
# integration test. Do not import its TestCase into this module's discovery.
_spec = importlib.util.spec_from_file_location(
    "_watch_mi_support", Path(__file__).with_name("test_gdb_async.py")
)
_support = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_support)


def _field(record: str, name: str) -> str:
    # changelist scalar tuples begin with {name=..., unlike result records.
    return _support._mi_string(record.lstrip("{"), name)


def _value(record: str) -> int:
    return int(_field(record, "value").split()[0], 0)


@unittest.skipUnless(GDB.is_file() and ELF.is_file(), "Set STCFORGE_GDB/STCFORGE_WATCH_ELF to real GDB and watch ELF")
class GdbWatchTests(unittest.TestCase):
    def exercise(self, inside_main: bool):
        server = _support._MockServer()
        self.addCleanup(server.close)
        mi = _support._MiSession(GDB)
        self.addCleanup(mi.close)
        mi.command("-gdb-set architecture mcs251")
        mi.command("-gdb-set endian big")
        mi.command("-gdb-set remotetimeout 3")
        mi.command("-file-exec-and-symbols " + json.dumps(ELF.as_posix()))
        symbols = {}
        sizes = {"watch16": 2, "watch32": 4, "tick_ms": 4}
        initial = {"watch16": 0x1234, "watch32": 0x12345678, "tick_ms": 1000}
        for name, size in sizes.items():
            address = _value(mi.command(f'-data-evaluate-expression "&{name}"'))
            self.assertEqual(_value(mi.command(f'-data-evaluate-expression "sizeof({name})"')), size)
            symbols[name] = address
            server.target.write_memory(address, initial[name].to_bytes(size, "big"))
        if inside_main:
            pc = _value(mi.command('-data-evaluate-expression "&main"'))
            server.target._set_pc(pc)
        # Only MockTarget RAM is changed. NOPs allow real GDB to step within
        # the ELF's function range without pretending to emulate its prologue.
        pc = server.target.pc
        server.target.memory.update({pc + i: 0 for i in range(4)})
        host, port = server.address
        mi.command(f"-target-select remote {host}:{port}", expected="connected")
        objects = {}
        for expression in sizes:
            reply = mi.command(f"-var-create - * {expression}")
            name = _field(reply, "name")
            self.assertNotIn(name, objects.values(), mi.details())
            self.assertEqual(_field(reply, "numchild"), "0", mi.details())
            self.assertEqual(_value(reply), initial[expression], mi.details())
            mi.command(f"-var-set-format {name} hexadecimal")
            objects[expression] = name
        self.assertEqual(len(objects), 3, mi.details())
        self.assertIn("changelist=[]", mi.command("-var-update --all-values *"), mi.details())

        for cycle in range(2):
            with self.subTest(cycle=cycle + 1):
                marker = mi.sequence
                mi.command("-exec-step-instruction", expected="running")
                mi.event("*stopped", after=marker, deadline=time.monotonic() + 10)
                self.assertEqual(_value(mi.command('-data-evaluate-expression "$pc"')), pc + cycle + 1, mi.details())
                # Globals with unchanged values must remain usable after a stop;
                # GDB represents this as an empty list, not an out-of-scope row.
                self.assertIn("changelist=[]", mi.command("-var-update --all-values *"), mi.details())
                # Force every scalar into changelist. An empty unchanged list
                # would not prove that all three objects remain in scope.
                expected = {name: value + cycle + 1 for name, value in initial.items()}
                for expression, size in sizes.items():
                    server.target.write_memory(symbols[expression], expected[expression].to_bytes(size, "big"))
                reply = mi.command("-var-update --all-values *")
                changes = {}
                for entry in re.findall(r"\{[^{}]*\}", reply):
                    changes[_field(entry, "name")] = entry
                self.assertEqual(set(changes), set(objects.values()), mi.details())
                for expression, name in objects.items():
                    entry = changes[name]
                    self.assertEqual(_field(entry, "in_scope"), "true", mi.details())
                    self.assertEqual(_value(entry), expected[expression], mi.details())
                    self.assertEqual(_field(mi.command(f"-var-info-expression {name}"), "exp"), expression, mi.details())
                    self.assertEqual(_value(mi.command(f"-var-evaluate-expression {name}")), expected[expression], mi.details())
        for name in objects.values():
            mi.command(f"-var-delete {name}")
        mi.command("-target-detach")
        self.assertFalse(server.errors, repr(server.errors))
        if os.environ.get("STCFORGE_WATCH_TRACE"):
            print("\n" + mi.details())

    def test_multiple_globals_survive_steps_at_reset(self):
        self.exercise(inside_main=False)

    def test_multiple_globals_survive_steps_in_main(self):
        self.exercise(inside_main=True)

    def test_frame_identity_survives_steps_but_changes_function(self):
        server = _support._MockServer()
        self.addCleanup(server.close)
        mi = _support._MiSession(GDB)
        self.addCleanup(mi.close)
        mi.command("-gdb-set architecture mcs251")
        mi.command("-gdb-set endian big")
        mi.command("-gdb-set remotetimeout 3")
        mi.command("-file-exec-and-symbols " + json.dumps(ELF.as_posix()))
        main = _value(mi.command('-data-evaluate-expression "&main"'))
        other = _value(mi.command('-data-evaluate-expression "&timer1_isr"'))
        self.assertNotEqual(main, other)
        server.target._set_pc(main)
        server.target.memory.update({main + i: 0 for i in range(4)})
        host, port = server.address
        mi.command(f"-target-select remote {host}:{port}", expected="connected")

        def python_console(source):
            marker = len(mi.transcript)
            mi.command("-interpreter-exec console " + json.dumps("python " + source))
            return "\n".join(mi.transcript[marker:])

        def step():
            marker = mi.sequence
            mi.command("-exec-step-instruction", expected="running")
            mi.event("*stopped", after=marker, deadline=time.monotonic() + 10)

        python_console("watch_saved_frame = gdb.selected_frame()")
        for cycle in range(2):
            with self.subTest(same_function_step=cycle + 1):
                step()
                self.assertEqual(_value(mi.command('-data-evaluate-expression "$pc"')), main + cycle + 1, mi.details())
                output = python_console(
                    'print("WATCH_FRAME_SAME=%s,%s" % (watch_saved_frame.is_valid(), '
                    'watch_saved_frame == gdb.selected_frame()))'
                )
                self.assertIn("WATCH_FRAME_SAME=True,True", output, mi.details())

        # Refresh the reference so this check still runs if same-function
        # subtests fail. This is not an unwind or simulated ISR execution.
        python_console("watch_saved_frame = gdb.selected_frame()")
        server.target.step = lambda: server.target._set_pc(other)
        step()
        self.assertEqual(_value(mi.command('-data-evaluate-expression "$pc"')), other, mi.details())
        output = python_console(
            'print("WATCH_FRAME_OTHER=%s,%s,%s" % (watch_saved_frame.is_valid(), '
            'watch_saved_frame == gdb.selected_frame(), gdb.selected_frame().name()))'
        )
        self.assertIn("WATCH_FRAME_OTHER=False,False,timer1_isr", output, mi.details())
        mi.command("-target-detach")
        self.assertFalse(server.errors, repr(server.errors))
        if os.environ.get("STCFORGE_WATCH_TRACE"):
            print("\n" + mi.details())


if __name__ == "__main__":
    unittest.main(verbosity=2)

