"""Tests for the SDCC CDB/HEX to minimal MCS-251 ELF converter."""

from __future__ import annotations

import struct
import os
import queue
import re
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

from stcforge.symbols import (
    SymbolConversionError,
    convert,
    read_hex,
)


ROOT = Path(__file__).resolve().parents[2]
STC_GDB = Path(os.environ.get('STCFORGE_GDB', str(ROOT / 'dist/windows/stc-gdb.exe')))


def _ihex_record(kind: int, offset: int, data: bytes = b"",
                 checksum: int | None = None) -> str:
    payload = bytes([len(data), (offset >> 8) & 0xFF, offset & 0xFF, kind]) + data
    if checksum is None:
        checksum = (-sum(payload)) & 0xFF
    return ":" + (payload + bytes([checksum])).hex().upper()


def _ihex_text(records: list[str], base: int = 0xFC0000, *,
               eof: bool = True, trailing: str | None = None) -> str:
    # Intel HEX type 04 carries the upper 16 bits of a 32-bit linear address.
    lines = [_ihex_record(0x04, 0, (base >> 16).to_bytes(2, "big"))]
    lines.extend(records)
    if eof:
        lines.append(_ihex_record(0x01, 0))
    if trailing:
        lines.append(trailing)
    return "\n".join(lines) + "\n"


def _fixture_hex() -> str:
    return _ihex_text([
        _ihex_record(0x00, 0x2800, bytes.fromhex("1122334455667788")),
        _ihex_record(0x00, 0x280A, b"\xCC"),
    ])


def _fixture_cdb() -> str:
    return """M:main
F:G$main$0_0$0({3}DF,SV:S),C,0,0,0,0,0
S:Lmain.main$local$1_0$1({2}SI:U),R,0,0,[r3,r2]
S:G$g_byte$0_0$0({1}SC:U),E,0,0
S:G$g_count$0_0$0({2}SI:U),E,0,0
S:G$g_xdata$0_0$0({4}SL:U),F,0,0
S:G$P0$0_0$0({1}SC:U),I,0,0
S:G$P0$0_0$0({1}SC:U),I,0,0
S:G$P00$0_0$0({1}SX:S),J,0,0
S:G$g_unknown$0_0$0({4}DA4d,SC:U),F,0,0
S:C$FOO$0_0$0({1}SC:U),I,0,0
M:alpha
F:Falpha$helper$0_0$0({3}DF,SV:S),C,0,0,0,0,0
S:Falpha$same$0_0$0({1}SC:U),E,0,0
S:Falpha$only$0_0$0({2}SI:S),E,0,0
M:beta
F:Fbeta$helper$0_0$0({3}DF,SV:S),C,0,0,0,0,0
S:Fbeta$same$0_0$0({1}SC:U),E,0,0
L:G$g_byte$0_0$0:8
L:G$g_count$0_0$0:9
L:G$g_xdata$0_0$0:10000
L:G$P0$0_0$0:80
L:G$P00$0_0$0:80
L:G$g_unknown$0_0$0:10004
L:Falpha$same$0_0$0:10
L:Falpha$only$0_0$0:12
L:Fbeta$same$0_0$0:11
L:G$main$0$0:FC2800
L:XG$main$0$0:FC2803
L:Falpha$helper$0$0:FC2804
L:XFalpha$helper$0$0:FC2805
L:Fbeta$helper$0$0:FC2806
L:XFbeta$helper$0$0:FC2807
L:C$main.c$10$0_0$1:FC2800
L:C$main.c$10$0_0$1:FC2800
L:C$main.c$12$1_0$1:FC2802
L:C$helper.c$5$0_0$2:FC2804
L:C$helper.c$6$0_0$3:FC2806
L:A$main.c$1:FC2800
L:Lmain.main$local$1_0$1:FC2801
"""


def _uleb(data: bytes, pos: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7


def _sleb(data: bytes, pos: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            if byte & 0x40:
                value -= 1 << shift
            return value, pos


def _cstr(data: bytes, pos: int) -> tuple[str, int]:
    end = data.index(0, pos)
    return data[pos:end].decode("utf-8"), end + 1


def _elf(data: bytes) -> tuple[dict, list[dict]]:
    header = struct.unpack_from(">16sHHIIIIIHHHHHH", data, 0)
    values = {
        "ident": header[0],
        "type": header[1],
        "machine": header[2],
        "version": header[3],
        "entry": header[4],
        "phoff": header[5],
        "shoff": header[6],
        "flags": header[7],
        "ehsize": header[8],
        "phentsize": header[9],
        "phnum": header[10],
        "shentsize": header[11],
        "shnum": header[12],
        "shstrndx": header[13],
    }
    sections = []
    for index in range(values["shnum"]):
        fields = struct.unpack_from(
            ">IIIIIIIIII", data, values["shoff"] + index * values["shentsize"]
        )
        sections.append({
            "name_offset": fields[0],
            "type": fields[1],
            "flags": fields[2],
            "addr": fields[3],
            "offset": fields[4],
            "size": fields[5],
            "link": fields[6],
            "info": fields[7],
            "align": fields[8],
            "entsize": fields[9],
        })
    shstr = sections[values["shstrndx"]]
    names = data[shstr["offset"]:shstr["offset"] + shstr["size"]]
    for section in sections:
        section["name"], _ = _cstr(names, section["name_offset"])
    return values, sections


def _section(sections: list[dict], name: str) -> dict:
    return next(section for section in sections if section["name"] == name)


def _symbols(data: bytes, sections: list[dict]) -> list[dict]:
    symtab = _section(sections, ".symtab")
    strtab = _section(sections, ".strtab")
    strings = data[strtab["offset"]:strtab["offset"] + strtab["size"]]
    result = []
    for offset in range(symtab["offset"], symtab["offset"] + symtab["size"], 16):
        name_offset, value, size, info, other, shndx = struct.unpack_from(
            ">IIIBBH", data, offset
        )
        name, _ = _cstr(strings, name_offset)
        result.append({
            "name": name,
            "value": value,
            "size": size,
            "bind": info >> 4,
            "kind": info & 0x0F,
            "other": other,
            "shndx": shndx,
        })
    return result


def _abbrev(data: bytes, offset: int = 0) -> dict[int, tuple[int, list[tuple[int, int]]]]:
    tables = {}
    pos = offset
    while data[pos] != 0:
        code, pos = _uleb(data, pos)
        tag, pos = _uleb(data, pos)
        pos += 1  # children flag
        attrs = []
        while True:
            attr, pos = _uleb(data, pos)
            form, pos = _uleb(data, pos)
            if attr == 0 and form == 0:
                break
            attrs.append((attr, form))
        tables[code] = (tag, attrs)
    return tables


def _form_value(data: bytes, pos: int, form: int):
    if form == 0x08:
        return _cstr(data, pos)
    if form == 0x0B:
        return data[pos], pos + 1
    if form == 0x01:
        return struct.unpack_from(">I", data, pos)[0], pos + 4
    if form == 0x06:
        return struct.unpack_from(">I", data, pos)[0], pos + 4
    if form == 0x13:
        return struct.unpack_from(">I", data, pos)[0], pos + 4
    if form == 0x0A:
        length = data[pos]
        pos += 1
        return data[pos:pos + length], pos + length
    if form == 0x0C:
        return bool(data[pos]), pos + 1
    raise AssertionError(f"unexpected DWARF form 0x{form:02x}")


def _dies(data: bytes, sections: list[dict]) -> list[tuple[int, dict, int]]:
    info = _section(sections, ".debug_info")
    blob = data[info["offset"]:info["offset"] + info["size"]]
    abbrev_offset = struct.unpack_from(">I", blob, 6)[0]
    abbrev_section = _section(sections, ".debug_abbrev")
    tables = _abbrev(
        data[abbrev_section["offset"]:abbrev_section["offset"] + abbrev_section["size"]],
        abbrev_offset,
    )
    pos = 11
    result = []
    while pos < len(blob):
        die_offset = pos
        code, pos = _uleb(blob, pos)
        if code == 0:
            break
        tag, forms = tables[code]
        attrs = {}
        for attr, form in forms:
            value, pos = _form_value(blob, pos, form)
            attrs[attr] = value
        result.append((tag, attrs, die_offset))
    return result


def _line_rows(data: bytes, sections: list[dict]) -> list[tuple[int, int, str]]:
    line_section = _section(sections, ".debug_line")
    blob = data[line_section["offset"]:line_section["offset"] + line_section["size"]]
    header_length = struct.unpack_from(">I", blob, 6)[0]
    # DWARF2 line table header: unit_length(4), version(2), header_length(4),
    # then minimum_instruction_length, maximum_operations_per_instruction,
    # default_is_stmt, line_base, line_range, and opcode_base.  The fixture
    # emits DWARF2, so maximum_operations_per_instruction is not present.
    pos = 10
    min_inst = blob[pos]
    default_is_stmt = blob[pos + 1]
    line_base = struct.unpack_from("b", blob, pos + 2)[0]
    line_range = blob[pos + 3]
    opcode_base = blob[pos + 4]
    pos += 5
    std_lengths = list(blob[pos:pos + opcode_base - 1])
    pos += opcode_base - 1
    while blob[pos] != 0:
        _, pos = _cstr(blob, pos)
    pos += 1
    files = []
    while blob[pos] != 0:
        name, pos = _cstr(blob, pos)
        _, pos = _uleb(blob, pos)
        _, pos = _uleb(blob, pos)
        _, pos = _uleb(blob, pos)
        files.append(name)
    pos = 10 + header_length
    address = 0
    line = 1
    file_index = 1
    rows = []
    while pos < len(blob):
        opcode = blob[pos]
        pos += 1
        if opcode == 0:
            length, pos = _uleb(blob, pos)
            end = pos + length
            subopcode = blob[pos]
            pos += 1
            if subopcode == 1:
                address = 0
                line = 1
                file_index = 1
            elif subopcode == 2:
                address = struct.unpack_from(">I", blob, pos)[0]
                pos += 4
            else:
                pos = end
            pos = end
            continue
        if opcode == 1:
            rows.append((address, line, files[file_index - 1]))
        elif opcode == 2:
            advance, pos = _uleb(blob, pos)
            address += advance * min_inst
        elif opcode == 3:
            advance, pos = _sleb(blob, pos)
            line += advance
        elif opcode == 4:
            file_index, pos = _uleb(blob, pos)
        elif opcode >= opcode_base:
            adjusted = opcode - opcode_base
            address += (adjusted // line_range) * min_inst
            line += line_base + adjusted % line_range
            rows.append((address, line, files[file_index - 1]))
        else:
            for _ in range(std_lengths[opcode - 1]):
                _, pos = _uleb(blob, pos)
    return rows


class SymbolConverterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cdb = self.root / "fixture.cdb"
        self.hex = self.root / "fixture.hex"
        self.output = self.root / "firmware.elf"
        self.cdb.write_text(_fixture_cdb(), encoding="utf-8")
        self.hex.write_text(_fixture_hex(), encoding="ascii")
        (self.root / "main.c").write_text("int main(void) { return 0; }\n" * 20,
                                          encoding="utf-8")
        (self.root / "helper.c").write_text("static int helper(void) { return 1; }\n" * 20,
                                            encoding="utf-8")

    def _convert(self, cdb: Path | None = None, hex_path: Path | None = None):
        return convert(cdb or self.cdb, hex_path or self.hex, self.output, self.root)

    def test_elf_header_sections_and_code_bytes(self):
        summary = self._convert()
        self.assertEqual(summary["elf"]["machine"], "EM_NONE")
        self.assertEqual(summary["entry"], 0xFC2800)
        data = self.output.read_bytes()
        header, sections = _elf(data)
        self.assertEqual(header["ident"][:4], b"\x7fELF")
        self.assertEqual(header["ident"][4], 1)  # ELFCLASS32
        self.assertEqual(header["ident"][5], 2)  # ELFDATA2MSB
        self.assertEqual(header["type"], 2)      # ET_EXEC
        self.assertEqual(header["machine"], 0)   # EM_NONE
        self.assertEqual(header["entry"], 0xFC2800)
        names = {section["name"] for section in sections}
        self.assertTrue({".text", ".debug_abbrev", ".debug_info", ".debug_line",
                         ".symtab", ".strtab", ".shstrtab"}.issubset(names))
        text = _section(sections, ".text")
        self.assertEqual(text["addr"], 0xFC2800)
        self.assertEqual(text["flags"] & 0x6, 0x6)
        self.assertEqual(
            data[text["offset"]:text["offset"] + text["size"]],
            bytes.fromhex("1122334455667788FFFFCC"),
        )
        self.assertEqual(summary["text"]["size"], 11)
        self.assertEqual(summary["text"]["hex_bytes"], 9)

    def test_symbols_function_end_and_address_mapping(self):
        self._convert()
        data = self.output.read_bytes()
        _, sections = _elf(data)
        symbols = _symbols(data, sections)
        by_name = {}
        for symbol in symbols:
            by_name.setdefault(symbol["name"], []).append(symbol)
        self.assertEqual(by_name["main"][0]["value"], 0xFC2800)
        self.assertEqual(by_name["main"][0]["size"], 4)  # XG byte is inclusive
        self.assertEqual(by_name["g_byte"][0]["value"], 0x8)
        self.assertEqual(by_name["g_count"][0]["value"], 0x9)
        self.assertEqual(by_name["g_xdata"][0]["value"], 0x10000)
        self.assertEqual(by_name["P0"][0]["value"], 0x10000080)
        self.assertNotIn("same", by_name)
        self.assertEqual(by_name["only"][0]["value"], 0x12)
        self.assertEqual(by_name["only"][0]["size"], 2)
        self.assertEqual(sorted(item["value"] for item in by_name["helper"]),
                         [0xFC2804, 0xFC2806])
        self.assertEqual(sorted(item["size"] for item in by_name["helper"]), [2, 2])
        self.assertNotIn("local", by_name)
        self.assertNotIn("g_unknown", by_name)
        self.assertNotIn("P00", by_name)

    def test_map_supplies_assembly_function_entries_without_guessing_sizes(self):
        self.cdb.write_text(_fixture_cdb() + """
S:G$system_idle$0_0$0({3}DF,SV:S),C,0,0
S:G$outside$0_0$0({3}DF,SV:S),C,0,0
S:G$conflict$0_0$0({3}DF,SV:S),C,0,0
S:G$in_main$0_0$0({3}DF,SV:S),C,0,0
S:G$data_only$0_0$0({3}DF,SV:S),C,0,0
""", encoding="utf-8")
        self.cdb.with_suffix(".map").write_text("""
C:   00FC280A  _system_idle                       idle
C:   00FC2820  _outside                           outside
C:   00FC2808  _conflict                          first
C:   00FC280A  _conflict                          second
C:   00FC2802  _in_main                           main
C:   00FC280A  _some_code                         idle
D:   00FC280A  _data_only                         data
""", encoding="ascii")
        self.assertEqual(self._convert()["map_functions"], 1)
        data = self.output.read_bytes()
        _, sections = _elf(data)
        syms = {row["name"]: row for row in _symbols(data, sections)}
        self.assertEqual(syms["system_idle"]["value"], 0xFC280A)
        self.assertEqual(syms["system_idle"]["size"], 0)
        self.assertFalse(syms.keys() & {"outside", "conflict", "in_main", "some_code", "data_only"})

    def test_dwarf_variables_and_line_table(self):
        summary = self._convert()
        self.assertEqual(summary["globals"], 4)
        self.assertEqual(summary["file_statics"], 1)
        self.assertEqual(summary["sfr"], 1)
        self.assertEqual(summary["lines"], 4)
        data = self.output.read_bytes()
        _, sections = _elf(data)
        dies = _dies(data, sections)
        compile_unit = next(attrs for tag, attrs, _ in dies if tag == 0x11)
        self.assertEqual(compile_unit[0x25],
                         "STCForge experimental SDCC CDB converter")
        self.assertEqual(compile_unit[0x1B],
                         str(self.root.resolve()).replace("\\", "/"))
        self.assertFalse(any(tag == 0x2E for tag, _, _ in dies))
        types = {offset: attrs for tag, attrs, offset in dies if tag == 0x24}
        variables = {}
        for tag, attrs, _ in dies:
            if tag == 0x34:
                variables.setdefault(attrs[0x03], []).append(attrs)
        g_count = variables["g_count"][0]
        self.assertEqual(g_count[0x02], b"\x03" + struct.pack(">I", 0x9))
        self.assertEqual(g_count[0x0B], 2)
        self.assertEqual(g_count[0x3E], 7)
        self.assertEqual(types[g_count[0x49]][0x03], "unsigned int")
        self.assertEqual(variables["P0"][0][0x02],
                         b"\x03" + struct.pack(">I", 0x10000080))
        self.assertEqual(variables["P0"][0][0x0B], 1)
        self.assertEqual(variables["P0"][0][0x3E], 8)
        self.assertNotIn("same", variables)
        self.assertEqual(variables["only"][0][0x02],
                         b"\x03" + struct.pack(">I", 0x12))
        self.assertEqual(types[variables["only"][0][0x49]][0x03], "int")
        rows = _line_rows(data, sections)
        self.assertIn((0xFC2800, 10, "main.c"), rows)
        self.assertIn((0xFC2802, 12, "main.c"), rows)
        self.assertIn((0xFC2804, 5, "helper.c"), rows)
        self.assertIn((0xFC2806, 6, "helper.c"), rows)

    def test_duplicate_registers_and_skipped_categories(self):
        summary = self._convert()
        self.assertEqual(summary["duplicates"]["duplicate_declarations"], 1)
        self.assertEqual(summary["duplicates"]["duplicate_lines"], 1)
        self.assertEqual(summary["skipped"]["locals"], 1)
        self.assertEqual(summary["skipped"]["unknown_types"], 1)
        self.assertEqual(summary["skipped"]["bit_variables"], 1)
        self.assertEqual(summary["skipped"]["macros"], 1)
        self.assertEqual(summary["skipped"]["ambiguous_file_statics"], 2)
        self.assertEqual(summary["file_static_ambiguities"]["count"], 2)
        self.assertEqual(summary["file_static_ambiguities"]["policy"],
                         "skip_all_same_name")
        self.assertEqual(summary["known_ignored"]["assembly_records"], 1)
        self.assertEqual(summary["known_ignored"]["local_address_records"], 1)
        self.assertEqual(summary["skipped"]["malformed_records"], 0)
        self.assertTrue(any("experimental" in line for line in summary["limitations"]))
        self.assertTrue(any("同名" in line for line in summary["limitations"]))
        self.assertTrue(any("2 条跨模块同名的文件静态变量" in line
                            for line in summary["limitations"]))

    def _stack_fixture(self):
        self.cdb.write_text("""M:main
F:G$main$0_0$0({3}DF,SV:S),C,0,0,0,0,0
S:Lmain.main$last_toggle$1_1$2({2}SI:U),B,1,1
S:Lmain.main$now$2_1$3({2}SI:U),R,0,0,[r3,r2]
L:G$main$0$0:FF0000
L:XG$main$0$0:FF0012
L:C$main.c$11$1_1$2:FF0002
L:C$main.c$12$2_1$3:FF000A
L:C$main.c$13$2_1$3:FF000C
""", encoding="utf-8")
        code = bytes.fromhex("0B FD 39 BF FF FF 7A FB B0 00 CA 98 00 DA 98 00 1B FD AA")
        self.hex.write_text(_ihex_text([_ihex_record(0, 0, code)], base=0xFF0000),
                            encoding="ascii")
        listing = self.root / "main.c.rst"
        listing.write_text("""      FF0000 0B FD            [12]   1 inc spx,#2
                           000002    2 C$main.c$11$1_1$2 ==.
                                     3 ; C:\\source\\main.c:11: unsigned int last_toggle = get_time();
      FF0002 39 BF FF FF       [12]   4 mov @spx-0x0001,a
      FF0006 7A FB B0          [12]   5 mov @spx,a
                           000009    6 C$main.c$12$2_1$3 ==.
                                     7 ; C:\\source\\main.c:12: use(last_toggle);
      FF0009 00               [12]   8 nop
      FF000A CA 98            [12]   9 push r9
      FF000C 00               [12]  10 nop
      FF000D DA 98            [24]  11 pop r9
      FF000F 00               [12]  12 nop
      FF0010 1B FD            [12]  13 dec spx,#2
      FF0012 AA               [24]  14 eret
""", encoding="utf-8")
        return code, listing

    def test_stack_ranges_require_matching_linked_listing(self):
        _, listing = self._stack_fixture()
        summary = self._convert()
        self.assertEqual(summary["stack_locals"], 1)
        self.assertEqual(summary["skipped"]["locals"], 1)
        data = self.output.read_bytes()
        _, sections = _elf(data)
        loc = _section(sections, ".debug_loc")
        self.assertEqual(data[loc["offset"]:loc["offset"] + loc["size"]],
                         struct.pack(">IIH2sIIH2sIIH2sII",
                                     9, 12, 2, b"\x89\x7f",
                                     12, 15, 2, b"\x89\x7e",
                                     15, 18, 2, b"\x89\x7f", 0, 0))
        original = listing.read_text(encoding="utf-8")
        for wrong in (original.replace("CA 98", "CA 88"),
                      original.replace("push r9", "pop r9"),
                      original.replace("mov @spx,a", "mov @spx-0x0001,a")):
            with self.subTest(listing=wrong):
                listing.write_text(wrong, encoding="utf-8")
                self.assertEqual(self._convert()["stack_locals"], 0)

    @unittest.skipUnless(STC_GDB.is_file(), "requires built stc-gdb")
    def test_gdb_mi_reads_stack_local_before_and_after_push(self):
        from stcforge.server import serve
        from stcforge.target import MockTarget

        code, _ = self._stack_fixture()
        self.assertEqual(self._convert()["stack_locals"], 1)

        for offset, spx, expected in ((2, 0x105, "<optimized out>"),
                                      (9, 0x105, "4660"), (12, 0x106, "4660"),
                                      (18, 0x103, "<optimized out>")):
            with self.subTest(pc=offset):
                target = MockTarget()
                target.memory.update({0xFF0000 + i: value for i, value in enumerate(code)})
                target._set_pc(0xFF0000 + offset)
                target.registers[36:40] = spx.to_bytes(4, "big")
                target.write_memory(0x103, b"\x99\x12\x34\xab")
                ready = queue.Queue()
                handler = threading.Thread(target=serve, args=(target,),
                                           kwargs=dict(port=0, once=True, ready=ready.put), daemon=True)
                handler.start()
                host, port = ready.get(timeout=5)
                result = subprocess.run([str(STC_GDB), "-nx", "-q", "--interpreter=mi2"],
                                        input="\n".join([
                                            "1-gdb-set architecture mcs251", "2-gdb-set endian big",
                                            f'3-file-exec-and-symbols "{self.output.as_posix()}"',
                                            f"4-target-select remote {host}:{port}",
                                            "5-stack-list-variables --simple-values",
                                            "6-data-evaluate-expression last_toggle",
                                            "7-target-detach", "8-gdb-exit", "",
                                        ]), text=True, capture_output=True, timeout=15)
                handler.join(5)
                self.assertFalse(handler.is_alive())
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('name="last_toggle"', result.stdout)
                self.assertIn(f'6^done,value="{expected}"', result.stdout)
                self.assertNotIn('name="now"', result.stdout)

    def test_register_local_initialized_in_loop_after_elided_declaration(self):
        source = self.root / "main.c"
        code = bytes.fromhex("00 9A FF 00 20 7E 91 82 7C B9 80 F5")
        self.hex.write_text(_ihex_text([_ihex_record(0, 0, code)], base=0xFF0000),
                            encoding="ascii")
        self.cdb.write_text("""M:main
F:G$main$0_0$0({3}DF,SV:S),C,0,0,0,0,0
S:Lmain.main$value$1_0$1({1}SC:U),R,0,0,[r9]
L:G$main$0$0:FF0000
L:XG$main$0$0:FF000B
L:C$main.c$2$1_0$1:FF0000
L:C$main.c$5$3_0$2:FF0001
L:C$main.c$6$3_0$2:FF0008
""", encoding="ascii")
        listing = self.root / "main.c.rst"
        listing_text = """                           000000    1 C$main.c$2$1_0$1 ==.
                                     2 ; main.c:2: nop();
      FF0000 00               [12]   3 nop
                           000001    4 C$main.c$5$3_0$2 ==.
                                     5 ; main.c:5: value = get_value();
      FF0001 9A FF 00 20      [12]   6 ecall _get_value
      FF0005 7E 91 82         [12]   7 mov r9,dpl
                           000008    8 C$main.c$6$3_0$2 ==.
                                     9 ; main.c:6: use(value);
      FF0008 7C B9            [12]  10 mov a,r9
      FF000A 80 F5            [12]  11 sjmp loop
"""
        source_text = """void main(void) {
    nop();
    unsigned char value = 0;
    for (;;) {
        value = get_value();
        use(value);
    }
}
"""
        listing.write_text(listing_text, encoding="ascii")
        source.write_text(source_text, encoding="ascii")
        self.assertEqual(self._convert()["register_locals"], 1)
        data = self.output.read_bytes()
        _, sections = _elf(data)
        loc = _section(sections, ".debug_loc")
        # Even on the back edge, the loop head has no guaranteed value.
        self.assertEqual(data[loc["offset"]:loc["offset"] + loc["size"]],
                         struct.pack(">IIH1sII", 8, 12, 1, b"\x59", 0, 0))

        for assignment in ("value = other_call();", "value = get_value() + (1);"):
            with self.subTest(assignment=assignment):
                listing.write_text(listing_text.replace("value = get_value();", assignment),
                                   encoding="ascii")
                source.write_text(source_text.replace("value = get_value();", assignment),
                                  encoding="ascii")
                self.assertEqual(self._convert()["register_locals"], 0)

    @unittest.skipUnless(STC_GDB.is_file(), "requires built stc-gdb")
    def test_gdb_mi_register_pieces_across_call_and_restore(self):
        from stcforge.server import serve
        from stcforge.target import MockTarget

        code = bytes.fromhex(
            "9A FF 00 30 7E F1 82 7E E1 83 7E D1 F0 7C CB 7C BF "
            "CA F8 CA E8 CA D8 CA C8 9A FF 00 30 DA C8 DA D8 DA E8 DA F8 "
            "7C BF 7E C0 00 7C BF AA")
        self.hex.write_text(_ihex_text([_ihex_record(0, 0, code)], base=0xFF0000),
                            encoding="ascii")
        self.cdb.write_text("""M:main
F:G$main$0_0$0({3}DF,SV:S),C,0,0,0,0,0
S:Lmain.main$now$3_1$2({4}SL:U),R,0,0,[r15,r14,r13,r12]
L:G$main$0$0:FF0000
L:XG$main$0$0:FF002C
L:C$main.c$12$3_1$2:FF000F
L:C$main.c$13$3_1$2:FF0025
""", encoding="utf-8")
        (self.root / "main.c.rst").write_text("""                           000000    1 C$main.c$11$3_1$2 ==.
                                     2 ; main.c:11: unsigned long now = get_time();
      FF0000 9A FF 00 30      [12]   3 ecall _get_time
      FF0004 7E F1 82         [12]   4 mov r15,dpl
      FF0007 7E E1 83         [12]   5 mov r14,dph
      FF000A 7E D1 F0         [12]   6 mov r13,b
      FF000D 7C CB            [12]   7 mov r12,a
                           00000F    8 C$main.c$12$3_1$2 ==.
                                     9 ; main.c:12: use(now);
      FF000F 7C BF            [12]  10 mov a,r15
      FF0011 CA F8            [12]  11 push r15
      FF0013 CA E8            [12]  12 push r14
      FF0015 CA D8            [12]  13 push r13
      FF0017 CA C8            [12]  14 push r12
      FF0019 9A FF 00 30      [12]  15 ecall _use
      FF001D DA C8            [12]  16 pop r12
      FF001F DA D8            [12]  17 pop r13
      FF0021 DA E8            [12]  18 pop r14
      FF0023 DA F8            [12]  19 pop r15
                           000025   20 C$main.c$13$3_1$2 ==.
                                    21 ; main.c:13: use_again(now);
      FF0025 7C BF            [12]  22 mov a,r15
      FF0027 7E C0 00         [12]  23 mov r12,#0
      FF002A 7C BF            [12]  24 mov a,r15
      FF002C AA               [12]  25 eret
""", encoding="ascii")
        self.assertEqual(self._convert()["register_locals"], 1)

        points = [(0x0D, 0, 3, "<optimized out>"), (0x0F, 0, 4, str(0x12345678)),
                  (0x1D, 4, 0, str(0x12345678)), (0x23, 1, 3, str(0x12345678)),
                  (0x25, 0, 4, str(0x12345678)), (0x2A, 0, 0, "<optimized out>")]
        for pc, stack_count, high_register_count, expected in points:
            with self.subTest(pc=pc):
                target = MockTarget()
                target.memory.update(dict(enumerate(code, 0xFF0000)))
                target._set_pc(0xFF0000 + pc)
                value = bytes.fromhex("12345678")
                target.registers[12:16] = value[:high_register_count].ljust(4, b"\xff")
                target.registers[36:40] = (0x100 + stack_count).to_bytes(4, "big")
                target.write_memory(0x101, value[::-1])
                ready = queue.Queue()
                handler = threading.Thread(target=serve, args=(target,),
                                           kwargs=dict(port=0, once=True, ready=ready.put), daemon=True)
                handler.start()
                host, port = ready.get(timeout=5)
                commands = ["1-gdb-set architecture mcs251", "2-gdb-set endian big",
                            f'3-file-exec-and-symbols "{self.output.as_posix()}"',
                            f"4-target-select remote {host}:{port}",
                            "5-stack-list-variables --simple-values", "6-var-create - * now",
                            "7-target-detach", "8-gdb-exit", ""]
                result = subprocess.run([str(STC_GDB), "-nx", "-q", "--interpreter=mi2"],
                                        input="\n".join(commands), text=True, capture_output=True,
                                        timeout=15)
                handler.join(5)
                self.assertFalse(handler.is_alive())
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f'name="now",type="unsigned long",value="{expected}"', result.stdout)
                self.assertRegex(result.stdout, rf'6\^done,[^\n]*value="{re.escape(expected)}"')

    def test_conflicting_duplicate_register_is_rejected(self):
        self.cdb.write_text(_fixture_cdb() + "L:G$P0$0_0$0:81\n", encoding="utf-8")
        with self.assertRaisesRegex(SymbolConversionError, "conflicting addresses"):
            self._convert()

    def test_hex_checksum_overlap_and_eof_are_strict(self):
        good = _ihex_record(0x00, 0x2800, b"\x11")
        bad_checksum = good[:-2] + ("00" if good[-2:] != "00" else "01")
        checksum_hex = self.root / "checksum.hex"
        checksum_hex.write_text(
            _ihex_text([bad_checksum]), encoding="ascii"
        )
        with self.assertRaisesRegex(SymbolConversionError, "checksum"):
            read_hex(checksum_hex)

        overlap_hex = self.root / "overlap.hex"
        overlap_hex.write_text(
            _ihex_text([_ihex_record(0x00, 0x2800, b"\x11"),
                        _ihex_record(0x00, 0x2800, b"\x22")]),
            encoding="ascii",
        )
        with self.assertRaisesRegex(SymbolConversionError, "overlapping"):
            read_hex(overlap_hex)

        no_eof_hex = self.root / "no-eof.hex"
        no_eof_hex.write_text(
            _ihex_text([_ihex_record(0x00, 0x2800, b"\x11")], eof=False),
            encoding="ascii",
        )
        with self.assertRaisesRegex(SymbolConversionError, "EOF"):
            read_hex(no_eof_hex)

        after_eof_hex = self.root / "after-eof.hex"
        after_eof_hex.write_text(
            _ihex_text([_ihex_record(0x00, 0x2800, b"\x11")],
                       trailing=_ihex_record(0x00, 0x2801, b"\x22")),
            encoding="ascii",
        )
        with self.assertRaisesRegex(SymbolConversionError, "after EOF"):
            read_hex(after_eof_hex)

        duplicate_eof_hex = self.root / "duplicate-eof.hex"
        duplicate_eof_hex.write_text(
            _ihex_text([_ihex_record(0x00, 0x2800, b"\x11")],
                       trailing=_ihex_record(0x01, 0)),
            encoding="ascii",
        )
        with self.assertRaisesRegex(SymbolConversionError, "duplicate EOF"):
            read_hex(duplicate_eof_hex)

        crossing_hex = self.root / "crossing.hex"
        crossing_hex.write_text(
            _ihex_text([_ihex_record(0x00, 0xFFFF, b"\x11\x22")]),
            encoding="ascii",
        )
        with self.assertRaisesRegex(SymbolConversionError, "boundary"):
            read_hex(crossing_hex)

    def test_low_keil_address_is_not_shifted(self):
        low_hex = self.root / "low.hex"
        low_hex.write_text(
            _ihex_text([_ihex_record(0x00, 0x2800, b"\x11")], base=0),
            encoding="ascii",
        )
        with self.assertRaisesRegex(SymbolConversionError, "low Keil addresses"):
            self._convert(hex_path=low_hex)

    def test_sparse_valid_64k_code_window(self):
        large_hex = self.root / "large.hex"
        large_hex.write_text(
            _ihex_text([
                _ihex_record(0x00, 0x0000, bytes.fromhex("11")),
                _ihex_record(0x00, 0xFFFF, bytes.fromhex("22")),
            ], base=0xFF0000),
            encoding="ascii",
        )
        # FF0000..FFFFFF 是合法的 64 KiB 窗口，不是超过 16 MiB 的范围。
        self.cdb.write_text(
            _fixture_cdb().replace("FC2800", "FF2800").replace("FC2802", "FF2802")
            .replace("FC2803", "FF2803").replace("FC2804", "FF2804")
            .replace("FC2805", "FF2805").replace("FC2806", "FF2806")
            .replace("FC2807", "FF2807"),
            encoding="utf-8",
        )
        summary = self._convert(hex_path=large_hex)
        self.assertEqual(summary['text']['size'], 65536)
        self.assertEqual(summary['text']['hex_bytes'], 2)

    def test_explicit_source_directories_exclude_other_examples(self):
        from stcforge.symbols import _Line, _resolve_sources
        actual = self.root / "Core" / "Src"
        other = self.root / "Keil"
        actual.mkdir(parents=True)
        other.mkdir()
        (actual / "main.c").write_text("int main(void) {}", encoding="utf-8")
        (other / "main.c").write_text("wrong example", encoding="utf-8")
        line = _Line("main.c", 1, 0xff0000)
        resolved = _resolve_sources([line], [actual])
        self.assertEqual(resolved[0].file, (actual / "main.c").resolve().as_posix())
        with self.assertRaisesRegex(SymbolConversionError, "must resolve uniquely"):
            _resolve_sources([line], [actual, other])
        with self.assertRaisesRegex(SymbolConversionError, "no match"):
            _resolve_sources([_Line("missing.c", 1, 0xff0000)], [actual])

    def test_static_collision_with_global_is_skipped(self):
        self.cdb.write_text(_fixture_cdb() +
            'S:Fthird$g_count$0_0$0({2}SI:U),E,0,0\n'
            'L:Fthird$g_count$0_0$0:12\n', encoding='utf-8')
        summary = self._convert()
        self.assertEqual(summary['skipped']['ambiguous_file_statics'], 3)
        data = self.output.read_bytes()
        _, sections = _elf(data)
        declarations = [attrs for tag, attrs, _ in _dies(data, sections)
                        if tag == 0x34 and attrs[0x03] == 'g_count']
        self.assertEqual(len(declarations), 1)
        self.assertEqual(declarations[0][0x02], b'\x03' + struct.pack('>I', 9))

    @unittest.skipUnless(STC_GDB.is_file() and (os.name == 'nt' or os.environ.get('STCFORGE_GDB')),
                         "STC MCS-251 GDB is not available")
    def test_real_gdb_can_query_source_lines_and_global(self):
        self._convert()
        script = self.root / "query.gdb"
        elf_path = self.output.resolve().as_posix()
        script.write_text("\n".join([
            "set pagination off",
            "set confirm off",
            "set architecture mcs251",
            f'file "{elf_path}"',
            "info line main.c:10",
            "info line main.c:12",
            "info line helper.c:6",
            "info sources",
            "ptype g_count",
            "info address g_count",
            "quit",
        ]) + "\n", encoding="ascii")
        process = subprocess.run(
            [str(STC_GDB), "-q", "-batch", "-nx", "-x", str(script)],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=30,
        )
        output = process.stdout + process.stderr
        self.assertEqual(process.returncode, 0, output)
        self.assertIn('Line 10 of "main.c" starts at address 0xfc2800', output)
        self.assertIn('Line 12 of "main.c" starts at address 0xfc2802', output)
        self.assertIn('Line 6 of "helper.c" starts at address 0xfc2806', output)
        self.assertIn("main.c", output)
        self.assertIn("helper.c", output)
        self.assertIn("type = unsigned int", output)
        self.assertIn("0x9", output)
        self.assertNotIn('"same"', output)


if __name__ == "__main__":
    unittest.main()
