"""Compare supplemental software USB records against the local 6.97C builder."""

import json
import runpy
import struct
from pathlib import Path

from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ESI

ROOT = Path(__file__).parent
api = runpy.run_path(str(ROOT / "verify-routines.py"))
OBJ, OPT, SOURCE, RECORDS = (api[n] for n in ("OBJ", "OPT", "SRC", "OUT"))
WORK = 0x280000

models = json.loads(
    (ROOT / "models-6.97c.json").read_text(encoding="utf-8")
)["models"]
index = next(m["index"] for m in models if m["name"] == "STC8H1K08")

header = bytes.fromhex("00 00 75 C7 20")
old = header + bytes([4, 28, 0x40, 3, 29, 0x80, 1, 2, 35, 36])
short = header + bytes([26, 25, 23, 24, 35, 36])
long = header + bytes([29, 28, *range(49, 41, -1), 26, 25, 23, 24, 35, 36])
v74 = header + bytes([30, 29, 28, 27, *range(49, 42, -1), 0x22, 26, 25, 23, 24, 35, 36])
uid = bytes.fromhex("82 83 84 85 86 87 88")


def record(address, payload):
    return struct.pack("<BIB", 0x5A, address, len(payload)) + payload


for version, patch, address, footer in (
    (0x71, 0, 0x1FEA, old),
    (0x72, 0, 0x1FEE, short),
    (0x73, 12, 0x1FE4, long),
    (0x74, 3, 0x1FE2, v74),
    (0x74, 4, None, b""),
):
    machine = api["emulator"]("C")
    machine.mem_map(WORK, 0x20000)
    machine.mem_write(SOURCE, b"\x02\x00\x00")
    machine.mem_write(OPT + 0x0F, b"\x02")
    machine.mem_write(OBJ + 0x688, bytes(range(54)))
    if version == 0x74:
        machine.mem_write(OBJ + 0x688 + 42, b"\x22")
    machine.mem_write(OBJ + 0xF25, uid)
    for offset, value in {
        0x44: 1, 0xFC: 3, 0x120: index, 0x17C: version, 0x180: patch,
        0x6CC: WORK, 0x6D4: SOURCE, 0x6D8: RECORDS, 0x6E0: OPT,
        0xF4C: 1, 0xF64: 0x10,
    }.items():
        api["write32"](machine, OBJ + offset, value)
    api["call"](machine, 0x44A540, 1, 0, count=200_000)
    if version < 0x72:
        assert machine.mem_read(WORK + 0x10, len(uid)) == uid
        assert machine.mem_read(WORK + address, len(footer)) == footer
        assert machine.mem_read(RECORDS, 1) == b"\x00"
    else:
        expected = record(0x10, uid) + (record(address, footer) if footer else b"") + b"\x00"
        actual = machine.mem_read(RECORDS, len(expected))
        assert actual == expected, (version, patch, actual.hex(), expected.hex())
    print(f"software USB BSL {version >> 4}.{version & 15}.{patch}: UID and footer matched")


for version, patch, extra in ((0x73, 12, 0), (0x73, 13, 1), (0x74, 2, 0), (0x74, 3, 1)):
    machine = api["emulator"]("C")
    for offset, value in ((0x120, index), (0x17C, version), (0x180, patch)):
        api["write32"](machine, OBJ + offset, value)
    machine.mem_write(OBJ + 0x698, b"\x1f")
    machine.mem_write(OBJ + 0x688 + 42, b"\x20")
    machine.reg_write(UC_X86_REG_EAX, 0x2000)
    machine.reg_write(UC_X86_REG_EBX, OBJ + 0xB1E)
    machine.reg_write(UC_X86_REG_ESI, OBJ)
    machine.emu_start(0x44DA7E, 0x44DAF5, count=80)
    assert machine.mem_read(OBJ + 0xB1E, 2) == bytes((extra, 0))
print("software USB partition erase: four BSL transition cases matched")


index = next(m["index"] for m in models if m["name"] == "STC15H4K08S4")
for version in (0x62, 0x70, 0x71):
    machine = api["emulator"]("C")
    for offset, value in ((0x120, index), (0x17C, version), (0x6E0, OPT)):
        api["write32"](machine, OBJ + offset, value)
    raw = bytearray(b"\xff" * 19)
    raw[1], raw[2], raw[14] = 0xAD, 0x5E, 0x0E
    raw[16], raw[17], raw[18] = 0x07, 0xFF, 0xFF
    machine.mem_write(OPT, bytes(raw))
    machine.mem_write(OBJ + 0x688, b"\x00\x01\x02\x03\x04\x05\x06\x07")
    assert api["call"](machine, 0x43E9E0) == 0
    assert api["call"](machine, 0x44B760, RECORDS) == 40
    expected = bytearray(b"\xff" * 40)
    expected[3] = expected[6] = expected[22] = 0
    expected[24:31] = bytes(range(1, 8))
    expected[32] = 0x0C
    expected[37:39] = b"\xad\x5e"
    assert machine.mem_read(RECORDS, 40) == expected
print("software USB compact 04 body: three legacy BSL versions matched")


index = next(m["index"] for m in models if m["name"] == "STC15F2K08S2")
for version, password_length in ((0x71, 0), (0x72, 2)):
    machine = api["emulator"]("C")
    for offset, value in ((0x120, index), (0x17C, version), (0x6E0, OPT), (0x18C, 1),
                          (0xF7C, password_length)):
        api["write32"](machine, OBJ + offset, value)
    machine.mem_write(OBJ + 0xF74, bytes((bool(password_length),)))
    raw = bytearray(b"\xff" * 19)
    raw[0], raw[1], raw[2], raw[8], raw[14] = 0x91, 0xC3, 0x25, 0xFD, 0xFC
    machine.mem_write(OPT, bytes(raw))
    live = bytearray(40)
    live[8:12] = bytes.fromhex("00 a8 c0 00")
    live[38:] = b"\x54\x40"
    machine.mem_write(OBJ + 0x688, bytes(live))
    assert api["call"](machine, 0x43E9E0) == 0
    assert api["call"](machine, 0x44B760, RECORDS) == 64
    expected = bytearray(b"\xff" * 64)
    expected[3] = expected[6] = expected[23] = expected[29] = 0
    expected[22] = password_length
    expected[25], expected[27] = 0xA8, 0xC0
    expected[31], expected[32] = (0xF6 if password_length else 0xFE), 1
    expected[55] = 0xFD
    expected[59:] = bytes.fromhex("54 7f 25 c3 91")
    assert machine.mem_read(RECORDS, 64) == expected
print("software USB legacy STC15 04 body, retained trim and next password matched")


for model, version, high, raw2 in (
    ("STC12C5424", 0x71, 0x00, 0xFF),
    ("STC12C5A08S2", 0x72, 0x91, 0x25),
):
    index = next(m["index"] for m in models if m["name"] == model)
    machine = api["emulator"]("C")
    for offset, value in ((0x120, index), (0x17C, version), (0x6E0, OPT), (0x18C, 1)):
        api["write32"](machine, OBJ + offset, value)
    raw = bytearray(b"\xff" * 19)
    raw[0], raw[1], raw[2] = 0x91, 0xC3, raw2
    raw[14] = 0xFD
    live = bytearray(40)
    live[8:12] = bytes((high, 0xA8, 0xC0, 0))
    live[38:] = b"\x54\x40"
    machine.mem_write(OBJ + 0x688, bytes(live))
    expected = bytearray(b"\xff" * 64)
    expected[3] = expected[6] = expected[22] = expected[29] = 0
    expected[23], expected[25], expected[27] = high, 0xA8, 0xC0
    expected[31], expected[32] = 0xFF, 1
    expected[59:] = bytes((0x54, 0x7F, raw2, 0xC3, 0x91))
    for raw4 in (0xFF, 0xBF):
        raw[4] = raw4
        machine.mem_write(OPT, bytes(raw))
        assert api["call"](machine, 0x43E9E0) == 0
        assert api["call"](machine, 0x44B760, RECORDS) == 64
        assert machine.mem_read(RECORDS, 64) == expected
    print(f"{model}: software USB 04 body matched; raw4 threshold bit is not carried")
