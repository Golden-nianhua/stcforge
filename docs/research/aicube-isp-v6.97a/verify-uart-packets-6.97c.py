"""Run original 6.97C packet builders without opening a device."""

import json
import runpy
import struct
from pathlib import Path

from unicorn import UC_HOOK_CODE, UcError
from unicorn.x86_const import (
    UC_X86_REG_EBP, UC_X86_REG_EBX, UC_X86_REG_ECX,
    UC_X86_REG_EDX, UC_X86_REG_EIP, UC_X86_REG_ESP,
)

ROOT = Path(__file__).parent
api = runpy.run_path(str(ROOT / "verify-routines.py"))
OBJ, SRC, STACK = (api[name] for name in ("OBJ", "SRC", "STACK"))
models = json.loads((ROOT / "models-6.97c.json").read_text(encoding="utf-8"))["models"]


def capture(model, start, setup, args=(), bp=False, cx=None, usb_offset=None, options=None,
            uart_offset=None, image_start=0, usb_erase=False, irc_coarse_reply=None,
            irc_fine_entry=0x440E9F, irc_fine_reply=None, irc_result_entry=None):
    machine = api["emulator"]("C")
    for addr, stub in (
        (0x43C890, b"\x31\xc0\xc2\x04\x00"),  # UI string lookup
        (0x43C8D0, b"\xc3"),                # UI reporting
        (0x43CA00, b"\xc2\x08\x00"),        # UI progress
        (STACK + 0xC00, b"\xc2\x04\x00"),   # Sleep
        (STACK + 0xC10, b"\x31\xc0\xc3"),   # GetTickCount
        # MSVCRT _ftol: truncate and pop ST(0), return the integer in EDX:EAX.
        (STACK + 0xC20, bytes.fromhex("DD 4C 24 F8 8B 44 24 F8 8B 54 24 FC C3")),
    ):
        machine.mem_write(addr, stub)
    entry = next(row for row in models if row["name"] == model)
    flags = entry["flags"]
    fields = {
        0x120: entry["index"], 0x1A4: (flags >> 6) & 7, 0x1A8: (flags >> 9) & 7,
        0x6E0: api["OPT"],
    }
    for addr, value in {**fields, **setup}.items():
        if isinstance(value, int):
            api["write32"](machine, OBJ + addr, value)
        else:
            machine.mem_write(OBJ + addr, value)
    api["write32"](machine, 0x503254, STACK + 0xC00)
    api["write32"](machine, 0x503108, STACK + 0xC10)
    api["write32"](machine, 0x503A60, STACK + 0xC20)
    if options is not None:
        machine.mem_write(api["OPT"], options)
    machine.mem_write(SRC, b"\xff" * image_start + b"\x02\x00\x00" + b"\xff" * 125)
    if uart_offset is not None:
        machine.mem_write(SRC + uart_offset, b"\x02\x00\x00" + b"\xff" * 125)

        def set_write_offset(uc, addr, size, _):
            api["write32"](uc, uc.reg_read(UC_X86_REG_ESP) + 0x14, uart_offset)

        machine.hook_add(UC_HOOK_CODE, set_write_offset, begin=0x4432D4, end=0x4432D4)
    if usb_offset is not None:
        machine.mem_write(SRC + usb_offset, b"\x02\x00\x00" + b"\xff" * 125)
        machine.reg_write(UC_X86_REG_EBX, OBJ + 0xB1E)
        machine.reg_write(UC_X86_REG_EDX, usb_offset)
    if usb_erase:
        machine.reg_write(UC_X86_REG_EBX, OBJ + 0xB1E)
    machine.reg_write(UC_X86_REG_ECX, OBJ if cx is None else cx)
    if bp:
        machine.reg_write(UC_X86_REG_EBP, OBJ)
    machine.reg_write(UC_X86_REG_ESP, STACK + 0x800)
    machine.mem_write(STACK + 0x800, struct.pack(f"<{1 + len(args)}I", api["END"], *args))
    sent = []

    if irc_coarse_reply is not None:
        def before_fine_search(uc, addr, size, _):
            uc.mem_write(OBJ + 0x71E, irc_coarse_reply)
            if addr in (0x4403FF, 0x4408F9):
                uc.reg_write(UC_X86_REG_EBP, 1)

        machine.hook_add(UC_HOOK_CODE, before_fine_search, begin=irc_fine_entry, end=irc_fine_entry)

    def on_send(uc, addr, size, _):
        sp = uc.reg_read(UC_X86_REG_ESP)
        first, second = struct.unpack("<II", uc.mem_read(sp + 4, 8))
        data, length = (second, first) if addr == 0x44BDC0 else (first, second)
        sent.append(bytes(uc.mem_read(data, length)))
        if irc_coarse_reply is not None and len(sent) == 1:
            uc.reg_write(UC_X86_REG_ESP, sp + 12)
            uc.reg_write(UC_X86_REG_EIP, irc_fine_entry)
            return
        if irc_fine_reply is not None and len(sent) == 2:
            uc.mem_write(OBJ + 0x71E, irc_fine_reply)
            uc.reg_write(UC_X86_REG_ESP, sp + 12)
            uc.reg_write(UC_X86_REG_EIP, irc_result_entry)
            return
        uc.emu_stop()

    machine.hook_add(UC_HOOK_CODE, on_send, begin=0x43D0D0, end=0x43D0D0)
    machine.hook_add(UC_HOOK_CODE, on_send, begin=0x44BDC0, end=0x44BDC0)
    try:
        machine.emu_start(start, api["END"], count=30000 + 4 * image_start)
    except UcError as error:
        raise RuntimeError(f"emulation failed at {machine.reg_read(UC_X86_REG_EIP):#x}") from error
    assert len(sent) == (1 if irc_coarse_reply is None else 2), (model, hex(start), sent)
    if irc_fine_reply is not None:
        return sent, struct.unpack("<II", machine.mem_read(OBJ + 0x118, 8)), bytes(
            machine.mem_read(OBJ + 0x718, 4))
    return sent[0] if irc_coarse_reply is None else sent


def verify_stc15e_calibration():
    setup = {0x118: 11_059_200, 0x719: b"\x40", 0xE4: 2400, 0xF8: 24_000_000,
             0x751: bytes.fromhex("12 34 56 78 9A BC DE")}
    coarse = bytes.fromhex("65 00 00 00 00 00 00 00 00 00 00 00"
                           " 98 00 12 C0 98 80 19 00 98 80 1F 40 98 B4 25 1C"
                           " 58 00 07 D0 58 65 0A 71")
    fine = bytes.fromhex("65") + bytes(11) + b"".join(
        bytes((0x98, 0x4C + i)) + (5789 + 5 * i).to_bytes(2, "big") for i in range(11))
    packets, frequencies, trims = capture(
        "STC15F104E", 0x43F140, setup, irc_coarse_reply=coarse, irc_fine_entry=0x43F4E8,
        irc_fine_reply=fine, irc_result_entry=0x43F860)
    prefix = bytes.fromhex("65 12 34 56 78 9A BC DE FF FF 06")
    assert packets[0] == prefix + bytes.fromhex(
        "06 98 00 02 00 98 80 02 00 98 80 02 00 98 FF 02 00 58 00 02 00 58 80 02 00")
    fast = capture("STC15F104E", 0x43F140, {**setup, 0x118: 22_118_400})
    assert fast == packets[0][:28] + bytes.fromhex("98 00 02 00 98 80 02 00")
    assert packets[1] == prefix + b"\x0b" + b"".join(
        bytes((0x98, i, 2, 0)) for i in range(0x4C, 0x57))
    assert frequencies == (11_041_176, 24_000_942) and trims == b"\x65\x40\x51\x98", (frequencies, trims)
    raw = bytearray(b"\xff" * 19)
    raw[0], raw[1], raw[2], raw[14] = 0x6F, 0xE0, 0xD7, 0xFC
    for version in (0x66, 0x71, 0x72):
        fields = {0x17C: version, 0x11C: frequencies[1], 0x71A: trims[2:], 0x1180: b"\x5a\xa5"}
        packet = capture("STC15F104E", 0x4439D0, fields, options=bytes(raw))
        if version < 0x71:
            assert packet == bytes.fromhex("8D FF E7 D7 98 51 FF FF FF FF FF FF FF FC FF FF FF FF FF FF")
        else:
            header = bytes.fromhex("04 00 00 5A A5" if version >= 0x72 else "04 00 00")
            body = bytearray(b"\xff" * 64)
            body[3] = body[6] = body[22] = 0
            body[23:31:2] = frequencies[1].to_bytes(4, "big")
            body[31] = 0xFC
            body[59:64] = b"\x51\xbf\xd7\xe7\xff"
            assert packet == header + bytes(body), packet.hex(" ")
    print("STC15E/EA: original coarse/fine IRC packets, selected trims and BSL 6.6/7.1/7.2 options")


def verify_uart_baud_and_old_uid():
    for model, clock, requested, baud in (
        ("STC8H8K64U", 24_000_000, 921600, "01 65 40 FF F3 00 00 98"),
        ("STC15F100W", 11_059_200, 115200, "01 65 40 FE E0 FE 50 83"),
    ):
        assert capture(model, 0x4416C0, {
            0x25: b"\x01", 0x17C: 0x75, 0xE8: requested, 0x118: clock, 0x718: b"\x65\x40",
        }) == bytes.fromhex(baud)
    for version, expected in ((0x60, b"STATUID"), (0x61, b"STATUID"),
                              (0x62, b"STATUID"), (0x63, b"ERASUID")):
        machine = api["emulator"]("C")
        api["write32"](machine, OBJ + 0x17C, version)
        machine.mem_write(OBJ + 0x6A7, b"STATUID")
        machine.mem_write(OBJ + 0x71F, b"ERASUID")
        machine.reg_write(UC_X86_REG_EBP, OBJ)
        machine.emu_start(0x442EA9, 0x442EEE, count=30)
        assert machine.mem_read(OBJ + 0xF1E, 7) == expected
    print("UART 1T/4T baud limits and BSL 6.0--6.3 UID source matched")


def verify_fixed_partition_lot():
    for magic, date, boundary, expected in (
        (0xF784, 0x220223, 0xF8, 0x43E87A),
        (0xF784, 0x220224, 0xF8, 0x43E83A),
        (0xF784, 0x220322, 0xF8, 0x43E83A),
        (0xF784, 0x220323, 0xF8, 0x43E87A),
        (0xF784, 0x220224, 0xFC, 0x43E87A),
        (0xF734, 0x220224, 0xF8, 0x43E87A),
    ):
        machine = api["emulator"]("C")
        api["write32"](machine, OBJ + 0x128, magic)
        api["write32"](machine, OBJ + 0x6E0, api["OPT"])
        machine.mem_write(OBJ + 0x6AD, date.to_bytes(3, "big"))
        machine.mem_write(api["OPT"] + 3, bytes((boundary,)))
        machine.reg_write(UC_X86_REG_EBP, OBJ)

        def stop(uc, address, _size, _user):
            if address in (0x43E83A, 0x43E87A):
                uc.emu_stop()

        machine.hook_add(UC_HOOK_CODE, stop, begin=0x43E83A, end=0x43E87A)
        machine.emu_start(0x43E77A, api["END"], count=100)
        assert machine.reg_read(UC_X86_REG_EIP) == expected
    print("STC8 fixed-EEPROM lot: model, date and boundary predicates matched")


def verify_blank_encrypted_uart_block():
    for version, command, expected in (
        (0x71, 0x02, 0x443483), (0x72, 0x02, 0x443631),
        (0x72, 0x82, 0x443483), (0x75, 0x82, 0x443483),
    ):
        machine = api["emulator"]("C")
        api["write32"](machine, OBJ + 0x17C, version)
        machine.mem_write(OBJ + 0xB23, b"\xff" * 64)
        api["write32"](machine, STACK + 0x82C, 5)
        api["write32"](machine, STACK + 0x83C, command)
        machine.reg_write(UC_X86_REG_EBP, OBJ)
        machine.reg_write(UC_X86_REG_EBX, 64)
        machine.reg_write(UC_X86_REG_ESP, STACK + 0x800)

        def stop(uc, address, _size, _user):
            if address in (0x443483, 0x443631):
                uc.emu_stop()

        machine.hook_add(UC_HOOK_CODE, stop, begin=0x443483, end=0x443631)
        machine.emu_start(0x443448, api["END"], count=1000)
        actual = machine.reg_read(UC_X86_REG_EIP)
        assert actual == expected, (hex(version), hex(command), hex(actual), hex(expected))
    print("UART blank block skip predicate matched 6.97C")

def verify_eeprom_fill_and_ai16_clock():
    eeprom = SRC + 0x1000
    out = api["OUT"]
    for fill in (0, 0xFF):
        machine = api["emulator"]("C")
        machine.mem_map(0x280000, 0x80000)
        obj = 0x280000
        for offset, value in ((0x7751C, 0x400), (0x77548, 3), (0x77550, 0x6C00),
                              (0x77558, SRC), (0x77560, eeprom), (0x767B4, out)):
            api["write32"](machine, obj + offset, value)
        machine.mem_write(SRC, b"\x02\0\0")
        machine.mem_write(eeprom, bytes((fill,)) * 0x6C00)
        machine.mem_write(0x566064, b"\xff")
        machine.reg_write(UC_X86_REG_EBP, obj)
        machine.reg_write(UC_X86_REG_EBX, 0)
        machine.emu_start(0x4C1DFF, 0x4C1EDC, count=0x4000)
        assert machine.reg_read(UC_X86_REG_EIP) == 0x4C1EDC
        assert machine.mem_read(out, 0x7000) == b"\x02\0\0" + b"\xff" * 1021 + bytes((fill,)) * 0x6C00
    for source in range(4):
        machine = api["emulator"]("C")
        index = next(item["index"] for item in models if item["name"] == "AI16F40K128-Beta")
        api["write32"](machine, OBJ + 0x120, index)
        api["write32"](machine, OBJ + 0x6E0, api["OPT"])
        machine.mem_write(api["OPT"], b"\xff" * 13 + bytes((0xFC | source,)) + b"\xff" * 5)
        assert api["call"](machine, 0x44B760, out) == 40
        assert machine.mem_read(out + 0x1F, 1) == bytes((0xFC | source,))
    print("STC12 EEPROM fill merge and AI16 USB ISP clock matched original x86")


def verify_test_parameters():
    for model, version, patch, suffix in (
        ("STC15F2K08S2", 0x71, 0, "04 1C 40 03 1D 80 01 02 23 24"),
        ("STC15F2K08S2", 0x72, 0, "04 1C 40 03 1D 80 01 02 23 24"),
        ("STC8A8K08S4A12", 0x73, 11, "1A 19 17 18 23 24"),
        ("STC8A8K08S4A12", 0x73, 12, "1D 1C 31 30 2F 2E 2D 2C 2B 2A 1A 19 17 18 23 24"),
        ("STC8A8K08S4A12", 0x74, 3, "1E 1D 1C 1B 31 30 2F 2E 2D 2C 2B 2A 1A 19 17 18 23 24"),
    ):
        machine = api["emulator"]("C")
        out = 0x300000
        machine.mem_map(out, 0x30000)
        row = next(row for row in models if row["name"] == model)
        for addr, value in ((0x17C, version), (0x180, patch), (0x120, row["index"]),
                            (0xFC, 3), (0x6CC, out), (0x6D4, SRC), (0x6D8, api["OUT"]),
                            (0x6E0, api["OPT"])):
            api["write32"](machine, OBJ + addr, value)
        machine.mem_write(OBJ + 0x688, bytes(range(54)))
        machine.mem_write(api["OPT"] + 15, b"\x02")
        machine.mem_write(SRC, b"\x02\0\0")
        api["call"](machine, 0x44A540, 1, 0)
        payload = bytes.fromhex("00 00 75 C7 20 " + suffix)
        address = row["code_size"] - (row["field28"] & 0xFF) - len(payload)
        if version < 0x72:
            result = machine.mem_read(out + address, len(payload))
            assert result == payload, (model, version, result.hex(" "))
        else:
            expected = b"\x5a" + struct.pack("<IB", address, len(payload)) + payload
            result = machine.mem_read(api["OUT"], len(expected))
            assert result == expected, (model, version, result.hex(" "))
    print("UART: original 11/15/21/23-byte test-parameter payloads and addresses matched")


def verify_usb_irc_presets():
    for model, version, patch, hz, trim in (
        ("STC8H8K64U", 0x73, 12, 36_864_000, "2E 80 01"),
        ("STC8H8K64U", 0x73, 12, 24_000_000, "1A 00 01"),
        ("STC8H8K64U", 0x74, 2, 24_000_000, "1A 20 01"),
        ("STC8H8K64U", 0x74, 8, 36_864_000, "2E 30 01"),
        ("AI8051U-34K64", 0x75, 8, 36_864_000, "2E 30 01"),
        ("AI32G12K128", 0x75, 8, 12_000_000, "1A 20 02"),
        ("AI32F12K16", 0x75, 8, 48_000_000, "2C 20 01"),
    ):
        machine = api["emulator"]("C")
        index = next(row["index"] for row in models if row["name"] == model)
        for offset, value in ((0x120, index), (0x17C, version), (0x180, patch), (0xF8, hz)):
            api["write32"](machine, OBJ + offset, value)
        machine.mem_write(OBJ + 0x688, bytes(range(54)))
        machine.mem_write(STACK, bytes.fromhex("DD 4C 24 F8 8B 44 24 F8 8B 54 24 FC C3"))
        api["write32"](machine, 0x503A60, STACK)
        api["call"](machine, 0x43EB30)
        assert api["call"](machine, 0x43EFC0) == 0
        assert machine.mem_read(OBJ + 0x11C, 4) == hz.to_bytes(4, "little")
        assert machine.mem_read(OBJ + 0x71A, 3) == bytes.fromhex(trim)
    print("USB: original live-status trims and prescaler for STC8U, AI8051U, AI32G12 and AI32F12 matched")

def verify_stc15_clock_source():
    machine = api["emulator"]("C")
    index = next(row["index"] for row in models if row["name"] == "STC15F2K08S2")
    raw = bytearray(b"\xff" * 19)
    raw[0] = 0x90
    for offset, value in ((0x120, index), (0x6E0, api["OPT"]), (0xE4, 2400), (0x18C, 1)):
        api["write32"](machine, OBJ + offset, value)
    machine.mem_write(api["OPT"], bytes(raw))
    machine.mem_write(OBJ + 0x722, b"\x65")
    machine.mem_write(OBJ + 0x72B, b"\x12\0")
    machine.reg_write(UC_X86_REG_EBP, OBJ)
    machine.emu_start(0x44F079, 0x44F0C1, count=100)
    assert machine.reg_read(UC_X86_REG_EIP) == 0x44F0C1
    assert machine.mem_read(OBJ + 0x11C, 4) == (11_059_200).to_bytes(4, "little")
    assert api["call"](machine, 0x44B760, api["OUT"]) == 64
    body = bytes(machine.mem_read(api["OUT"], 64))
    assert body[23:31:2] == (11_059_200).to_bytes(4, "big")
    assert body[59:61] == b"\x65\x7f" and body[63] == 0x90
    print("Legacy STC15 clock-source change uses the handshake clock, matching original x86")


def verify_legacy_stc12_mixed():
    erase = capture("STC12C1052AD", 0x4429D6, {
        0x17C: 0x50, 0xFC: 0x600, 0x6CC: SRC,
    }, bp=True)
    assert len(erase) == 134 and erase[:8] == bytes.fromhex("84 00 00 06 00 00 04 00")
    block = capture("STC12C1052AD", 0x443240, {
        0x17C: 0x50, 0x100: 0x600, 0x114: 128, 0x6CC: SRC,
    }, args=(0, 0), uart_offset=0x400)
    assert block == bytes.fromhex("00 00 00 04 00 00 80 02 00 00") + b"\xff" * 125
    print("Legacy STC12: original 84 erase covers merged EEPROM and 00 data uses the EEPROM address")


def verify_simulation_options():
    # Synthetic status equivalents for the C++ link test. Execute the original
    # complete UART 04 sender, not just a reimplementation of its packer.
    cases = (
        ("STC8A8K08S4A12", 6, 0xFF, 0xFF, 0xFF, 0xFF, 0x6E, 0xFF),
        ("STC8H3K16S4", 6, 0xFF, 0xFF, 0xFF, 0xFF, 0x6E, 0xFF),
        ("STC8H8K64U", 6, 0xFF, 0xBF, 0xFC, 0xFC, 0x6E, 0xFF),
        ("STC8H8K64U", 6, 0xFF, 0x1F, 0xFC, 0xFC, 0x6E, 0xFF),
        ("USB-2UART", 6, 0xFF, 0x1F, 0xFC, 0xFC, 0x6E, 0xFF),
        ("USB-2CDC+HID", 6, 0xFF, 0x1F, 0xFC, 0xFC, 0x6E, 0xFF),
        ("AI8051U-34K64", 6, 0x3F, 0x1F, 2, 2, 0x6E, 0xFF),
        ("AI32G12K128", 8, 0xBF, 0x3F, 0x7E, 1, 0xEE, 0xFF),
        ("AI32G12K128", 6, 0x3F, 0xBF, 0x7E, 1, 0x6E, 0xFF),
        ("AI32G12K128", 6, 0x3F, 0x1F, 0x7E, 1, 0x6E, 0xFF),
        ("AI32F12K54", 8, 0x7F, 0x3F, 0xD0, 0xD0, 0xEE, 1),
    )
    for model, task, opt4, opt5, boundary, wire_boundary, wdt, wait in cases:
        raw = bytearray(b"\xff" * 19)
        raw[:6] = bytes((0x92, 0x51, 0x6E, boundary, opt4, opt5))
        raw[11], raw[12], raw[14] = 4, 0, 0xFC
        setup = {0x17C: 0x75, 0xDC: task, 0x1180: b"\x5a\xa5", 0x11C: 48_000_000,
                 0x71A: b"\x65\x30\x01"}
        body = bytearray(b"\xff" * (41 if model.startswith("AI8051U") else 40))
        body[3] = body[6] = body[22] = 0
        body[23] = wait
        body[24:31] = bytes.fromhex("02 DC 6C 00 65 30 01")
        body[32] = 0xFE
        body[34:40] = bytes((opt4 & (0xDF if task == 8 else 0xFF),
                             opt5, 0x92, 0x51, wdt, wire_boundary))
        if len(body) == 41:
            body[40] = 4
        expected = b"\x04\x00\x00\x5a\xa5" + body
        for origin in (0x443F2C, 0x44D2B6):
            actual = capture(model, origin, setup, bp=True, usb_offset=0, options=bytes(raw))
            assert actual == expected, (model, hex(origin), actual.hex(" "), expected.hex(" "))
        print(f"{model} simulation task {task}: {expected.hex(' ')}")


def verify_added_downloads():
    for name in ("STC8H8K64U", "AI8H2K02U", "STC8A8K64S4A12"):
        setup = {0x17C: 0x75, 0xFC: 0x601, 0x698: b"\x04", 0x1180: b"\x5a\xa5",
                 0x100: 3, 0x114: 64, 0x6CC: SRC, 0xB1E: b"\x22"}
        for origin in (0x442C82, 0x44CC6A):
            assert capture(name, origin, setup, bp=True, usb_erase=True) == b"\x03\x02\x00\x5a\xa5"
        uart = capture(name, 0x443240, setup, args=(2, 1), uart_offset=0x600)
        usb = capture(name, 0x44CFC5, setup, bp=True, usb_offset=0x600)
        assert uart == bytes.fromhex("02 06 00 00 00 02 00 00")
        assert usb == bytes.fromhex("12 06 00 00 00 02 00 00") + b"\xff" * 125

    for model, baud in (("STC15F100W", "01 65 40 FD C0 FC A0 83"),
                        ("STC15F2K08S2", "01 65 40 FF 70 00 00 83")):
        for version in (0x66, 0x71, 0x72, 0x75):
            modern = version >= 0x72
            setup = {0x17C: version, 0xE4: 2400, 0xE8: 19200, 0x118: 11_059_200,
                     0xFC: 3, 0x100: 3, 0x114: 64, 0x6CC: SRC,
                     0x1180: b"\x5a\xa5", 0x718: b"\x65\x40", 0x698: b"\x10"}
            assert capture(model, 0x4416C0, setup) == bytes.fromhex(baud)
            assert capture(model, 0x4428D0, setup) == (b"\x05\0\0\x5a\xa5" if modern else b"\x05")
            assert capture(model, 0x442C82 if modern else 0x442DEA, setup, bp=True) == (
                b"\x03\0\0\x5a\xa5" if modern else b"\x03\0")
            marker = b"\0\0" if version >= 0x75 else b"\x5a\xa5" if modern else b""
            assert capture(model, 0x443240, setup, args=(2, 1)) == b"\x22\0\0" + marker + b"\x02\0\0"
        print(f"{model}: selector 3 download commands matched")

    for version in (0x71, 0x72):
        # STC15F104E has 4 KiB of program Flash followed by 1 KiB of EEPROM.
        setup = {0x17C: version, 0xFC: 0x1201, 0x1180: b"\x5a\xa5"}
        address = 0x442DEA if version == 0x71 else 0x442C82
        expected = b"\x03\x02" if version == 0x71 else b"\x03\x02\x00\x5a\xa5"
        assert capture("STC15F104E", address, setup, bp=True) == expected
    for name in ("STC15F104E", "STC15F204EA"):
        legacy = {0x17C: 0x65, 0xFC: 0x1201}
        expected = bytes.fromhex("84 FF 00 12 01 00 10 00") + b"\0" * 11 + bytes(range(0x80, 0x5E, -1))
        assert capture(name, 0x442AAA, legacy, bp=True) == expected
        print(f"{name}: legacy erase includes the EEPROM end address")

    model = "AI32G12K128"
    setup = {0x3E: b"\1", 0xDC: 2, 0x17C: 0x75, 0x100: 3,
             0x114: 64, 0x6CC: SRC, 0x6D4: SRC, 0x1180: b"\x5a\xa5"}
    for offset, prefix in ((0x400, b"\0\x04"), (0x800, b"\0\x08"), (0x10000, b"\x01\0")):
        expected = b"\x03" + prefix + b"\x5a\xa5"
        # Run the original prefix scan, including its loop over the erased
        # EEPROM region (up to 64 KiB before the fixed-size G12K64 program).
        name = model if offset < 0x10000 else "AI32G12K64"
        assert capture(name, 0x442C82, setup, bp=True, image_start=offset) == expected
        assert capture(name, 0x44CC6A, setup, bp=True, image_start=offset, usb_erase=True) == expected
    for offset, header in ((0, "32 00 00 00 00"), (0x800, "12 08 00 00 00"),
                           (0x10000, "02 00 00 00 01")):
        uart = capture(model, 0x443240, setup, args=(2, 1), uart_offset=offset)
        usb = capture(model, 0x44CFC5, {**setup, 0xB1E: b"\x22"}, bp=True, usb_offset=offset)
        expected = bytes.fromhex(header) + b"\x02\0\0"
        assert uart == expected, uart.hex(" ")
        assert usb == expected + b"\xff" * 125, usb.hex(" ")
        old = {**setup, 0x17C: 0x74, 0x180: 13}
        expected = expected[:3] + b"\x5a\xa5" + expected[5:]
        uart = capture(model, 0x443240, old, args=(2, 1), uart_offset=offset)
        usb = capture(model, 0x44CFC5, {**old, 0xB1E: b"\x22"}, bp=True, usb_offset=offset)
        assert uart == expected and usb == expected + b"\xff" * 125, (uart.hex(" "), usb.hex(" "))
    print(f"{model} / AI32G12K64: banked UART and USB commands matched")

    for name in ("AI16F40K128-Beta", "STC16F40K128-Beta"):
        beta = {**setup, 0x3E: b"\0", 0xFC: 3, 0x698: b"\xfe", 0xB1E: b"\x22",
                0xE4: 2400, 0xE8: 19200, 0x118: 24_000_000, 0x718: b"\x65\x40"}
        assert capture(name, 0x4416C0, beta) == bytes.fromhex("01 65 40 FE C7 00 00 98")
        assert capture(name, 0x4428D0, beta) == bytes.fromhex("05 00 00 5A A5")
        for origin in (0x442C82, 0x44CC6A):
            assert capture(name, origin, beta, bp=True, usb_erase=True) == bytes.fromhex("03 00 00 5A A5")
            high = {**beta, 0xFC: 0x10003}
            assert capture(name, origin, high, bp=True, usb_erase=True) == bytes.fromhex("03 02 00 5A A5")
        for offset in (0, 0x80, 0x10000, 0x1DFF0):
            tail = bytes(((offset >> 8) & 0xFF, offset & 0xFF, 0, offset >> 16, 2, 0, 0))
            command = 0x22 if offset == 0 else 0x02
            assert capture(name, 0x443240, beta, args=(2, 1), uart_offset=offset) == bytes((command,)) + tail
            assert capture(name, 0x44CFC5, beta, bp=True, usb_offset=offset) == (
                bytes((command | (0x10 if offset < 0x10000 else 0),)) + tail + b"\xff" * 125)
        print(f"{name}: lower- and upper-bank UART and USB commands matched")

    # Family 88 uses the ordinary nonextended erase-size calculation.
    # The program and EEPROM data share the FF bank and are merged before sending.
    for model, status_byte, extent, offset, sectors in (
        ("AI8051U-34K64", 3, 0xF003, 0xF000, 120),
        ("STC8051U-34K16", 0x40, 0x4203, 0x4200, 2),
    ):
        merged = {0x17C: 0x75, 0xFC: extent, 0x698: bytes((status_byte,)),
                  0x1180: b"\x5a\xa5", 0x100: 3, 0x114: 64, 0x6CC: SRC, 0xB1E: b"\x22"}
        for origin in (0x442C82, 0x44CC6A):
            assert capture(model, origin, merged, bp=True, usb_erase=True) == bytes((3, sectors, 0, 0x5A, 0xA5))
        write = bytes((0x12, offset >> 8, 0, 0, 0, 2, 0, 0)) + b"\xff" * 125
        assert capture(model, 0x44CFC5, merged, bp=True, usb_offset=offset) == write
        assert capture(model, 0x443240, merged, args=(2, 1), uart_offset=offset) == b"\x02" + write[1:8]
        print(f"{model}: mixed-image UART and USB erase and EEPROM writes matched")


def verify_download_configuration():
    raw = bytearray(b"\xff" * 19)
    raw[0], raw[1], raw[2], raw[3], raw[14] = 0x81, 0x51, 0x4C, 0x20, 0xFC
    settings = {0xDC: 2, 0x1180: b"\x5a\xa5", 0x11C: 24_000_000,
                0x71A: b"\x40\x02\x01"}
    for version in (0x71, 0x72):
        header = b"\x04\0\0" + (b"\x5a\xa5" if version >= 0x72 else b"")
        body = bytearray(b"\xff" * 40)
        body[3] = body[6] = body[22] = 0
        body[24:31] = bytes.fromhex("01 6E 36 00 40 02 01")
        body[32] = 0xFE
        body[36:40] = bytes.fromhex("81 51 4C FF")
        actual = capture("STC15H4K08S4", 0x4439D0, {**settings, 0x17C: version}, options=bytes(raw))
        assert actual == header + body, (version, actual.hex(" "))
    print("STC15H: BSL 7.1 short and BSL 7.2 long hardware configuration headers verified")

    for model, version in (("STC15F100W", 0x71), ("STC15F2K08S2", 0x72)):
        raw = bytearray(b"\xff" * 19)
        raw[0], raw[1], raw[2], raw[8], raw[14] = 0x91, 0xc3, 0x25, 0xfd, 0xfc
        body = bytearray(b"\xff" * 64)
        body[3] = body[6] = body[22] = body[23] = body[29] = 0
        body[25], body[27], body[31], body[32] = 0xa8, 0xc0, 0xfe, 1
        body[55] = 0xfd
        body[59:64] = bytes.fromhex("54 7f 25 c3 91")
        header = b"\x04\0\0" + (b"\x5a\xa5" if version >= 0x72 else b"")
        actual = capture(model, 0x4439D0, {**settings, 0x17C: version, 0x18C: 1,
                         0x11C: 11_059_200, 0x71A: b"\x54\x40"}, options=bytes(raw))
        assert actual == header + body, (model, actual.hex(" "))
    print("STC15F: original short and long configuration packets with 64-byte body verified")

    for patch, command in ((1, 7), (2, 4)):
        raw[14] = 0xfc
        actual = capture("STC8A8K08S4A12", 0x4439D0,
                         {**settings, 0x17C: 0x72, 0x180: patch,
                          0xF74: b"\1", 0xF7C: 4, 0x1080: b"new!"}, options=bytes(raw))
        if command == 7:
            assert actual == b"\x07\0\0\x5a\xa5new!", actual.hex(" ")
        else:
            assert len(actual) == 45 and actual[0] == 4 and actual[27] == 4 and actual[37] == 0xf6
    print("BSL 7.2: original UART switches its first configuration command from 07 to 04 at patch 2")

    for model in ("STC8H8K64U", "AI8051U-34K64", "STC32G144K246"):
        for password_length in (0, 4):
            raw = bytearray(b"\xff" * 19)
            raw[:6] = bytes.fromhex("90 51 4C 03 00 BF")
            if model == "STC8H8K64U":
                raw[3], raw[4] = 0xF0, 0xFF
            raw[14] = 0xFC
            setup = {0x17C: 0x79, 0xDC: 2, 0x1180: b"\x5a\xa5",
                     0x11C: 24_000_000, 0x71A: b"\x48\x20\x01",
                     0xF74: bytes((bool(password_length),)), 0xF7C: password_length}
            expected = bytearray(b"\x04\x00\x00\x5a\xa5" + b"\xff" * 41)
            expected[8] = expected[11] = 0
            expected[27] = password_length
            expected[29:36] = bytes.fromhex("01 6E 36 00 48 20 01")
            expected[37] = 0xF6 if password_length else 0xFE
            expected[39:45] = bytes((raw[4] | 0x20, 0xBF, 0x90, 0x51, 0xCC, raw[3]))
            if model == "STC8H8K64U":
                expected.pop()
            elif model == "STC32G144K246":
                expected[44], expected[45] = 119, 123
            for origin in (0x443F2C, 0x44D2B6):
                actual = capture(model, origin, setup, bp=True, usb_offset=0, options=bytes(raw))
                assert actual == expected, (model, hex(origin), actual.hex(" "), expected.hex(" "))
        print(f"{model}: normal 04 sender verified with and without next password")

    model = "AI32G12K128"
    raw = bytearray(b"\xff" * 19)
    raw[:6] = bytes.fromhex("00 00 04 7E 00 00")
    raw[14], raw[16], raw[17], raw[18] = 0xFC, 0x04, 0xB2, 0xCC
    setup = {0x17C: 0x75, 0xDC: 2, 0x1180: b"\x5a\xa5"}
    for origin in (0x443F2C, 0x44D2B6):
        actual = capture(model, origin, setup, bp=True, usb_offset=0, options=bytes(raw))
        assert (actual[8], actual[9], actual[11], actual[12], actual[37], actual[43], actual[44]) == (
            0x10, 0xB2, 0, 0xCC, 0xFA, 0x84, 1)


def verify_new_uart_irc_packets():
    model = "STC32G144K246"
    counts = (3750, 6250, 6300, 8400, 8450, 11000, 8450, 11000)
    reply = bytes((0, 8)) + struct.pack(">8H", *counts)
    coarse, fine = capture(model, 0x440CE0, {0xE4: 2400, 0xF8: 24_000_000},
                           irc_coarse_reply=reply)
    assert coarse == bytes.fromhex("00 08 00 00 FF 00 00 10 FF 10 00 20 FF 20 00 20 FF 20")
    assert fine == b"\0\x0c" + b"".join(bytes((trim, 0)) for trim in range(121, 133))
    print(f"{model}: original dynamic IRC coarse and fine UART probes matched")


def verify_older_uart_irc_packets():
    model = "STC15F2K08S2"
    reply = bytes((0, 11)) + struct.pack(">12H", 3000, 6000, 8000, 8500, 11000, 13000, 14000,
                                         17000, 19500, 20500, 24000, 27000)
    coarse, fine = capture(model, 0x43F920, {0xE4: 2400, 0xF8: 24_000_000, 0x118: 12_000_000},
                           irc_coarse_reply=reply, irc_fine_entry=0x43FAA9)
    assert coarse == bytes.fromhex("00 0B 00 C0 80 C0 FF C0 00 80 80 80 FF 80 00 40 80 40 FF 40 00 00 80 00 00 00")
    assert fine == bytes.fromhex("00 0C 00 00 01 00 02 00 03 00 04 00 05 00 49 80 4A 80 4B 80 4C 80 4D 80 4E 80")
    print(f"{model}: original IRC sweep uses separate program and ISP clock samples")

    model = "STC8H8K64U"
    reply = bytes((0, 5)) + struct.pack(">5H", 7500, 12500, 14000, 18000, 21000)
    coarse, fine = capture(model, 0x4407C0, {0xE4: 2400, 0xF8: 24_000_000},
                           irc_coarse_reply=reply, irc_fine_entry=0x4408F9)
    assert coarse == bytes.fromhex("00 05 00 00 80 00 00 80 80 80 FF 00")
    assert fine == b"\0\x0c" + b"".join(bytes((trim, sub)) for trim in range(63, 66)
                                      for sub in range(4))
    print(f"{model}: original two-band dynamic IRC coarse and fine packets matched")
    model = "STC8A8K08S4A12"
    reply = bytes((0, 2)) + struct.pack(">2H", 15000, 25000)
    coarse, fine = capture(model, 0x4402F0, {0xE4: 2400, 0xF8: 24_000_000},
                           irc_coarse_reply=reply, irc_fine_entry=0x4403FF)
    assert coarse == bytes.fromhex("00 02 00 00 80 00")
    assert fine == b"\0\x0c" + b"".join(bytes((trim, sub)) for trim in range(63, 66)
                                      for sub in range(4)), fine.hex(" ")
    print(f"{model}: original single-band dynamic IRC coarse and fine packets matched")


def verify_upgraded_stc12_eeprom():
    model = "STC12C5A08S2"
    setup = {0xFC: 0x1201, 0x17C: 0x75, 0x698: b"\x10", 0x1180: b"\x5a\xa5"}
    erase = capture(model, 0x442C82, setup, bp=True)
    assert erase == bytes.fromhex("03 02 00 5A A5"), erase.hex(" ")
    print(f"{model}: original mixed-image erase uses the active EEPROM boundary")


if __name__ == "__main__":
    verify_uart_baud_and_old_uid()
    verify_fixed_partition_lot()
    verify_blank_encrypted_uart_block()
    verify_stc15e_calibration()
    verify_eeprom_fill_and_ai16_clock()
    verify_test_parameters()
    verify_usb_irc_presets()
    verify_legacy_stc12_mixed()
    verify_stc15_clock_source()
    verify_added_downloads()
    verify_simulation_options()
    verify_download_configuration()
    verify_new_uart_irc_packets()
    verify_older_uart_irc_packets()
    verify_upgraded_stc12_eeprom()
    h8u = "STC8H8K64U"
    for link1d in (0, 1):
        baud = capture(h8u, 0x4416C0, {
            0x25: bytes([link1d]), 0xE8: 19200, 0x118: 24_000_000,
            0x718: b"\x65\x40",
        })
        assert baud == bytes.fromhex("01 65 40 FE C7 00 00 98"), baud.hex(" ")
        print(f"H8U {'Link1D' if link1d else 'COM'} baud: {baud.hex(' ')}")
    prepare = capture(h8u, 0x442B54, {0x1180: b"\x5a\xa5"}, bp=True)
    assert prepare == bytes.fromhex("05 00 00 5A A5"), prepare.hex(" ")
    print("H8U UART prepare:", prepare.hex(" "))
    erase = capture(h8u, 0x442C82, {
        0xFC: 128, 0x17C: 0x75, 0x698: b"\xfe", 0x1180: b"\x5a\xa5",
    }, bp=True)
    assert erase == bytes.fromhex("03 00 00 5A A5"), erase.hex(" ")
    print("H8U UART erase:", erase.hex(" "))
    block = capture(h8u, 0x443240, {
        0x100: 64, 0x114: 64, 0x17C: 0x75, 0x6CC: SRC,
    }, args=(2, 1))
    assert block == bytes.fromhex("22 00 00 00 00 02 00 00") + b"\xff" * 61, block.hex(" ")
    print("H8U UART first write:", block[:8].hex(" "), f"({len(block)} bytes)")
    for model in ("STC8H8K64U", "AI8H2K02U", "AI8H2K16U", "STC8H2K32UT"):
        for version in (0x72, 0x73, 0x74, 0x75):
            header = "22 00 00 5A A5" if version < 0x75 else "22 00 00 00 00"
            setup = {
                0x17C: version, 0x180: 3, 0x25: b"\1", 0xE4: 2400, 0xE8: 19200,
                0x118: 24_000_000, 0xFC: 3, 0x100: 3, 0x114: 64, 0x6CC: SRC,
                0x1180: b"\x5a\xa5", 0x718: b"\x65\x40", 0x698: b"\x08",
            }
            assert capture(model, 0x4416C0, setup) == bytes.fromhex("01 65 40 FE C7 00 00 98")
            assert capture(model, 0x4428D0, setup) == bytes.fromhex("05 00 00 5A A5")
            assert capture(model, 0x442C82, setup, bp=True) == bytes.fromhex("03 00 00 5A A5")
            assert capture(model, 0x443240, setup, args=(2, 1)) == bytes.fromhex(header + " 02 00 00")
            print(f"{model} UART BSL {version:x}: {header}")
    erase = capture("STC89C52RC/LE52RC", 0x44293B, {0xFC: 128, 0x17C: 0x46}, bp=True, cx=0x72)
    assert erase == bytes.fromhex("84 01 33 33 33 33 33 33"), erase.hex(" ")
    print("STC89 UART erase:", erase.hex(" "))
    for model, option, expected in (
        ("STC89C52RC/LE52RC", 0xBF, "8D BD FF F6 FF"),
        ("STC90C52RC", 0xBF, "8D BD FF F6 FF"),
        ("STC89C516RD/LV516RD", 0, "8D 40"),
        ("STC89C51", 0xBF, "8D BD FF F6 FF"),
    ):
        data = capture(model, 0x4439D0, {0x17C: 0x46}, options=bytes([0xFF, option]) + b"\xff" * 17)
        assert data == bytes.fromhex(expected), (model, data.hex(" "))
        print(f"{model} UART options: {data.hex(' ')}")
    for model, version, entry, code_size in (
        ("STC12C1052AD", 0x50, 0x4429BC, 1024),
        ("STC12C5A08S2", 0x58, 0x4429CA, 8192),
    ):
        baud = capture(model, 0x4416C0, {
            0xE4: 2400, 0xE8: 19200, 0x118: 11_059_200, 0x17C: version,
        })
        assert baud == bytes.fromhex("8F C0 DC 3F 48 28 83"), (model, baud.hex(" "))
        erase = capture(model, entry, {0xFC: 128, 0x17C: version}, bp=True, cx=0x72)
        size = code_size.to_bytes(3, "big")
        assert erase == b"\x84\x00" + size * 2 + b"\0" * 11 + bytes(range(128, 13, -1)), (
            model, erase.hex(" "),
        )
        block = capture(model, 0x443240, {
            0x100: 128, 0x114: 128, 0x17C: version, 0x6CC: SRC,
        }, args=(2, 1))
        assert block == bytes.fromhex("00 00 00 00 00 00 80 02 00 00") + b"\xff" * 125, (
            model, block.hex(" "),
        )
        print(f"{model} UART: {baud.hex(' ')}, {len(erase)}-byte erase, {len(block)}-byte write")
        settings = bytearray(b"\xff" * 19)
        settings[1 if version == 0x50 else 2] = 0xFC
        settings[14] = 0xFD
        data = capture(model, 0x4439D0, {
            0x17C: version, 0x118: 11_059_200,
        }, options=bytes(settings))
        if version == 0x50:
            expected = bytes.fromhex(
                "8D FF FC F5 FF FF 00 A8 C0 00 FF FF FF FC FF FF FF FF F5 FF FF FF FF FF FF FF 00 A8 C0 00 FF FF FF"
            )
        else:
            expected = bytes.fromhex(
                "8D FF FF FC FF FF FF FF FF FD FF FF FF FF FF FF FF 00 A8 C0 00"
            )
        assert data == expected, (model, data.hex(" "))
        print(f"{model} UART options: {data.hex(' ')}")
    for model, marker, speed, options, registers in (
        ("STC89C52RC/LE52RC", b"\x46\xb9", "01 FF EE 82",
         "04 00 00 46 B9 B9", {1: 0xB9}),
        ("STC12C1052AD", b"\x46\xb9", "01 C0 DC 83",
         "04 00 00 46 B9 00 A8 C0 00 E7 DC BF 7F", {14: 0xE7, 1: 0xDC, 0: 0xBF, 4: 0x7F}),
        ("STC12C5A08S2", b"\x5a\xa5", "01 C0 DC 83",
         "04 00 00 5A A5 00 A8 C0 00 E7 DC BF 7F", {14: 0xE7, 2: 0xDC, 1: 0xBF, 0: 0x7F}),
    ):
        for version in (0x72, 0x75):
            setup = {
                0x1A4: 5, 0xE4: 2400, 0xE8: 19200, 0x118: 11_059_200, 0x17C: version,
                0xFC: 128, 0x100: 128, 0x114: 128, 0x6CC: SRC, 0x698: b"\xfe", 0x1180: marker,
            }
            assert capture(model, 0x4416C0, setup) == bytes.fromhex(speed)
            assert capture(model, 0x442B54, setup, bp=True) == b"\x05\0\0" + marker
            assert capture(model, 0x442C82, setup, bp=True) == b"\x03\0\0" + marker
            header = marker if version < 0x75 else b"\0\0"
            block = capture(model, 0x443240, setup, args=(2, 0))
            assert block == b"\x22\0\0" + header + b"\x02\0\0" + b"\xff" * 125
            short_block = capture(model, 0x443240, {**setup, 0x100: 3}, args=(2, 0))
            assert short_block == block[:8]
            settings = bytearray(b"\xff" * 19)
            for offset, value in registers.items():
                settings[offset] = value
            data = capture(model, 0x4439D0, setup, options=bytes(settings))
            assert data == bytes.fromhex(options), (model, data.hex(" "))
            print(f"{model} BSL {version:x}: {speed}, {block[:5].hex(' ')}, {options}")
    for model, baud in (
        ("IRC15W107", "01 00 00 FD C0 FC A0 83"),
        ("IRC15F2K63S2", "01 00 00 FF 70 00 00 83"),
    ):
        for version, erase, block in (
            (0x71, "03 00", "02 00 00 02 00 00"),
            (0x72, "03 00 00 5A A5", "02 00 00 5A A5 02 00 00"),
            (0x75, "03 00 00 5A A5", "02 00 00 00 00 02 00 00"),
        ):
            setup = {
                0x17C: version, 0xE4: 2400, 0xE8: 19200, 0x118: 11_059_200,
                0xFC: 3, 0x100: 3, 0x114: 64, 0x6CC: SRC, 0x1180: b"\x5a\xa5", 0x698: b"\x1c",
            }
            assert capture(model, 0x4416C0, setup) == bytes.fromhex(baud)
            assert capture(model, 0x4428D0, setup) == bytes.fromhex(erase)
            assert capture(model, 0x443240, setup, args=(2, 1)) == bytes.fromhex(block)
            print(f"{model} BSL {version:x}: {baud}, {erase}, {block}")
    for model in ("STC15F104E", "STC15F204EA"):
        legacy = {
            0x17C: 0x71, 0xE4: 2400, 0xE8: 19200, 0x118: 11_059_200, 0xFC: 3, 0x100: 3,
            0x114: 64, 0x6CC: SRC, 0x718: b"\x65\x40",
        }
        assert capture(model, 0x4416C0, legacy) == bytes.fromhex("01 65 40 FD C0 FC A0 83")
        assert capture(model, 0x4428D0, legacy) == b"\x05"
        assert capture(model, 0x442DEA, legacy, bp=True) == b"\x03\0"
        assert capture(model, 0x443240, legacy, args=(2, 1)) == bytes.fromhex("00 00 00 00 00 00 03 02 00 00")
        magic = next(row["magic"] for row in models if row["name"] == model)
        assert capture(model, 0x44388E, legacy, bp=True) == b"\x69\0\0\x36\x01" + magic.to_bytes(2, "big")
        for version in (0x60, 0x61, 0x66, 0x70):
            old = {**legacy, 0x17C: version}
            assert capture(model, 0x4415C0, old) == b"\x50\0\0\x36\x01" + magic.to_bytes(2, "big")
            assert capture(model, 0x4416C0, old) == bytes.fromhex("8E 58 65 06 A0 64 DB FF 83 20 FF 00")
            erase = bytes.fromhex("84 FF 00 00 03 00 10 00") + bytes(11) + bytes(range(0x80, 0x5E, -1))
            assert capture(model, 0x4428D0, old) == erase
            assert capture(model, 0x443240, old, args=(0, 0)) == bytes.fromhex("00 00 00 00 00 00 03 02 00 00")
        for version, header in ((0x72, "22 00 00 5A A5"), (0x75, "22 00 00 00 00")):
            setup = {
                0x17C: version, 0x1A4: 5, 0xE4: 2400, 0xE8: 19200, 0x118: 11_059_200,
                0xFC: 3, 0x100: 3, 0x114: 64, 0x6CC: SRC,
                0x1180: b"\x5a\xa5", 0x718: b"\x65\x40", 0x698: b"\x10",
            }
            assert capture(model, 0x4416C0, setup) == bytes.fromhex("01 65 40 FD C0 FC A0 83")
            assert capture(model, 0x4428D0, setup) == bytes.fromhex("05 00 00 5A A5")
            assert capture(model, 0x442C82, setup, bp=True) == bytes.fromhex("03 00 00 5A A5")
            assert capture(model, 0x443240, setup, args=(2, 1)) == bytes.fromhex(header + " 02 00 00")
            print(f"{model} BSL {version:x}: {header}")
    modern_models = [
        row for row in models if 45 <= row["family"] <= 85 and row["flags"] & 0x1FC0 == 0x02C0
        and 0 < row["code_size"] <= 0xFE00 and row["family"] != 61
    ]
    by_family = {row["family"]: row["name"] for row in modern_models}
    assert len(modern_models) == 352 and len(by_family) == 35
    for family, model in sorted(by_family.items()):
        setup = {
            0xE4: 2400, 0xE8: 19200, 0x118: 24_000_000,
            0xFC: 3, 0x100: 3, 0x114: 64, 0x6CC: SRC,
            0x1180: b"\x5a\xa5", 0x718: b"\x65\x40", 0x698: b"\x08",
        }
        wait = 0x80 if family <= 52 else 0x98
        for version in (0x72, 0x73, 0x74, 0x75):
            current = {**setup, 0x17C: version}
            assert capture(model, 0x4416C0, current) == bytes.fromhex("01 65 40 FE C7 00 00") + bytes((wait,))
            if family <= 52:
                slow = {**current, 0x118: 11_059_200}
                assert capture(model, 0x4416C0, slow) == bytes.fromhex("01 65 40 FF 70 00 00 83")
            assert capture(model, 0x4428D0, current) == bytes.fromhex("05 00 00 5A A5")
            assert capture(model, 0x442C82, current, bp=True) == bytes.fromhex("03 00 00 5A A5")
            marker = "5A A5" if version < 0x75 else "00 00"
            assert capture(model, 0x443240, current, args=(2, 1)) == bytes.fromhex(f"22 00 00 {marker} 02 00 00")
        print(f"8-bit UART family {family}: {model}")
    f8d1 = "STC32G144K246"
    for mode in (6, 8):
        baud = capture(f8d1, 0x4416C0, {
            0x25: b"\1", 0xDC: mode, 0xE4: 2400, 0xE8: 19200,
            0x118: 24_000_000, 0x17C: 0x75, 0x718: b"\x65\x40",
        })
        assert baud == bytes.fromhex("01 65 40 FE C7 00 00 98"), baud.hex(" ")
        erase = capture(f8d1, 0x442C82, {
            0xDC: mode, 0xFC: 0, 0x17C: 0x75, 0x1180: b"\x5a\xa5",
        }, bp=True)
        assert erase == bytes.fromhex("03 00 00 5A A5"), erase.hex(" ")
        print(f"F8D1 simulation mode {mode}: {baud.hex(' ')}, {erase.hex(' ')}")
    for model in ("AI8051U-34K64", "STC8051U-34K16"):
        for offset, header in ((0, "32 00 00 00 00"), (0x100, "12 01 00 00 00")):
            block = capture(model, 0x44CFC5, {
                0xDC: 2, 0x17C: 0x75, 0x6CC: SRC, 0xB1E: b"\x22",
            }, bp=True, usb_offset=offset)
            assert block == bytes.fromhex(header + " 02 00 00") + b"\xff" * 125, (model, block.hex(" "))
            old = capture(model, 0x44CFC5, {
                0xDC: 2, 0x17C: 0x74, 0x180: 13, 0x6CC: SRC, 0xB1E: b"\x22", 0x1180: b"\x5a\xa5",
            }, bp=True, usb_offset=offset)
            assert old == block[:3] + b"\x5a\xa5" + block[5:]
            print(f"{model} USB block {offset:04x}: {block[:5].hex(' ')}")
    for model in ("STC8H8K64U", "AI8H2K02U", "AI8H2K16U", "STC8H2K32UT"):
        for version, marker in ((0x74, b"\x5a\xa5"), (0x75, b"\0\0")):
            setup = {0x180: 3, 0xDC: 2, 0x17C: version, 0x6CC: SRC, 0xB1E: b"\x22",
                     0x1180: b"\x5a\xa5", 0x100: 131}
            for offset, command in ((0, 0x32), (128, 0x12)):
                block = capture(model, 0x44CFC5, setup, bp=True, usb_offset=offset)
                assert block == bytes((command, 0, offset)) + marker + b"\x02\0\0" + b"\xff" * 125
            print(f"{model} USB BSL {version:x}: 32/12, marker {marker.hex(' ')}")
