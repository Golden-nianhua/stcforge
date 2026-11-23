"""Verify explicit USB and UART tool-controller provisioning without a physical device."""

import argparse
import runpy
import struct
import subprocess
from pathlib import Path

from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_EBP, UC_X86_REG_EBX, UC_X86_REG_EDX, UC_X86_REG_ESP

ROOT = Path(__file__).resolve().parent
api = runpy.run_path(str(ROOT / "verify-routines.py"))
OBJ, SRC, OUT, STACK = (api[key] for key in ("OBJ", "SRC", "OUT", "STACK"))


def original_packets(resource, version):
    machine = api["emulator"]("C")
    machine.mem_write(SRC, resource)
    api["call"](machine, 0x4E7FC0, SRC, OUT, len(resource), 1, count=1_000_000)
    machine.mem_write(OUT + 0x1000, bytes.fromhex("5A A5 A4") + bytes(13))
    api["call"](machine, 0x4E7F10, OUT, SRC, len(resource), 1, count=1_000_000)
    end = (len(resource) + 127) & ~127
    machine.mem_write(SRC + len(resource), b"\xff" * (end - len(resource)))
    machine.mem_write(OBJ + 0x1180, b"\x5a\xa5")
    for offset, value in ((0xDC, 7), (0x17C, version), (0x6CC, SRC)):
        api["write32"](machine, OBJ + offset, value)
    packets = []

    def capture(uc, *_):
        size, address = struct.unpack("<II", uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 4, 8))
        packets.append(bytes(uc.mem_read(address, size)))
        uc.emu_stop()

    machine.hook_add(UC_HOOK_CODE, capture, begin=0x44BDC0, end=0x44BDC0)
    for offset in range(0, end, 128):
        machine.mem_write(OBJ + 0xB1E, b"\x62")
        machine.reg_write(UC_X86_REG_EBP, OBJ)
        machine.reg_write(UC_X86_REG_EBX, OBJ + 0xB1E)
        machine.reg_write(UC_X86_REG_EDX, offset)
        machine.reg_write(UC_X86_REG_ESP, STACK + 0x800)
        machine.emu_start(0x44CFC5, api["END"], count=2000)
    return packets


def original_uart_packets(resource, version, magic, clear_tag):
    machine = api["emulator"]("C")
    machine.mem_write(SRC, resource)
    machine.mem_write(OBJ + 0x6B5, b"\x5a" if clear_tag else b"\x4a")
    for offset, value in ((0x124, magic), (0x17C, version), (0x6F4, len(resource)),
                          (0x6F0, SRC), (0x6CC, OUT), (0x114, 64), (0x1A4, 3)):
        api["write32"](machine, OBJ + offset, value)
    machine.mem_write(OBJ + 0x1180, b"\x5a\xa5")
    machine.reg_write(UC_X86_REG_EBP, OBJ)
    machine.reg_write(UC_X86_REG_ESP, STACK + 0x800)
    machine.emu_start(0x44F130, 0x44F22A, count=1_000_000)
    machine.mem_write(0x43CA60, b"\x31\xc0\xc2\x0c\x00")  # Unused legacy block checksum.
    packets = []

    def capture(uc, *_):
        address, size = struct.unpack("<II", uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 4, 8))
        packets.append(bytes(uc.mem_read(address, size)))
        uc.emu_stop()

    machine.hook_add(UC_HOOK_CODE, capture, begin=0x43D0D0, end=0x43D0D0)
    for offset in range(0, len(resource), 64):
        for field, value in ((0x14, offset), (0x18, len(resource) - offset), (0x3C, 0x42)):
            api["write32"](machine, STACK + 0x800 + field, value)
        machine.reg_write(UC_X86_REG_ESP, STACK + 0x800)
        machine.emu_start(0x4432D4, api["END"], count=2000)
    return packets


parser = argparse.ArgumentParser()
parser.add_argument("test_exe", type=Path)
args = parser.parse_args()
resources = ROOT / "resources"
resource = (resources / "res65.bin").read_bytes()
for version in (0x74, 0x75):
    result = subprocess.run([str(args.test_exe.resolve()), "--tool-controller", str(resources), hex(version)],
                            capture_output=True)
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    actual = [bytes.fromhex(line[6:].decode("ascii")) for line in result.stdout.splitlines()
              if line.startswith(b"block ")]
    expected = original_packets(resource, version)
    assert actual == expected, (hex(version), len(actual), len(expected),
                                [i for i, (got, want) in enumerate(zip(actual, expected)) if got != want][:8])
    print(f"Tool controller BSL {version >> 4}.{version & 15}: {len(actual)} original packets matched.")

resource = (resources / "res11.bin").read_bytes()
for magic, version, clear_tag in (
    (0xF44B, 0x71, True), (0xF4CB, 0x72, False), (0xF44C, 0x74, True),
    (0xF4CC, 0x75, True), (0xF56C, 0x75, False),
):
    result = subprocess.run([
        str(args.test_exe.resolve()), "--uart-tool-controller", str(resources),
        hex(version), hex(magic), "clear" if clear_tag else "keep",
    ], capture_output=True)
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    actual = [bytes.fromhex(line[6:].decode("ascii")) for line in result.stdout.splitlines()
              if line.startswith(b"block ")]
    expected = original_uart_packets(resource, version, magic, clear_tag)
    assert actual == expected, (hex(magic), hex(version), len(actual), len(expected),
                                [i for i, (got, want) in enumerate(zip(actual, expected)) if got != want][:8])
    print(f"UART controller {magic:04X} BSL {version >> 4}.{version & 15}: {len(actual)} original packets matched.")
