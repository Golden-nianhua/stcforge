"""Compare the C++ IAP15 simulation packets with AiCube 6.97C, without a target."""

import argparse
from pathlib import Path
import runpy
import struct
import subprocess

from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_EBP, UC_X86_REG_ESP

ROOT = Path(__file__).resolve().parent
env = runpy.run_path(str(ROOT / "verify-uart-packets-6.97c.py"))
api, capture = env["api"], env["capture"]
OBJ, SRC, OUT, STACK = (api[key] for key in ("OBJ", "SRC", "OUT", "STACK"))
RESOURCES = ROOT / "resources"


def original_blocks(machine, wrapped, version):
    machine.mem_write(OUT, wrapped)
    machine.mem_write(OBJ + 0x1180, b"\x5a\xa5")
    machine.mem_write(0x43CA60, b"\x31\xc0\xc2\x0c\x00")
    for offset, value in ((0x17C, version), (0x6CC, OUT), (0x114, 64), (0x1A4, 3)):
        api["write32"](machine, OBJ + offset, value)
    machine.reg_write(UC_X86_REG_EBP, OBJ)
    packets = []

    def record(uc, *_):
        address, size = struct.unpack("<II", uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 4, 8))
        packets.append(bytes(uc.mem_read(address, size)))
        uc.emu_stop()

    machine.hook_add(UC_HOOK_CODE, record, begin=0x43D0D0, end=0x43D0D0)
    for offset in range(0, len(wrapped), 64):
        for field, value in ((0x14, offset), (0x18, len(wrapped) - offset), (0x3C, 0x42)):
            api["write32"](machine, STACK + 0x800 + field, value)
        machine.reg_write(UC_X86_REG_ESP, STACK + 0x800)
        machine.emu_start(0x4432D4, api["END"], count=2000)
    return packets


def verify(executable, magic, version, resource, monitor_address):
    result = subprocess.run([str(executable), "--iap15-simulation", str(RESOURCES), hex(version), hex(magic)],
                            capture_output=True)
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    packets = [bytes.fromhex(line[7:].decode("ascii")) for line in result.stdout.splitlines()
               if line.startswith(b"packet ")]
    name = next(m["name"] for m in env["models"] if m["magic"] == magic)
    setup = {0x17C: version, 0xDC: 6, 0x1180: b"\x5a\xa5", 0x11C: 24_000_000,
             0x18C: 1, 0x71A: b"\x65\x40", 0x100: 0}
    raw = bytes.fromhex("21 43 65 FF FF FF FF FF 87 FF FF FF FF FF 10 FF FF FF FF")
    assert packets[1] == capture(name, 0x4428D0, setup)
    erase_entry = 0x442DEA if version == 0x71 else 0x442C82
    assert packets[2] == capture(name, erase_entry, setup, bp=True), (name, version, packets[2].hex())
    option = capture(name, 0x4439D0, setup, options=raw)
    assert packets[-2] == option, (name, version, packets[-2].hex(), option.hex())
    assert packets[-1] == b"\xff"

    blocks = packets[3:-2]
    wrapped = b"".join(packet[-64:] for packet in blocks)
    assert len(wrapped) == monitor_address + 4096
    machine = api["emulator"]("C")

    def unwrap(blob):
        machine.mem_write(SRC, blob)
        api["call"](machine, 0x4E7FC0, SRC, OUT, len(blob), 1, count=2_000_000)
        return bytes(machine.mem_read(OUT, len(blob)))

    plain = unwrap(wrapped)
    assert plain[:512] == unwrap((RESOURCES / "res2.bin").read_bytes())
    assert plain[monitor_address:] == unwrap((RESOURCES / f"res{resource}.bin").read_bytes())
    assert blocks == original_blocks(machine, wrapped, version)
    print(f"{name}, BSL {version >> 4}.{version & 15}: {len(blocks)} original data packets and 05/03/04 matched.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("test_exe", type=Path)
    args = parser.parse_args()
    for case in ((0xF449, 0x71, 6, 0xE000), (0xF4C9, 0x72, 6, 0xE000),
                 (0xF569, 0x74, 30, 0xD400), (0xF56D, 0x75, 30, 0xD400),
                 (0xF56A, 0x75, 31, 0xE000)):
        verify(args.test_exe.resolve(), *case)
