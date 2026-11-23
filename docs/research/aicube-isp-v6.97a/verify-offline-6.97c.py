"""Compare complete offline images against the local 6.97C packer."""

import argparse
import json
import runpy
import struct
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parent
api = runpy.run_path(str(ROOT / "verify-routines.py"))
OBJ, OPT, SRC, STACK = (api[name] for name in ("OBJ", "OPT", "SRC", "STACK"))
MODELS = {item["name"]: item for item in json.loads(
    (ROOT / "models-6.97c.json").read_text(encoding="utf-8"))["models"]}


def original(model, program, options, hz, isp_hz, bindings=(), counters=()):
    machine = api["emulator"]("C")
    output = 0x4000000
    source = 0x4100000
    machine.mem_map(output, 0x80000)
    machine.mem_map(source, 0x80000)
    data = bytearray(program + b"\xff" * (0x80000 - len(program)))
    for i, (offset, op, operands) in enumerate(bindings):
        data[offset:offset + 7] = b"\xff" * 7
        machine.mem_write(OBJ + 0xF4C + i, b"\x01")
        machine.mem_write(OBJ + 0xF50 + i, bytes([op]))
        machine.mem_write(OBJ + 0xF54 + 4 * i, bytes(operands).ljust(4, b"\x00"))
    for i in range(4):
        api["write32"](machine, OBJ + 0xF64 + 4 * i, bindings[i][0] if i < len(bindings) else 0xFFFFFFFF)
    for i, (address, width, mode, start, step) in enumerate(counters):
        data[address:address + width] = b"\xff" * width
        machine.mem_write(OBJ + 0x30 + i, b"\x01")
        api["write32"](machine, OBJ + 0x88 + 4 * i, address)
        api["write32"](machine, OBJ + 0x90 + 4 * i, width)
        api["write32"](machine, OBJ + 0x98 + 4 * i, mode)
        machine.mem_write(OBJ + 0x48 + 16 * i, start.to_bytes(16, "little"))
        machine.mem_write(OBJ + 0x68 + 16 * i, step.to_bytes(16, "little"))
    if counters:
        machine.mem_write(OBJ + 0x2A, b"\x01")
    machine.mem_write(source, bytes(data))
    machine.mem_write(output, b"\xff" * 0x80000)
    machine.mem_write(OPT, options + b"\xff\xff\xff")
    machine.mem_write(STACK + 0xC10, b"\x31\xc0\xc3")
    machine.mem_write(STACK + 0xC20, bytes.fromhex("DD 4C 24 F8 8B 44 24 F8 8B 54 24 FC C3"))
    api["write32"](machine, 0x503108, STACK + 0xC10)
    api["write32"](machine, 0x503A60, STACK + 0xC20)
    for offset, value in (
        (0xE4, 2400), (0xF8, hz), (0xFC, len(program)), (0x110, 15),
        (0x118, isp_hz), (0x120, model["index"]), (0x170, 5),
        (0x6CC, output), (0x6D4, source), (0x6E0, OPT),
    ):
        api["write32"](machine, OBJ + offset, value)
    machine.mem_write(OBJ + 0x1EC, struct.pack("<f", 0.015625))
    api["call"](machine, 0x449800, stop=0x44A346, count=3_000_000)
    length, = struct.unpack("<I", machine.mem_read(OBJ + 0x100, 4))
    return bytes(machine.mem_read(output, length))


def hex_record(address, kind, data):
    body = struct.pack(">BHB", len(data), address, kind) + data
    return ":" + (body + bytes((-sum(body) & 255,))).hex().upper()


def verify(exe, root, name, base, offset, raw_options, bind_uid=False, counter_mode=None):
    profile = root / "hardware.cfg"
    profile.write_text(
        f"[MCU]\nMcuType={name}\nOption={raw_options.hex()}{sum(raw_options) & 255:02x}\n"
        "Frequency=22.1184\n",
        encoding="ascii",
    )
    tail = bytes(range(256)) + b"\x01\x02\x03\x04"
    program = b"\xff" * offset + tail
    image = root / "image.hex"
    records = []
    high = None
    for pos in range(0, len(tail), 16):
        address = base + offset + pos
        if address >> 16 != high:
            high = address >> 16
            records.append(hex_record(0, 4, high.to_bytes(2, "big")))
        records.append(hex_record(address & 0xffff, 0, tail[pos:pos + 16]))
    records.append(hex_record(0, 1, b""))
    image.write_text("\n".join(records) + "\n", encoding="ascii")
    output = root / "offline.bin"
    output.unlink(missing_ok=True)
    command = [str(exe), "--offline-profile", str(profile), "--image", str(image),
               "--offline-output", str(output), "--option", "offline_irc_tolerance_ppm=15625"]
    bindings = ()
    if bind_uid:
        command += ["--uid-bind", f"{base + offset + 0x10:#x}=xor:0x80,mul:2",
                    "--uid-bind", f"{base + offset + 0x205:#x}=div:2,add:1"]
        bindings = ((offset + 0x10, 7, (0x80, 2)), (offset + 0x205, 2, (2, 1)))
    counters = ()
    if counter_mode is not None:
        command += ["--option", f"offline_program_counter={counter_mode},0x20,4,1234,10",
                    "--option", "offline_eeprom_counter=hex,0xFE02,4,ca01,2",
                    "--option", "offline_increment_on_failure=true"]
        counters = ((0x20, 4, {"hex": 0, "dec": 1, "ascii": 2}[counter_mode], 0x1234, 0x10),
                    (0xFE02, 4, 0, 0xCA01, 2))
    subprocess.run(command, check=True, capture_output=True)
    expected = original(MODELS[name], program, raw_options, 22_118_400, 22_118_400, bindings, counters)
    actual = output.read_bytes()
    mismatches = [f"{i:04X}={want:02X}/{got:02X}"
                  for i, (want, got) in enumerate(zip(expected, actual)) if want != got]
    assert len(expected) == len(actual) and not mismatches, (
        name, len(expected), len(actual), mismatches[:32])
    subprocess.run([str(exe), "--if", "usb", "--offline-image", str(output), "--offline-resources",
                    str(ROOT / "resources"), "--dry-run"],
                   check=True, capture_output=True)
    detail = " (UID)" if bind_uid else f" ({counter_mode} counter)" if counter_mode else ""
    print(f"{name}{detail}: {len(actual)} offline bytes match the original x86 image.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("exe", type=Path)
    args = parser.parse_args()
    with TemporaryDirectory(prefix="stc-isp-offline-oracle-") as directory:
        root = Path(directory)
        raw = bytes.fromhex("FF FE FA F8 F7 F6 F5 F4 F3 F2 F1 F0 EF EE ED FD")
        for name, base, offset in (
            ("STC89C52RC/LE52RC", 0, 0),
            ("STC8H8K64U", 0, 0),
            ("STC32G144K246", 0xFC2800, 0x2D800),
            ("AI32G12K128", 0xFE0000, 0x800),
        ):
            verify(args.exe.resolve(), root, name, base, offset, raw)
            verify(args.exe.resolve(), root, name, base, offset, raw, bind_uid=True)
        for mode in ("hex", "dec", "ascii"):
            verify(args.exe.resolve(), root, "STC8H8K64U", 0, 0, raw, counter_mode=mode)


if __name__ == "__main__":
    main()
