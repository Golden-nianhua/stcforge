"""Offline builds only. Run with the project's uv-managed Python:
D:/Code/uv/uv.exe run --project D:/Projects/stcforge --no-sync python D:/Projects/stcforge/docs/examples/simulation-matrix/minimal/build.py
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

SOURCE = Path(__file__).resolve().parent
BIN = Path("D:/Code/c-env/SDCC/SDCC-4.6.0-MCS251/bin")
OUTPUT = Path("D:/Code/CLionProjects/STC/STC32K144G246_32BIT_SDCC_Template/Misc/Experiments/Simulation Firmware Matrix")
VARIANTS = ("M00_minimal_led", "M01_led_uart", "M02_led_uart_timer")
FLAGS = ["-mmcs251", "--model-large", "--stack-auto", "--int-long-reent", "--std-c11", "--debug"]
LINK = ["--code-loc", "0xFF0000", "--iram-size", "0x4000", "--xram-loc", "0x010000", "--xram-size", "0x20000", "--stack-size", "1"]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_hex(path: Path) -> dict[int, int]:
    image: dict[int, int] = {}
    base = 0
    eof = False
    for line in path.read_text(encoding="ascii").splitlines():
        assert line.startswith(":"), line
        rec = bytes.fromhex(line[1:])
        assert len(rec) == rec[0] + 5 and sum(rec) % 256 == 0, line
        assert not eof, "Record after EOF"
        address = int.from_bytes(rec[1:3], "big")
        kind, data = rec[3], rec[4:-1]
        if kind == 0:
            for offset, value in enumerate(data):
                key = base + address + offset
                assert key not in image or image[key] == value, "Conflicting HEX data"
                image[key] = value
        elif kind == 4:
            assert len(data) == 2
            base = int.from_bytes(data, "big") << 16
        elif kind == 2:
            assert len(data) == 2
            base = int.from_bytes(data, "big") << 4
        elif kind == 1:
            assert len(data) == 0
            eof = True
        else:
            raise AssertionError(f"Unexpected record kind {kind}")
    assert eof and image
    assert min(image) == 0xFF0000 and max(image) <= 0xFFFFFF
    return image


def build(index: int) -> None:
    stem = VARIANTS[index]
    out = OUTPUT / stem
    out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["PATH"] = str(BIN) + os.pathsep + env.get("PATH", "")
    transcript: list[str] = []
    commands: list[list[str]] = []

    def run(args: list[str], stdin: bytes | None = None) -> bytes:
        commands.append(args)
        result = subprocess.run(args, cwd=out, env=env, input=stdin, capture_output=True)
        transcript.append("$ " + subprocess.list2cmdline(args) + "\n")
        if stdin is None:
            transcript.append(result.stdout.decode("utf-8", errors="replace"))
        transcript.append(result.stderr.decode("utf-8", errors="replace"))
        (out / "build.log").write_text("".join(transcript), encoding="utf-8")
        if result.returncode:
            raise RuntimeError(f"{stem}: command failed ({result.returncode}); see {out / 'build.log'}")
        return result.stdout

    version = run([str(BIN / "sdcc.exe"), "--version"]).decode("utf-8", errors="replace")
    for name in ("main.c", "registers.h", "startup.asm"):
        shutil.copyfile(SOURCE / name, out / name)
    # Compile source copies: every generated/intermediate file stays in this output.
    run([str(BIN / "sdcc.exe"), *FLAGS, f"-DMATRIX_VARIANT={index}", "-c", "main.c", "-o", "main.rel"])
    run([str(BIN / "sdas251.exe"), "-plosgff", "startup.rel", "startup.asm"])
    # main must come first: its area declarations establish HOME/GSINIT order.
    # Putting the standalone GSINIT1 object first places it at address zero.
    run([str(BIN / "sdcc.exe"), *FLAGS, *LINK, "main.rel", "startup.rel", "-o", stem + ".ihx"])
    packed = run([str(BIN / "packihx.exe")], (out / (stem + ".ihx")).read_bytes())
    hex_path = out / (stem + ".hex")
    hex_path.write_bytes(packed)
    image = read_hex(hex_path)
    assert image == read_hex(out / (stem + ".ihx")), "packihx changed payload"
    asm = (out / "main.asm").read_text(encoding="utf-8")
    map_text = (out / (stem + ".map")).read_text(encoding="utf-8")
    hook = asm.split("___sdcc_external_startup:", 1)[1].split(";\tfunction", 1)[0]
    assert re.search(r"mov\s+dpl,\s*#0x01", hook), "Recheck actual return ABI"
    assert "___sdcc_external_startup" in map_text
    assert ("_timer1_isr:" in asm) == (index == 2)
    assert not re.search(r"setb\s+_EA", asm) or index == 2
    assert "movc" not in asm.lower(), "Unexpected code constant read"

    def symbol(name: str) -> int:
        match = re.search(r"^[CD]:\s+([0-9A-F]+)\s+" + re.escape(name) + r"\s", map_text, re.M)
        assert match, f"Missing MAP symbol: {name}"
        return int(match[1], 16)

    def raw(address: int, count: int) -> bytes:
        return bytes(image[address + offset] for offset in range(count))

    def at(name: str, expected: bytes) -> None:
        address = symbol(name)
        assert raw(address, len(expected)) == expected, f"Unexpected {name} bytes at {address:06X}"

    gs0 = symbol("s_GSINIT0")
    gs1 = symbol("s_GSINIT1")
    gs2 = symbol("s_GSINIT2")
    program = symbol("__sdcc_program_startup")
    external = symbol("___sdcc_external_startup")
    # Validate linked HEX bytes, not just the generic installed runtime source.
    at("s_GSINIT0", bytes.fromhex("7E FC 00 07"))  # MOV SPX,#0007 placeholder.
    assert gs1 == gs0 + 4 and gs2 == gs1 + 6
    at("s_GSINIT1", bytes.fromhex("75 81 FF 75 85 00"))
    assert symbol("__stc32_stack_init") == gs1
    at("s_GSINIT2", b"\x9a" + external.to_bytes(3, "big") + bytes.fromhex("E5 82 60 04 8A") + program.to_bytes(3, "big"))
    at("___sdcc_external_startup", bytes.fromhex("C2 AF 75 82 01 AA"))
    at("__sdcc_program_startup", b"\x9a" + symbol("_main").to_bytes(3, "big"))
    reset_trampoline = symbol("__sdcc_mcs251_reset_trampoline")
    assert raw(0xFF0000, 3) == b"\x02" + (reset_trampoline & 0xFFFF).to_bytes(2, "big")
    at("__sdcc_mcs251_reset_trampoline", b"\x8a" + gs0.to_bytes(3, "big"))
    assert symbol("l_XINIT") == 0 and symbol("l_XISEG") == 0
    assert symbol("_led_state") == 0x010000
    assert symbol("l_XSEG") == (5 if index == 2 else 1)
    isr_details = "No Timer1 ISR; no EA/TR1/ET1 enable instructions."
    if index == 2:
        assert symbol("_tick_ms") == 0x010001
        assert raw(0xFF001B, 4) == b"\x8a" + symbol("_timer1_isr").to_bytes(3, "big")
        isr = asm.split("_timer1_isr:", 1)[1].split("\treti", 1)[0]
        assert re.findall(r"^\s*push\s+(\S+)", isr, re.M) == ["acc", "b", "dpl", "dph", "psw", "0x84"]
        assert re.findall(r"^\s*pop\s+(\S+)", isr, re.M) == ["0x84", "psw", "dph", "dpl", "b", "acc"]
        assert not re.search(r"^\s*(?:mov|add|sub|inc|dec)\s+(?:dr|wr|r)[0-9]", isr, re.M)
        assert not re.search(r"^\s*(?:e?call|lcall)\s", isr, re.M)
        assert re.search(r"mov\s+_TH1,#0xf0", asm)
        assert re.search(r"mov\s+_TL1,#0x60", asm)
        isr_details = f"Timer1 vector FF001B -> {symbol('_timer1_isr'):06X}; saves/restores ACC, B, DPL, DPH, PSW, DPXL; no C calls or ordinary register writes."
    else:
        assert not re.search(r"^\s*setb\s+_(?:EA|TR1|ET1)\b", asm, re.M)
        assert "_timer1_init:" not in asm and "_tick_ms" not in asm

    addresses = {name: f"{symbol(name):06X}" for name in ("__sdcc_gsinit_startup", "__stc32_stack_init", "s_GSINIT2", "s_GSINIT3", "s_GSINIT4", "___sdcc_external_startup", "__sdcc_program_startup", "_main", "_led_state")}
    if index == 2:
        addresses.update({name: f"{symbol(name):06X}" for name in ("_tick_ms", "_timer1_isr")})
    checks = {
        "hex_checksums_and_eof": "PASS",
        "ihx_equals_packed_hex": "PASS",
        "code_range": f"{min(image):06X}..{max(image):06X}",
        "code_bytes": len(image),
        "hook_symbol": "___sdcc_external_startup",
        "hook_return": "DPL=1 (checked in main.asm)",
        "linked_startup_bytes": "PASS: GSINIT0 -> GSINIT1(SPX=00FF) -> ECALL hook -> A=DPL -> JZ not taken -> EJMP program startup -> ECALL main",
        "automatic_initialization": "Bypassed; GSINIT3/4 code remains linked but is not on the reset execution path",
        "xinit_xiseg_bytes": 0,
        "ram": "led_state=010000; tick_ms=010001..010004 only in M02; actual stack starts at EDATA 000100",
        "addresses": addresses,
        "timer1_isr_present": index == 2,
        "isr_check": isr_details,
        "hardware_validation": "NOT PERFORMED",
    }
    manifest = {
        "variant": stem,
        "compiler_version": version.strip(),
        "commands": commands,
        "inputs_sha256": {name: sha256(SOURCE / name) for name in ("main.c", "registers.h", "startup.asm", "build.py")},
        "checks": checks,
        "artifacts_sha256": {name: sha256(out / name) for name in (stem + ".hex", stem + ".map", "main.asm", "main.rst", "startup.rst")},
    }
    (out / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    rows = "\n".join(f"| `{name}` | `{value}` |" for name, value in addresses.items())
    report = f"""# {stem}: offline build verification

Built using SDCC MCS251, model-large, stack-auto, int-long-reent, C11, debug.
See build.log for the actual commands; manifest.json records source and artifact SHA-256 values.
Rebuild all three using:

```powershell
& D:/Code/uv/uv.exe run --project D:/Projects/stcforge --no-sync python D:/Projects/stcforge/docs/examples/simulation-matrix/minimal/build.py
```

HEX: `{stem}.hex`, SHA-256 `{sha256(hex_path)}`.
Payload: {len(image)} bytes at `{min(image):06X}..{max(image):06X}`.
HEX record checksums/EOF and IHX-to-HEX payload equality passed.

| Symbol | Address |
| --- | --- |
{rows}

The linked HEX was checked byte-for-byte for reset -> GSINIT0 -> GSINIT1 -> GSINIT2.
GSINIT0 sets the linker's placeholder SPX=0007. GSINIT1 is `75 81 FF 75 85 00`,
sets SP=FF/SPH=00 before the first C ECALL, and makes the first stack write EDATA 000100.
The one-byte SSEG at 000008 in MAP/MEM is only the linker's placeholder, not the runtime stack.
GSINIT2 ECALLs `___sdcc_external_startup`, reads DPL into A, and conditionally skips the
EJMP only if A is zero. The C function `__sdcc_external_startup` emits exactly
`C2 AF 75 82 01 AA` (CLR EA; MOV DPL,#1; ERET), so the EJMP to program startup is taken.
The latter ECALLs main. Runtime GSINIT3/4 copy/clear instructions remain in the image but
are bypassed. XINIT/XISEG lengths are zero. No own static initializer or code constant
table is used, and generated main.asm contains no MOVC instruction.

Every own RAM object is assigned explicitly in main before any read. M02 initializes
all four tick bytes and last_toggle before enabling Timer1 or EA. The atomic snapshot
saves EA, clears it, reads all four tick bytes, and restores EA in generated assembly.
{isr_details}

LED: P9.3, active high. M00 changes only P9.3 GPIO configuration.
M01/M02 UART7: P9.0 RX, P9.1 TX, timer7 FF98, nominal 115200 baud, polling only.
M00/M01 delay loops are uncalibrated; UART polling/traffic changes M01's blink period.
M02: Timer1 F060 at 48 MHz / 12 gives a nominal 1 ms tick, toggles after 500 ticks.
TX waits are bounded to 60000 spins. Fast UART bursts may overrun while polling or transmitting.
No P3/P3.0/P3.1 registers or USB controller configuration is included.
No original global-state driver library is linked.

This is build and static verification only. No board, flashing, service, or hardware
validation was performed. The compiler's macro-redefinition warnings and DPTR cache
diagnostics are retained verbatim in build.log.
"""
    (out / "verification.md").write_text(report, encoding="utf-8")
    print(json.dumps({"variant": stem, "hex": str(hex_path), "sha256": sha256(hex_path), **checks}, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--variant", choices=VARIANTS, help="Default: rebuild all three")
    args = parser.parse_args()
    for index, name in enumerate(VARIANTS):
        if args.variant is None or args.variant == name:
            build(index)
