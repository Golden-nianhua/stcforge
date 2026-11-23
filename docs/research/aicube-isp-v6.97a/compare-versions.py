import difflib
import re
import struct
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, Cs


BASE = 0x400000
FOLDER = Path("D:/Code/MCU/AiCube-ISP")
engine = Cs(CS_ARCH_X86, CS_MODE_32)
engine.detail = True
engine.skipdata = True
a, c = ((FOLDER / f"AiCube-ISP-v6.97{v}.exe").read_bytes() for v in "AC")


def code(image, va, end):
    return list(engine.disasm(image[va-BASE:end-BASE], va))


def rs485_pins(image):
    # Both versions initialize 62 (label pointer, item data) pairs on the stack.
    fields = {}
    for insn in code(image, 0x411FE0, 0x412510):
        match = re.fullmatch(r"dword ptr \[esp \+ (0x[0-9a-f]+)\], (0x[0-9a-f]+|\d+)", insn.op_str)
        if insn.mnemonic == "mov" and match:
            fields[int(match[1], 16)] = int(match[2], 0)
    pins = []
    for offset in range(0x18, 0x208, 8):
        start = fields[offset] - BASE
        name = image[start:image.index(0, start)].decode("ascii")
        pins.append((name, fields[offset+4]))
    return pins


def relocations(insn):
    if insn.id == 0:
        return []
    fields = []
    if insn.imm_size and insn.mnemonic.startswith(("j", "call")):
        fields.append((insn.imm_offset, insn.imm_size))
    if insn.imm_size == 4 and 0x401000 <= int.from_bytes(insn.bytes[insn.imm_offset:insn.imm_offset+4], "little") < 0x600000:
        fields.append((insn.imm_offset, 4))
    if insn.disp_size == 4 and 0x401000 <= insn.disp < 0x600000:
        fields.append((insn.disp_offset, 4))
    return fields


def masked(insn, wildcard=b"?"):
    buf = bytearray(insn.bytes)
    for offset, size in relocations(insn):
        buf[offset:offset+size] = wildcard*size
    return bytes(buf)


def pattern(insns):
    return b"".join(pattern_for_instruction(i) for i in insns)


def pattern_for_instruction(insn):
    ignored = set()
    for offset, size in relocations(insn):
        ignored.update(range(offset, offset+size))
    return b"".join(b"." if index in ignored else re.escape(bytes((v,)))
                    for index, v in enumerate(insn.bytes))


regions = [
    ("serial frame TX", 0x43cea0, 0x43d010),
    ("serial frame RX", 0x43d010, 0x43d280),
    ("status decode", 0x43dfc0, 0x43e7b0),
    ("preserve IRC", 0x43e7b0, 0x43e900),
    ("preset IRC match", 0x43e900, 0x43ed90),
    ("preset IRC output", 0x43ed90, 0x43ef10),
    ("serial IRC dynamic", 0x440ab0, 0x4411a0),
    ("serial IRC dispatch", 0x4411c0, 0x441390),
    ("UID transform", 0x442400, 0x442660),
    ("F8D1 status messages", 0x447040, 0x447600),
    ("config serialize", 0x44b530, 0x44ba70),
    ("HID frame RX", 0x44bab0, 0x44bb90),
    ("HID frame TX", 0x44bb90, 0x44bce0),
    ("native HID download", 0x44c580, 0x44d530),
    ("alternate USB download", 0x44d570, 0x44e310),
    ("serial download", 0x44e310, 0x44f868),
    ("user file encode", 0x45bf10, 0x45bfe0),
    ("user file inverse", 0x45bfe0, 0x45c080),
    ("SWD mode UI", 0x47e590, 0x47e5e0),
    ("send reset action", 0x4a81c0, 0x4a81e0),
    ("reset command builder", 0x4a85c0, 0x4a87b0),
    ("publish executable", 0x4b9300, 0x4b9600),
    ("download dispatch setup", 0x4bf540, 0x4c1b4c),
    ("shell encode", 0x4e6d90, 0x4e6e40),
    ("shell inverse", 0x4e6e40, 0x4e6ed0),
]


def compare():
    for name, start, end in regions:
        src = code(a, start, end)
        lengths = (min(24, len(src)), min(14, len(src)), min(7, len(src)))
        for count in lengths:
            candidates = [BASE+0x1000+m.start() for m in re.finditer(pattern(src[:count]), c[0x1000:0x1028d5], re.S)]
            if len(candidates) == 1:
                break
        if len(candidates) != 1:
            print(f"{name:<24} {start:08X} ambiguous {candidates[:3]}")
            continue
        match, = candidates
        size = end-start
        literal = a[start-BASE:end-BASE] == c[match-BASE:match-BASE+size]
        dst = code(c, match, match+size)
        changes = [(tag, n, m, o, p) for tag,n,m,o,p in
                   difflib.SequenceMatcher(None, [masked(i) for i in src], [masked(i) for i in dst], autojunk=False).get_opcodes() if tag != "equal"]
        print(f"{name:<24} {start:08X} {match:08X} {size:5d} {'byte identical' if literal else f'{len(changes)} structural diffs'}")
        for tag, n, m, o, p in changes[:7]:
            left = "; ".join(f"{i.address:x}:{i.mnemonic} {i.op_str}" for i in src[n:min(n+3,m)])
            right = "; ".join(f"{i.address:x}:{i.mnemonic} {i.op_str}" for i in dst[o:min(o+3,p)])
            print(f"  {tag} {m-n}/{p-o} {left} -> {right}")


if __name__ == "__main__":
    compare()
    pins = rs485_pins(a)
    assert pins == rs485_pins(c)
    print(f"RS485 pin table identical across A/C ({len(pins)} entries).")
    for pin, value in pins:
        print(f"  {pin} {value:02X}")
