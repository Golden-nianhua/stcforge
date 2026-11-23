import argparse
import re
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

BASE = 0x400000
TEXT_BASE = BASE + 0x1000


def word(offset):
    return struct.unpack_from("<I", BINARY, offset)[0]


def cstr(offset):
    return BINARY[offset:BINARY.index(0, offset)].decode("ascii", errors="replace")


def imports():
    pe = word(60)
    offset = word(pe + 0x80)
    while word(offset + 12):
        dll = cstr(word(offset + 12))
        lookup, thunks = word(offset), word(offset + 16)
        for rel in range(0, len(BINARY), 4):
            key = word(lookup + rel)
            if not key:
                break
            if key < 0x80000000:
                yield BASE + thunks + rel, f"{dll}!{cstr(key + 2)}"
        offset += 20


def positions(data, pattern):
    return [match.start() for match in re.finditer(re.escape(pattern), data)]


def refs(address):
    return [TEXT_BASE + x for x in positions(TEXT, address.to_bytes(4, "little"))]


def sites(values, maximum=25):
    return " ".join(f"{value:08x}" for value in values[:maximum])


def dump_code(start, end):
    engine = Cs(CS_ARCH_X86, CS_MODE_32)
    engine.skipdata = True
    names = dict(imports())
    for addr, _, op, args in engine.disasm_lite(BINARY[start - BASE:end - BASE], start):
        labels = [name for value, name in names.items() if f"0x{value:x}" in args] if "[" in args else []
        print(f"{addr:08x}  {op:<8} {args:<46} {' '.join(labels)}")


def scan():
    for addr, name in imports():
        if re.search(r"HID|WriteFile$|ReadFile$|Comm(State|Timeouts)|^SETUPAPI", name, re.I):
            print(f"{addr:08x} {name:38} {sites(refs(addr), 12)}")
    for term in (
        "STC32G144K246", "总是动态调节IRC频率", "内部预置", "动态调节", "正在调节",
        "调节内部", "不支持", "正在设置硬件选项", "正在擦除", "正在下载", "下载口令",
        "用户系统区", "USB-Writer", "正在检测", "自定义", "校准", "ISP工作频率",
    ):
        print(term)
        for enc in ("gbk", "utf-16le"):
            for loc in positions(BINARY, term.encode(enc))[:22]:
                if loc >= 0x197000:
                    continue
                print(f"  {enc:<8} {BASE+loc:08x}  {sites(refs(BASE + loc), 12)}")
    for hz in (5529600, 6000000, 11059200, 18432000, 24000000, 45158400, 49152000,
               50803200, 55296000, 60000000):
        print(f"{hz:>9}", sites([BASE + x for x in positions(BINARY[:0x197000], word_bytes(hz))], 30))


def word_bytes(value):
    return struct.pack("<I", value)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", choices=["A", "C"], default="A")
    parser.add_argument("command", choices=["scan", "dis", "refs", "calls", "hex"])
    parser.add_argument("addresses", type=lambda arg: int(arg, 16), nargs="*")
    args = parser.parse_args()
    BINARY = Path(f"D:/Code/MCU/AiCube-ISP/AiCube-ISP-v6.97{args.version}.exe").read_bytes()
    pe = word(60)
    optional_size = struct.unpack_from("<H", BINARY, pe+20)[0]
    text_size = word(pe+24+optional_size+8)
    TEXT = BINARY[0x1000:0x1000+text_size]
    if args.command == "scan":
        scan()
    elif args.command == "dis":
        dump_code(*args.addresses)
    elif args.command == "refs":
        for address in args.addresses:
            print(hex(address), sites(refs(address), 60))
    elif args.command == "calls":
        for address in args.addresses:
            locations = [
                TEXT_BASE + m.start() for m in re.finditer(b"\xe8", TEXT[:-4])
                if TEXT_BASE + m.start() + 5 + struct.unpack_from("<i", TEXT, m.start() + 1)[0] == address
            ]
            print(hex(address), sites(locations, 100))
    else:
        start, end = args.addresses
        for address in range(start, end, 16):
            line = BINARY[address - BASE:min(address + 16, end) - BASE]
            print(f"{address:08x} {line.hex(' '):47} {''.join(chr(c) if 32 <= c < 127 else '.' for c in line)}")
