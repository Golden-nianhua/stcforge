import argparse
import struct

from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("version", choices=("A", "C"), nargs="?", default="A")
version = parser.parse_args().version
b = Path(f"D:/Code/MCU/AiCube-ISP/AiCube-ISP-v6.97{version}.exe").read_bytes()


def unpack(fmt, p):
    return struct.unpack_from("<" + fmt, b, p)


def number(p, wide=False):
    return unpack("I" if wide else "H", p)[0]


def string(p):
    h = number(p)
    if h == 0xffff:
        return f"#{number(p+2)}", p+4
    q = p
    while number(q):
        q += 2
    return b[p:q].decode("utf-16le"), q+2


def align(p):
    return (p+3) & ~3


def read_dialog(p):
    ext = unpack("HH", p) == (1, 0xffff)
    if ext:
        style, count = unpack("IH", p+12)
        p += 26
    else:
        style = number(p, True)
        count = number(p+8)
        p += 18
    _, p = string(p)
    _, p = string(p)
    title, p = string(p)
    if style & 0x40:
        _, p = string(p+(6 if ext else 2))
    items = []
    for _ in range(count):
        p = align(p)
        ctl = number(p+(20 if ext else 16), ext)
        cls, p = string(p+(24 if ext else 18))
        label, p = string(p)
        size = number(p)
        p += 2+size
        items.append((ctl, cls, label))
    return title, items


pe = number(60, True)
sections = [
    unpack("8sIIII", pe+24+number(pe+20)+40*i)
    for i in range(number(pe+6))
]


def file_offset(rva):
    for _, virtual_size, va, disk_size, disk in sections:
        if va <= rva < va + min(virtual_size, disk_size):
            return disk + rva - va
    raise ValueError(f"No mapped file bytes at 0x{rva:x}")


root = file_offset(number(pe+136, True))


def directory(rva):
    named, ids = unpack("HH", root+rva+12)
    return [unpack("II", root+rva+16+8*i) for i in range(named+ids)]


for kind, rel in directory(0):
    if kind != 5:
        continue
    for dlgid, dr in directory(rel & 0x7fffffff):
        for lang, lr in directory(dr & 0x7fffffff):
            va, size = unpack("II", root+lr)
            title, items = read_dialog(file_offset(va))
            print(f"Dialog {dlgid:04X} {lang:04X} {title}")
            for ident, cls, label in items:
                print(f"  {ident:04X} {cls:<13} {label}")

for kind, rel in directory(0):
    if kind != 240:
        continue
    for dlgid, dr in directory(rel & 0x7fffffff):
        if dlgid not in (0xBE, 0xD5):
            continue
        for lang, lr in directory(dr & 0x7fffffff):
            va, size = unpack("II", root+lr)
            start = file_offset(va)
            p = start
            print(f"Dialog init {dlgid:04X} {lang:04X}")
            while number(p):
                control, message, length = unpack("HHI", p)
                p += 8
                assert p + length <= start + size
                if control in (0x418, 0x419, 0x41B, 0x41D, 0x453, 0x454):
                    label = b[p:p+length].rstrip(b"\0").decode("gbk")
                    print(f"  {control:04X} {message:04X} {label}")
                p += length

print("Message table")
messages = {"A": 0x127230, "C": 0x128410}
for p in range(messages[version], 0x14a000, 20):
    ident, en, cn, _, _ = unpack("IIIII", p)
    if ident == 0xffffffff:
        break
    def read(va):
        if not 0x400000 <= va < 0x400000+len(b):
            return ""
        p = va-0x400000
        return b[p:b.index(0,p)].decode("gbk","replace").strip().replace("\r","").replace("\n"," | ")
    print(f"{ident:04X} {read(en)} / {read(cn)}")
