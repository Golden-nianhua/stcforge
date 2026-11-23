import random
import runpy
import struct
from hashlib import sha256
from pathlib import Path

from unicorn import UC_ARCH_X86, UC_MODE_32, Uc
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EIP, UC_X86_REG_ESP


BASE = 0x400000
OBJ = 0x200000
OPT = 0x210000
SRC = 0x220000
OUT = 0x240000
STACK = 0x260000
END = 0x260f00
FOLDER = Path("D:/Code/MCU/AiCube-ISP")
HASHES = {
    "A": "6194b42b9f7812e745ab19e6f5a25b474f740f84c7ac9e7cfa940cbbbfe1cbcc",
    "C": "d857b147f2f4e527c5566a2dd40e63f875c94f4e344fa5ce800ab13a770db420",
}


def emulator(version):
    image = (FOLDER / f"AiCube-ISP-v6.97{version}.exe").read_bytes()
    assert sha256(image).hexdigest() == HASHES[version]
    machine = Uc(UC_ARCH_X86, UC_MODE_32)
    machine.mem_map(BASE, 0x198000)
    machine.mem_write(BASE, image[:0x198000])
    machine.mem_map(OBJ, 0x71000)
    return machine


def write32(machine, addr, value):
    machine.mem_write(addr, struct.pack("<I", value))


def call(machine, fn, *args, this=OBJ, stop=END, count=100000):
    machine.reg_write(UC_X86_REG_ECX, this)
    machine.reg_write(UC_X86_REG_ESP, STACK+0x800)
    machine.mem_write(STACK+0x800, struct.pack(f"<{len(args)+1}I", END, *args))
    machine.emu_start(fn, stop, count=count)
    assert machine.reg_read(UC_X86_REG_EIP) == stop, hex(machine.reg_read(UC_X86_REG_EIP))
    return machine.reg_read(UC_X86_REG_EAX)


def encode(plain, table, inverse):
    state = 0x4c
    out = bytearray()
    for index, value in enumerate(plain):
        mixed = (table[value] - inverse[(state+1) & 255]) & 255
        out.append(table[mixed ^ inverse[state]])
        state = ((value ^ state) + index) & 255
    return bytes(out)


def test_crypto(machine, key, data, address_delta):
    inverse = bytes(key.index(n) for n in range(256))
    for offset, address in ((0x278, OPT), (0x28c, OPT+256), (0x2b0, 1)):
        write32(machine, OBJ+offset, address)
    machine.mem_write(OPT, key+inverse)
    machine.mem_write(SRC, data)
    assert call(machine, 0x45bf10+address_delta, SRC, OUT, len(data)) == 1
    ciphertext = bytes(machine.mem_read(OUT, len(data)))
    assert ciphertext == encode(data, key, inverse)
    assert call(machine, 0x45bfe0+address_delta, OUT, OUT+0x1000, len(data)) == 1
    assert machine.mem_read(OUT+0x1000, len(data)) == data


def test_project_records(machine):
    inspector = runpy.run_path(str(Path(__file__).with_name("inspect-project.py")))
    decode = inspector["decode_resource"]
    records = inspector["iter_records"]
    inverse = machine.mem_read(0x5374C8, 256)
    plain = bytearray(b"STC\0")
    expected = []
    for kind, data, flags in ((0x10, b"\xd1\xf8\0\0", 0), (0x11, bytes(16), 0),
                              (0x23, bytes(range(256)), 1), (0, b"", 0)):
        machine.mem_write(SRC, struct.pack("<4BI", 0x70, kind, 0, flags, len(data)) + data)
        call(machine, 0x4B6C30, this=SRC)
        expected.append((len(plain), kind, flags, data))
        plain.extend(machine.mem_read(SRC, 8 + len(data)))
    plain.extend(bytes(-len(plain) % 4))
    machine.mem_write(SRC, bytes(plain))
    for step in (1, 2):
        call(machine, 0x4E7F10, SRC, OUT, len(plain), step)
        encrypted = bytes(machine.mem_read(OUT, len(plain)))
        call(machine, 0x4E7FC0, OUT, OUT + 0x1000, len(plain), step)
        assert bytes(machine.mem_read(OUT + 0x1000, len(plain))) == decode(encrypted, inverse, step) == plain
        assert list(records(decode(encrypted, inverse, step))) == expected
        if step == 1:
            wrapped = inspector["release_resource"](synthetic_release(encrypted))
            assert wrapped == encrypted
    broken = bytearray(plain)
    broken[6] ^= 1
    try:
        list(records(broken))
    except ValueError as error:
        assert "checksum" in str(error)
    else:
        raise AssertionError("malformed project checksum accepted")
    print("Project records, checksums and wrapped payloads matched 6.97C x86 routines.")


def synthetic_release(payload):
    # A minimal resource-only PE layout for checking file offsets and language selection.
    root, rva, resource_header = 0x200, 0x3000, 88
    image = bytearray(root + resource_header)
    resource_size = resource_header + len(payload)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HH", image, 0x84, 0x14C, 1)
    struct.pack_into("<H", image, 0x94, 0xE0)
    struct.pack_into("<H", image, 0x98, 0x10B)
    struct.pack_into("<II", image, 0x98 + 112, rva, resource_size)
    struct.pack_into("<IIII", image, 0x178 + 8, resource_size, rva, resource_size, root)
    for start, key, target in ((0, 10, 0x80000018), (24, 1, 0x80000030), (48, 0x0804, 72)):
        struct.pack_into("<HII", image, root + start + 14, 1, key, target)
    struct.pack_into("<II", image, root + 72, rva + resource_header, len(payload))
    return bytes(image) + payload


def test_offline_header():
    machine = emulator("C")
    image = 0x300000
    program = bytes(range(256)) + b"\x01\x02\x03\x04"
    machine.mem_map(image, 0x30000)
    machine.mem_write(SRC, program)
    machine.mem_write(OPT, b"\xff" * 15 + b"\xfd\xff\xff\xff")
    machine.mem_write(STACK, b"\x31\xc0\xc3")  # GetTickCount and fixture's zero conversion
    write32(machine, 0x503108, STACK)
    write32(machine, 0x503A60, STACK)
    for offset, value in ((0xFC, len(program)), (0x120, 1), (0x6CC, image),
                          (0x6D4, SRC), (0x6E0, OPT), (0x118, 24_000_000)):
        write32(machine, OBJ + offset, value)
    call(machine, 0x449800, stop=0x44A346, count=250000)
    header = bytes(machine.mem_read(image, 0x800))
    assert header[:2] == b"\x5a\xa5"
    fields = struct.unpack_from(">HHIHHH", header, 2)
    assert fields == (
        sum(header[4:0x400]) & 0xFFFF, sum(program) & 0xFFFF, len(program),
        0x0000, 0xF8D1, 0x78D1,
    ), (fields, header[:32].hex(" "), sum(header[4:0x400]), sum(program))
    assert struct.unpack_from(">I", header, 0x18) == (24_000_000,)
    assert machine.mem_read(image + 0x800, len(program) + 124) == program + b"\xff" * 124
    assert struct.unpack("<I", machine.mem_read(OBJ + 0x100, 4)) == (0x980,)
    print("F8D1 offline header, program placement and checksums verified to 6.97C pre-send boundary.")


def option_packet(machine, delta, options, mode, password):
    # The first record after the sentinel is the F8D1 model.
    write32(machine, OBJ+0x120, 1)
    write32(machine, OBJ+0x67c+delta, OPT)
    write32(machine, OBJ+0xdc, mode)
    write32(machine, OBJ+0x11c, 24000000)
    machine.mem_write(OBJ+0x6b6+delta, bytes.fromhex("26 10 01"))
    machine.mem_write(OBJ+0xf10+delta, bytes((bool(password),)))
    write32(machine, OBJ+0xf18+delta, password)
    machine.mem_write(OPT, bytes(options))
    fn = 0x44b760 if delta else 0x44b530
    assert call(machine, fn, OUT) == 41
    return b"\x04\0\0\x5a\xa5" + bytes(machine.mem_read(OUT, 41))


def test_ice_selectors(machine, delta):
    for selector in range(4):
        settings = bytearray(19)
        settings[4] = selector << 6
        settings[5] = selector << 6
        ordinary = option_packet(machine, delta, settings, 0, 0)
        swd = option_packet(machine, delta, settings, 8, 0)
        usb = option_packet(machine, delta, settings, 6, 0)
        assert ordinary[39:41] == bytes(((selector << 6) | 0x20, selector << 6))
        assert swd[39:41] == bytes((selector << 6, selector << 6))
        assert usb[39:41] == ordinary[39:41]
        assert usb[43] == ordinary[43] & 0x7F


def test_options(a, c):
    def packet(options, mode=0, password=0):
        first = option_packet(a, 0, options, mode, password)
        second = option_packet(c, 0x64, options, mode, password)
        assert first == second
        return first

    expected = packet(bytes(19))
    for mode in (6, 8, 0):
        result = packet(bytes(19), mode)
        print("mode", mode, "changes", [(i, f"{a:02X}->{b:02X}")
                                         for i, (a, b) in enumerate(zip(expected, result)) if a != b])
    for option in range(19):
        for bit in range(8):
            options = bytearray(19)
            options[option] = 1 << bit
            actual = packet(bytes(options))
            changes = [(i, f"{a ^ b:02X}") for i, (a, b) in enumerate(zip(expected, actual)) if a != b]
            if changes:
                print(f"option[{option:02d}] bit {bit} -> {changes}")
    rng = random.Random(697)
    for _ in range(256):
        packet(rng.randbytes(19), mode=rng.choice((0, 6, 8)), password=rng.choice((0, 5, 63)))
    print("A/C option packets matched for 412 model-1 inputs.")


if __name__ == "__main__":
    machine_a, machine_c = emulator("A"), emulator("C")
    test_options(machine_a, machine_c)
    test_ice_selectors(machine_a, 0)
    test_ice_selectors(machine_c, 0x64)
    print("All four ICE selector values passed original A/C serializers in modes 0, 6, and 8.")
    rng = random.Random(618)
    for size in (1, 16, 256, 512, 1024):
        key, data = bytes(rng.sample(range(256), 256)), rng.randbytes(size)
        test_crypto(machine_a, key, data, 0)
        test_crypto(machine_c, key, data, 0x280)
    print("A/C encode output and decode round trip matched x86 for 5 synthetic vector sizes.")
    test_project_records(machine_c)
    test_offline_header()
