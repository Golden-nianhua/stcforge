"""Print the 6.97C F8D1 hardware-page descriptors as a Markdown table."""

import struct
from hashlib import sha256
from pathlib import Path


IMAGE = Path("D:/Code/MCU/AiCube-ISP/AiCube-ISP-v6.97C.exe")
EXPECTED_HASH = "d857b147f2f4e527c5566a2dd40e63f875c94f4e344fa5ce800ab13a770db420"
BASE = 0x400000
WIRE_BYTES = {0: 41, 1: 42, 2: 43, 3: 44, 4: 39, 5: 40, 11: 45, 14: 37}


def number(image, address):
    return struct.unpack_from("<I", image, address - BASE)[0]


def string(image, address):
    start = address - BASE
    return image[start:image.index(0, start)].decode("gbk")


def messages(image):
    names = {}
    offset = 0x128410
    while (entry := number(image, BASE + offset)) != 0xFFFFFFFF:
        names[entry] = number(image, BASE + offset + 8)
        offset += 20
    return names


def dump(image):
    family = (number(image, 0x505488) >> 15) & 0xFF
    slot = image[0x48C06C + family - 1 - BASE]
    assert number(image, 0x48BFF8 + 4 * slot) == 0x48BFAF
    count = number(image, 0x48BFB4)
    table = number(image, 0x48BFBA)
    assert (count, table) == (27, 0x520118)
    names = messages(image)

    print("| 界面项 | 控件 | 原始字节 | 掩码 | 默认选择 | 读取标志 | `04` 偏移 |")
    print("|---|---|---:|---|---:|---|---:|")
    for position in range(count):
        key, offset, mask, default, flags = struct.unpack_from(
            "<IBBBB", image, table - BASE + 8 * position
        )
        layout = 0x560860 + 16 * (key & 0xFFFF)
        control = number(image, layout)
        label = string(image, names[number(image, layout + 16)]).strip().replace("\n", " ").replace("\r", "")
        if control == 0x423:
            label = "用户 EEPROM 容量"
        raw = "—" if offset == 0xFF else str(offset)
        print(f"| {label} | `{control:04X}` | {raw} | `{mask:02X}` | {default} | `{flags:02X}` | {WIRE_BYTES.get(offset, '—')} |")


if __name__ == "__main__":
    image = IMAGE.read_bytes()
    if sha256(image).hexdigest() != EXPECTED_HASH:
        raise SystemExit("Unexpected AiCube-ISP 6.97C binary")
    dump(image)
