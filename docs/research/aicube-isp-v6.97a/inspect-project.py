"""Inventory AiCube project records and published PE resources without loading the EXE."""

import argparse
import struct
from hashlib import sha256
from pathlib import Path
from zipfile import ZipFile, _ZipDecrypter
from io import BytesIO
from zlib import decompress


ISP_IMAGE = Path("D:/Code/MCU/AiCube-ISP/AiCube-ISP-v6.97C.exe")
ISP_HASH = "d857b147f2f4e527c5566a2dd40e63f875c94f4e344fa5ce800ab13a770db420"

RECORD_NAMES = {
    0x01: "项目版本与文件名",
    0x02: "保存时间",
    0x10: "MCU 型号",
    0x11: "硬件选项 16 字节",
    0x12: "IRC 目标频率",
    0x13: "主配置与程序区参数",
    0x14: "RS485 控制设置",
    0x15: "本次下载代码为加密代码",
    0x16: "串口和 USB 连接设置",
    0x17: "用户命令复位到 ISP",
    0x18: "用户界面通信参数",
    0x19: "提示音设置",
    0x1A: "程序区自动增量名称",
    0x1B: "数据区自动增量名称",
    0x1C: "离线编程器设置",
    0x1D: "离线 ISP 频率覆盖",
    0x1E: "自动增量起始值",
    0x1F: "自动增量步进值",
    0x20: "自动增量配置",
    0x21: "自动增量信号参数",
    0x22: "用户系统区或 EEPROM 参数",
    0x23: "程序区边界和增量参数",
    0x24: "程序文件名",
    0x25: "EEPROM 或第二文件名",
    0xF5: "Keil CDB 或调试资源",
    0xF6: "辅助资源",
    0xF7: "辅助资源",
    0xF8: "辅助资源",
    0xF9: "辅助资源",
    0xFA: "辅助资源",
    0xFB: "辅助资源",
    0xFC: "发布权限和安全设置",
    0xFD: "用户密钥",
    0xFE: "EEPROM 或第二代码数据",
    0xFF: "程序代码数据",
}


def record_checksum(record):
    return (-sum(record[:2]) - sum(record[3:])) & 0xFF


def iter_records(data):
    if not data.startswith(b"STC\0"):
        raise ValueError("missing STC project signature")
    offset = 4
    while len(data) - offset >= 8:
        marker, kind, checksum, flags, size = struct.unpack_from("<4BI", data, offset)
        end = offset + 8 + size
        if marker != 0x70 or end > len(data):
            raise ValueError(f"invalid project record at 0x{offset:X}")
        if checksum != record_checksum(data[offset:end]):
            raise ValueError(f"checksum mismatch at 0x{offset:X}")
        yield offset, kind, flags, data[offset + 8:end]
        if kind == 0 and size == 0:
            if len(data) - end > 3 or any(data[end:]):
                raise ValueError("unexpected bytes after the end record")
            return
        offset = end
    raise ValueError("missing project end record")


def release_resource(image, resource_id=1, language=0x0804):
    if not image.startswith(b"MZ"):
        raise ValueError("missing DOS header")
    pe, = struct.unpack_from("<I", image, 0x3C)
    if image[pe:pe + 4] != b"PE\0\0":
        raise ValueError("missing PE header")
    count, = struct.unpack_from("<H", image, pe + 6)
    optional_size, = struct.unpack_from("<H", image, pe + 20)
    optional = pe + 24
    magic, = struct.unpack_from("<H", image, optional)
    if magic != 0x10B or optional_size < 120:
        raise ValueError("expected a 32-bit PE resource directory")
    resource_rva, size = struct.unpack_from("<II", image, optional + 112)
    sections = [
        struct.unpack_from("<IIII", image, optional + optional_size + 40 * index + 8)
        for index in range(count)
    ]

    def file_offset(rva, length):
        for virtual_size, virtual, raw_size, raw in sections:
            delta = rva - virtual
            if 0 <= delta and delta + length <= min(virtual_size, raw_size):
                if raw + delta + length <= len(image):
                    return raw + delta
        raise ValueError(f"resource RVA 0x{rva:X} is outside mapped file data")

    root = file_offset(resource_rva, size)
    tree = memoryview(image)[root:root + size]

    def entry(directory, wanted):
        named, ids = struct.unpack_from("<HH", tree, directory + 12)
        for index in range(named + ids):
            key, target = struct.unpack_from("<II", tree, directory + 16 + 8 * index)
            if key == wanted:
                return target
        raise ValueError(f"PE resource entry 0x{wanted:X} not found")

    directory = 0
    for key in (10, resource_id):
        target = entry(directory, key)
        if target & 0x80000000 == 0:
            raise ValueError("expected a resource subdirectory")
        directory = target & 0x7FFFFFFF
    data_entry = entry(directory, language)
    rva, length = struct.unpack_from("<II", tree, data_entry)
    start = file_offset(rva, length)
    return image[start:start + length]


def decode_resource(data, inverse, step=1):
    state, counter = 0x4C, 0
    output = bytearray()
    for byte in data:
        mixed = (inverse[byte] ^ inverse[state]) + inverse[(state + 1) & 0xFF]
        plain = inverse[mixed & 0xFF]
        output.append(plain)
        state = ((plain ^ state) + counter) & 0xFF
        counter = (counter + step) & 0xFF
    return bytes(output)


def release_zip_key(stock):
    """Reproduce the key initialization in the 6.97C startup routine."""
    initial = struct.unpack_from("<4I", stock, 0x166068)
    additions = (0x310068, 0x230033, 0x330021, 0x390031)
    return struct.pack(
        "<4I",
        *((~value + addition) & 0xFFFFFFFF for value, addition in zip(initial, additions)),
    )


def release_archive(image, stock):
    """Return the decrypted members from the embedded release archive."""
    archive = release_resource(image, resource_id=184)
    result = {}
    with ZipFile(BytesIO(archive)) as package:
        key = release_zip_key(stock)
        for info in package.infolist():
            local = struct.unpack_from("<4s5H3I2H", archive, info.header_offset)
            payload_offset = info.header_offset + 30 + local[-2] + local[-1]
            encrypted = archive[payload_offset:payload_offset + info.compress_size]
            payload = _ZipDecrypter(key)(encrypted)[12:]
            if info.compress_type == 8:
                payload = decompress(payload, -15)
            if len(payload) != info.file_size:
                raise ValueError(f"resource size mismatch for {info.filename}")
            result[info.filename] = payload
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project", type=Path)
    parser.add_argument("--stock-exe", type=Path, default=ISP_IMAGE)
    parser.add_argument(
        "--extract-resources",
        type=Path,
        metavar="DIR",
        help="从发布 EXE 的内置资源中解出固件和辅助文件",
    )
    args = parser.parse_args()
    try:
        data = args.project.read_bytes()
        stock = args.stock_exe.read_bytes()
        if sha256(stock).hexdigest() != ISP_HASH:
            raise ValueError("unexpected 6.97C reference binary")
        if args.extract_resources:
            output = args.extract_resources
            output.mkdir(parents=True, exist_ok=True)
            for name, payload in release_archive(stock, stock).items():
                (output / name).write_bytes(payload)
            print(f"extracted {len(list(output.glob('res*.bin')))} resources to {output}")
            return
        if data.startswith(b"MZ"):
            data = decode_resource(release_resource(data), stock[0x1374C8:0x1375C8])
        for offset, kind, flags, payload in iter_records(data):
            name = RECORD_NAMES.get(kind, "未命名记录")
            print(f"{offset:08X}  type={kind:02X}  flags={flags:02X}  bytes={len(payload):6}  {name}")
    except (OSError, ValueError, struct.error) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
