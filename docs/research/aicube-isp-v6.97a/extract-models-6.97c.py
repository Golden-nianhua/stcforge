"""Extract the model catalogue and option-family dispatch table from AiCube-ISP 6.97C.

The executable stores one 32-byte model record for each selectable device.  The
record starts with the model flags and display-name pointer.  The device code,
capacity fields and model magic follow at offsets 8 through 28.  The flags select
one entry in the option-family dispatch table at 0x48C06C.  Each dispatch routine
returns the option descriptor count and the descriptor-table address.

This is deliberately a static extractor.  It does not execute the vendor
program or contact hardware.
"""

from __future__ import annotations

import argparse
import json
import re
import struct
from collections import defaultdict
from hashlib import sha256
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32


IMAGE = Path("D:/Code/MCU/AiCube-ISP/AiCube-ISP-v6.97C.exe")
EXPECTED_SHA256 = "d857b147f2f4e527c5566a2dd40e63f875c94f4e344fa5ce800ab13a770db420"
BASE = 0x400000
MODEL_TABLE = 0x505468
MODEL_RECORD_SIZE = 32
FAMILY_TABLE = 0x48C06C
DISPATCH_POINTER_TABLE = 0x48BFF8
CONTROL_LAYOUT_TABLE = 0x560860
MESSAGE_TABLE = 0x528410
FAMILY_ROUTE_TABLE = 0x4C31A8
FAMILY_ROUTE_TARGETS = 0x4C3188
RESOURCE_ROUTE_VARIANTS = {
    0: {"condition": "esp+0x13 != 0", "true": "res12.bin", "false": "res66.bin"},
    1: {"condition": "esp+0x13 != 0", "true": "res13.bin", "false": "res67.bin"},
    2: {"condition": "esp+0x13 != 0", "true": "res14.bin", "false": "res68.bin"},
    3: {
        "condition": "(flags & 0x1C0)",
        "0x080": {"condition": "esp+0x13 != 0", "true": "res15.bin", "false": "res69.bin"},
        "0x100": {"condition": "esp+0x13 != 0", "true": "res26.bin", "false": "res71.bin"},
        "other": {"condition": "esp+0x13 != 0", "true": "res16.bin", "false": "res70.bin"},
    },
    4: {"condition": "esp+0x13 != 0", "true": "res55.bin", "false": "res72.bin"},
    5: {"condition": "esp+0x13 != 0", "true": "res63.bin", "false": "res74.bin"},
    6: {"condition": "esp+0x13 != 0", "true": "res63.bin", "false": "res74.bin"},
    7: {"condition": "esp+0x13 != 0", "true": "res57.bin", "false": "res73.bin"},
}


def u32(image: bytes, address: int) -> int:
    return struct.unpack_from("<I", image, address - BASE)[0]


def read_c_string(image: bytes, address: int) -> str | None:
    offset = address - BASE
    if offset < 0 or offset >= len(image):
        return None
    end = image.find(b"\0", offset)
    if end < 0 or end - offset > 256:
        return None
    raw = image[offset:end]
    if not raw:
        return ""
    for encoding in ("gbk", "utf-8", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("gbk", errors="replace")


def read_label(image: bytes, address: int) -> str:
    value = read_c_string(image, address)
    if value is not None:
        return value.replace("\r", " ").replace("\n", " ").strip()
    offset = address - BASE
    if 0 <= offset + 2 < len(image):
        end = image.find(b"\0\0", offset)
        if end >= 0:
            return image[offset:end].decode("utf-16le", errors="replace").strip()
    return f"<invalid 0x{address:08X}>"


def messages(image: bytes) -> dict[int, int]:
    """Read the numeric message-id to string-pointer table used by controls."""

    result: dict[int, int] = {}
    offset = MESSAGE_TABLE - BASE
    while offset + 12 <= len(image):
        message_id, _, string_pointer = struct.unpack_from("<III", image, offset)
        if message_id == 0xFFFFFFFF:
            break
        if message_id == 0 and string_pointer == 0:
            break
        result[message_id] = string_pointer
        offset += 20
    return result


def parse_model_records(image: bytes) -> list[dict]:
    records = []
    for index in range(1, 10000):
        address = MODEL_TABLE + index * MODEL_RECORD_SIZE
        offset = address - BASE
        if offset + MODEL_RECORD_SIZE > len(image):
            break
        flags, name_pointer, magic, code_size, field16, field20, total_size, field28 = struct.unpack_from(
            "<8I", image, offset
        )
        name = read_c_string(image, name_pointer)
        if not flags and not name_pointer and not magic and not code_size:
            break
        if name is None:
            raise ValueError(f"model table ended unexpectedly at 0x{address:08X}")
        family = (flags >> 15) & 0xFF
        slot = image[FAMILY_TABLE - BASE + family - 1] if 1 <= family <= 0xFF else None
        dispatch = None
        if slot is not None:
            dispatch = u32(image, DISPATCH_POINTER_TABLE + slot * 4)
        records.append(
            {
                "index": index,
                "address": address,
                "name": name,
                "flags": flags,
                "family": family,
                "dispatch_slot": slot,
                "dispatch_function": dispatch,
                "magic": magic & 0xFFFF,
                "alternate_magic": magic >> 16,
                "code_size": code_size,
                "field16": field16,
                "field20": field20,
                "total_size": total_size,
                "field28": field28,
                "name_pointer": name_pointer,
            }
        )
    return records


def parse_dispatch(image: bytes, address: int) -> dict:
    """Decode the short x86 routine that returns one option table."""

    engine = Cs(CS_ARCH_X86, CS_MODE_32)
    instructions = list(engine.disasm(image[address - BASE : address - BASE + 32], address))
    table = None
    count = None
    for instruction in instructions:
        if instruction.mnemonic == "ret":
            break
        operands = instruction.op_str
        immediate = re.search(r",\s*(0x[0-9a-f]+|[0-9]+)$", operands)
        if not immediate:
            continue
        token = immediate.group(1)
        value = int(token, 16 if token.lower().startswith("0x") else 10)
        if instruction.mnemonic == "mov" and "dword ptr [" in operands and value >= 0x500000:
            table = value
        elif instruction.mnemonic == "mov" and operands.startswith("eax, "):
            count = value
    return {
        "function": address,
        "option_count": count,
        "option_table": table,
        "instructions": [
            {"address": i.address, "mnemonic": i.mnemonic, "operands": i.op_str}
            for i in instructions
            if i.address < address + 24
        ],
    }


def parse_options(image: bytes, table: int, count: int, message_map: dict[int, int]) -> list[dict]:
    entries = []
    for index in range(count):
        address = table + index * 8
        key, raw_offset, mask, default, flags = struct.unpack_from("<IBBBB", image, address - BASE)
        control_key = key & 0xFFFF
        layout = CONTROL_LAYOUT_TABLE + control_key * 16
        control = u32(image, layout)
        message_id = u32(image, layout + 16)
        label_pointer = message_map.get(message_id)
        label = read_label(image, label_pointer) if label_pointer else f"message 0x{message_id:08X}"
        entries.append(
            {
                "index": index,
                "address": address,
                "key": key,
                "control_key": control_key,
                "control": control,
                "message_id": message_id,
                "label": label,
                "raw_offset": raw_offset,
                "mask": mask,
                "default": default,
                "flags": flags,
            }
        )
    return entries


def family_asset_route(image: bytes, family: int) -> dict:
    """Decode the model-family resource route used by the download task.

    This route selects resource-file names used by the task's model-specific
    preparation branch.  It is recorded separately from the USB/UART transport
    selection because the latter is selected by the connection mode.
    """

    family_index = family - 1
    if family_index < 0 or family_index > 0x58:
        route = 7
    else:
        route = image[FAMILY_ROUTE_TABLE - BASE + family_index]
    target = u32(image, FAMILY_ROUTE_TARGETS + route * 4)
    return {"route": route, "target": target, "resources": RESOURCE_ROUTE_VARIANTS[route]}


def config_layout(flags_values: list[int]) -> dict:
    """Classify the statically visible output layout branches in 0x44B760."""

    masked_values = sorted({flags & 0x7F8000 for flags in flags_values})
    legacy_40_values = {
        0x168000,
        0x170000,
        0x178000,
        0x180000,
        0x188000,
        0x190000,
        0x198000,
        0x1A0000,
    }
    if any(value < 0x1A8000 or value in legacy_40_values for value in masked_values):
        layout = "legacy-0x40"
        length = 0x40
    elif any(value in {0x2C0000, 0x2C8000} for value in masked_values):
        layout = "extended-0x29"
        length = 0x29
    else:
        layout = "extended-0x28"
        length = 0x28
    return {
        "masked_flags": masked_values,
        "layout": layout,
        "return_length": length,
        "has_byte_27_source": any(flags & 8 for flags in flags_values),
        "uses_1e8000_old_bsl_xor": 0x1E8000 in masked_values,
        "uses_260000_byte_27_transform": 0x260000 in masked_values,
        "uses_2c8000_byte_27_transform": 0x2C8000 in masked_values,
    }


def status_layout(flags_values: list[int]) -> dict:
    """Classify the status parser's statically visible block-size branch."""

    fixed_40_values = {0x0C8000, 0x0D8000, 0x108000, 0x0E0000, 0x100000}
    results = []
    for flags in flags_values:
        masked = flags & 0x7F8000
        status_selector = (flags >> 6) & 7
        if masked in fixed_40_values or status_selector not in {0, 1}:
            block_size = 0x40
        else:
            block_size = 0x80
        results.append(
            {
                "flags": flags,
                "masked_flags": masked,
                "selector": status_selector,
                "status_block_size": block_size,
            }
        )
    return {
        "variants": results,
        "status_block_sizes": sorted({item["status_block_size"] for item in results}),
    }


def irc_table_layout(flags_values: list[int]) -> dict:
    """Resolve the USB IRC frequency table selected by 0x43EB30."""

    tables = []
    for flags in flags_values:
        masked = flags & 0x7F8000
        if (flags & 0x3000) == 0x1000 or (flags & 0x4000):
            if masked == 0x2C8000:
                table = 0x51AD08
            elif masked == 0x2A0000:
                table = 0x51ACB8
            else:
                table = 0x51AC68
        elif masked < 0x168000:
            table = 0x51AC68
        elif masked < 0x1A8000:
            table = 0x51ABF0
        else:
            table = 0x51AC18
        tables.append({"flags": flags, "masked_flags": masked, "table": table})
    return {"variants": tables, "tables": sorted({item["table"] for item in tables})}


def extract(image: bytes) -> tuple[list[dict], list[dict]]:
    records = parse_model_records(image)
    grouped: dict[int, list[dict]] = defaultdict(list)
    for record in records:
        grouped[record["family"]].append(record)

    message_map = messages(image)
    families = []
    for family, family_records in sorted(grouped.items()):
        first = family_records[0]
        dispatch = parse_dispatch(image, first["dispatch_function"])
        options = []
        if dispatch["option_table"] is not None and dispatch["option_count"] is not None:
            options = parse_options(
                image,
                dispatch["option_table"],
                dispatch["option_count"],
                message_map,
            )
        family_flags = sorted({record["flags"] for record in family_records})
        families.append(
            {
                "family": family,
                "flags": family_flags,
                "model_count": len(family_records),
                "first_model": family_records[0]["name"],
                "dispatch_slot": first["dispatch_slot"],
                "dispatch_function": first["dispatch_function"],
                "dispatch": dispatch,
                "asset_route": family_asset_route(image, family),
                "config_layout": config_layout(family_flags),
                "status_layout": status_layout(family_flags),
                "irc_table": irc_table_layout(family_flags),
                "options": options,
            }
        )
    return records, families


def markdown(records: list[dict], families: list[dict], digest: str) -> str:
    lines = [
        "# AiCube-ISP 6.97C 型号与配置族逆向清单",
        "",
        f"样本：`AiCube-ISP-v6.97C.exe`，SHA-256 `{digest}`。型号表起点为 `0x{MODEL_TABLE:08X}`，每条记录 32 字节，索引 0 是保留槽。",
        "",
        f"共提取 **{len(records)}** 条型号记录，归并为 **{len(families)}** 个型号族。型号族由记录标志的 `(flags >> 15) & 0xFF` 选择，随后通过 `0x{FAMILY_TABLE:08X}` 和 `0x{DISPATCH_POINTER_TABLE:08X}` 找到配置描述表。",
        "",
        "## 字段说明",
        "",
        "| 字段 | 含义 |",
        "| --- | --- |",
        "| `address` | 型号记录地址 |",
        "| `name` | 型号显示名称 |",
        "| `magic` | 下载协议使用的型号识别码 |",
        "| `code_size` | 记录中的程序区容量字段 |",
        "| `total_size` | 记录中的总容量字段 |",
        "| `flags` | 界面、协议和配置族选择标志 |",
        "| `family` | 由 `flags` 派生的配置族编号 |",
        "",
        "## 配置族总表",
        "",
        "| 族 | 型号数 | 首个型号 | flags | 状态块 | IRC 表 | 配置分发 | 载荷布局 | 描述数 | 描述表 | 资源分支 |",
        "| ---: | ---: | --- | --- | ---: | --- | --- | --- | ---: | --- | --- |",
    ]
    for family in families:
        flags = ", ".join(f"`0x{x:08X}`" for x in family["flags"])
        dispatch = family["dispatch"]
        option_count = dispatch["option_count"] if dispatch["option_count"] is not None else "—"
        option_table = (
            f"`0x{dispatch['option_table']:08X}`"
            if dispatch["option_table"] is not None
            else "—"
        )
        asset_route = family["asset_route"]
        config = family["config_layout"]
        status_sizes = ", ".join(f"0x{size:X}" for size in family["status_layout"]["status_block_sizes"])
        irc_tables = ", ".join(f"0x{table:08X}" for table in family["irc_table"]["tables"])
        lines.append(
            f"| `0x{family['family']:02X}` | {family['model_count']} | {family['first_model']} | {flags} | "
            f"{status_sizes} | {irc_tables} | `0x{family['dispatch_function']:08X}` | `{config['layout']}` ({config['return_length']:#x}) | "
            f"{option_count} | {option_table} | "
            f"route {asset_route['route']} (`0x{asset_route['target']:08X}`) |"
        )

    lines.extend(["", "## 各配置族的界面描述", ""])
    for family in families:
        dispatch = family["dispatch"]
        lines.extend(
            [
                f"### 族 `0x{family['family']:02X}`，{family['first_model']} 等 {family['model_count']} 个型号",
                "",
                f"分发表入口 `0x{family['dispatch_function']:08X}`，返回 {dispatch['option_count'] or '未知'} 项，描述表 `0x{dispatch['option_table']:08X}`。",
                "",
                "| 序号 | 控件 | 文本 | 原始偏移 | 掩码 | 默认 | 标志 |",
                "| ---: | ---: | --- | ---: | ---: | ---: | ---: |",
            ]
        )
        for option in family["options"]:
            raw = "—" if option["raw_offset"] == 0xFF else str(option["raw_offset"])
            lines.append(
                f"| {option['index']} | `0x{option['control']:04X}` | {option['label']} | {raw} | "
                f"`0x{option['mask']:02X}` | {option['default']} | `0x{option['flags']:02X}` |"
            )
        lines.append("")

    lines.extend(["## 全部型号", "", "| 序号 | 名称 | magic | 程序字段 | 总容量字段 | flags | 族 | 记录地址 |", "| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |"])
    for record in records:
        lines.append(
            f"| {record['index']} | {record['name']} | `0x{record['magic']:04X}` | `0x{record['code_size']:06X}` | "
            f"`0x{record['total_size']:06X}` | `0x{record['flags']:08X}` | `0x{record['family']:02X}` | `0x{record['address']:08X}` |"
        )
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", type=Path, default=IMAGE)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--markdown", type=Path)
    args = parser.parse_args()

    image = args.image.read_bytes()
    digest = sha256(image).hexdigest()
    if digest != EXPECTED_SHA256:
        raise SystemExit(f"Unexpected AiCube-ISP 6.97C binary: {digest}")
    records, families = extract(image)
    result = {
        "image": str(args.image),
        "sha256": digest,
        "base": BASE,
        "model_table": MODEL_TABLE,
        "record_size": MODEL_RECORD_SIZE,
        "model_count": len(records),
        "family_count": len(families),
        "families": families,
        "models": records,
    }
    if args.json:
        args.json.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.markdown:
        args.markdown.write_text(markdown(records, families, digest), encoding="utf-8")
    print(json.dumps({"model_count": len(records), "family_count": len(families)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
