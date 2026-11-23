"""Create a reproducible manifest for resources extracted from AiCube-ISP 6.97C."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROUTES = {
    0: {"true": "res12.bin", "false": "res66.bin"},
    1: {"true": "res13.bin", "false": "res67.bin"},
    2: {"true": "res14.bin", "false": "res68.bin"},
    3: {"true": "res15.bin", "false": "res69.bin"},
    4: {"true": "res55.bin", "false": "res72.bin"},
    5: {"true": "res63.bin", "false": "res74.bin"},
    6: {"true": "res57.bin", "false": "res73.bin"},
    7: {"true": "res57.bin", "false": "res73.bin"},
}

RESOURCE_ROUTES = {
    "res12.bin": [0], "res66.bin": [0],
    "res13.bin": [1], "res67.bin": [1],
    "res14.bin": [2], "res68.bin": [2],
    "res15.bin": [3], "res69.bin": [3],
    "res26.bin": [3], "res71.bin": [3],
    "res16.bin": [3], "res70.bin": [3],
    "res55.bin": [4], "res72.bin": [4],
    "res63.bin": [5, 6], "res74.bin": [5, 6],
    "res57.bin": [6, 7], "res73.bin": [6, 7],
}


def manifest(directory: Path) -> list[dict]:
    rows = []
    for path in sorted(directory.glob("res*.bin"), key=lambda item: int(item.stem[3:])):
        data = path.read_bytes()
        rows.append(
            {
                "name": path.name,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "prefix": data[:16].hex(" "),
                "routes": RESOURCE_ROUTES.get(path.name, []),
            }
        )
    return rows


def markdown(rows: list[dict]) -> str:
    lines = [
        "# AiCube-ISP 6.97C 随附资源清单",
        "",
        "这些文件从 6.97C 的资源区解出。当前记录文件大小、SHA-256 和型号族资源分支引用。资源内容可能是压缩或加密的固件数据，清单不对其内部格式作假设。",
        "",
        "| 文件 | 字节数 | SHA-256 | 资源分支 | 前 16 字节 |",
        "| --- | ---: | --- | --- | --- |",
    ]
    for row in rows:
        routes = ", ".join(str(value) for value in row["routes"]) or "—"
        lines.append(
            f"| `{row['name']}` | {row['size']} | `{row['sha256']}` | {routes} | `{row['prefix']}` |"
        )
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--directory",
        type=Path,
        default=Path(__file__).resolve().parent / "resources",
    )
    parser.add_argument("--json", type=Path)
    parser.add_argument("--markdown", type=Path)
    args = parser.parse_args()

    rows = manifest(args.directory)
    if args.json:
        args.json.write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.markdown:
        args.markdown.write_text(markdown(rows), encoding="utf-8")
    print(json.dumps({"resource_count": len(rows)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
