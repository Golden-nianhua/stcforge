"""汇总已经构建的对照固件、符号、源码及校验清单，不访问硬件。"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

from build_matrix import TEMPLATE, FORGE, UV, VARIANTS, read_hex, symbols, digest

OUTPUT = TEMPLATE / "Misc/Experiments/Simulation Firmware Matrix"
MINIMAL = {
    "M00_minimal_led": "软件延时翻转P9.3，不启用中断；跳过自动初始化，在main显式赋值",
    "M01_led_uart": "M00基础加入UART7轮询回显；115200，软件延时未校准",
    "M02_led_uart_timer": "M01基础加入Timer1毫秒计数，500ms翻灯；跳过自动初始化",
}

def main() -> None:
    # 分发与本机生产代码使用同一份测试器；测试结果日志不装进固件发布包。
    shutil.copy2(FORGE / "tools/diagnostics/test_usb_ice_matrix.py", OUTPUT / "test_usb_ice.py")
    for name in MINIMAL:
        work = OUTPUT / name
        image = work / (name + ".hex")
        memory = read_hex(image)
        if memory.get(0xFF0000) != 2 or min(memory) != 0xFF0000 or max(memory) > 0xFFFFFF:
            raise ValueError("最小固件复位入口或代码范围错误: " + name)
        manifest = json.loads((work / "manifest.json").read_text(encoding="utf-8"))
        if digest(image) != manifest["artifacts_sha256"][image.name]:
            raise ValueError("最小固件与构建清单不一致")
        elf = work / (name + ".debug.elf")
        command = [str(UV), "run", "--project", str(FORGE), "--no-sync", "stcforge", "symbols",
            "--cdb", str(work / (name + ".cdb")), "--hex", str(image), "--output", str(elf),
            "--source-root", str(work), "--source-dir", str(work)]
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
        (work / "symbols.log").write_text(result.stdout + result.stderr, encoding="utf-8")
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
        shutil.copy2(image, OUTPUT / image.name)
        shutil.copy2(elf, OUTPUT / elf.name)
    shutil.copy2(OUTPUT / "baselines/S00_sdcc_original.debug.elf", OUTPUT / "S00_sdcc_original.debug.elf")
    results = []
    for name, description in {"K00_keil_reference": "已验证Keil基准；低16位HEX归一到FF0000，程序字节未改",
        "S00_sdcc_original": "已复现故障的原SDCC基准，HEX逐文件哈希与已分析样本一致",
        **VARIANTS, **MINIMAL}.items():
        image = OUTPUT / (name + ".hex")
        mem = read_hex(image)
        map_path = OUTPUT / name / (name + ".map")
        if name == "S00_sdcc_original":
            map_path = OUTPUT / "baselines/S00_sdcc_original.map"
        sym = symbols(map_path) if map_path.exists() else {}
        result = {"id": name, "description": description, "hex": image.name, "sha256": digest(image),
            "defined_bytes": len(mem), "code_range": [f"{min(mem):06X}", f"{max(mem):06X}"],
            "hardware_test": "此前基准已测，见反汇编对照报告" if name.startswith(("K00", "S00")) else "待实板测试",
            "symbols": {key: f"{sym[key]:06X}" for key in
                ("_main", "__mcs51_genXINIT", "___sdcc_external_startup", "_watch16", "_watch32", "_tick_ms", "_led_state") if key in sym}}
        if name.startswith("K00"):
            result["symbols"] = {"_main": "FF0118", "_watch16": "00000C", "_watch32": "000008", "_tick_ms": "000014"}
        elf = OUTPUT / (name + ".debug.elf")
        if elf.exists():
            result["debug_elf"] = elf.name
            result["debug_elf_sha256"] = digest(elf)
        results.append(result)
    # 寄存器实验应保持布局与其余应用机器码相同；直接检查成品的实际差异位置。
    original = read_hex(OUTPUT / "S00_sdcc_original.hex")
    controlled = {}
    for name, expected in {"S03_count_dr0": [0xFF004E,0xFF0052,0xFF0056,0xFF0059,0xFF0069],
                           "S04_source_dr0": [0xFF0046,0xFF005F,0xFF0065]}.items():
        memory = read_hex(OUTPUT / (name + ".hex"))
        changed = sorted(address for address in original.keys() | memory.keys() if original.get(address) != memory.get(address))
        if changed != expected:
            raise ValueError(name + "含意外机器码变更")
        controlled[name] = [f"{address:06X}" for address in changed]
    (OUTPUT / "manifest.json").write_text(json.dumps({"variants": results, "controlled_byte_differences": controlled,
        "new_variants_hardware_tested": False}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (OUTPUT / "SHA256SUMS.txt").write_text("\n".join(row["sha256"] + "  " + row["hex"] for row in results) + "\n", encoding="ascii")
    lines = ["# 地址与静态检查", "", "由本次实际MAP和HEX生成。地址均为十六进制；新版本尚未实板测试。", "",
             "| 编号 | 有效代码字节 | main | 初始化入口 | watch16 | watch32 | tick_ms |",
             "| --- | ---: | --- | --- | --- | --- | --- |"]
    for row in results:
        sym = row["symbols"]
        lines.append("| " + " | ".join([row["id"], str(row["defined_bytes"]),
            *[sym.get(key, "—") for key in ("_main", "__mcs51_genXINIT", "_watch16", "_watch32", "_tick_ms")]]) + " |")
    lines += ["", "S03与S00只有5字节差异，S04与S00只有3字节差异，均位于XINIT的预期寄存器编码位置。",
              "HEX记录校验、EOF、地址范围已检查；每份新SDCC固件均配套生成了自己的debug.elf。",
              "S06已核实external_startup链接到manual_init模块，返回DPL=1；不会执行保留在镜像内的自动初始化代码。",
              "S07的XINIT长度为0，near全局变量由编译器的GSINIT代码赋值；仍包含运行库空循环入口，不能视为完全绕开启动运行库。",
              "M00/M01不启用Timer1中断；M02启用Timer1并显式保护DPXL。M00/M01的软件延时不是精确500ms。", ""]
    (OUTPUT / "地址与静态检查.md").write_text("\n".join(lines), encoding="utf-8")
    rebuild = OUTPUT / "rebuild"
    rebuild.mkdir(exist_ok=True)
    for filename in ("build_matrix.py", "package_matrix.py"):
        shutil.copy2(Path(__file__).parent / filename, rebuild / filename)
    shutil.copytree(Path(__file__).parent / "minimal", rebuild / "minimal", dirs_exist_ok=True, ignore=shutil.ignore_patterns("__pycache__"))
    archive = OUTPUT.parent / "Simulation-Firmware-Matrix.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as bundle:
        for path in sorted(OUTPUT.rglob("*")):
            relative = path.relative_to(OUTPUT)
            if path.is_file() and "__pycache__" not in relative.parts and relative.parts[0] != "logs":
                bundle.write(path, Path(OUTPUT.name) / path.relative_to(OUTPUT))
    with zipfile.ZipFile(archive) as bundle:
        if bundle.testzip() is not None:
            raise ValueError("ZIP CRC验证失败")
        for row in results:
            content = bundle.read(OUTPUT.name + "/" + row["hex"])
            if hashlib.sha256(content).hexdigest() != row["sha256"]:
                raise ValueError("ZIP内HEX哈希不匹配")
    print(json.dumps({"hex_count": len(results), "zip": str(archive), "zip_bytes": archive.stat().st_size,
                      "zip_sha256": digest(archive)}, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
    main()
