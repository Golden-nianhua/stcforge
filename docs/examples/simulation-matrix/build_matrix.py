"""构建 USB-ICE 启动路径对照固件；只生成文件，不访问设备。

运行：uv run --project D:/Projects/stcforge --no-sync python 本文件
所有源码替换都写进输出目录，不修改模板或编译器安装文件。
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
import sys

TEMPLATE = Path("D:/Code/CLionProjects/STC/STC32K144G246_32BIT_SDCC_Template")
COMPILER = Path("D:/Code/c-env/SDCC/SDCC-4.6.0-MCS251")
FORGE = Path("D:/Projects/stcforge")
UV = Path("D:/Code/uv/uv.exe")
VARIANTS = {
    "S01_no_cmp32": "只替换 XINIT 入口的 CMP DR12,#0，改用四字节 OR 判断；32位递减保留",
    "S02_count16": "XINIT 使用 WR14 的16位计数；源DR4、目的DPX不变",
    "S03_count_dr0": "XINIT 32位计数由DR12改成DR0；源DR4、目的DPX不变",
    "S04_source_dr0": "XINIT源指针由DR4改成DR0；DR12计数、DPX目的不变",
    "S05_movc": "XINIT显式MOVC读取CODE；每次读取时保存和恢复DPX，使用DR0暂存",
    "S06_manual_init": "external_startup逐项写立即数初始化全部8个全局对象，返回1跳过自动初始化",
    "S07_edata": "同一C源码改用small-stack-auto模型，全局移入EDATA；属于整体数据模型对照",
}

def replace_once(text: str, old: str, new: str) -> str:
    if text.count(old) != 1:
        raise ValueError(f"替换锚点必须唯一: {old!r}")
    return text.replace(old, new, 1)

def xinit_for(name: str, original: str) -> str:
    text = original
    if name == "S01_no_cmp32":
        text = replace_once(text, "\tcmp\tdr12,#0\n\tje\t00002$",
            "\tmov\ta,r12\n\torl\ta,r13\n\torl\ta,r14\n\torl\ta,r15\n\tjz\t00002$")
    elif name == "S02_count16":
        text = replace_once(text, "\tmov\tdr12,#0\n\tmov\twr14,#l_XINIT\n\tmov\tr13,#(l_XINIT >> 16)\n\tcmp\tdr12,#0",
            "\tmov\twr14,#l_XINIT\n\tcmp\twr14,#0")
        text = replace_once(text, "\tdec\tdr12", "\tdec\twr14")
    elif name == "S03_count_dr0":
        text = text.replace("dr12", "dr0").replace("wr14", "wr2").replace("r13", "r1")
    elif name == "S04_source_dr0":
        text = text.replace("dr4", "dr0")
    elif name == "S05_movc":
        text = replace_once(text, "\tmov\ta,@dr4",
            "\tmov\tdr0,dpx\n\tmov\tdpx,dr4\n\tclr\ta\n\tmovc\ta,@a+dptr\n\tmov\tdpx,dr0")
    else:
        raise ValueError(name)
    return "; 实验版本: " + name + "\n; " + VARIANTS[name] + "\n" + text

MANUAL_INIT = """/* 在任何系统初始化/中断启用之前设置全部静态数据。 */
#include "system_stc32.h"
unsigned char __sdcc_external_startup(void)
{
    EA = 0;
    heartbeat_count = 0UL;
    rx_count = 0UL;
    tx_count = 0UL;
    last_rx = 0U;
    led_state = 0U;
    watch16 = 0x1234U;
    watch32 = 0x12345678UL;
    tick_ms = 0UL;
    return 1U; /* 跳过运行库数据初始化；栈已由GSINIT1设置。 */
}
"""

def read_hex(path: Path) -> dict[int, int]:
    mem: dict[int, int] = {}
    base = 0
    eof = False
    for line in path.read_text(encoding="ascii").splitlines():
        if not line:
            continue
        if not line.startswith(":"):
            raise ValueError(f"坏HEX记录: {path}")
        raw = bytes.fromhex(line[1:])
        if len(raw) != raw[0] + 5 or sum(raw) & 255:
            raise ValueError(f"HEX校验失败: {path}")
        address = int.from_bytes(raw[1:3], "big")
        kind, payload = raw[3], raw[4:-1]
        if eof:
            raise ValueError("EOF之后仍有记录")
        if kind == 0:
            for offset, value in enumerate(payload):
                target = base + address + offset
                if target in mem and mem[target] != value:
                    raise ValueError("重叠HEX数据不同")
                mem[target] = value
        elif kind == 4:
            base = int.from_bytes(payload, "big") << 16
        elif kind == 2:
            base = int.from_bytes(payload, "big") << 4
        elif kind == 1:
            eof = True
    if not eof or not mem:
        raise ValueError("HEX缺少EOF或数据")
    return mem

def emit_hex(path: Path, memory: dict[int, int]) -> None:
    def record(address: int, kind: int, payload: bytes) -> str:
        data = bytes([len(payload), address >> 8, address & 255, kind]) + payload
        return ":" + (data + bytes([-sum(data) & 255])).hex().upper()
    lines: list[str] = []
    addresses = sorted(memory)
    index, bank = 0, -1
    while index < len(addresses):
        start = addresses[index]
        if start >> 16 != bank:
            bank = start >> 16
            lines.append(record(0, 4, bank.to_bytes(2, "big")))
        chunk = bytearray([memory[start]])
        index += 1
        while index < len(addresses) and len(chunk) < 16 and addresses[index] == start + len(chunk) and addresses[index] >> 16 == bank:
            chunk.append(memory[addresses[index]])
            index += 1
        lines.append(record(start & 65535, 0, bytes(chunk)))
    lines.append(record(0, 1, b""))
    path.write_text("\n".join(lines) + "\n", encoding="ascii")

def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def symbols(path: Path) -> dict[str, int]:
    found = {}
    for line in path.read_text(errors="replace").splitlines():
        match = re.match(r"\s*(?:[CD]:\s+)?([0-9A-Fa-f]{8})\s+(\S+)", line)
        if match:
            found[match[2]] = int(match[1], 16)
    return found

def run(command: list[str | Path], cwd: Path, environment: dict[str, str], log: list[str]) -> subprocess.CompletedProcess:
    args = [str(arg) for arg in command]
    result = subprocess.run(args, cwd=cwd, env=environment, text=True, encoding="utf-8", errors="replace", capture_output=True)
    log.extend([subprocess.list2cmdline(args), result.stdout, result.stderr])
    if result.returncode:
        (cwd / "build.log").write_text("\n".join(log), encoding="utf-8")
        raise RuntimeError(f"构建失败({result.returncode}): {args[0]}\n{result.stdout}\n{result.stderr}")
    return result

def build(name: str, template: Path, compiler: Path, output: Path, make_symbols: bool) -> dict:
    work = output / name
    work.mkdir(parents=True, exist_ok=True)
    src = work / "sources"
    src.mkdir(exist_ok=True)
    baseline = template / "Misc/Experiments/SDCC Simulation Test"
    for filename in ("main.c", "system_stc32.c", "startup.asm"):
        shutil.copy2(baseline / "Core/Src" / filename, src / filename)
    shutil.copytree(baseline / "Core/Inc", src / "Core/Inc", dirs_exist_ok=True)
    # 测试工程的Drivers入口是相对转发头；独立快照应复制真正的寄存器头。
    shutil.copytree(template / "Drivers/Inc", src / "Drivers/Inc", dirs_exist_ok=True)
    model = "small" if name == "S07_edata" else "large"
    if name.startswith("S0") and name[2] in "12345":
        runtime = (compiler / "lib/src/mcs251/crtxinit.asm").read_text(encoding="utf-8")
        (src / "xinit.asm").write_text(xinit_for(name, runtime), encoding="utf-8")
    if name == "S06_manual_init":
        (src / "manual_init.c").write_text(MANUAL_INIT, encoding="utf-8")
    environment = os.environ.copy()
    environment["PATH"] = str(compiler / "bin") + os.pathsep + environment.get("PATH", "")
    flags = ["-mmcs251", f"--model-{model}", "--stack-auto", "--int-long-reent", "--std-c11", "--debug"]
    includes = ["-I" + str(src / "Core/Inc"), "-I" + str(src / "Drivers/Inc")]
    log: list[str] = []
    objects: list[Path] = []
    for filename in ("main.c", "system_stc32.c", "manual_init.c"):
        if (src / filename).exists():
            obj = work / (Path(filename).stem + ".rel")
            run([compiler / "bin/sdcc.exe", *flags, *includes, "-c", src / filename, "-o", obj], work, environment, log)
            objects.append(obj)
    for filename in ("startup.asm", "xinit.asm"):
        if (src / filename).exists():
            obj = work / (Path(filename).stem + ".rel")
            # 运行库源码依赖链接器s_*/l_*符号；与其官方Makefile一样用-g导出未定义符号。
            run([compiler / "bin/sdas251.exe", "-olsg", obj, src / filename], work, environment, log)
            objects.append(obj)
    run([compiler / "bin/sdcc.exe", *flags, "--code-loc", "0xFF0000", "--iram-size", "0x4000",
         "--xram-loc", "0x010000", "--xram-size", "0x20000", "--stack-size", "1",
         *objects, "-o", work / (name + ".ihx")], work, environment, log)
    packed = run([compiler / "bin/packihx.exe", work / (name + ".ihx")], work, environment, log)
    image = work / (name + ".hex")
    image.write_text(packed.stdout, encoding="ascii")
    memory = read_hex(image)
    if memory.get(0xFF0000) != 2 or any(not 0xFF0000 <= addr <= 0xFFFFFF for addr in memory):
        raise ValueError(f"{name}: 地址范围或复位跳转不正确")
    sym = symbols(work / (name + ".map"))
    if name == "S02_count16" and sym["l_XINIT"] > 65535:
        raise ValueError("16位实验仅适用于长度小于64KiB的样本")
    if name == "S07_edata" and any(sym[key] >= 0x100 for key in ("_watch16", "_watch32", "_tick_ms")):
        raise ValueError("small模型变量未落在预期EDATA页")
    if name == "S06_manual_init":
        map_text = (work / (name + ".map")).read_text(errors="replace")
        if not re.search(r"\b___sdcc_external_startup\s+manual_init\b", map_text):
            raise ValueError("external_startup并非链接到本实验的manual_init模块")
    if make_symbols:
        run([UV, "run", "--project", FORGE, "--no-sync", "stcforge", "symbols",
             "--cdb", work / (name + ".cdb"), "--hex", image, "--output", work / (name + ".debug.elf"),
             "--source-root", src, "--source-dir", src], work, environment, log)
    (work / "build.log").write_text("\n".join(log), encoding="utf-8")
    shutil.copy2(image, output / image.name)
    if make_symbols:
        shutil.copy2(work / (name + ".debug.elf"), output / (name + ".debug.elf"))
    result = {"id": name, "description": VARIANTS[name], "hex": image.name, "sha256": digest(image),
              "defined_bytes": len(memory), "range": [f"{min(memory):06X}", f"{max(memory):06X}"],
              "status": "已构建并静态检查；未实板验证",
              "symbols": {key: f"{value:06X}" for key, value in sym.items() if key in
                  {"_main", "__mcs51_genXINIT", "___sdcc_external_startup", "_watch16", "_watch32", "_tick_ms", "s_XINIT", "s_XISEG", "l_XINIT"}}}
    (work / "variant.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False), flush=True)
    return result

def baselines(template: Path, output: Path) -> None:
    work = output / "baselines"
    work.mkdir(exist_ok=True)
    sdcc = template / "Misc/Experiments/SDCC Simulation Test/build/Debug/firmware/STC32G144K246_Simulation_Test.hex"
    keil = template / "Misc/Experiments/Keil Simulation Test/Objects/Keil Simulation Test.hex"
    if digest(sdcc) != "2d7b7609bbd5a0db001d81588c9b78451ff212eebe34e396de283290a79755cf":
        raise ValueError("SDCC基线与已分析样本不同")
    if digest(keil) != "6a572bc409f7baaa694452be9ed1853992081f6ea097c57325815565b90dc5d0":
        raise ValueError("Keil基线与已分析样本不同")
    shutil.copy2(sdcc, output / "S00_sdcc_original.hex")
    shutil.copy2(keil, work / "K00_keil_original_low16.hex")
    native = {0xFF0000 + address: value for address, value in read_hex(keil).items()}
    emit_hex(output / "K00_keil_reference.hex", native)
    if read_hex(output / "K00_keil_reference.hex") != native:
        raise ValueError("Keil地址归一校验失败")
    for suffix in (".map", ".cdb", ".debug.elf"):
        path = sdcc.with_suffix(suffix)
        if path.exists():
            shutil.copy2(path, work / ("S00_sdcc_original" + suffix))

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template", type=Path, default=TEMPLATE)
    parser.add_argument("--compiler", type=Path, default=COMPILER)
    parser.add_argument("--output", type=Path, default=TEMPLATE / "Misc/Experiments/Simulation Firmware Matrix")
    parser.add_argument("--variant", action="append", choices=tuple(VARIANTS))
    parser.add_argument("--no-symbols", action="store_true")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    baselines(args.template, output)
    results = [build(name, args.template, args.compiler, output, not args.no_symbols) for name in (args.variant or VARIANTS)]
    (output / "build-results.json").write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
    main()
