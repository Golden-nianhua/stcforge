"""生成 CLion 调试入口与 SDCC 调试 ELF；配置阶段不访问 USB。"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys
import tomllib
import xml.etree.ElementTree as ET

from .swd import SWD_SPEED_CODES

SWD_PINS = ("p3.0-p3.1", "p3.6-p3.7", "p1.6-p1.7", "p4.3-p4.4")


def read_config(path: Path) -> dict:
    with path.open("rb") as stream:
        document = tomllib.load(stream)
    config = document["stcforge"]
    mode = config["simulation_mode"]
    if mode not in ("usb", "swd", "uart"):
        raise ValueError('simulation_mode 必须为 "usb"、"swd" 或 "uart"')
    if not isinstance(config["model"], str) or not config["model"].strip():
        raise ValueError("model 必须填写芯片型号")
    for pins in ("swd_pins", "uart_simulation_pins"):
        if config.get(pins, SWD_PINS[0]) not in SWD_PINS:
            raise ValueError(f"{pins} 必须为 {', '.join(SWD_PINS)} 之一")
    for name, lower, upper in (("port", 1, 65535), ("warmup_ms", 0, 60000)):
        value = config[name]
        if type(value) is not int or not lower <= value <= upper:
            raise ValueError(f"{name} 应在 {lower}～{upper} 范围内")
    for name in ("device_path", "swd_device_path", "uart_port"):
        if not isinstance(config.get(name, ""), str):
            raise ValueError(f"{name} 必须为字符串")
    speed = config.get("swd_speed_khz", 600)
    if type(speed) is not int or speed not in SWD_SPEED_CODES:
        raise ValueError("swd_speed_khz 必须为 100、300、600 或 1000")
    config["swd_speed_khz"] = speed
    config["simulation_isp"] = document.get("simulation_isp", {})
    if type(config["simulation_isp"].get("download_image", False)) is not bool:
        raise ValueError("simulation_isp.download_image 必须为布尔值")
    if mode == "uart":
        if not config.get("uart_port"):
            raise ValueError("UART 调试需要 uart_port")
        if type(config.get("uart_baud", 115200)) is not int or config.get("uart_baud", 115200) <= 0:
            raise ValueError("uart_baud 必须为正整数")
    return config


def swd_args(config: dict) -> list[str]:
    args = ["--swd-speed", str(config["swd_speed_khz"])]
    if config.get("swd_device_path"):
        args += ["--device-path", config["swd_device_path"]]
    return args


def enable_command(config: dict, isp: Path, image: Path, firmware_dir: Path) -> list[str]:
    mode = config["simulation_mode"]
    settings = config["simulation_isp"]
    interface = settings.get("if", "usb" if mode == "usb" else "link1d")
    if interface not in (("serial", "link1d") if mode == "swd" else ("usb", "serial", "link1d")):
        raise ValueError(f"{mode} 仿真不支持使用 ISP 接口 {interface!r}")
    command = [str(isp), "--model", config["model"], "--if", interface]
    for key in ("port", "device_path", "handshake_baud", "baud", "timeout_ms",
                "link1d_auto_power", "link1d_keep_power"):
        if key not in settings or settings[key] == "":
            continue
        if key.startswith("link1d_") and interface != "link1d":
            continue
        value = settings[key]
        if type(value) is bool:
            value = "true" if value else "false"
        command += ["--" + key.replace("_", "-"), str(value)]
    if mode == "usb" and settings.get("download_image", False):
        image = image.with_suffix(".hex").resolve()
        if image.parent != firmware_dir.resolve():
            raise ValueError("USB-ICE 启用必须使用 Debug 预设的固件")
        if not image.is_file():
            raise ValueError(f"未找到 Debug 固件：{image}")
        command += ["--image", str(image), "--option", "modify_hardware_options=false",
                    "--option", "usb_ice_enabled=true"]
    else:
        command += ["--make-simulation", "--option", f"simulation_mode={mode}"]
        pins = {"swd": "swd_pins", "uart": "uart_simulation_pins"}.get(mode)
        if pins and pins in config:
            command += ["--option", f"{pins}={config[pins]}"]
    return command


def check_model_mode(isp: Path, model: str, mode: str) -> None:
    index = subprocess.run([str(isp), "--list-models"], check=True,
                           stdout=subprocess.PIPE, encoding="utf-8")
    for line in index.stdout.splitlines():
        if not line.strip():
            continue
        name, *fields = line.split()
        if name.casefold() != model.casefold():
            continue
        modes = dict(field.split("=", 1) for field in fields)["simulation-make"].split(",")
        if mode not in modes:
            raise ValueError(f"{model} 不支持 {mode.upper()} 仿真")
        return
    raise ValueError(f"stc-isp 型号索引中未找到 {model}")


def write_configurations(config: dict, root_dir: Path, launcher: str, project_name: str,
                         config_path: Path, image: Path, preset: str, toolchain: str,
                         isp: Path):
    run_dir = root_dir / ".idea/runConfigurations"
    other = run_dir / "STC32_Auto_STCForge_debug.xml"
    direct = run_dir / "STC32_Auto_STCForge_swd_attach.xml"
    flash = run_dir / "STC32_Auto_STCForge_swd_flash.xml"
    if config["simulation_mode"] == "swd":
        # Older CLion sessions can retain the rejected STCForge_swd scheme name.
        other.unlink(missing_ok=True)
        write_configuration(config, root_dir, launcher, project_name, config_path, image,
                            preset, toolchain, isp, direct, "STCForge_swd_attach")
        write_configuration(config, root_dir, launcher, project_name, config_path, image,
                            preset, toolchain, isp, flash,
                            "STCForge_swd_flash", download=True)
    else:
        direct.unlink(missing_ok=True)
        flash.unlink(missing_ok=True)
        write_configuration(config, root_dir, launcher, project_name, config_path, image,
                            preset, toolchain, isp, other, "STCForge_debug")


def write_configuration(config: dict, root_dir: Path, launcher: str, project_name: str,
                        config_path: Path, image: Path, preset: str, toolchain: str,
                        isp: Path, output: Path, name: str, *, download=False):
    """采用本机 CLion 2026.1 的 Embedded GDB Server 序列化格式。"""
    # 调试入口固定使用 Debug，避免误用 Release 遗留的 CDB。
    elf = image.with_suffix(".debug.elf").resolve()
    run_path = ("$ProjectFileDir$/" + elf.relative_to(root_dir).as_posix()
                if elf.is_relative_to(root_dir) else elf.as_posix())
    command = ["clion", "--config", config_path.resolve().as_posix(),
               "serve", "--image", image.resolve().as_posix(), "--isp", isp.as_posix()]
    if download:
        command.append("--swd-load")
    root = ET.Element("component", name="ProjectRunConfigurationManager")
    run = ET.SubElement(root, "configuration", {
        "default": "false", "name": name,
        "type": "com.jetbrains.cidr.embedded.customgdbserver.type",
        "factoryName": "com.jetbrains.cidr.embedded.customgdbserver.factory",
        "PROGRAM_PARAMS": subprocess.list2cmdline(command),
        "REDIRECT_INPUT": "false", "ELEVATE": "false", "USE_EXTERNAL_CONSOLE": "false",
        "EMULATE_TERMINAL": "false", "PASS_PARENT_ENVS_2": "true",
        "WORKING_DIR": "file://$ProjectFileDir$", "PROJECT_NAME": project_name,
        "TARGET_NAME": project_name, "folderName": "Debug",
        "CONFIG_NAME": preset,
        "version": "1", "RUN_PATH": run_path,
    })
    envs = ET.SubElement(run, "envs")
    ET.SubElement(envs, "env", name="PYTHONUTF8", value="1")
    ET.SubElement(envs, "env", name="PYTHONUNBUFFERED", value="1")
    server = ET.SubElement(run, "custom-gdb-server", {
        "version": "1", "gdb-connect": f"127.0.0.1:{config['port']}",
        "executable": launcher, "warmup-ms": str(config["warmup_ms"]),
        "download-type": "ALWAYS" if download else "NONE", "reset-cmd": "", "reset-type": "NEVER",
    })
    # 和预设绑定相同的工具链，使用用户已配置的 MCS-251 GDB。
    ET.SubElement(server, "debugger", toolchainName=toolchain)
    method = ET.SubElement(run, "method", v="2")
    ET.SubElement(method, "option", name="CLION.COMPOUND.BUILD", enabled="true")
    ET.indent(root)
    output.parent.mkdir(parents=True, exist_ok=True)
    text = ET.tostring(root, encoding="unicode") + "\n"
    if not output.exists() or output.read_text(encoding="utf-8") != text:
        output.write_text(text, encoding="utf-8")


def add_arguments(parser):
    parser.add_argument("--config", type=Path, required=True)
    actions = parser.add_subparsers(dest="action", required=True)
    configure = actions.add_parser("configure")
    configure.add_argument("--project-name", required=True)
    configure.add_argument("--root", type=Path, required=True)
    configure.add_argument("--image", type=Path, required=True)
    configure.add_argument("--preset", required=True)
    configure.add_argument("--toolchain", required=True)
    configure.add_argument("--launcher", required=True)
    configure.add_argument("--isp", type=Path, required=True)
    prepare = actions.add_parser("prepare")
    prepare.add_argument("--image", type=Path, required=True)
    prepare.add_argument("--output", type=Path, required=True)
    prepare.add_argument("--root", type=Path, required=True)
    prepare.add_argument("--source-dir", action="append", default=[])
    serve = actions.add_parser("serve")
    serve.add_argument("--image", type=Path, required=True)
    serve.add_argument("--isp", type=Path)
    serve.add_argument("--swd-load", action="store_true")
    enable = actions.add_parser("enable")
    enable.add_argument("--image", type=Path, required=True)
    enable.add_argument("--debug-firmware-dir", type=Path, required=True)
    enable.add_argument("--isp", type=Path, required=True)
    enable.add_argument("--dry-run", action="store_true", help="只校验启用配置和固件，不连接芯片")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="stcforge clion", description=__doc__)
    add_arguments(parser)
    return execute(parser.parse_args(argv))


def execute(args) -> int:
    try:
        config = read_config(args.config)
        if args.action == "configure":
            write_configurations(config, args.root.resolve(), args.launcher, args.project_name,
                                 args.config, args.image, args.preset, args.toolchain, args.isp)
            print("firmware-target")
            return 0
        if args.action == "enable":
            command = enable_command(config, args.isp, args.image, args.debug_firmware_dir)
            if args.dry_run:
                command.append("--dry-run")
            elif "--image" in command:
                print(f"下载 Debug 固件并启用 USB-ICE：{command[command.index('--image') + 1]}", flush=True)
            return subprocess.run(command, check=False).returncode
        stcforge = [sys.executable, "-m", "stcforge"]
        image = str(args.image.with_suffix(".hex"))
        mode = config["simulation_mode"]
        if args.action == "serve":
            if args.swd_load and mode != "swd":
                raise ValueError("--swd-load 需要 simulation_mode = \"swd\"")
            if args.isp is not None:
                check_model_mode(args.isp, config["model"], mode)
            command = stcforge + ["gdbserver", f"--{mode}", "--once",
                                  "--host", "127.0.0.1", "--port", str(config["port"])]
            if mode == "swd":
                command += swd_args(config)
                if args.swd_load:
                    command += ["--swd-load", "--image", image]
            else:
                command += ["--image", image]
                if mode == "uart":
                    command += ["--serial-port", config["uart_port"],
                                "--serial-baud", str(config.get("uart_baud", 115200))]
                elif config.get("device_path"):
                    command += ["--device-path", config["device_path"]]
        else:
            command = stcforge + ["symbols", "--cdb", str(args.image.with_suffix(".cdb")),
                                  "--hex", image, "--output", str(args.output), "--source-root", str(args.root)]
            for folder in args.source_dir:
                command += ["--source-dir", str(args.root / folder)]
        environment = os.environ.copy()
        environment["PYTHONUTF8"] = "1"
        return subprocess.run(command, env=environment, check=False).returncode
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print(f"STCForge 配置错误：{error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
