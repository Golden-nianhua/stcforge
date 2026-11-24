"""STCForge 命令行，默认测试流程不会连接 USB。"""
import argparse
import logging
import os
from pathlib import Path
import sys

from . import clion
from .swd import DEFAULT_SWD_SPEED_KHZ, SWD_SPEED_CODES


def parser():
    root = argparse.ArgumentParser(prog="stcforge", description="STC MCS-251 USB-ICE / UART / Link1D SWD 调试工具")
    root.add_argument("--verbose", action="store_true", help="显示协议诊断日志")
    sub = root.add_subparsers(dest="command", required=True)
    clion.add_arguments(sub.add_parser("clion", help="生成和运行 CLion 调试入口"))
    server = sub.add_parser("gdbserver", help="启动 MCS-251 GDB 远程服务")
    modes = server.add_mutually_exclusive_group(required=True)
    modes.add_argument("--mock", action="store_true", help="使用离线模拟目标")
    modes.add_argument("--usb", action="store_true", help="连接已经进入 USB-ICE 状态的设备（实验性）")
    modes.add_argument("--swd", action="store_true", help="通过官方 Link1D 连接已启用 SWD 的目标（实验性）")
    modes.add_argument("--uart", action="store_true", help="连接已启用 UART 仿真的 MCS-251 目标（实验性）")
    server.add_argument("--swd-speed", type=int, choices=sorted(SWD_SPEED_CODES),
                        help=f"Link1D SWD 速度（kHz），仅用于 --swd，默认 {DEFAULT_SWD_SPEED_KHZ}")
    server.add_argument("--device-path", help="hidapi 设备路径；仅多设备时需要")
    server.add_argument("--serial-port", help="UART 调试端口，例如 COM3")
    server.add_argument("--serial-baud", type=int, help="UART 调试波特率，默认 115200（8N2）")
    server.add_argument("--image", help="与目标一致的 SDCC HEX；USB/UART 调试必填")
    server.add_argument("--swd-load", action="store_true", help="允许 GDB 下载指定的 SWD 镜像（仅本机单次会话）")
    server.add_argument("--host", default="127.0.0.1", help="监听地址，默认仅本机")
    server.add_argument("--port", type=int, default=3333)
    server.add_argument("--once", action="store_true", help="客户端断开后退出")
    symbols = sub.add_parser("symbols", help="把 SDCC CDB/HEX 转为 GDB 可读的调试 ELF")
    symbols.add_argument("--cdb", required=True)
    symbols.add_argument("--hex", required=True)
    symbols.add_argument("--output", "-o", required=True)
    symbols.add_argument("--source-root", help="CDB 记录的相对源码路径基准")
    symbols.add_argument("--source-dir", action="append", default=[],
                         help="源码所在目录，可重复指定；同名文件必须唯一匹配")
    symbols.add_argument("--listing-dir", type=Path, action="append", default=[],
                         help="递归查找链接后的 .rst，用于验证局部变量位置")
    symbols.add_argument("--json", action="store_true", help="以 JSON 输出完整转换统计")
    devices = sub.add_parser("list", help="枚举调试探针，不打开设备")
    devices.add_argument("--swd", action="store_true", help="枚举 Link1D SWD 而不是直连 USB-ICE")
    probe = sub.add_parser("swd-probe", help="连接 Link1D，暂停并读取目标寄存器；不写固件")
    probe.add_argument("--device-path", help="hidapi Link1D 设备路径；仅多设备时需要")
    probe.add_argument("--swd-speed", type=int, choices=sorted(SWD_SPEED_CODES),
                       default=DEFAULT_SWD_SPEED_KHZ, help="Link1D SWD 速度（kHz），默认 %(default)s")
    uart_probe = sub.add_parser("uart-probe", help="握手并读取 UART 仿真版本和寄存器，不下载固件")
    uart_probe.add_argument("--serial-port", required=True)
    uart_probe.add_argument("--serial-baud", type=int)
    flash = sub.add_parser("swd-flash", help="通过 Link1D 下载并校验 STC32G144K246 程序区")
    flash.add_argument("--image", type=Path, required=True, help="带 24 位地址的 Intel HEX")
    flash.add_argument("--device-path", help="hidapi Link1D 设备路径；仅多设备时需要")
    flash.add_argument("--swd-speed", type=int, choices=sorted(SWD_SPEED_CODES),
                       default=DEFAULT_SWD_SPEED_KHZ, help="Link1D SWD 速度（kHz），默认 %(default)s")
    flash.add_argument("--dry-run", action="store_true", help="只校验 HEX，不连接 Link1D")
    return root


def connect_swd(path, speed_khz):
    from .swd import Link1DHidTransport, Link1DSession, Link1DTarget
    transport = Link1DHidTransport(os.fsencode(path) if path else None)
    transport.open()
    session = Link1DSession(transport, speed_khz=speed_khz)
    try:
        identity, state = session.initialize_debug()
    except BaseException:
        try:
            session.close()
        except (RuntimeError, OSError):
            logging.exception("关闭 Link1D 失败，保留首次连接错误")
        raise
    print(f"Link1D SWD：{speed_khz} kHz；握手 {identity.hex(' ')}；已暂停，PC={state.pc:06X}", flush=True)
    return Link1DTarget(session), state


def connect_uart(port, baud):
    from .uart import DEFAULT_BAUD, SerialIceSession, SerialLink
    if not port or (baud is not None and baud <= 0):
        raise ValueError("UART 调试需要 --serial-port；--serial-baud 必须为正整数")
    baud = baud or DEFAULT_BAUD
    link = SerialLink(port, baud)
    try:
        session = SerialIceSession(link)
        version, state = session.initialize_debug()
    except BaseException:
        try:
            link.close()
        except OSError:
            logging.exception("关闭串口失败，保留首次连接错误")
        raise
    print(f"UART 仿真：{port}，{baud} 8N2，{version}，PC={state.pc:06X}", flush=True)
    return session, state


def swd_progress(index, total, written):
    if index == total or index % 8 == 0:
        print(f"SWD 校验 {index}/{total} 页；已更新 {written} 页", flush=True)


def main(argv=None):
    args = parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s: %(message)s")
    try:
        if args.command == "clion":
            return clion.execute(args)
        if args.command == "gdbserver":
            from .server import serve
            from .target import MockTarget, IceTarget
            if not 0 <= args.port <= 65535:
                raise ValueError("端口范围应为 0～65535")
            if args.swd_speed is not None and not args.swd:
                raise ValueError("--swd-speed 仅用于 --swd")
            if args.swd_load and (not args.swd or not args.image or not args.once or args.host != "127.0.0.1"):
                raise ValueError("--swd-load 需要 --swd --image --once，并且仅监听 127.0.0.1")
            if not args.uart and (args.serial_port is not None or args.serial_baud is not None):
                raise ValueError("--serial-port 和 --serial-baud 仅用于 --uart")
            if args.mock:
                if args.device_path or args.image:
                    raise ValueError("模拟模式不接受 --device-path 或 --image")
                target = MockTarget()
                print("目标：离线模拟器（NOP/SJMP 测试程序）")
            elif args.swd:
                if args.image and not args.swd_load:
                    raise ValueError("Link1D 直接读取目标代码，不需要 --image；ELF 请在 GDB 中加载")
                if args.swd_load:
                    from .symbols import read_hex
                    from .swd import FlashLoad, plan_code_pages
                    image = read_hex(Path(args.image))
                    plan_code_pages(image)  # Reject invalid images before contacting the probe.
                target, _ = connect_swd(args.device_path, args.swd_speed or DEFAULT_SWD_SPEED_KHZ)
                print("代码读取来源：Link1D 目标程序存储器；使用硬件断点", flush=True)
                if args.swd_load:
                    flash = FlashLoad(target.session, image, swd_progress)
                    serve(target, args.host, args.port, args.once, flash=flash)
                    return 0
            elif args.uart:
                from .symbols import read_hex
                if args.device_path or not args.image:
                    raise ValueError("UART 模式需要 --image，不接受 HID --device-path")
                image = read_hex(Path(args.image))
                if not any(0xfc2800 <= address <= 0xffffff for address in image):
                    raise ValueError("UART 调试需要带原生 24 位代码地址的 MCS-251 HEX")
                session, _ = connect_uart(args.serial_port, args.serial_baud)
                target = IceTarget(session, image)
            else:
                from .symbols import read_hex
                if not args.image: raise ValueError("USB 模式需要 --image 指定目标正在运行的 SDCC HEX")
                image = read_hex(Path(args.image))
                if not any(0xfc2800 <= a <= 0xffffff for a in image):
                    raise ValueError("HEX 缺少原生 24 位代码地址；Keil 低 16 位 HEX 需先显式转换")
                from .ice import IceSession
                from .transport import HidTransport
                transport = HidTransport(args.device_path.encode() if args.device_path else None)
                transport.open()
                try:
                    session = IceSession(transport)
                    version, state = session.initialize_debug()
                    print(f"USB-ICE：{version}；实验性硬件后端；"
                          f"已按 Keil 流程初始化，PC={state.pc:06X}", flush=True)
                    target = IceTarget(session, image)
                    print(f"代码读取来源：本地镜像 {args.image}（应与目标固件一致）", flush=True)
                except BaseException:
                    transport.close()
                    raise
            serve(target, args.host, args.port, args.once)
        elif args.command == "swd-flash":
            from .symbols import read_hex
            from .swd import plan_code_pages
            image = read_hex(args.image)
            pages = plan_code_pages(image)
            if args.dry_run:
                print(f"SWD 镜像校验通过：{len(image)} 字节，{len(pages)} 个代码页")
                return 0
            target, _ = connect_swd(args.device_path, args.swd_speed)
            try:
                total, written = target.session.program_code(image, swd_progress)
                print(f"SWD 下载完成：写入 {written} 页，保留 {total - written} 页，全部回读一致", flush=True)
            finally:
                target.close()
        elif args.command == "swd-probe":
            target, state = connect_swd(args.device_path, args.swd_speed)
            try:
                print(f"DPX={state.dpx:08X} SPX={state.spx:08X} PSW={state.psw:02X} PSW1={state.psw1:02X}")
            finally:
                target.close()
        elif args.command == "uart-probe":
            session, state = connect_uart(args.serial_port, args.serial_baud)
            try:
                print(f"DPX={state.dpx:08X} SPX={state.spx:08X} PSW={state.psw:02X} PSW1={state.psw1:02X}")
            finally:
                session.transport.close()
        elif args.command == "symbols":
            from .symbols import convert
            result = convert(Path(args.cdb), Path(args.hex), Path(args.output),
                             source_root=Path(args.source_root) if args.source_root else None,
                             source_dirs=[Path(folder) for folder in args.source_dir],
                             listing_dirs=args.listing_dir)
            if args.json:
                import json
                print(json.dumps(result, ensure_ascii=False, indent=2))
            else:
                print(f"调试符号已生成：{args.output}")
                print(f"函数 {result['functions']} 个；变量 {result['variables']} 个（SFR {result['sfr']} 个）；"
                      f"局部变量 {result['stack_locals']} 个栈、{result['register_locals']} 个寄存器；"
                      f"源码行 {result['lines']} 条，来自 {result['files']} 个文件。")
                skipped = {name: count for name, count in result['skipped'].items() if count}
                if skipped:
                    labels = {'locals': '局部变量', 'unknown_types': '未知类型',
                              'bit_variables': '位变量', 'unsupported_storage': '未知存储类别',
                              'macros': '宏', 'missing_variable_address': '缺地址的变量',
                              'missing_function_address': '缺地址的函数', 'malformed_records': '无法解析的记录'}
                    labels['ambiguous_file_statics'] = '有歧义的文件静态变量'
                    print('已跳过：' + '、'.join(f"{labels.get(name, name)} {count} 条" for name, count in skipped.items()))
        else:
            import hid
            if args.swd:
                from .swd import Link1DHidTransport
                devices = Link1DHidTransport.enumerate_devices(hid)
                if not devices:
                    print("未找到 Link1D SWD（34BF:1004 / 34BF:1005）")
                for device in devices:
                    print(f"{device.get('product_string') or 'Link1D SWD'} "
                          f"({device['vendor_id']:04X}:{device['product_id']:04X}): {os.fsdecode(device['path'])}")
            else:
                devices = hid.enumerate(0x34bf, 0x1002)
                if not devices: print("未找到 STC USB-ICE")
                for device in devices:
                    print(f"{device.get('product_string', 'STC USB-ICE')}: {device['path']!r}")
        return 0
    except KeyboardInterrupt:
        return 130
    except (ValueError, RuntimeError, OSError, ImportError) as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
