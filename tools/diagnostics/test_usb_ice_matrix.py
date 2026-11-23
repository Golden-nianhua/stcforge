"""对照固件的一键 USB-ICE / GDB 测试；默认不下载、不擦除固件。

通过真实USB空间5核对板内完整代码，再使用生产版server/target和stc-gdb。
无参数仍选择 K00；任意当前固件用 --image 显式指定，ELF/MAP 可取同名旁文件。
--mock只验证本机流程，不能证明USB或固件正常。所有测试均保存完整日志。
临时覆盖诊断可显式使用--restore-overlay，在同一暂停会话内恢复已登记备份。
"""
from __future__ import annotations

import argparse
from collections import deque
from datetime import datetime
import hashlib
import json
import logging
import os
from pathlib import Path
import queue
import re
import subprocess
import sys
import threading
import time

DEFAULT_MATRIX = Path("D:/Code/CLionProjects/STC/STC32K144G246_32BIT_SDCC_Template/Misc/Experiments/Simulation Firmware Matrix")
DEFAULT_GDB = Path("D:/Projects/stcforge/dist/windows/stc-gdb.exe")
MARKER = "@@ICE_MATRIX@@"
WATCH_SYMBOLS = (("_watch16", 2, "1234"), ("_watch32", 4, "12345678"))


class TestFailure(RuntimeError):
    pass


def restore_overlay_in_session(session, image_path, directory, journal):
    """测试成功且代码核对完成后，同一暂停会话内恢复完整扇区备份。"""
    from stcforge.ice import CMD_READ
    directory = Path(directory)
    record_path = directory / 'result.json'
    metadata = json.loads(record_path.read_text(encoding='utf-8'))
    saved = (directory / 'code-before.bin').read_bytes()
    replacement = (directory / 'replacement.bin').read_bytes()
    base = metadata['base']
    if (not metadata.get('erase_sectors') or base != 0xff0000
            or len(saved) != metadata['size'] or len(saved) != len(replacement)
            or len(saved) % 512 or not 512 <= len(saved) <= 4096):
        raise TestFailure('同会话恢复的扇区备份范围无效')
    for data, key in ((saved, 'backup_sha256'), (replacement, 'replacement_sha256')):
        if hashlib.sha256(data).hexdigest() != metadata[key]:
            raise TestFailure('同会话恢复的备份哈希不匹配')
    if digest(Path(image_path)) != metadata['candidate_hex_sha256']:
        raise TestFailure('同会话恢复的候选身份不符')
    baseline = Path(metadata['baseline'])
    if digest(baseline) != metadata['baseline_hex_sha256']:
        raise TestFailure('同会话恢复的基线身份不符')
    from stcforge.symbols import read_hex
    if any(not base <= address < base + len(saved) or saved[address-base] != value
           for address, value in read_hex(baseline).items()):
        raise TestFailure('同会话备份不属于已登记基线')
    def read_all():
        data = bytearray()
        for offset in range(0, len(saved), 48):
            count = min(48, len(saved) - offset)
            data.extend(session._data_exchange(CMD_READ,
                b'\x05' + (base + offset).to_bytes(4, 'big') + bytes([count]),
                expected_data_length=count).data)
        return bytes(data)
    actual = read_all()
    if actual != replacement:
        raise TestFailure('同会话恢复前，完整扇区与候选不一致，拒绝擦写')
    # 调用者必须已确认target停止、断点全部恢复；此处不复位、不重新初始化。
    session.read_state()
    journal.log('overlay_restore_begin', bytes=len(saved), directory=str(directory))
    for address in range(base, base + len(saved), 512):
        session._event_exchange(0x06, address.to_bytes(4, 'big'))
    for offset in range(0, len(saved), 48):
        session.write_memory(5, base + offset, saved[offset:offset+48])
    if read_all() != saved:
        raise TestFailure('同会话恢复后完整扇区回读不符')
    metadata.update(restored=True, recovery_verified=True, recovery_same_session=True)
    record_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding='utf-8')
    (directory / 'same-session-restored.json').write_text(json.dumps(dict(
        backup_sha256=metadata['backup_sha256'], bytes=len(saved), verified=True)), encoding='utf-8')
    journal.log('overlay_restore_verified', bytes=len(saved))
    return len(saved)


class Journal:
    def __init__(self, path: Path):
        self.file = path.open("x", encoding="utf-8", buffering=1)
        self.start = time.monotonic()
        self.lock = threading.Lock()

    def log(self, event: str, **fields):
        row = {"seconds": round(time.monotonic() - self.start, 6), "event": event, **fields}
        with self.lock:
            self.file.write(json.dumps(row, ensure_ascii=False) + "\n")

    def close(self):
        self.file.close()


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_variant(matrix, requested):
    rows = json.loads((matrix / "manifest.json").read_text(encoding="utf-8"))["variants"]
    matches = [row for row in rows if row["id"].lower() == requested.lower()]
    if not matches:
        matches = [row for row in rows if row["id"].split("_")[0].lower() == requested.lower()]
    if len(matches) != 1:
        raise TestFailure("固件编号不唯一或不存在：" + requested)
    row = matches[0]
    image = (matrix / row["hex"]).resolve()
    if image.parent != matrix.resolve() or digest(image) != row["sha256"]:
        raise TestFailure("本地HEX与固件清单不一致，请重新构建或恢复原包")
    elf = matrix / row["debug_elf"] if row.get("debug_elf") else None
    if elf and (elf.resolve().parent != matrix.resolve() or digest(elf) != row["debug_elf_sha256"]):
        raise TestFailure("调试ELF与固件清单不一致")
    return row, image, elf


def sibling(path, suffix):
    path = Path(path)
    return path.with_name(path.stem + suffix)


def default_variant(matrix):
    rows = json.loads((matrix / "manifest.json").read_text(encoding="utf-8"))["variants"]
    matches = [row for row in rows if row["id"].startswith("K00")]
    if len(matches) != 1:
        raise TestFailure("默认矩阵中K00不唯一")
    return matches[0]["id"]


def choose_files(args):
    """校验来源互斥，并把显式HEX与同名ELF/MAP统一成绝对路径。"""
    variant = getattr(args, "variant", None)
    image = getattr(args, "image", None)
    elf = getattr(args, "elf", None)
    map_path = getattr(args, "map", None)
    if variant and image:
        raise TestFailure("--variant 与 --image 只能选一种固件来源")
    if variant and (elf or map_path):
        raise TestFailure("--variant 不能与 --elf/--map 混用")
    if (elf or map_path) and not image:
        raise TestFailure("--elf/--map 必须配合显式--image使用")
    if not image:
        return None
    image_path = Path(image).resolve()
    elf_path = Path(elf).resolve() if elf else None
    if elf_path is None:
        inferred = sibling(image_path, ".debug.elf")
        elf_path = inferred if inferred.is_file() else None
    if map_path:
        map_file = Path(map_path).resolve()
        if not map_file.is_file():
            raise TestFailure("找不到MAP文件：" + str(map_file))
    else:
        inferred = sibling(image_path, ".map")
        map_file = inferred if inferred.is_file() else None
    if not image_path.is_file():
        raise TestFailure("找不到固件HEX：" + str(image_path))
    return image_path, elf_path, map_file


def map_symbols(text):
    """读取 SDCC MAP 的代码/数据符号；XF 是函数结束标签，不能作为入口。"""
    found = {}
    pattern = re.compile(r"^[ \t]*([CD]):[ \t]+([0-9a-fA-F]{1,8})[ \t]+(\S+)", re.MULTILINE)
    for kind, address, name in pattern.findall(text):
        if name.startswith(("XF", "XG")):
            continue
        found[name] = int(address, 16)
    return found


def breakpoint_from_map(text, args, variant=None):
    if getattr(args, "no_breakpoints", False):
        return None
    return breakpoint_address_from_text(text, strict_classification=bool(variant and variant.startswith("K00")))


def watch_addresses(text):
    """只把变量地址交给GDB；函数符号不能误当成寄存器/EDATA观察地址。"""
    found = {}
    wanted = {symbol for symbol, _, _ in WATCH_SYMBOLS}
    pattern = re.compile(r"^[ \t]*D:[ \t]+([0-9a-fA-F]{1,8})[ \t]+(\S+)", re.MULTILINE)
    for address, name in pattern.findall(text):
        if name in wanted:
            found[name] = int(address, 16)
    return found


def map_watch_symbols(text):
    """兼容旧调用；变量地址只接受 MAP 的 D: 数据符号。"""
    return watch_addresses(text)


def select_firmware(args):
    """把矩阵或自定义文件统一为同一条可校验的固件选择。"""
    variant = getattr(args, "variant", None)
    files = choose_files(args)
    default = not (files or variant)
    if default:
        variant = default_variant(args.matrix)
    if files:
        image, elf, map_path = files
        if elf and not elf.is_file():
            raise TestFailure("找不到调试ELF：" + str(elf))
        text = map_path.read_text(encoding="utf-8", errors="replace") if map_path else ""
        watch = map_watch_symbols(text) if text else {}
        breakpoint = custom_breakpoint(text, args) if text else None
        row = {"id": image.stem, "symbols": {name: f"{address:06X}" for name, address in watch.items()},
               "custom": True, "map": str(map_path) if map_path else None, "image": str(image),
               "matrix": str(args.matrix.resolve()),
               "breakpoint": f"{breakpoint:06X}" if breakpoint is not None else None}
        return FirmwareSelection(row, image, elf, map_path, breakpoint, watch)

    if variant:
        row, image, elf = load_variant(args.matrix, variant)
        row = dict(row, matrix=str(args.matrix.resolve()))
        map_path = None
        symbol_addresses = {name: int(address, 16) for name, address in row.get("symbols", {}).items()}
        breakpoint = None
        path = args.matrix / row["id"] / (row["id"] + ".map")
        if row["id"].startswith("S00"):
            path = args.matrix / "baselines/S00_sdcc_original.map"
        if path.is_file():
            map_path = path.resolve()
            text = map_path.read_text(encoding="utf-8", errors="replace")
            symbol_addresses.update(map_watch_symbols(text))
            breakpoint = breakpoint_from_map(text, args, row["id"])
        return FirmwareSelection(row, image, elf, map_path, breakpoint, symbol_addresses)
    raise AssertionError("固件来源选择不完整")


class FirmwareSelection:
    def __init__(self, row, image, elf, map_path, breakpoint, symbols):
        self.row = row
        self.image = Path(image).resolve()
        self.elf = Path(elf).resolve() if elf else None
        self.map = Path(map_path).resolve() if map_path else None
        self.breakpoint = breakpoint
        self.symbols = dict(symbols)
        self.hashes = {name: digest(path) for name, path in
                       (("hex", self.image), ("elf", self.elf), ("map", self.map)) if path is not None}

    def report(self):
        return {"id": self.row["id"], "hex": str(self.image), "hex_sha256": self.hashes["hex"],
                "elf": str(self.elf) if self.elf else None,
                "elf_sha256": self.hashes.get("elf"),
                "map": str(self.map) if self.map else None,
                "map_sha256": self.hashes.get("map"),
                "custom": bool(self.row.get("custom")), "symbols": self.row.get("symbols", {}),
                "input": {name: str(path) for name, path in
                          (("hex", self.image), ("elf", self.elf), ("map", self.map)) if path is not None},
                "input_sha256": dict(self.hashes),
                "breakpoint_from_map": f"{self.breakpoint:06X}" if self.breakpoint is not None else None}


def native_verify(session, image, log, phase):
    """不可通过IceTarget.read_memory读CODE：它返回本地镜像，不能用于板内核对。"""
    from stcforge.ice import CMD_READ
    addresses = sorted(image)
    if not addresses or any(not 0xFC2800 <= address <= 0xFFFFFF for address in addresses):
        raise TestFailure("设备核对需要原生24位代码地址，拒绝空镜像或错误地址")
    offset = 0
    while offset < len(addresses):
        start = addresses[offset]
        count = 1
        while offset + count < len(addresses) and count < 48 and addresses[offset + count] == start + count:
            count += 1
        # 与diagnose_usb_ice.py已实测的DLL空间5诊断读取一致。
        # 生产read_memory仍明确拒绝space5；此处不修改它的接口边界。
        payload = b"\x05" + start.to_bytes(4, "big") + bytes((count,))
        actual = session._data_exchange(CMD_READ, payload, expected_data_length=count).data
        if len(actual) != count:
            raise TestFailure("板内代码回读长度异常")
        expected = bytes(image[address] for address in addresses[offset:offset + count])
        if actual != expected:
            mismatch = next((index for index, pair in enumerate(zip(expected, actual)) if pair[0] != pair[1]), 0)
            log.log("image_mismatch", phase=phase, address=f"{start + mismatch:06X}",
                    expected=expected.hex(), actual=actual.hex())
            raise TestFailure(f"{phase}板内代码与所选HEX不同，首个差异约在0x{start + mismatch:06X}；请先下载对应固件")
        offset += count
    log.log("image_verified", phase=phase, bytes=len(addresses))


def worker_selection_error(args):
    """在worker读取调试符号或打开USB前，复核父进程选定的全部输入。"""
    if getattr(args, "mock", False):
        return None
    inputs = (("HEX", "image", "image_sha256", True),
              ("ELF", "elf", "elf_sha256", False),
              ("MAP", "map", "map_sha256", False))
    for label, path_field, hash_field, required in inputs:
        path_text = getattr(args, path_field, None)
        expected = getattr(args, hash_field, None)
        if not path_text:
            if expected:
                return f"worker收到{label}摘要但缺少{label}路径"
            if required:
                return f"worker缺少--{path_field}"
            continue
        if not expected:
            return f"worker缺少父进程的{label}摘要"
        path = Path(path_text)
        if not path.is_file():
            return f"worker找不到{label}文件：{path}"
        if digest(path) != expected:
            return f"worker接收的{label}摘要不一致，拒绝访问设备"
    return None


def worker(args):
    from stcforge.server import serve
    from stcforge.target import IceTarget, MockTarget
    from stcforge.symbols import read_hex
    from stcforge.transport import HidTransport, TransportTimeout
    from stcforge.ice import IceSession

    directory = args.log_dir
    journal = Journal(directory / "usb.jsonl")
    validation_error = worker_selection_error(args)

    def event(kind, **fields):
        journal.log(kind, **fields)
        print(MARKER + json.dumps({"event": kind, **fields}, ensure_ascii=False), flush=True)

    if validation_error:
        event("worker_failed", error="TestFailure: " + validation_error)
        journal.close()
        return 1

    class TracedTransport:
        def __init__(self, wrapped):
            self.wrapped = wrapped

        def write_report(self, report, *, timeout_ms=None):
            journal.log("usb_out", hex=bytes(report).hex())
            self.wrapped.write_report(report, timeout_ms=timeout_ms)

        def read_report(self, timeout_ms):
            try:
                report = self.wrapped.read_report(timeout_ms)
            except TransportTimeout:
                if timeout_ms >= 100:
                    journal.log("usb_timeout", timeout_ms=timeout_ms)
                raise
            journal.log("usb_in", hex=bytes(report).hex())
            return report

        def close(self):
            self.wrapped.close()

    class VerifiedTarget(IceTarget):
        """只增加退出前的板内代码复核；运行/暂停/断点仍使用生产实现。"""
        def halt(self):
            super().halt()
            if args.halt_settle_ms:
                time.sleep(args.halt_settle_ms / 1000)

        def close(self):
            try:
                self.restore_breakpoints()
                if self._halt_failure is not None or self._communication_failure is not None or self.running:
                    event("cleanup_unverified", breakpoints=[f"{x:06X}" for x in self.breakpoints])
                    raise TestFailure("通信失败，无法确认停止状态或断点恢复")
                native_verify(self.session, self.image, journal, "退出后")
                event("cleanup_verified", bytes=len(self.image))
                restore = getattr(args, 'restore_overlay', None)
                if restore is not None:
                    if self.breakpoints:
                        raise TestFailure('同会话恢复前仍有未恢复断点')
                    count = restore_overlay_in_session(self.session, args.image, restore, journal)
                    event('overlay_restored', bytes=count)
            except BaseException as exc:
                event("cleanup_failed", error=str(exc), breakpoints=[f"{x:06X}" for x in self.breakpoints])
                raise
            finally:
                self.session.transport.close()

    transport = None
    handed_to_server = False
    try:
        if args.mock:
            target = MockTarget()
            event("mock", note="仅验证本机流程，没有USB硬件测试")
        else:
            selected = select_firmware(args)
            image = read_hex(selected.image)
            transport = TracedTransport(HidTransport(args.device_path))
            transport.wrapped.open()
            session = IceSession(transport)
            version, state = session.initialize_debug()
            event("usb_ready", version=version, pc=f"{state.pc:06X}")
            native_verify(session, image, journal, "运行前")
            event("preflight_verified", bytes=len(image))
            target = VerifiedTarget(session, image)
        handed_to_server = True
        serve(target, host="127.0.0.1", port=0, once=True,
              ready=lambda address: event("server_ready", host=address[0], port=address[1]))
        event("worker_complete")
        return 0
    except BaseException as exc:
        event("worker_failed", error=f"{type(exc).__name__}: {exc}")
        logging.exception("测试服务失败")
        return 1
    finally:
        if transport is not None and not handed_to_server:
            transport.close()
        journal.close()


def worker_command(args, selection, directory):
    command = [sys.executable, "-u", Path(__file__).resolve(), "--worker", "--matrix", args.matrix,
               "--log-dir", directory, "--image", str(selection.image),
               "--image-sha256", selection.hashes["hex"]]
    if selection.elf:
        command += ["--elf", str(selection.elf), "--elf-sha256", selection.hashes["elf"]]
    if selection.map:
        command += ["--map", str(selection.map), "--map-sha256", selection.hashes["map"]]
    if args.mock:
        command.append("--mock")
    if getattr(args, 'restore_overlay', None) is not None:
        command += ['--restore-overlay', str(args.restore_overlay)]
    if args.device_path:
        command += ["--device-path", args.device_path]
    if getattr(args, "halt_settle_ms", 0):
        command += ["--halt-settle-ms", str(args.halt_settle_ms)]
    return command


class ProcessLines:
    def __init__(self, command, log, name, journal):
        env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
        self.process = subprocess.Popen([str(part) for part in command], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace",
            bufsize=1, env=env, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        self.queue = queue.Queue()
        self.log = log.open("x", encoding="utf-8", buffering=1)
        self.name, self.journal = name, journal
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        try:
            for line in self.process.stdout:
                line = line.rstrip("\r\n")
                self.log.write(line + "\n")
                self.journal.log(self.name + "_out", text=line)
                self.queue.put(line)
        finally:
            self.queue.put(None)
            self.log.close()

    def line(self, timeout):
        try:
            result = self.queue.get(timeout=max(0.001, timeout))
        except queue.Empty:
            raise TestFailure(self.name + "等待响应超时") from None
        if result is None:
            raise TestFailure(f"{self.name}已退出，退出码={self.process.poll()}；见原始日志")
        return result

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        self.reader.join(timeout=2)


class MI:
    def __init__(self, gdb, directory, journal, timeout):
        self.wire = ProcessLines([gdb, "-nx", "-nh", "--quiet", "--interpreter=mi2"], directory / "gdb.log", "gdb", journal)
        self.token = 0
        self.stops = deque()
        self.running = False
        self.timeout = timeout
        self.journal = journal

    def consume(self, line):
        if line.startswith("*running"):
            self.running = True
        elif line.startswith("*stopped"):
            self.running = False
            self.stops.append(line)

    def command(self, command, expected=("done",), timeout=None):
        self.token += 1
        prefix = str(self.token) + "^"
        self.journal.log("gdb_command", token=self.token, command=command)
        self.wire.process.stdin.write(str(self.token) + command + "\n")
        self.wire.process.stdin.flush()
        deadline = time.monotonic() + (timeout or self.timeout)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TestFailure("GDB命令超时：" + command)
            line = self.wire.line(remaining)
            self.consume(line)
            if line.startswith(prefix):
                kind = line[len(prefix):].split(",", 1)[0]
                if kind not in expected:
                    raise TestFailure("GDB命令失败：" + command + "；" + line)
                if kind == "running":
                    self.running = True
                return line

    def stop_event(self):
        deadline = time.monotonic() + self.timeout
        while not self.stops:
            if deadline <= time.monotonic():
                raise TestFailure("GDB未收到目标停止事件")
            self.consume(self.wire.line(deadline - time.monotonic()))
        return self.stops.popleft()

    def pc(self):
        line = self.command('-data-evaluate-expression "$pc"')
        match = re.search(r'value="(0x[0-9a-fA-F]+|[0-9]+)(?:[" ])', line)
        if not match:
            raise TestFailure("无法解析GDB返回的PC：" + line)
        return int(match[1], 0)

    def read_bytes(self, address, size):
        line = self.command(f"-data-read-memory-bytes 0x{address:x} {size}")
        chunks = re.findall(r'contents="([0-9a-fA-F]+)"', line)
        value = bytes.fromhex("".join(chunks))
        if len(value) != size:
            raise TestFailure("GDB内存读取长度不正确")
        return value


def interrupt_context(gdb, journal, label):
    """先落盘寄存器，再读取用户栈；后续读失败时保留最后一个有效现场。"""
    reply = gdb.command('-data-list-register-values x')
    values = {int(n): int(v, 16) for n, v in
              re.findall(r'number="(\d+)",value="(0x[0-9a-fA-F]+)"', reply)}
    if not all(n in values for n in range(29)):
        raise TestFailure('中断现场缺少完整的MCS251寄存器组')
    context = dict(pc=values[28], spx=values[25], dpx=values[24],
                   psw=values[26], psw1=values[27], registers=values)
    journal.log('isr_registers', label=label, **context)
    # 只取实际SPX以下的EDATA，绝不跨越本工程的16KiB边界。
    if not 4 <= context['spx'] < 0x4000:
        raise TestFailure(f"中断现场SPX不在可核对的EDATA范围：{context['spx']:X}")
    base = max(0, context['spx'] - 15)
    stack = gdb.read_bytes(base, context['spx'] - base + 1)
    context['frame'] = stack[-4:]
    journal.log('isr_stack', label=label, address=base, data=stack.hex())
    return context


def trace_entry_isr(gdb, journal, image):
    """诊断4字节中断帧及RETI；只对已命中的入口逐指令取证，不替换固件。"""
    entry = interrupt_context(gdb, journal, 'entry')
    # 手册RETI(INTR=1)：弹出PC15:8、PC7:0、PC23:16、PSW1。
    # 因而按EDATA地址递增排列的帧为PSW1、PC23:16、PC7:0、PC15:8。
    frame = entry['frame']
    return_pc = (frame[1] << 16) | (frame[3] << 8) | frame[2]
    journal.log('isr_frame_candidate', pc=return_pc, psw1=frame[0],
                entry_spx=entry['spx'], data=frame.hex())
    if return_pc not in image:
        raise TestFailure('入口栈不符合返回本地固件的4字节中断帧；保留现场，不继续运行')
    before = entry
    for index in range(64):
        pc = before['pc']
        if pc not in image:
            raise TestFailure(f'中断单步离开已核对镜像：{pc:06X}')
        reti = image[pc] == 0x32
        journal.log('isr_step_begin', index=index, pc=pc, reti=reti)
        gdb.stops.clear()
        gdb.command('-exec-step-instruction', expected=('running', 'done'))
        gdb.stop_event()
        after = interrupt_context(gdb, journal, f'after-{index}')
        if reti:
            expected_spx = entry['spx'] - 4
            if (before['spx'] != entry['spx'] or
                    before['frame'] != frame or
                    after['spx'] != expected_spx or after['pc'] != return_pc):
                raise TestFailure('RETI前后栈/PC与入口4字节帧不一致，详见isr_*记录')
            changed = [n for n in range(25)
                       if after['registers'][n] != entry['registers'][n]]
            if changed or after['psw1'] & 0xFE != frame[0] & 0xFE:
                journal.log('isr_context_mismatch', register_numbers=changed,
                            saved_psw1=frame[0], actual_psw1=after['psw1'])
                raise TestFailure('RETI后的通用寄存器/DPX或PSW1未恢复，详见isr_*记录')
            journal.log('isr_return_verified', pc=after['pc'], spx=after['spx'],
                        saved_psw1=frame[0], psw1=after['psw1'], steps=index + 1)
            return
        if after['pc'] == pc:
            raise TestFailure(f'中断单步PC未前进：{pc:06X}')
        before = after
    raise TestFailure('中断跟踪64条指令内未遇到RETI；保留现场，不继续自由运行')


def breakpoint_address_from_text(text, strict_classification=False, mock=False):
    if mock:
        return 0xFF0000
    symbols = ("_system_millis", "_millis_snapshot", "_led_toggle", "_software_delay")
    address = r"^[ \t]*C:[ \t]*([0-9a-fA-F]{8})[ \t]+"
    end_symbol = r"(?:[ \t]|$)"
    for symbol in symbols:
        match = re.search(address + re.escape(symbol) + end_symbol, text, re.MULTILINE)
        if match:
            return int(match[1], 16)
    # SDCC records static entries as F<module>$<function>$0$0. Keep all
    # exported candidates ahead of these, and never accept XF end labels.
    for symbol in symbols:
        static = r"F[^\s$]+\$" + re.escape(symbol[1:]) + r"\$0\$0"
        match = re.search(address + static + end_symbol, text, re.MULTILINE)
        if match:
            return int(match[1], 16)
    raise TestFailure("未找到可重复命中的函数断点地址")


def custom_breakpoint(text, args):
    """自定义MAP优先解析函数入口；没有候选时退回显式地址或关闭软件断点。"""
    if getattr(args, "no_breakpoints", False):
        return None
    explicit = getattr(args, "breakpoint_address", None)
    if explicit is not None:
        return explicit
    try:
        return breakpoint_address_from_text(text)
    except TestFailure:
        return None


def breakpoint_address(matrix, row, mock):
    if mock:
        return 0xFF0000
    if row["id"].startswith("K00"):
        return 0xFF0478  # 已由Keil MAP/列表核对的循环调用millis入口。
    if row.get("map"):
        text = Path(row["map"]).read_text(encoding="utf-8", errors="replace")
        return breakpoint_address_from_text(text, row["id"].startswith("K00"))
    path = matrix / row["id"] / (row["id"] + ".map")
    if row["id"].startswith("S00"):
        path = matrix / "baselines/S00_sdcc_original.map"
    text = path.read_text(encoding="utf-8", errors="replace")
    return breakpoint_address_from_text(text, row["id"].startswith("K00"))


def validate_run_pc(pc, image):
    """收到暂停回复不等于应用已运行，拒绝复位入口及镜像外的PC。"""
    if pc == 0xFF0000:
        raise TestFailure('运行后仍停在复位入口FF0000，不能确认应用已运行')
    if pc not in image:
        raise TestFailure(f'运行后PC={pc:06X}不在所选固件的已定义代码中')


def main_test(args):
    selection = select_firmware(args)
    row, image, elf = selection.row, selection.image, selection.elf
    if not args.gdb.is_file():
        raise TestFailure("找不到STC专用GDB：" + str(args.gdb))
    directory = args.matrix / "logs" / (datetime.now().strftime("%Y%m%d-%H%M%S-%f") + "-" + row["id"] + ("-mock" if args.mock else ""))
    directory.mkdir(parents=True)
    journal = Journal(directory / "events.jsonl")
    report = {**selection.report(), "variant": row["id"], "mode": "mock" if args.mock else "usb",
              "log_dir": str(directory), "checks": [], "hardware_passed": False,
              "breakpoints_used": False, "input_source": "custom" if row.get("custom") else "matrix",
              "input_source_id": row["id"]}
    server = None
    gdb = None
    stage = "启动"
    success = False
    worker_events = []

    def check(name, **fields):
        report["checks"].append({"name": name, "status": "PASS", **fields})
        journal.log("check_pass", name=name, **fields)
        print("[通过] " + name, flush=True)

    def server_event(line):
        if not line.startswith(MARKER):
            return None
        value = json.loads(line[len(MARKER):])
        worker_events.append(value)
        return value

    try:
        print(f"固件：{row['id']}\n日志：{directory}", flush=True)
        print("模式：本机模拟，只验证脚本流程" if args.mock else "模式：USB-ICE实板测试", flush=True)
        check("本地固件和符号校验")
        stage = "USB连接与板内固件核对"
        command = worker_command(args, selection, directory)
        server = ProcessLines(command, directory / "server.log", "server", journal)
        deadline = time.monotonic() + 20
        while True:
            event = server_event(server.line(deadline - time.monotonic()))
            if event and event["event"] == "worker_failed":
                raise TestFailure(event["error"])
            if event and event["event"] == "server_ready":
                port = event["port"]
                break
            if time.monotonic() >= deadline:
                raise TestFailure("USB初始化超时")
        if not args.mock:
            if not any(e["event"] == "preflight_verified" for e in worker_events):
                raise TestFailure("服务启动前没有完成板内固件核对")
            check("USB连接与板内全部代码核对")
        stage = "GDB连接"
        gdb = MI(args.gdb, directory, journal, args.timeout)
        gdb.command("-gdb-set pagination off")
        gdb.command("-gdb-set confirm off")
        gdb.command("-gdb-set mi-async on")
        gdb.command(f"-gdb-set remotetimeout {int(args.timeout)}")
        if elf:
            gdb.command("-file-exec-and-symbols " + json.dumps(str(elf).replace("\\", "/")))
        else:
            gdb.command('-interpreter-exec console "set architecture mcs251"')
        gdb.command(f"-target-select remote 127.0.0.1:{port}", expected=("connected", "done"))
        # 连接带来的初始停止事件不可被后面的单步/暂停误消费。
        initial = gdb.stop_event()
        check("GDB连接与读取寄存器", pc=f"{gdb.pc():06X}", stop=initial)
        gdb.command("-data-list-register-values x")
        stage = "初始指令单步"
        gdb.stops.clear()
        before = gdb.pc()
        gdb.command("-exec-step-instruction", expected=("running", "done"))
        gdb.stop_event()
        after = gdb.pc()
        if after == before:
            raise TestFailure("复位跳转单步后PC未改变")
        check("初始指令单步", before=f"{before:06X}", after=f"{after:06X}")
        run_image = None
        if not args.mock:
            from stcforge.symbols import read_hex
            run_image = read_hex(image)
        entry = getattr(args, 'entry_breakpoint', None)
        if entry is not None:
            stage = '启动入口断点'
            if run_image is None or entry not in run_image or args.no_breakpoints:
                raise TestFailure('启动入口断点要求真实固件内的地址，且不能使用--no-breakpoints')
            inserted = gdb.command(f'-break-insert *0x{entry:x}')
            match = re.search(r'number="(\d+)"', inserted)
            if not match:
                raise TestFailure('GDB未返回启动断点编号')
            number = match[1]
            gdb.stops.clear()
            gdb.command('-exec-continue', expected=('running',))
            stopped = gdb.stop_event()
            actual = gdb.pc()
            if 'reason="breakpoint-hit"' not in stopped or actual != entry:
                raise TestFailure(f'启动断点未命中{entry:06X}：{stopped}')
            gdb.command('-break-delete ' + number)
            check(stage + '命中与删除', pc=f'{actual:06X}')
            if getattr(args, 'trace_entry_isr', False):
                stage = '中断入口到RETI现场跟踪'
                trace_entry_isr(gdb, journal, run_image)
                check(stage)
            else:
                gdb.stops.clear()
                gdb.command('-exec-step-instruction', expected=('running', 'done'))
                gdb.stop_event()
                after_entry = gdb.pc()
                if after_entry == entry:
                    raise TestFailure('删除启动断点后单步未离开入口')
                check('启动断点删除后单步', pc=f'{after_entry:06X}')
        runtime_symbols = {}
        if not args.mock and selection.map:
            runtime_symbols = map_symbols(selection.map.read_text(encoding='utf-8', errors='replace'))
        for cycle in range(1, args.cycles + 1):
            stage = f"运行/暂停第{cycle}轮"
            gdb.stops.clear()
            gdb.command("-exec-continue", expected=("running",))
            time.sleep(args.run_ms / 1000)
            gdb.command("-exec-interrupt --all")
            stopped = gdb.stop_event()
            gdb.command("-data-list-register-values x")
            paused_pc = gdb.pc()
            if run_image is not None:
                validate_run_pc(paused_pc, run_image)
            counters = {}
            for name in ('_tick_ms', '_heartbeat_count', '_rx_count', '_tx_count'):
                if name in runtime_symbols:
                    address = runtime_symbols[name]
                    counters[name] = int.from_bytes(gdb.read_bytes(address, 4), 'big')
            check(stage, pc=f"{paused_pc:06X}", stop=stopped, counters=counters)
        if not args.mock:
            for name, size, expected in WATCH_SYMBOLS:
                if name in selection.symbols:
                    stage = "变量初值核对：" + name
                    address = selection.symbols[name]
                    actual = gdb.read_bytes(address, size).hex()
                    if actual != expected:
                        raise TestFailure(f"{name}初值错误：地址{address:06X}，预期{expected}，实际{actual}")
                    check(stage, address=f"{address:06X}", value=actual)
        if not args.no_breakpoints:
            stage = "软件断点"
            address = getattr(args, 'breakpoint_address', None)
            if address is None:
                if args.mock:
                    address = 0xFF0000
                elif selection.breakpoint is not None:
                    address = selection.breakpoint
                elif row["id"].startswith("K00"):
                    address = 0xFF0478
                else:
                    address = breakpoint_address(args.matrix, row, False)
            elif run_image is None or address not in run_image:
                raise TestFailure('指定的主循环断点必须位于真实固件内')
            inserted = gdb.command(f"-break-insert *0x{address:x}")
            match = re.search(r'number="(\d+)"', inserted)
            if not match:
                raise TestFailure("GDB未返回断点编号")
            number = match[1]
            report["breakpoints_used"] = True
            report["breakpoint_address"] = f"{address:06X}"
            gdb.stops.clear()
            gdb.command("-exec-continue", expected=("running",))
            stop = gdb.stop_event()
            actual_pc = gdb.pc()
            if 'reason="breakpoint-hit"' not in stop or actual_pc != address:
                raise TestFailure(f"未命中预期断点{address:06X}：{stop}")
            gdb.command("-break-delete " + number)
            check("软件断点命中与删除", address=f"{address:06X}")
            stage = "断点删除后单步"
            gdb.stops.clear()
            gdb.command("-exec-step-instruction", expected=("running", "done"))
            gdb.stop_event()
            actual_pc = gdb.pc()
            if actual_pc == address:
                raise TestFailure("断点删除后单步未离开该地址")
            check(stage, pc=f"{actual_pc:06X}")
        stage = "断开与断点恢复复核"
        gdb.command("-target-detach")
        gdb.command("-gdb-exit", expected=("exit", "done"))
        gdb.wire.process.wait(timeout=5)
        server.process.wait(timeout=8)
        server.reader.join(timeout=2)
        while not server.queue.empty():
            line = server.queue.get_nowait()
            if line is not None:
                server_event(line)
        if server.process.returncode:
            raise TestFailure("服务端退出失败，见server.log")
        if not args.mock and not any(e["event"] == "cleanup_verified" for e in worker_events):
            raise TestFailure("缺少退出后的板内代码复核，不能确认断点已恢复")
        check("退出与代码恢复复核" if not args.mock else "模拟服务正常退出")
        success = True
        report["hardware_passed"] = not args.mock
        return 0
    except (Exception, KeyboardInterrupt) as exc:
        report["failure"] = {"stage": stage, "error": f"{type(exc).__name__}: {exc}"}
        journal.log("failure", **report["failure"])
        print(f"[失败] {stage}：{exc}", flush=True)
        return 1
    finally:
        # 关闭本脚本创建的GDB，让生产server执行其停止/断点恢复逻辑。
        # 不杀其他GDB、不自动下载、不在通信失败后尝试恢复执行。
        if gdb:
            gdb.wire.stop()
        if server:
            try:
                server.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                report["server_forced_stop"] = True
            server.stop()
            while not server.queue.empty():
                line = server.queue.get_nowait()
                if line is not None:
                    server_event(line)
        report["status"] = "MOCK_PASS" if success and args.mock else "PASS" if success else "FAIL"
        if args.mock:
            report["hardware_passed"] = False
        report["worker_events"] = worker_events
        report["cleanup_code_verified"] = any(e["event"] == "cleanup_verified" for e in worker_events)
        (directory / "result.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        lines = [f"固件：{row['id']}", f"输入HEX：{selection.image}", f"结果：{report['status']}",
                 "模式：本机模拟（不能证明USB仿真可用）" if args.mock else "模式：真实USB-ICE + STC GDB", ""]
        lines += ["通过：" + item["name"] for item in report["checks"]]
        if report.get("failure"):
            lines += ["失败阶段：" + report["failure"]["stage"], "原因：" + report["failure"]["error"],
                      "如通信失败，停止状态及断点恢复需结合usb.jsonl/server.log核对；不要自动重试运行。"]
        lines += ["", "完整日志目录：" + str(directory)]
        (directory / "summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
        journal.log("result", status=report["status"])
        journal.close()
        print(f"结果：{report['status']}；日志：{directory}", flush=True)


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    default = Path(__file__).resolve().parent
    p.add_argument("--matrix", type=Path, default=default if (default / "manifest.json").exists() else DEFAULT_MATRIX)
    p.add_argument("--variant", help="矩阵固件编号；省略时仍使用K00，如S01、M00或完整ID")
    p.add_argument("--image", type=Path, help="自定义固件HEX；与--variant互斥，不写入设备")
    p.add_argument("--elf", type=Path, help="配合--image的调试ELF；省略时取同名.debug.elf")
    p.add_argument("--map", type=Path, help="配合--image的MAP；省略时取同名.map")
    p.add_argument("--gdb", type=Path, default=DEFAULT_GDB)
    p.add_argument("--device-path", help="多块USB-ICE连接时指定HID路径")
    p.add_argument("--cycles", type=int, default=3)
    p.add_argument("--run-ms", type=int, default=300)
    p.add_argument("--timeout", type=float, default=8)
    p.add_argument("--halt-settle-ms", type=int, choices=range(0,2001), metavar="MS", default=0, help="仅诊断：暂停确认后延迟0..2000毫秒读取快照，默认0保持生产时序")
    p.add_argument("--no-breakpoints", action="store_true", help="只测单步/运行/暂停/变量，不写软件断点")
    p.add_argument('--entry-breakpoint', type=lambda value: int(value, 0), help='运行主循环前先验证指定原生地址的启动断点，如0xff0497')
    p.add_argument('--trace-entry-isr', action='store_true', help='配合--entry-breakpoint：记录中断入口、逐指令寄存器/栈与RETI返回帧；不证明全速中断时序正常')
    p.add_argument('--breakpoint-address', type=lambda value: int(value, 0), help='指定运行/暂停之后的断点地址，供相同位置对照')
    p.add_argument("--mock", action="store_true", help="只验证本机流程，不访问USB硬件")
    p.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--log-dir", type=Path, help=argparse.SUPPRESS)
    p.add_argument('--restore-overlay', type=Path, help=argparse.SUPPRESS)
    p.add_argument("--image-sha256", help=argparse.SUPPRESS)
    p.add_argument("--elf-sha256", help=argparse.SUPPRESS)
    p.add_argument("--map-sha256", help=argparse.SUPPRESS)
    return p


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
    cli = parser()
    options = cli.parse_args()
    options.matrix = options.matrix.resolve()
    if options.restore_overlay is not None and (options.mock or options.image is None):
        cli.error('--restore-overlay要求显式--image，不能配合--mock')
    if options.trace_entry_isr and (options.entry_breakpoint is None or options.no_breakpoints or options.mock):
        cli.error('--trace-entry-isr要求--entry-breakpoint，不能配合--no-breakpoints或--mock')
    if options.variant and options.image:
        cli.error("--variant 与 --image 互斥")
    if options.variant and (options.elf or options.map):
        cli.error("--variant 不能与 --elf/--map 混用")
    if not 1 <= options.cycles <= 20 or not 50 <= options.run_ms <= 3000 or not 2 <= options.timeout <= 30:
        cli.error("cycles应为1..20，run-ms应为50..3000，timeout应为2..30秒")
    try:
        if options.worker:
            if options.log_dir is None:
                cli.error("worker缺少日志目录")
            if not options.image:
                cli.error("worker必须接收父进程选定的--image")
            logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
            sys.exit(worker(options))
        sys.exit(main_test(options))
    except (TestFailure, OSError, ValueError, KeyError) as exc:
        print("[失败] " + str(exc), file=sys.stderr)
        sys.exit(1)
