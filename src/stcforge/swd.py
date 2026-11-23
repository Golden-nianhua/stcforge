"""STC Link1D SWD 调试协议与显式代码下载。"""
from dataclasses import dataclass
import logging
import os
import time

from .ice import IceDisconnectedError, IceError, IceTimeoutError, ProtocolError, State
from .target import Target, region_for
from .transport import HidTransport, TransportDisconnected, TransportError, TransportTimeout

LOG = logging.getLogger(__name__)
CONNECT, DISCONNECT, SNAPSHOT, STATUS, RUN, STEP, HALT, READ_PC = range(0x80, 0x88)
BREAKPOINT = 0x94
WRITE_CODE, ERASE_CODE_PAGE = 0x92, 0x93
FLASH_BASE, FLASH_END = 0xFF0000, 0x1000000
FLASH_PAGE_SIZE, FLASH_WRITE_SIZE = 512, 40
# 左侧是 GDB 目标共用的地址空间编号；右侧是 Link1D 线上命令。
READ_COMMANDS = {1: 0x88, 2: 0x89, 4: 0x8b, 5: 0x8c}
WRITE_COMMANDS = {1: 0x8e, 2: 0x8f, 4: 0x91}
MAX_CHUNK = 56
SLOTS = 8
# STCMON251.DLL sends the Speed dropdown index with CONNECT.
SWD_SPEED_CODES = {1000: 0, 600: 1, 300: 2, 100: 3}
DEFAULT_SWD_SPEED_KHZ = 600


def plan_code_pages(image):
    """限定为 G144K246 模板使用的代码窗；不接受 EEPROM 或 16 位 HEX。"""
    reset = tuple(image.get(FLASH_BASE + i) for i in range(3))
    if None in reset or reset[0] == 0xff:
        raise ValueError("SWD 下载要求 HEX 包含 FF0000 的有效复位入口")
    pages = {}
    for address, value in image.items():
        if not FLASH_BASE <= address < FLASH_END:
            raise ValueError(f"SWD 下载只支持 FF0000..FFFFFF 代码区：{address:06X}")
        base = address & ~(FLASH_PAGE_SIZE - 1)
        if base not in pages:
            pages[base] = bytearray(b"\xff" * FLASH_PAGE_SIZE)
        pages[base][address - base] = value
    return tuple((base, bytes(pages[base])) for base in sorted(pages))


class FlashLoad:
    """Validate GDB's load against the local HEX before touching target flash."""

    def __init__(self, session, image, progress):
        pages = plan_code_pages(image)
        self.session = session
        self.image = image
        self.progress = progress
        self.start = pages[0][0]
        self.end = pages[-1][0] + FLASH_PAGE_SIZE
        self.expected = bytes(image.get(address, 0xff) for address in range(self.start, max(image) + 1))
        self.erased = set()
        self.received = set()
        self.finished = False

    def erase(self, address, length):
        if (self.finished or length <= 0 or address < self.start or address + length > self.end
                or address % FLASH_PAGE_SIZE or length % FLASH_PAGE_SIZE):
            raise ValueError("Invalid SWD load erase range")
        self.erased.update(range(address, address + length, FLASH_PAGE_SIZE))

    def write(self, address, data):
        offset = address - self.start
        if (self.finished or not data or offset < 0 or offset + len(data) > len(self.expected)
                or data != self.expected[offset:offset + len(data)]
                or any(page not in self.erased for page in range(
                    address & ~(FLASH_PAGE_SIZE - 1), address + len(data), FLASH_PAGE_SIZE))):
            raise ValueError("SWD load data does not match the prepared HEX")
        self.received.update(range(offset, offset + len(data)))

    def finish(self):
        if self.finished or len(self.received) != len(self.expected):
            raise ValueError("Incomplete SWD image; no flash written")
        self.session.program_code(self.image, self.progress)
        self.finished = True

    def set_entry(self, address):
        if not self.finished or address != self.start:
            raise ValueError("Invalid SWD load entry point")
        if self.session.read_pc() != address:
            self.session.set_entry_pc(address)
            if self.session.read_pc() != address:
                raise ProtocolError("Link1D did not set the SWD load entry point")


class Link1DHidTransport(HidTransport):
    device_name = "STC Link1D SWD"
    usb_ids = ((0x34bf, 0x1004), (0x34bf, 0x1005))

    def open(self):
        if not self.is_open and self.device_path is not None:
            # 即使手动指定路径，也不能误把 SWD 命令发给 USB-ICE 或 CDC 接口。
            entries = self.enumerate_devices(self._load_module())
            path = os.fsencode(self.device_path)
            if not any(entry.get("path") is not None and os.fsencode(entry["path"]) == path
                       for entry in entries):
                raise TransportDisconnected("指定路径不属于已枚举的 Link1D SWD HID 接口")
        super().open()


def pack_command(command, *, address=0, count=0, data=b""):
    if not 0 <= command <= 0xff or not 0 <= address <= 0xffffff:
        raise ValueError("Link1D 命令或 24 位地址越界")
    if not 0 <= count <= MAX_CHUNK or len(data) > MAX_CHUNK or (data and len(data) != count):
        raise ValueError("Link1D 负载长度无效")
    report = (b"\x5a" + bytes((command,)) + address.to_bytes(4, "big")
              + bytes((count,)) + data).ljust(63, b"\x00")
    return report + bytes((-sum(report) & 0xff,))


def unpack_reply(report):
    if len(report) != 64 or report[0] != 0xa5:
        raise ProtocolError("Link1D 回复不是 64 字节 A5 报告")
    if sum(report) & 0xff:
        raise ProtocolError("Link1D 回复校验和错误")
    size = report[2]
    if size > 60:
        raise ProtocolError(f"Link1D 回复长度字段越界：{size}")
    if report[1]:
        raise ProtocolError(f"Link1D 命令失败，状态 0x{report[1]:02X}")
    return report[3:3 + size]


def decode_snapshot(data, pc):
    """用独立读 PC 校对网页与 Keil 两种布局，不将未知字节当寄存器。"""
    address = pc.to_bytes(4, "big")
    short = len(data) >= 44 and data[41:44] == address[1:]
    wide = len(data) == 46 and data[42:46] == address
    if short and wide:
        raise ProtocolError("Link1D 快照布局有歧义，不能确认寄存器位置")
    if wide:
        return State(data)
    if not short:
        raise ProtocolError("Link1D 快照长度或内含 PC 与独立 PC 读取不符")
    # 网页 SWD：32字节寄存器堆、1字节保留、24位DPX、16位SPX、PSW/PSW1、
    # 1字节保留、24位PC。零扩展至 GDB 的 DPX32/SPX32/PC32。
    return State(data[:32] + b"\0" + data[33:36] + b"\0\0" + data[36:40] + address)


@dataclass(frozen=True)
class SwdStatus:
    running: bool
    breakpoint: bool


class Link1DSession:
    """每次同步请求只收一个报告；任何失步后禁止继续发包。"""
    def __init__(self, transport, *, timeout_ms=1000, speed_khz=DEFAULT_SWD_SPEED_KHZ):
        if not 1 <= timeout_ms <= 60000:
            raise ValueError("Link1D 超时必须为 1～60000 ms")
        if speed_khz not in SWD_SPEED_CODES:
            raise ValueError("Link1D SWD 速度必须为 100、300、600 或 1000 kHz")
        self.transport = transport
        self.timeout_ms = timeout_ms
        self.speed_khz = speed_khz
        self.failure = None
        self.connected = False

    def _fail(self, error):
        self.failure = error
        raise error

    def _exchange(self, command, *, expected=None, timeout_ms=None, **fields):
        if self.failure is not None:
            raise IceError("Link1D 会话通信已失败，请重新连接") from self.failure
        if not self.connected and command != CONNECT:
            raise ValueError("尚未连接 Link1D 目标")
        packet = pack_command(command, **fields)
        timeout_ms = self.timeout_ms if timeout_ms is None else timeout_ms
        try:
            self.transport.write_report(packet, timeout_ms=timeout_ms)
            data = unpack_reply(self.transport.read_report(timeout_ms))
            if expected is not None and len(data) != expected:
                raise ProtocolError(f"Link1D 命令 {command:02X} 数据长度错误：{len(data)}/{expected}")
            return data
        except TransportTimeout as exc:
            self.failure = IceTimeoutError(f"Link1D 命令 {command:02X} 等待回复超时；停止后续请求")
            raise self.failure from exc
        except (TransportError, OSError) as exc:
            self.failure = IceDisconnectedError(f"Link1D 命令 {command:02X} 通信失败：{exc}")
            raise self.failure from exc
        except IceError as exc:
            self._fail(exc)

    def connect(self):
        if self.connected:
            raise ValueError("Link1D 会话已经连接")
        data = self._exchange(CONNECT, count=1, data=bytes((SWD_SPEED_CODES[self.speed_khz],)))
        # STCMON251.DLL 检查握手数据偏移 3..5，避免把探针应答当作目标握手成功。
        if data[3:6] != b"\x06\x55\x45":
            self._fail(ProtocolError(
                "Link1D 未收到有效的 SWD 目标握手；请检查目标供电、SWD 引脚和仿真模式"))
        self.connected = True
        return data

    def read_status(self):
        value = self._exchange(STATUS, expected=1)[0]
        if value & ~0x03:
            self._fail(ProtocolError(
                f"Link1D 返回无效的 SWD 目标状态 0x{value:02X}；请检查目标供电和 SWD 连接"))
        return SwdStatus(bool(value & 1), bool(value & 2))

    def read_pc(self):
        data = self._exchange(READ_PC, expected=4)
        return int.from_bytes(data[1:], "big")

    def set_entry_pc(self, address):
        self._exchange(0x8d, address=address, expected=0)

    def read_state(self):
        snapshot = self._exchange(SNAPSHOT)
        if len(snapshot) < 44:
            self._fail(ProtocolError(f"Link1D 快照长度不足：{len(snapshot)}/44"))
        pc = self.read_pc()
        try:
            return decode_snapshot(snapshot, pc)
        except ProtocolError as exc:
            self._fail(exc)

    def initialize_debug(self):
        identity = self.connect()
        if self.read_status().running:
            self.halt()
        return identity, self.read_state()

    def resume(self):
        self._exchange(RUN)

    def _confirm_stopped(self, operation):
        # 本机协议是请求/应答加状态轮询，不等待 USB-ICE 的 06 异步事件。
        end = time.monotonic() + self.timeout_ms / 1000
        while self.read_status().running:
            if time.monotonic() >= end:
                self._fail(IceTimeoutError(f"Link1D {operation}后未确认停止"))
            time.sleep(0.01)

    def halt(self):
        self._exchange(HALT)
        self._confirm_stopped("暂停")

    def step(self):
        self._exchange(STEP)
        self._confirm_stopped("单步")

    def read_memory(self, space, address, count):
        if space not in READ_COMMANDS or not 1 <= count <= MAX_CHUNK or address + count > 0x1000000:
            raise ValueError("Link1D 读内存空间或范围不支持")
        return self._exchange(READ_COMMANDS[space], address=address, count=count, expected=count)

    def write_memory(self, space, address, data):
        if space not in WRITE_COMMANDS or not 1 <= len(data) <= MAX_CHUNK or address + len(data) > 0x1000000:
            raise ValueError("Link1D 仅允许写入 RAM、SFR，不写程序区")
        self._exchange(WRITE_COMMANDS[space], address=address, count=len(data), data=data)

    def program_code(self, image, progress=None):
        pages = plan_code_pages(image)
        if self.read_status().running:
            raise IceError("请暂停目标后再通过 Link1D 下载")

        def read_page(base):
            return b"".join(
                self.read_memory(5, base + offset, min(FLASH_WRITE_SIZE, FLASH_PAGE_SIZE - offset))
                for offset in range(0, FLASH_PAGE_SIZE, FLASH_WRITE_SIZE)
            )

        changed = 0
        for index, (base, data) in enumerate(pages, 1):
            if read_page(base) != data:
                # STCMON251.DLL (RVA 0x1e60, 0x1ed1): 0x93 per 512-byte page,
                # then 0x92 in blocks of at most 40 bytes. Ack alone is not verification.
                self._exchange(ERASE_CODE_PAGE, address=base, timeout_ms=max(5000, self.timeout_ms))
                for offset in range(0, FLASH_PAGE_SIZE, FLASH_WRITE_SIZE):
                    block = data[offset:offset + FLASH_WRITE_SIZE]
                    if block != b"\xff" * len(block):
                        self._exchange(WRITE_CODE, address=base + offset, count=len(block), data=block)
                actual = read_page(base)
                if actual != data:
                    offset = next(i for i, (a, b) in enumerate(zip(actual, data)) if a != b)
                    self._fail(ProtocolError(
                        f"SWD 下载校验失败：{base + offset:06X} "
                        f"实际 {actual[offset]:02X}，应为 {data[offset]:02X}"))
                changed += 1
            if progress is not None:
                progress(index, len(pages), changed)
        return len(pages), changed

    def set_breakpoint(self, slot, address=None):
        if not 0 <= slot < SLOTS:
            raise ValueError("Link1D 断点槽范围为 0～7")
        if address is not None and region_for(address, 1).space != 5:
            raise ValueError("Link1D 硬件断点必须在程序区")
        payload = bytes(((slot << 4) | (address is not None),))
        self._exchange(BREAKPOINT, address=address or 0, count=1, data=payload)

    def close(self):
        try:
            if self.connected and self.failure is None:
                self._exchange(DISCONNECT)
        finally:
            self.connected = False
            self.transport.close()


class Link1DTarget(Target):
    hardware_breakpoints = True

    def __init__(self, session):
        super().__init__()
        self.session = session
        self.last_hardware_break = False
        self.slots = {}
        self._next_poll = 0.0

    def read_registers(self):
        if self.running:
            raise RuntimeError("请暂停后读取 Link1D 寄存器")
        return self.session.read_state().raw

    def read_register(self, index):
        if index == 28:
            if self.running:
                raise RuntimeError("请暂停后读取 Link1D PC")
            return self.session.read_pc().to_bytes(4, "big")
        return super().read_register(index)

    def _read(self, region, address, count):
        if self.running:
            raise RuntimeError("请暂停后读取 Link1D 设备内存")
        return b"".join(self.session.read_memory(region.space, address + offset - region.base,
                                                 min(MAX_CHUNK, count - offset))
                        for offset in range(0, count, MAX_CHUNK))

    def _write(self, region, address, data):
        for offset in range(0, len(data), MAX_CHUNK):
            self.session.write_memory(region.space, address + offset - region.base,
                                      data[offset:offset + MAX_CHUNK])

    def insert_breakpoint(self, address, kind=1):
        if self.running or kind != 1 or region_for(address, 1).space != 5:
            raise ValueError("仅支持暂停时在程序区设置 Link1D 硬件断点")
        if address not in self.slots:
            slot = next((index for index in range(SLOTS) if index not in self.slots.values()), None)
            if slot is None:
                raise ValueError("Link1D 的 8 个硬件断点槽已用完")
            self.session.set_breakpoint(slot, address)
            self.slots[address] = slot

    def remove_breakpoint(self, address):
        if self.running:
            raise ValueError("运行期间不修改 Link1D 硬件断点")
        if address in self.slots:
            self.session.set_breakpoint(self.slots[address])
            del self.slots[address]

    def halt(self):
        if self.running:
            self.session.halt()
        self.running = self.last_hardware_break = False

    def step(self):
        if self.running:
            raise RuntimeError("请先暂停 Link1D 目标")
        self.last_hardware_break = False
        self.session.step()

    def resume(self):
        if self.running:
            raise RuntimeError("Link1D 目标已经运行")
        self.session.resume()
        self.running = True
        self.last_hardware_break = False
        self._next_poll = 0.0

    def poll_stop(self):
        if not self.running or time.monotonic() < self._next_poll:
            return False
        state = self.session.read_status()
        self._next_poll = time.monotonic() + 0.05
        if state.running:
            return False
        self.running = False
        self.last_hardware_break = state.breakpoint
        return True

    def restore_breakpoints(self):
        if self.session.failure is not None:
            if self.slots:
                LOG.warning("Link1D 通信失败，不能确认 %d 个硬件断点已清除", len(self.slots))
            return
        if self.running:
            self.halt()
        for address in list(self.slots):
            self.remove_breakpoint(address)

    def close(self):
        try:
            self.restore_breakpoints()
        finally:
            self.session.close()
