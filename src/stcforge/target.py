"""MCS-251 调试目标：地址空间、寄存器和软件断点。

USB 后端仅连接已经进入 ICE 的芯片，不负责 ISP 或装载官方仿真驱动。
"""
from dataclasses import dataclass
import logging

from .ice import IceError

LOG = logging.getLogger(__name__)

REGISTERS = [(f"r{i}", 8) for i in range(16)] + [
    (f"wr{i}", 16) for i in range(16, 32, 2)
] + [("dpx", 32), ("spx", 32), ("psw", 8), ("psw1", 8), ("pc", 32)]
REG_OFFSETS = []
_offset = 0
for _name, _bits in REGISTERS:
    REG_OFFSETS.append((_offset, _bits // 8))
    _offset += _bits // 8

@dataclass(frozen=True)
class Region:
    start: int
    end: int
    space: int
    base: int = 0
    writable: bool = True

REGIONS = (
    Region(0, 0x3fff, 1),
    Region(0x10000, 0x2ffff, 2),
    Region(0xfc2800, 0xffffff, 5, writable=False),
    Region(0x10000080, 0x100000ff, 4, base=0x10000000),
)

def region_for(address, count):
    if count <= 0 or count > 4096:
        raise ValueError("单次内存请求长度必须为 1～4096 字节")
    for region in REGIONS:
        if region.start <= address <= region.end and address + count - 1 <= region.end:
            return region
    raise ValueError(f"未映射或跨区域的地址: 0x{address:x}+{count}")

def register_slice(index):
    if not 0 <= index < len(REGISTERS):
        raise ValueError("无效的寄存器编号")
    off, size = REG_OFFSETS[index]
    return slice(off, off + size)

class Target:
    """单客户端目标公共逻辑。普通内存写入不会覆盖代码。"""
    hardware_breakpoints = False

    def __init__(self):
        self.running = False
        self.breakpoints = {}

    def read_register(self, index):
        return self.read_registers()[register_slice(index)]

    @property
    def pc(self):
        return int.from_bytes(self.read_register(28), "big")

    def read_memory(self, address, count):
        region = region_for(address, count)
        if self.running and region.space != 5:
            raise RuntimeError("当前为 all-stop 调试，请暂停后读取设备内存")
        data = bytearray(self._read(region, address, count))
        # 给 GDB 呈现原始指令，不把临时的 B9 当作用户代码。
        for addr, original in self.breakpoints.items():
            if address <= addr < address + count:
                data[addr - address] = original
        return bytes(data)

    def write_memory(self, address, data):
        if self.running:
            raise RuntimeError("运行期间不允许写内存")
        region = region_for(address, len(data))
        if not region.writable:
            raise ValueError("程序区仅允许通过断点专用路径修改")
        self._write(region, address, bytes(data))

    def insert_breakpoint(self, address, kind=1):
        if self.running or kind != 1:
            raise ValueError("仅支持暂停时设置的单字节软件断点")
        region = region_for(address, 1)
        if region.space != 5:
            raise ValueError("断点必须位于程序区")
        if address not in self.breakpoints:
            old = self._read(region, address, 1)[0]
            # 先登记，写入失败后仍可尝试恢复。
            self.breakpoints[address] = old
            self._write(region, address, b"\xb9")

    def remove_breakpoint(self, address):
        if self.running:
            raise RuntimeError("运行期间不允许修改断点")
        if address in self.breakpoints:
            region = region_for(address, 1)
            self._write(region, address, bytes([self.breakpoints[address]]))
            del self.breakpoints[address]

    def restore_breakpoints(self):
        if self.running:
            self.halt()
        for address in list(self.breakpoints):
            self.remove_breakpoint(address)

    def close(self):
        self.restore_breakpoints()

class MockTarget(Target):
    """确定性的协议测试目标，不模拟完整指令集或时序。"""
    def __init__(self):
        super().__init__()
        self.registers = bytearray(46)
        self.registers[0] = 0x2a
        self.registers[16:18] = b"\x12\x34"
        self.registers[36:40] = (0x37).to_bytes(4, "big")
        self.registers[42:46] = (0xff0000).to_bytes(4, "big")
        self.memory = {0xff0000: 0, 0xff0001: 0, 0xff0002: 0x80, 0xff0003: 0xfc}
        self.memory.update({0x30: 0x12, 0x31: 0x34, 0x100000a8: 0x80})

    def read_registers(self):
        if self.running:
            raise RuntimeError("请暂停后读取寄存器")
        return bytes(self.registers)

    def _read(self, region, address, count):
        return bytes(self.memory.get(i, 0) for i in range(address, address + count))

    def _write(self, region, address, data):
        self.memory.update({address + i: value for i, value in enumerate(data)})

    def _set_pc(self, pc):
        self.registers[42:46] = pc.to_bytes(4, "big")

    def halt(self):
        self.running = False

    def resume(self):
        self.running = True

    def step(self):
        if self.running:
            raise RuntimeError("目标正在运行")
        pc = self.pc
        opcode = self.read_memory(pc, 1)[0]
        if opcode == 0:
            self._set_pc(pc + 1)
        elif opcode == 0x80:
            rel = int.from_bytes(self.read_memory(pc + 1, 1), "big", signed=True)
            self._set_pc(pc + 2 + rel)
        else:
            raise ValueError("模拟目标只实现 NOP/SJMP")

    def poll_stop(self):
        if self.running and self.breakpoints:
            self._set_pc(min(self.breakpoints))
            self.running = False
            return True
        return False

class IceTarget(Target):
    def __init__(self, session, image):
        super().__init__()
        self.session = session
        self.image = image
        self._halt_failure = None
        self._communication_failure = None

    def _communicate(self, operation, *args, **kwargs):
        if self._communication_failure is not None:
            raise IceError("本会话通信已失败，需要重新建立 ICE 会话") from self._communication_failure
        try:
            return operation(*args, **kwargs)
        except IceError as exc:
            # ICE回复没有事务编号。超时后继续请求可能将迟到数据误配给下一请求，
            # 因而保留首个错误并禁止本会话继续通信，包括退出时的断点写回。
            self._communication_failure = exc
            raise

    def read_registers(self):
        if self.running:
            raise RuntimeError("请暂停后读取寄存器")
        state = self._communicate(self.session.read_state)
        # 快照保持线上原始字节顺序，RSP 层无需重新组装字段。
        return state.raw

    def _read(self, region, address, count):
        if region.space == 5:
            try:
                return bytes(self.image[i] for i in range(address, address + count))
            except KeyError as exc:
                raise ValueError(f"本地 HEX 不包含代码地址 0x{exc.args[0]:x}") from exc
        result = bytearray()
        while count:
            size = min(count, 54)
            result.extend(self._communicate(self.session.read_memory, region.space, address - region.base, size))
            address += size
            count -= size
        return bytes(result)

    def _write(self, region, address, data):
        for off in range(0, len(data), 48):
            self._communicate(self.session.write_memory, region.space, address + off - region.base, data[off:off + 48])

    def halt(self):
        if self._halt_failure is not None:
            raise RuntimeError("本会话暂停通信已失败，需要重新建立 ICE 会话") from self._halt_failure
        try:
            self._communicate(self.session.halt, expect_running=self.running)
        except (RuntimeError, OSError, TimeoutError) as exc:
            # 停止状态未知，不能假装已暂停，也不在退出清理时重复发命令。
            self._halt_failure = exc
            raise
        self.running = False

    def restore_breakpoints(self):
        if self._halt_failure is not None or self._communication_failure is not None:
            if self.breakpoints:
                LOG.error("通信失败，%d 个软件断点尚未恢复：%s",
                          len(self.breakpoints),
                          ", ".join(f"{address:06X}" for address in self.breakpoints))
            return
        super().restore_breakpoints()

    def resume(self):
        if self.running:
            raise RuntimeError("目标已经运行")
        # 暂停/写断点遗留的事件不能变成本轮运行的停止事件。
        for _ in range(64):
            if self._communicate(self.session.poll_event, 0) is None:
                break
        else:
            raise RuntimeError("旧 ICE 事件持续到达，拒绝继续运行")
        self._communicate(self.session.resume)
        self.running = True

    def step(self):
        if self.running:
            raise RuntimeError("请先暂停目标")
        window = self.read_memory(self.pc, 4)
        ie = self.read_memory(0x100000a8, 1)[0]
        if ie & 0x80:
            self.write_memory(0x100000a8, bytes([ie & 0x7f]))
        try:
            event = self._communicate(self.session.step, window)
            if event.pc is None:
                event = self._communicate(self.session.poll_event, self.session.timeout_ms)
                if event is None or event.pc is None:
                    raise RuntimeError("单步未返回停止 PC，无法确认目标已停下")
        except Exception:
            # 未确认停止前不能恢复中断位；交由调用者报错、暂停和恢复。
            self.running = True
            raise
        if ie & 0x80 and window[:2] != b"\xc2\xaf":
            now = self.read_memory(0x100000a8, 1)[0]
            self.write_memory(0x100000a8, bytes([now | 0x80]))

    def poll_stop(self):
        event = self._communicate(self.session.poll_event, 1)
        if event is not None:
            self.running = False
            return True
        return False

    def close(self):
        try:
            super().close()
        finally:
            self.session.transport.close()
