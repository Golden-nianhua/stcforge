"""借用 pyOCD 0.43 的 RSP 报文线程，实现独立的 MCS-251 请求处理。

未继承 pyOCD 的 Cortex-M Target，也不冒充 pyocd gdbserver 的现成芯片支持。
仅单客户端、all-stop、线程号 1。服务默认仅监听回环地址。
"""
import logging
import socket
import sys
import time

from pyocd.gdbserver.packet_io import GDBServerPacketIOThread, ConnectionClosedException, checksum
from .target import REGISTERS, REGIONS
from .ice import IceError

LOG = logging.getLogger(__name__)

def target_xml():
    regs = "".join(f'<reg name="{name}" bitsize="{bits}" regnum="{idx}" type="uint{bits}"/>'
                   for idx, (name, bits) in enumerate(REGISTERS))
    return ('<?xml version="1.0"?><!DOCTYPE target SYSTEM "gdb-target.dtd">'
            '<target><architecture>mcs251</architecture>'
            f'<feature name="org.stcforge.mcs251.core">{regs}</feature></target>').encode()

def memory_xml(*, hardware_breakpoints=False, flash=None):
    # 调试视图的代码支持 Z0 软件补丁。声明 rom 会让 GDB 自动改用硬件断点。
    # 普通 M 写代码仍由 Target 拒绝，不代表芯片的物理程序区是 RAM。
    regions = ""
    for r in REGIONS:
        if r.space == 5 and flash is not None:
            from .swd import FLASH_PAGE_SIZE
            if r.start < flash.start:
                regions += (f'<memory type="rom" start="{r.start:#x}" '
                            f'length="{flash.start - r.start:#x}"/>')
            regions += (f'<memory type="flash" start="{flash.start:#x}" '
                        f'length="{flash.end - flash.start:#x}">'
                        f'<property name="blocksize">{FLASH_PAGE_SIZE:#x}</property></memory>')
            if flash.end <= r.end:
                regions += (f'<memory type="rom" start="{flash.end:#x}" '
                            f'length="{r.end + 1 - flash.end:#x}"/>')
        else:
            kind = "rom" if hardware_breakpoints and r.space == 5 else "ram"
            regions += f'<memory type="{kind}" start="{r.start:#x}" length="{r.end-r.start+1:#x}"/>'
    return ('<?xml version="1.0"?><!DOCTYPE memory-map SYSTEM "gdb-memory-map.dtd">'
            f'<memory-map>{regions}</memory-map>').encode()

def escape_binary(data):
    result = bytearray()
    for byte in data:
        if byte in b"$#}*":
            result.extend((ord("}"), byte ^ 0x20))
        else:
            result.append(byte)
    return bytes(result)


def unescape_binary(data):
    result = bytearray()
    pos = 0
    while pos < len(data):
        byte = data[pos]
        pos += 1
        if byte == ord("}"):
            if pos == len(data):
                raise ValueError("Incomplete RSP binary escape")
            byte = data[pos] ^ 0x20
            pos += 1
        result.append(byte)
    return bytes(result)


class SocketAdapter:
    def __init__(self, sock): self.sock = sock
    def set_timeout(self, timeout): self.sock.settimeout(timeout)
    def read(self): return self.sock.recv(8192)
    def write(self, data): return self.sock.send(data)

class Client:
    def __init__(self, sock, target, flash=None):
        self.target = target
        self.flash = flash
        self.io = GDBServerPacketIOThread(SocketAdapter(sock), 0)
        self.waiting = False
        self.detached = False
        self.last_request = None
        self.last_operation = "连接"
        self.report_hwbreak = False

    def send(self, data):
        self.io.send(b"$" + data + b"#" + checksum(data))

    def stop_reply(self, signal=5):
        self.last_operation = "读取停止状态"
        reason = (b"hwbreak:;" if signal == 5 and self.report_hwbreak
                  and self.target.last_hardware_break else b"")
        return f"T{signal:02x}thread:1;1c:".encode() + self.target.read_register(28).hex().encode() + b";" + reason

    def xfer(self, data):
        _, obj, op, annex, tail = data.split(b":", 4)
        if op != b"read": return b""
        if obj == b"features" and annex == b"target.xml": payload = target_xml()
        elif obj == b"memory-map" and not annex:
            payload = memory_xml(hardware_breakpoints=self.target.hardware_breakpoints, flash=self.flash)
        else: return b""
        off, length = (int(value, 16) for value in tail.split(b","))
        length = min(length, 2048)
        chunk = payload[off:off + length]
        return (b"l" if off + length >= len(payload) else b"m") + escape_binary(chunk)

    def dispatch(self, data):
        if data.startswith(b"qSupported"):
            hardware = self.target.hardware_breakpoints
            self.report_hwbreak = hardware and b"hwbreak+" in data.partition(b":")[2].split(b";")
            return (b"PacketSize=1000;qXfer:features:read+;qXfer:memory-map:read+;QStartNoAckMode+;"
                    + (b"hwbreak+" if hardware else b"swbreak+"))
        if data == b"QStartNoAckMode":
            self.io.set_send_acks(False)
            return b"OK"
        if data.startswith(b"qXfer:"): return self.xfer(data)
        if data == b"?": return self.stop_reply()
        if data == b"g": return self.target.read_registers().hex().encode()
        if data.startswith(b"p"): return self.target.read_register(int(data[1:], 16)).hex().encode()
        if self.flash is not None:
            if data.startswith(b"vFlashErase:"):
                address, length = (int(part, 16) for part in data.split(b":", 1)[1].split(b","))
                self.flash.erase(address, length)
                return b"OK"
            if data.startswith(b"vFlashWrite:"):
                _, address, payload = data.split(b":", 2)
                self.flash.write(int(address, 16), unescape_binary(payload))
                return b"OK"
            if data == b"vFlashDone":
                self.flash.finish()
                return b"OK"
            if data.startswith(b"P1c="):
                value = bytes.fromhex(data[4:].decode("ascii"))
                if len(value) != 4:
                    return b"E01"
                self.flash.set_entry(int.from_bytes(value, "big"))
                return b"OK"
        if data.startswith((b"P", b"G")): return b"E01"  # 未掌握寄存器写回命令。
        if data.startswith(b"m"):
            address, length = (int(v, 16) for v in data[1:].split(b","))
            return self.target.read_memory(address, length).hex().encode()
        if data.startswith(b"M"):
            args, encoded = data[1:].split(b":", 1)
            address, length = (int(v, 16) for v in args.split(b","))
            payload = bytes.fromhex(encoded.decode("ascii"))
            if length != len(payload): return b"E22"
            self.target.write_memory(address, payload)
            return b"OK"
        if data.startswith((b"Z", b"z")):
            kind, address, size = (int(v, 16) for v in data[1:].split(b","))
            if kind != int(self.target.hardware_breakpoints): return b""
            if size != 1: return b"E22"
            if data[:1] == b"Z": self.target.insert_breakpoint(address, size)
            else: self.target.remove_breakpoint(address)
            return b"OK"
        if data == b"vCont?": return b"vCont;c;s;t"
        if data.startswith(b"vCont;"):
            action = data[6:]
            if b";" in action: return b"E22"
            op, _, thread = action.partition(b":")
            if thread not in (b"", b"1", b"-1"): return b"E22"
            if op not in (b"c", b"s", b"t"): return b""
            data = op
        if data == b"s":
            self.target.step()
            return self.stop_reply()
        if data == b"c":
            self.target.resume()
            self.waiting = True
            return None
        if data == b"t":
            self.target.halt()
            return self.stop_reply(2)
        if data.startswith((b"c", b"s")): return b"E01"  # 暂不支持指定新 PC。
        if data == b"qC": return b"QC1"
        if data == b"qfThreadInfo": return b"m1"
        if data == b"qsThreadInfo": return b"l"
        if data == b"qAttached": return b"1"
        if data.startswith(b"qThreadExtraInfo"):
            return b"STC MCS-251".hex().encode()
        if data.startswith(b"H"):
            return b"OK" if data[1:2] in (b"g", b"c") and data[2:] in (b"0", b"1", b"-1") else b"E22"
        if data == b"T1": return b"OK"
        if data.startswith(b"qRcmd,"):
            command = bytes.fromhex(data[6:].decode()).decode("ascii")
            if command == "halt": self.target.halt(); return b"OK"
            if command in ("help", "info"):
                message = b"STCForge: monitor halt; registers read-only; no reset/flash support.\n"
                self.send(b"O" + message.hex().encode())
                return b"OK"
            return b"E01"
        if data == b"D" or data.startswith(b"D;"):
            self.target.restore_breakpoints()
            self.detached = True
            return b"OK"
        if data == b"k":
            self.target.restore_breakpoints()
            self.detached = True
            return None
        return b""  # RSP 要求未知扩展以空包回答。

    def run(self):
        try:
            while not self.detached:
                packet = self.io.receive(block=False)
                if packet is None:
                    # pyOCD 把 Ctrl-C 放入 Event，普通包放入 Queue。
                    # 先消费已经排队的 continue，避免先停下、随后又执行旧 continue。
                    if self.io.interrupt_event.is_set():
                        self.io.interrupt_event.clear()
                        self.last_request = b"\x03"
                        self.last_operation = "请求暂停"
                        self.target.halt()
                        self.waiting = False
                        self.send(self.stop_reply(2))
                    if self.waiting:
                        self.last_operation = "等待停止事件"
                        if self.target.poll_stop():
                            self.waiting = False
                            self.send(self.stop_reply())
                    time.sleep(0.005)
                    continue
                data = packet[1:packet.rfind(b"#")]
                self.last_request = data
                self.last_operation = "处理 GDB 请求"
                LOG.debug("RSP %r", data)
                try:
                    reply = self.dispatch(data)
                except IceError:
                    # E01会让GDB把失败读拆为更小的请求重试。ICE通信错误已失去
                    # 请求/回复同步，必须结束会话，不能再消费迟到数据。
                    raise
                except (ValueError, RuntimeError, OSError, TimeoutError) as exc:
                    LOG.warning("请求失败 %r: %s", data[:80], exc)
                    reply = b"E01"
                if reply is not None: self.send(reply)
        except ConnectionClosedException:
            pass
        except (ValueError, RuntimeError, OSError, TimeoutError) as exc:
            # 运行中轮询、Ctrl-C 和初始停止回复也会访问 USB，失败时须保留上下文。
            # 普通 dispatch 请求的错误仍由上面的 E01 回复处理。
            LOG.error("目标通信失败：阶段=%s，状态=%s，最近 GDB 请求=%r；%s",
                      self.last_operation,
                      "运行中" if self.target.running else "已暂停",
                      self.last_request, exc)
            raise
        finally:
            failing = sys.exc_info()[0] is not None
            self.io.stop()
            try:
                self.target.restore_breakpoints()
            except (ValueError, RuntimeError, OSError, TimeoutError) as exc:
                if not failing:
                    raise
                LOG.error("异常退出时恢复断点失败，保留首个通信错误：%s", exc)

def serve(target, host="127.0.0.1", port=3333, once=False, ready=None, *, flash=None):
    try:
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((host, port))
            listener.listen(1)
            address = listener.getsockname()
            print(f"STCForge GDB server: {address[0]}:{address[1]}", flush=True)
            if ready: ready(address)
            while True:
                sock, peer = listener.accept()
                LOG.info("GDB 已连接: %s", peer)
                with sock: Client(sock, target, flash).run()
                if once: break
    finally:
        failing = sys.exc_info()[0] is not None
        try:
            target.close()
        except (ValueError, RuntimeError, OSError, TimeoutError) as exc:
            if not failing:
                raise
            LOG.error("异常退出时关闭目标失败，保留首个通信错误：%s", exc)
