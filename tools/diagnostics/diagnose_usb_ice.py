"""绕过 GDB 做 USB-ICE 分层诊断；默认只查询，--run-ms 才执行运行/暂停。

Windows native 后端复现官方 DLL 的 overlapped ReadFile/GetOverlappedResult
行为，并保留底层 Windows 错误码。日志逐条刷新，进程卡住也保留最后一笔 I/O。
本工具不烧录、不写寄存器或断点。--official-start 仅在 PC 已是 FF0000 时
重发官方启动请求并等待 2 秒；--run-ms 会执行板上已有程序。
"""
from __future__ import annotations

import argparse
import ctypes as C
from ctypes import wintypes as W
import faulthandler
import hashlib
import json
import os
from pathlib import Path
import sys
import time

from stcforge.ice import IceSession, CMD_WRITE, CMD_READ
from stcforge.symbols import read_hex
from stcforge.transport import HidTransport, TransportTimeout


class WindowsHid:
    """诊断用 Win32 HID 通道，未完成的读取跨超时保留。"""

    def __init__(self, path):
        if os.name != "nt":
            raise RuntimeError("native 后端仅支持 Windows")

        class Overlapped(C.Structure):
            _fields_ = [("Internal", C.c_size_t), ("InternalHigh", C.c_size_t),
                        ("Offset", W.DWORD), ("OffsetHigh", W.DWORD), ("hEvent", W.HANDLE)]

        self.k = C.WinDLL("kernel32", use_last_error=True)
        signatures = {
            "CreateFileW": ([W.LPCWSTR, W.DWORD, W.DWORD, C.c_void_p, W.DWORD, W.DWORD, W.HANDLE], W.HANDLE),
            "CreateEventW": ([C.c_void_p, W.BOOL, W.BOOL, W.LPCWSTR], W.HANDLE),
            "ReadFile": ([W.HANDLE, C.c_void_p, W.DWORD, C.POINTER(W.DWORD), C.POINTER(Overlapped)], W.BOOL),
            "WriteFile": ([W.HANDLE, C.c_void_p, W.DWORD, C.POINTER(W.DWORD), C.POINTER(Overlapped)], W.BOOL),
            "GetOverlappedResult": ([W.HANDLE, C.POINTER(Overlapped), C.POINTER(W.DWORD), W.BOOL], W.BOOL),
            "CancelIoEx": ([W.HANDLE, C.c_void_p], W.BOOL),
            "CloseHandle": ([W.HANDLE], W.BOOL),
            "ResetEvent": ([W.HANDLE], W.BOOL),
            "WaitForSingleObject": ([W.HANDLE, W.DWORD], W.DWORD),
        }
        for name, (args, result) in signatures.items():
            fn = getattr(self.k, name)
            fn.argtypes, fn.restype = args, result
        # 官方 DLL RVA 19C7..19D8：读写、共享读写、OPEN_EXISTING、OVERLAPPED。
        self.handle = self.k.CreateFileW(os.fsdecode(path), 0xC0000000, 3, None, 3, 0x40000000, None)
        if self.handle == C.c_void_p(-1).value:
            raise C.WinError(C.get_last_error())
        self.read = Overlapped()
        self.write = Overlapped()
        self.pending = False
        self.buffer = C.create_string_buffer(65)
        for ov in (self.read, self.write):
            ov.hEvent = self.k.CreateEventW(None, True, False, None)
            if not ov.hEvent:
                error = C.get_last_error()
                self.close()
                raise C.WinError(error)

    def read_report(self, timeout_ms):
        count = W.DWORD()
        if not self.pending:
            self.k.ResetEvent(self.read.hEvent)
            if self.k.ReadFile(self.handle, self.buffer, 65, C.byref(count), C.byref(self.read)):
                return self._received(count.value)
            error = C.get_last_error()
            if error != 997:  # ERROR_IO_PENDING
                raise C.WinError(error)
            self.pending = True
        deadline = time.perf_counter() + timeout_ms / 1000
        while True:
            # 官方 DLL RVA 1BF7..1C07：bWait=FALSE，未完成则保留原请求。
            if self.k.GetOverlappedResult(self.handle, C.byref(self.read), C.byref(count), False):
                self.pending = False
                return self._received(count.value)
            error = C.get_last_error()
            if error != 996:  # ERROR_IO_INCOMPLETE
                self.pending = False
                raise C.WinError(error)
            if time.perf_counter() >= deadline:
                raise TransportTimeout(f"native 读取超时（{timeout_ms} ms）")
            time.sleep(0.001)

    def _received(self, count):
        data = self.buffer.raw[:count]
        if len(data) != 65 or data[0] != 0:
            raise RuntimeError(f"native HID 报告格式异常：{data.hex()}")
        return data[1:]

    def write_report(self, report, *, timeout_ms=None):
        wire = b"\0" + report
        if len(wire) != 65:
            raise ValueError("必须写入 64 字节负载")
        buffer = C.create_string_buffer(wire)
        count = W.DWORD()
        self.k.ResetEvent(self.write.hEvent)
        if not self.k.WriteFile(self.handle, buffer, 65, C.byref(count), C.byref(self.write)):
            error = C.get_last_error()
            if error != 997:
                raise C.WinError(error)
            result = self.k.WaitForSingleObject(self.write.hEvent, 1000 if timeout_ms is None else timeout_ms)
            if result != 0:
                # 取消并完成 I/O 后才能释放它引用的本地缓冲区。
                self.k.CancelIoEx(self.handle, C.byref(self.write))
                self.k.GetOverlappedResult(self.handle, C.byref(self.write), C.byref(count), True)
                raise TransportTimeout("native 写入超时")
            if not self.k.GetOverlappedResult(self.handle, C.byref(self.write), C.byref(count), False):
                raise C.WinError(C.get_last_error())
        if count.value != 65:
            raise RuntimeError(f"native 写入不完整：{count.value}/65")

    def close(self):
        if self.handle:
            self.k.CancelIoEx(self.handle, None)
            if self.pending:
                count = W.DWORD()
                self.k.GetOverlappedResult(self.handle, C.byref(self.read), C.byref(count), True)
            self.k.CloseHandle(self.handle)
            self.handle = None
        for ov in (self.read, self.write):
            if ov.hEvent:
                self.k.CloseHandle(ov.hEvent)
                ov.hEvent = None


class Trace:
    def __init__(self, transport, output):
        self.transport, self.output = transport, output
        self.start = time.perf_counter()

    def log(self, operation, **fields):
        row = dict(seconds=round(time.perf_counter() - self.start, 6), operation=operation, **fields)
        print(json.dumps(row, ensure_ascii=False), file=self.output, flush=True)

    def write_report(self, report, **kwargs):
        self.log("OUT", hex=report.hex())
        try:
            return self.transport.write_report(report, **kwargs)
        except Exception as exc:
            self.log("WRITE_ERROR", error=str(exc), winerror=getattr(exc, "winerror", None))
            raise

    def read_report(self, timeout_ms):
        try:
            report = self.transport.read_report(timeout_ms)
        except TransportTimeout:
            if timeout_ms:
                self.log("TIMEOUT", timeout_ms=timeout_ms)
            raise
        except Exception as exc:
            self.log("READ_ERROR", error=str(exc), winerror=getattr(exc, "winerror", None))
            raise
        self.log("IN", hex=report.hex())
        return report


def verify_image(session, image, trace):
    """按官方 DLL 3172 -> 2D92 的空间 5 读取核对 HEX 已定义的字节。

    只用于诊断。当前生产后端仍从本地 HEX 提供代码，不能用它作设备回读依据。
    不读取 HEX 空洞，不擦写代码；发现首个差异即终止，避免继续错误固件。
    """
    addresses = sorted(image)
    if not addresses or any(not 0xFC2800 <= address <= 0xFFFFFF for address in addresses):
        raise ValueError("代码核对要求 HEX 使用 FC2800..FFFFFF 范围内的原生地址")
    trace.log("VERIFY_BEGIN", bytes=len(addresses), source="device-space-5")
    offset = 0
    while offset < len(addresses):
        address = addresses[offset]
        count = 1
        while count < 48 and offset + count < len(addresses) and addresses[offset + count] == address + count:
            count += 1
        payload = b"\x05" + address.to_bytes(4, "big") + bytes((count,))
        # 3172 直接调用 2D92，不走 3FF5/4441 的 Keil 主机缓存。
        response = session._data_exchange(CMD_READ, payload, expected_data_length=count)
        expected = bytes(image[address + index] for index in range(count))
        actual = response.data
        if len(actual) != count:
            raise RuntimeError(f"设备代码读取长度异常：{len(actual)}/{count}")
        if actual != expected:
            index = next(index for index in range(count) if actual[index] != expected[index])
            trace.log("VERIFY_MISMATCH", address=f"{address + index:06X}",
                      expected=f"{expected[index]:02X}", actual=f"{actual[index]:02X}")
            raise RuntimeError(f"固件不一致：0x{address + index:06X}，"
                               f"本地 {expected[index]:02X}，设备 {actual[index]:02X}；停止后续运行")
        offset += count
    trace.log("VERIFY_PASS", bytes=len(addresses))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=("hidapi", "native"), default="hidapi")
    parser.add_argument("--device-path")
    parser.add_argument("--verify-image", type=Path,
                        help="通过官方空间 5 只读接口核对 HEX；不同则拒绝后续运行（实验性）")
    parser.add_argument("--official-start", action="store_true",
                        help="仅在 PC 已是 FF0000 时重发官方启动请求，并等待 2 秒；实验性诊断")
    parser.add_argument("--run-ms", type=int, help="运行已有固件指定毫秒，再暂停并读状态；默认只查询")
    parser.add_argument("--output", type=Path, required=True, help="新建 JSONL 日志，不覆盖已有文件")
    args = parser.parse_args(argv)
    if args.run_ms is not None and not 1 <= args.run_ms <= 5000:
        parser.error("--run-ms 必须在 1..5000")
    faulthandler.dump_traceback_later(20, exit=True)
    transport = None
    try:
        with args.output.open("x", encoding="utf-8") as output:
            trace = Trace(None, output)
            image = None
            if args.verify_image is not None:
                image = read_hex(args.verify_image)
                if not image or any(not 0xFC2800 <= address <= 0xFFFFFF for address in image):
                    raise ValueError("代码核对要求 HEX 使用 FC2800..FFFFFF 范围内的原生地址")
                trace.log("IMAGE", path=str(args.verify_image.resolve()), bytes=len(image),
                          sha256=hashlib.sha256(args.verify_image.read_bytes()).hexdigest())
            trace.log("OPEN", backend=args.backend)
            if args.backend == "native":
                import hid
                path = args.device_path
                if path is None:
                    devices = hid.enumerate(0x34BF, 0x1002)
                    if len(devices) != 1:
                        raise RuntimeError("需要恰好一台 USB-ICE，或指定 --device-path")
                    path = devices[0]["path"]
                transport = WindowsHid(path)
                trace.log("OPENED", device_path=os.fsdecode(path))
            else:
                transport = HidTransport(args.device_path)
                transport.open()
                trace.log("OPENED", device_path=os.fsdecode(transport.device_path)
                          if transport.device_path is not None else "auto")
            trace.transport = transport
            session = IceSession(trace)
            trace.log("VERSION", value=session.version())
            snapshot = session.read_state()
            trace.log("BEFORE", snapshot=snapshot.raw.hex())
            if args.official_start:
                if snapshot.pc != 0xFF0000:
                    raise RuntimeError("官方启动对照要求初始 PC=FF0000，拒绝改变现有执行位置")
                # 官方 4602 -> 2C28 -> 2BAC；仅限独立诊断，不开放通用 set_pc。
                trace.log("OFFICIAL_START", pc="FF0000", wait_ms=2000)
                session._event_exchange(CMD_WRITE, b"\0\0\xff\0\0\0")
                time.sleep(2)
                trace.log("STARTUP_STATE", snapshot=session.read_state().raw.hex())
            if image is not None:
                verify_image(session, image, trace)
            if args.run_ms is not None:
                trace.log("RUN", duration_ms=args.run_ms)
                session.resume()
                deadline = time.monotonic() + args.run_ms / 1000
                while time.monotonic() < deadline:
                    event = session.poll_event(1)
                    if event is not None:
                        trace.log("EVENT", content=event.content.hex())
                    time.sleep(0.005)
                trace.log("HALT")
                session.halt()
                trace.log("AFTER", snapshot=session.read_state().raw.hex())
            trace.log("PASS")
        return 0
    except Exception as exc:
        # with 块退出后文件已关闭，不能在此写入；I/O 错误已由 Trace 原地记录。
        print(f"诊断失败：{exc}；日志：{args.output}", file=sys.stderr)
        return 1
    finally:
        try:
            if transport is not None:
                transport.close()
        finally:
            faulthandler.cancel_dump_traceback_later()


if __name__ == "__main__":
    raise SystemExit(main())
