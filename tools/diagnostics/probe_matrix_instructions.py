"""在已验证M02上逐条注入非控制流指令，核对寄存器/标志/代码读取。

使用USB-ICE单步报文的四字节指令窗口；不改Flash、不运行用户程序。
启动和结束均重建FF0000调试会话。日志保存每次指令前后完整状态。
"""
import argparse
import importlib.util
import json
from pathlib import Path
import sys
import time

from stcforge.ice import IceSession
from stcforge.symbols import read_hex
from stcforge.transport import HidTransport

SPEC = importlib.util.spec_from_file_location("matrix_tool", Path(__file__).with_name("test_usb_ice_matrix.py"))
TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOL)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", type=Path, default=TOOL.DEFAULT_MATRIX)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    row, path, _ = TOOL.load_variant(args.matrix, "M02")
    image = read_hex(path)
    journal = TOOL.Journal(args.output)
    wire = HidTransport()
    try:
        wire.open()
        session = IceSession(wire)
        version, state = session.initialize_debug()
        TOOL.native_verify(session, image, journal, "probe-before")
        journal.log("start", version=version, state=state.raw.hex())

        def step(name, code):
            before = session.read_state()
            event = session.step(bytes.fromhex(code).ljust(4, b"\0"))
            after = session.read_state()
            journal.log("injected_step", name=name, bytes=code, response=event.content.hex(), before=before.raw.hex(),
                        after=after.raw.hex(), pc=f"{after.pc:06X}", psw=f"{after.psw:02X}", psw1=f"{after.psw1:02X}",
                        dr0=after.heap[0:4].hex(), dr4=after.heap[4:8].hex(), dr12=after.heap[12:16].hex(),
                        dpx=f"{after.dpx:08X}", acc=f"{after.heap[11]:02X}")
            print(name, f"PC={after.pc:06X}", f"DR12={after.heap[12:16].hex()}", f"PSW1={after.psw1:02X}",
                  f"ACC={after.heap[11]:02X}", flush=True)
            return after

        step("DR12=0", "7E380000")
        step("WR14=24", "7E740018")
        step("R13=0", "7ED000")
        step("CMP DR12,#0", "BE380000")
        step("DEC DR12", "1B3C")
        step("DPTR=0000", "900000")
        step("DPXL=FF", "7584FF")
        step("DR4=DPX", "7F1E")
        value = step("ACC=@DR4 code reset byte", "7E1BB0")
        journal.log("native_code_result", expected=f"{image[0xFF0000]:02X}", actual=f"{value.heap[11]:02X}")
        step("DR0=DPX", "7F0E")
        step("ACC=@DR0 code reset byte", "7E0BB0")
        step("ACC=0", "E4")
        step("MOVC ACC,@ACC+DPTR", "93")
        _, state = session.initialize_debug()
        TOOL.native_verify(session, image, journal, "probe-after")
        journal.log("end", pc=f"{state.pc:06X}", code_restored=True)
    finally:
        if wire.is_open:
            try:
                session.initialize_debug()
            except Exception as exc:
                journal.log("reset_failed", error=str(exc))
        wire.close()
        journal.close()


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
