"""在已核对的M02上，仅通过ICE指令窗口逐条检查S06启动；不下载代码。

这不是S06全速运行测试。被执行的数据写入只涉及用户RAM，预先备份并在结束恢复。
不进入S06的system_init，不写外设配置或软件断点。
"""
import importlib.util
import json
from pathlib import Path
import sys

from stcforge.ice import IceSession
from stcforge.symbols import read_hex
from stcforge.transport import HidTransport

SPEC = importlib.util.spec_from_file_location("matrix_tool", Path(__file__).with_name("test_usb_ice_matrix.py"))
TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOL)


def main():
    journal = TOOL.Journal(Path(sys.argv[1]))
    _, original_path, _ = TOOL.load_variant(TOOL.DEFAULT_MATRIX, "M02")
    row, stream_path, _ = TOOL.load_variant(TOOL.DEFAULT_MATRIX, "S06")
    original = read_hex(original_path)
    stream = read_hex(stream_path)
    wire = HidTransport()
    session = None
    saved = []
    try:
        wire.open()
        session = IceSession(wire)
        session.initialize_debug()
        TOOL.native_verify(session, original, journal, "before")
        for space, address, size in ((1, 0x100, 96), (2, 0x10000, 24)):
            saved.append((space, address, session.read_memory(space, address, size)))
        for index in range(220):
            before = session.read_state()
            if before.pc == int(row["symbols"]["_main"], 16):
                actual = session.read_memory(2, 0x10000, 24)
                journal.log("reached_s06_main", pc=f"{before.pc:06X}", data=actual.hex(), instructions=index)
                print("REACHED S06 main", actual.hex(), flush=True)
                break
            window = bytes(stream.get(before.pc + offset, 0) for offset in range(4))
            if before.pc not in stream:
                raise RuntimeError(f"S06指令流越界: {before.pc:06X}")
            journal.log("before_step", index=index, pc=f"{before.pc:06X}", bytes=window.hex(), spx=f"{before.spx:08X}")
            session.step(window)
            after = session.read_state()
            journal.log("after_step", index=index, pc=f"{after.pc:06X}", state=after.raw.hex())
            print(index, f"{before.pc:06X}", window.hex(), "->", f"{after.pc:06X}", f"SPX={after.spx:08X}", flush=True)
        else:
            raise RuntimeError("超过启动步骤上限")
    finally:
        if session is not None and wire.is_open:
            for space, address, data in saved:
                session.write_memory(space, address, data)
                if session.read_memory(space, address, len(data)) != data:
                    raise RuntimeError("RAM备份恢复校验失败")
            session.initialize_debug()
            TOOL.native_verify(session, original, journal, "after")
            journal.log("restored", code_unchanged=True, saved_ram_restored=True)
        wire.close()
        journal.close()


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
