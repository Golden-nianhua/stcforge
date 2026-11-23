"""临时改变 M02 的启动钩子返回值，核对自动启动在实板上的行为。
仅接受已核验 M02；备份原码到日志，结束时恢复并完整回读。
"""
import importlib.util
from pathlib import Path
import sys
import time
from stcforge.ice import IceSession, CMD_READ
from stcforge.symbols import read_hex
from stcforge.transport import HidTransport

spec = importlib.util.spec_from_file_location('matrix_tool', Path(__file__).with_name('test_usb_ice_matrix.py'))
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)

def main():
    if '--allow-temporary-patches' not in sys.argv:
        raise SystemExit('此探针曾触发目标失联；仅限诊断，必须显式传入--allow-temporary-patches。恢复请用recover_m02_probe.py。')
    journal = tool.Journal(Path(sys.argv[1]))
    row, path, _ = tool.load_variant(tool.DEFAULT_MATRIX, 'M02')
    original = read_hex(path)
    wire = HidTransport()
    session = None
    changed = []
    def patch(address, data):
        saved = bytes(original[address+i] for i in range(len(data)))
        journal.log('patch_backup', address=f'{address:06X}', original=saved.hex(), replacement=data.hex())
        changed.append((address,saved))
        session.write_memory(5,address,data)
        got = session._data_exchange(CMD_READ, b'\x05'+address.to_bytes(4,'big')+bytes([len(data)]), expected_data_length=len(data)).data
        if got != data: raise RuntimeError('patch readback mismatch')
    try:
        wire.open()
        session = IceSession(wire)
        session.initialize_debug()
        tool.native_verify(session,original,journal,'before')
        assert bytes(original[0xFF00BB+i] for i in range(6)) == bytes.fromhex('c2af758201aa')
        if '--auto-startup' in sys.argv:
            patch(0xFF00BF,b'\x00')
        patch(0xFF0497,b'\xb9')
        session.step(bytes(original[0xFF0000+i] for i in range(4)))
        session.resume()
        deadline = time.monotonic()+2
        while time.monotonic()<deadline:
            event=session.poll_event(100)
            if event is not None:
                state=session.read_state()
                journal.log('stop', pc=f'{state.pc:06X}', state=state.raw.hex())
                print('STOP', f'{state.pc:06X}', flush=True)
                if state.pc == 0xFF0497: break
        else:
            session.halt(expect_running=True)
            state=session.read_state()
            journal.log('halt',pc=f'{state.pc:06X}',state=state.raw.hex())
            print('HALT',f'{state.pc:06X}',flush=True)
    finally:
        if session is not None and changed:
            try:
                wire.close()
                wire.open()
                session=IceSession(wire)
                session.initialize_debug()
                for address,data in reversed(changed):
                    session.write_memory(5,address,data)
                tool.native_verify(session,original,journal,'after')
                journal.log('restored',code_unchanged=True)
                print('RESTORED',flush=True)
            except Exception as exc:
                journal.log('restore_failed',error=str(exc))
                raise
        wire.close()
        journal.close()

if __name__=='__main__':
    sys.stdout.reconfigure(encoding='utf-8')
    main()
