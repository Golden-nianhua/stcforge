"""恢复启动对照探针留下的两个已知字节；完整匹配M02才允许恢复。

先重新给开发板上电，再用uv执行本脚本。不会下载整份固件或运行程序。
读取与恢复均使用限时的原生Win32 HID接口。
"""
import importlib.util
from datetime import datetime
import faulthandler
from pathlib import Path
import sys
import hid
from stcforge.ice import IceSession, CMD_READ
from stcforge.symbols import read_hex
from diagnose_usb_ice import WindowsHid

spec = importlib.util.spec_from_file_location('matrix_tool', Path(__file__).with_name('test_usb_ice_matrix.py'))
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
PATCH_BYTES = {0xFF00BF: (0x01, 0x00), 0xFF0497: (0x0B, 0xB9),
               0xFF04F2: (0x9A, 0xB9)}

def main():
    _, image_path, _ = tool.load_variant(tool.DEFAULT_MATRIX, 'M02')
    original = read_hex(image_path)
    devices = hid.enumerate(0x34BF, 0x1002)
    if len(devices) != 1:
        raise RuntimeError(f'需要恰好一台USB-ICE设备，当前{len(devices)}台')
    log_path = Path(__file__).resolve().parents[2] / '.cache' / ('m02-probe-recovery-' + datetime.now().strftime('%Y%m%d-%H%M%S-%f') + '.jsonl')
    journal = tool.Journal(log_path)
    wire = None
    try:
        wire = WindowsHid(devices[0]['path'])
        session = IceSession(wire)
        version, state = session.initialize_debug()
        # 验证全镜像：只准许探针已登记的位置存在已知临时值。
        observed = dict(original)
        for address, allowed in PATCH_BYTES.items():
            value = session._data_exchange(CMD_READ, b'\x05'+address.to_bytes(4,'big')+b'\x01', expected_data_length=1).data[0]
            if value not in allowed:
                raise RuntimeError(f'{address:06X}不是已知临时值，拒绝写入')
            observed[address] = value
        tool.native_verify(session, observed, journal, '恢复前身份核验')
        for address, _ in PATCH_BYTES.items():
            if observed[address] != original[address]:
                session.write_memory(5, address, bytes([original[address]]))
                journal.log('byte_restored', address=f'{address:06X}', value=f'{original[address]:02X}')
        tool.native_verify(session, original, journal, '恢复后')
        print('M02已恢复，1375个代码字节全部匹配；调试会话停在复位入口。')
    finally:
        if wire is not None:
            wire.close()
        journal.close()

if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
    faulthandler.dump_traceback_later(20, exit=True)
    try:
        main()
    finally:
        faulthandler.cancel_dump_traceback_later()
