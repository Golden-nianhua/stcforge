"""备份调试代码区后装载原S00/S06，测试无断点运行；不改ISP硬件选项。

所有写入范围限于指定镜像的FF程序区；先保存完整范围的原始读回数据。
失败时只尝试重开一次、读取状态，不用假停止掩盖运行/暂停失败。
代码装载不等价于冷启动ISP烧录；日志单独注明装载途径。
"""
import argparse
from datetime import datetime
import faulthandler
import importlib.util
import json
from pathlib import Path
import sys
import time

import hid
from stcforge.ice import IceSession, CMD_READ
from stcforge.symbols import read_hex
from diagnose_usb_ice import WindowsHid, Trace

spec = importlib.util.spec_from_file_location('matrix_tool', Path(__file__).with_name('test_usb_ice_matrix.py'))
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)

# 两份原例的应用区/公共启动区地址一致；用预先核对的2字节替换点，
# 只把该处改为SJMP -2。它不使用已知会干扰早期定位的B9监控断点。
CHECKPOINTS = {
    'before-xinit-compare': (0xFF0058, 'be38'),
    'after-xinit-compare': (0xFF005C, '680e'),
    'main': (0xFF00BB, '0bfe'),
    'first-millis': (0xFF00C5, 'c0e0'),
    'main-loop': (0xFF00E7, '9aff'),
    'before-interrupts': (0xFF05CD, 'd2af'),
}

def native_read(session, address, size):
    data = bytearray()
    while len(data) < size:
        count = min(48, size-len(data))
        data.extend(session._data_exchange(CMD_READ,
            b'\x05'+(address+len(data)).to_bytes(4,'big')+bytes([count]),
            expected_data_length=count).data)
    return bytes(data)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--variant', choices=('S00','S06'))
    source.add_argument('--image', type=Path, help='加载任意本地 MCS-251 HEX；仅执行代码回读与运行/暂停检查')
    parser.add_argument('--run-ms', type=int, default=100)
    parser.add_argument('--load-only', action='store_true')
    parser.add_argument('--resume-existing', action='store_true')
    parser.add_argument('--checkpoint', choices=tuple(CHECKPOINTS),
                        help='普通SJMP自循环检查点；不使用B9软件断点')
    args=parser.parse_args()
    if not 1 <= args.run_ms <= 1000:
        parser.error('run-ms必须为1..1000')
    if args.image is not None:
        row = None
        image_path = args.image.resolve()
        image_name = image_path.stem
    else:
        row, image_path, _ = tool.load_variant(tool.DEFAULT_MATRIX, args.variant)
        image_name = args.variant
    image=read_hex(image_path)
    lo,hi=min(image),max(image)+1
    if lo != 0xFF0000 or hi > 0xFF1000:
        raise RuntimeError('拒绝超出原测试程序4KiB边界的镜像')
    directory=Path(__file__).resolve().parents[2]/'.cache'/('original-'+image_name+'-'+datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
    directory.mkdir()
    log_file=(directory/'usb.jsonl').open('x',encoding='utf-8')
    trace=Trace(None, log_file)
    devices=hid.enumerate(0x34BF,0x1002)
    if len(devices)!=1: raise RuntimeError('需要唯一USB-ICE')
    path=devices[0]['path']
    wire=None
    checkpoint_saved=None
    confirmed_halted=False
    try:
        wire=WindowsHid(path)
        trace.transport=wire
        session=IceSession(trace)
        version,state=session.initialize_debug()
        trace.log('INPUT',variant=args.variant or 'custom',image=str(image_path),path='USB-ICE code writes, not ISP',state=state.raw.hex())
        if not args.resume_existing:
            # 备份空洞也在内的完整装载范围，绝不依赖本地HEX冒充设备数据。
            saved=native_read(session,lo,hi-lo)
            (directory/'code-before.bin').write_bytes(saved)
            (directory/'backup.json').write_text(json.dumps({'base':lo,'size':len(saved),'target':str(image_path)},indent=2),encoding='utf-8')
            addresses=sorted(image)
            index=0
            while index<len(addresses):
                start=addresses[index]
                chunk=bytearray([image[start]])
                index+=1
                while index<len(addresses) and len(chunk)<48 and addresses[index]==start+len(chunk):
                    chunk.append(image[addresses[index]])
                    index+=1
                session.write_memory(5,start,chunk)
            trace.log('LOADED',bytes=len(image),backup=str(directory/'code-before.bin'))
        actual=native_read(session,lo,hi-lo)
        mismatches=[address for address,value in image.items() if actual[address-lo]!=value]
        if mismatches: raise RuntimeError(f'板内代码差异{len(mismatches)}，首个{mismatches[0]:06X}')
        trace.log('VERIFIED',bytes=len(image))
        print(f'{args.variant} loaded/verified: {len(image)} bytes; logs: {directory}',flush=True)
        if args.load_only:
            return
        session.initialize_debug()
        if args.checkpoint:
            address, expected = CHECKPOINTS[args.checkpoint]
            saved=bytes(image[address+i] for i in range(2))
            if saved.hex()!=expected:
                raise RuntimeError('检查点指令与原固件不符，拒绝修改')
            checkpoint_saved=(address,saved)
            trace.log('CHECKPOINT_BACKUP',name=args.checkpoint,address=f'{address:06X}',original=saved.hex())
            session.write_memory(5,address,b'\x80\xfe')
            if native_read(session,address,2)!=b'\x80\xfe':
                raise RuntimeError('检查点回读不一致')
        # 只单步实际原固件的复位跳转；不写任何软件断点。
        from stcforge.target import IceTarget
        target=IceTarget(session,image)
        target.step()
        trace.log('RESET_STEP',pc=f'{target.pc:06X}')
        target.resume()
        time.sleep(args.run_ms/1000)
        target.halt()
        confirmed_halted=True
        state=session.read_state()
        trace.log('HALTED',pc=f'{state.pc:06X}',state=state.raw.hex())
        print('HALTED',f'{state.pc:06X}',flush=True)
        if state.pc==0xFF0000 or state.pc not in image:
            raise RuntimeError('暂停PC未证明原程序执行')
        if checkpoint_saved is not None:
            address,saved=checkpoint_saved
            # 即使PC不符合预期，已确认暂停后也应先恢复临时指令。
            session.write_memory(5,address,saved)
            if native_read(session,address,2)!=saved:
                raise RuntimeError('检查点恢复回读失败')
            checkpoint_saved=None
            restored=native_read(session,lo,hi-lo)
            if any(restored[a-lo]!=v for a,v in image.items()):
                raise RuntimeError('检查点恢复后的完整原代码校验失败')
            trace.log('CHECKPOINT_RESTORED',address=f'{address:06X}',bytes=len(image))
            if state.pc!=address:
                raise RuntimeError(f'未到达指定检查点{address:06X}，暂停在{state.pc:06X}')
            trace.log('CHECKPOINT_PASS',name=args.checkpoint,address=f'{address:06X}')
            print('CHECKPOINT PASS',args.checkpoint,f'{address:06X}',flush=True)
            return
        if row is not None:
            for name,size in (('_watch16',2),('_watch32',4),('_tick_ms',4)):
                address=int(row['symbols'][name],16)
                data=session.read_memory(2,address,size)
                trace.log('GLOBAL',name=name,address=f'{address:06X}',data=data.hex())
                print(name,data.hex(),flush=True)
        trace.log('PASS')
    except Exception as exc:
        trace.log('FAIL',error=str(exc))
        print('FAILED:',str(exc),flush=True)
        if checkpoint_saved is not None:
            trace.log('CHECKPOINT_UNRESTORED',address=f'{checkpoint_saved[0]:06X}',original=checkpoint_saved[1].hex(),confirmed_halted=confirmed_halted)
        if wire is not None: wire.close()
        wire=None
        try:
            wire=WindowsHid(path)
            trace.transport=wire
            session=IceSession(trace)
            state=session.read_state()
            trace.log('REOPEN_STATE',pc=f'{state.pc:06X}',state=state.raw.hex())
            print('REOPEN STATE',f'{state.pc:06X}',flush=True)
            # 只有已经确认暂停或设备处于冷复位入口时才恢复临时代码；
            # 一条任意状态快照不能作为正在运行的目标已经停止的证据。
            if checkpoint_saved is not None and (confirmed_halted or state.pc==0xFF0000):
                address,saved=checkpoint_saved
                session.write_memory(5,address,saved)
                if native_read(session,address,2)!=saved:
                    raise RuntimeError('重开后的检查点恢复核验失败')
                trace.log('REOPEN_CHECKPOINT_RESTORED',address=f'{address:06X}')
                checkpoint_saved=None
        except Exception as reopen_exc:
            trace.log('REOPEN_FAILED',error=str(reopen_exc))
        raise
    finally:
        if wire is not None: wire.close()
        log_file.close()

if __name__=='__main__':
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
    faulthandler.dump_traceback_later(40,exit=True)
    try:
        main()
    finally:
        faulthandler.cancel_dump_traceback_later()
