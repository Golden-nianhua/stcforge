"""网页协议诊断的原生 HID 桥；仅传输报文，不使用 IceSession 编解码。"""
from __future__ import annotations

import argparse
import faulthandler
import json
import sys

from diagnose_usb_ice import WindowsHid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device-path", required=True)
    args = parser.parse_args()
    faulthandler.dump_traceback_later(30, exit=True)
    transport = WindowsHid(args.device_path)
    try:
        for line in sys.stdin:
            try:
                request = json.loads(line)
                timeout = request.get("timeout", 1000)
                if not isinstance(timeout, int) or not 0 <= timeout <= 5000:
                    raise ValueError("timeout must be within 0..5000 ms")
                if request["op"] == "exchange":
                    transport.write_report(bytes.fromhex(request["hex"]), timeout_ms=timeout)
                elif request["op"] != "read":
                    raise ValueError("unknown operation")
                result = {"ok": True, "hex": transport.read_report(timeout).hex()}
            except Exception as exc:
                result = {"ok": False, "error": str(exc), "type": type(exc).__name__,
                          "winerror": getattr(exc, "winerror", None)}
            print(json.dumps(result, ensure_ascii=False), flush=True)
    finally:
        transport.close()
        faulthandler.cancel_dump_traceback_later()


if __name__ == "__main__":
    main()
