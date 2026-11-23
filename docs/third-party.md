# 第三方组件和协议来源

- GNU GDB 16.3：<https://sourceware.org/pub/gdb/releases/gdb-16.3.tar.xz>。
  维护的覆盖层在 `src/native/gdb/`，集成脚本在 `tools/gdb/prepare_gdb.py`。GNU GPLv3 或后续版本。
- pyOCD 0.43.1：<https://github.com/pyocd/pyOCD>。Apache-2.0。
  当前通过 Python 依赖使用 `pyocd.gdbserver.packet_io`，不复制其 Cortex-M 目标实现。
- hidapi / Python hidapi：<https://github.com/libusb/hidapi>、<https://github.com/trezor/cython-hidapi>。
  作为 USB 可选依赖使用，许可证以各依赖发行包为准。
- GMP 6.3.0、MPFR 4.2.2：GNU 官方发行包，分别用于 GDB 的整数与浮点计算。
  GMP 为 LGPLv3+/GPLv2+ 双重授权，MPFR 为 LGPLv3+；本项目随 GDB 的 GPLv3 发布路径使用。
- Expat 2.7.3：<https://github.com/libexpat/libexpat>，MIT，用于 XML 目标描述解析。
- libiconv 1.18：<https://www.gnu.org/software/libiconv/>，库为 LGPLv2.1+，用于 Windows 字符集转换。
- Windows CPython 3.12.13：使用 uv 管理的 python-build-standalone 发行包，
  <https://github.com/astral-sh/python-build-standalone>。Windows GDB 随目录携带
  CPython、标准库、原生扩展及其依赖 DLL；随附的 `licenses/Python.txt` 保留该发行包
  的完整许可说明（包括 OpenSSL、libffi、SQLite、Microsoft 运行库等第三方组件）。
  GDB 的 GPL 许可副本位于 `licenses/GDB.txt`。
- MCS-251 指令核对：<https://github.com/gevico/sdcc-c251> 的指令文档及测试表。
  当前有限反汇编器不代表完整的 MCS-251 指令集支持。

USB-ICE 协议来自用户提供的 `simulation.pcapng` 和官方 Keil 驱动静态分析。
原分析位于模板工程的 `Misc/Reference/stc32g144k246-usb-ice-protocol.md`。
捕获 SHA-256：`7bbaebfee6682346713849116ee6a21ac3ce9e72ac09b7e39119ca07ecb8a51e`。
这里没有复制或分发官方驱动、仿真固件或原始抓包。

发布二进制时，应同时提供对应的完整可构建源码、覆盖层和第三方许可证；
仅分发这个小仓库不能替代 GNU GDB 等组件的源码提供义务。
