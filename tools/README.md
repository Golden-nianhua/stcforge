# STCForge 维护工具

| 目录 | 用途 |
| --- | --- |
| [gdb/](gdb/) | 准备 GDB 源码、构建和打包。见[构建说明](../docs/build.md)。 |
| [isp/](isp/) | 从协议分析数据生成型号库、硬件选项表和配置模板。生成的 C++ 数据放在 `src/isp/`，用户配置模板放在 `docs/examples/hardware-families/`。 |
| [diagnostics/](diagnostics/) | USB-ICE 报文记录、固件矩阵和专项探针。部分脚本会操控目标或写入固件，仅用于排查，不是常规构建、下载和调试的依赖。 |
| [package/](package/) | 组装 Windows x64 ZIP，并针对解压后的程序验证不依赖开发环境。见[构建说明](../docs/build.md#windows-x64-发布包)。 |
| [tests/](tests/) | C++ ISP 回归测试、Python 服务端测试及真实 GDB 离线联调。 |

日常直接使用 `stc-isp`、`stcforge` 和 `stc-gdb`。
