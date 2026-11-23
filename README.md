# STCForge

STC 下载与调试工具。`stc-isp` 负责 ISP 下载；`stcforge` 提供 GDB 服务端及 SDCC 符号转换，配合 `stc-gdb` 调试 MCS-251。UART 仿真后端已通过离线测试，尚未实机验证。

## 目录

| 路径 | 内容 |
| --- | --- |
| [`src/`](src/) | C++ 下载器、Python 调试服务端、GDB 补丁及 Windows 入口 |
| [`docs/`](docs/) | 使用说明、[配置示例](docs/examples/)、[历史实验](docs/history/README.md)和[协议资料](docs/research/) |
| [`tools/`](tools/README.md) | 构建、数据生成、组包、诊断和回归测试 |
| `dist/` | Windows 便携 ZIP 与本机调试入口 |

Windows x64 用户使用一个 ZIP，内含 `stc-isp.exe`、`stcforge.exe`、`stc-gdb.exe` 和 Python 运行库；解压后模板只需指到包内的 `bin/`。见[快速开始](docs/windows-quickstart.md)和[发布组包](docs/build.md#windows-x64-发布包)。编译、暂存和实验文件集中在 `.cache/`，不随包分发。

```text
CLion / GDB 命令行
      │
      ▼
stc-gdb.exe（真正的 mcs251 架构）
      │ GDB Remote Serial Protocol
      ▼
stcforge gdbserver（复用 pyOCD 的报文层）
      │
      ├── --mock：离线模拟目标
      ├── --usb：实验性 STC USB-ICE 后端
      ├── --uart：实验性 MCS-251 串口仿真后端
      └── --swd：实验性 STC-USB Link1D 后端

SDCC .cdb + .hex ── stcforge symbols ── .elf（源码行、简单整型全局变量）
```

## 先跑通离线调试

在本目录打开 PowerShell：

```powershell
D:/Code/uv/uv.exe sync --extra usb
D:/Code/uv/uv.exe run stcforge gdbserver --mock --once
```

另开终端：

```powershell
./dist/windows/stc-gdb.exe -nx -q -x docs/examples/mock.gdb
```

示例会读取寄存器和内存、执行一条 NOP、设置断点并运行到断点，最后断开。
模拟器仅用于协议联调，不是完整 MCS-251 CPU 模拟器。

## 使用 SDCC 符号

编译固件时启用 `--debug`，保留链接生成的 `.cdb` 和对应的 `.hex`：

```powershell
D:/Code/uv/uv.exe run stcforge symbols --cdb path/to/firmware.cdb --hex path/to/firmware.hex --output build/firmware.debug.elf --source-root path/to/project
```

转换器输出 ELF32 大端、`EM_NONE`，通过 MCS-251 GDB 解释架构。
ELF 用于符号和本地代码查看，不能拿它执行 `load` 烧录。
转换器会报告跳过的局部变量、数组、结构体、未知类型和未知存储类别，避免猜测地址。
详见 [符号转换说明](docs/symbols.md)。

## USB 调试

USB-ICE 服务端连接前，目标必须已经启用 USB 仿真，并运行与本地 HEX 一致的固件。
启用操作走 ISP，不由调试服务端隐式执行；可通过模板的 `stc_debug_enable` 调用 `stc-isp`。

```powershell
D:/Code/uv/uv.exe run stcforge list
D:/Code/uv/uv.exe run stcforge gdbserver --usb --image path/to/firmware.hex --port 3333
./dist/windows/stc-gdb.exe -nx -q
```

在 GDB 中：

```gdb
set architecture mcs251
set endian big
file build/firmware.debug.elf
directory path/to/project/Core/Src
directory path/to/project/Hardware/Src
target remote 127.0.0.1:3333
info registers
x/8bx 0x30
stepi
break main
continue
```

硬件后端按已有抓包和驱动静态证据实现，V4.0 实机已验证连接、寄存器读取与单指令步进。
USB 服务端现已采用 Keil 启动顺序：查询版本、发送 FF0000 入口请求、等待 2 秒、
读取 CPU 状态，然后监听 GDB。它建立从入口开始的新会话，不保留上次暂停位置。
报文顺序回归和本轮实板结果见 [Keil 启动流程对齐](docs/keil-startup-alignment.md)。
2026-11-15 已修正自定义 GDB 的 MI 异步默认值；当前测试固件通过真实 GDB 的继续/暂停、单步、软件断点及恢复回读。原模板固件的此前失联与初始化异常仍需使用同一份固件复验。详情见 [GDB 修正与实板验收](docs/gdb-mi-async-fix.md)。
CPU 状态、RAM 和 SFR 从设备读取；代码窗口来自 `--image` 指定的本地 HEX，启动时会显示来源。
当前不会假定空间 5 的读命令已经验证。镜像不一致会导致单步和断点恢复错误，必须使用目标实际运行的固件。
多设备时使用 `--device-path` 选择具体 HID 路径。

运行后失联时，可用 [USB-ICE 分层诊断](docs/usb-ice-diagnosis.md) 中的独立脚本，
绕开 GDB 并直接取得 Windows 错误码和原始报文。该流程用于定位，尚不代表全速运行已修复。

## Link1D SWD 调试

用 AiCube-ISP 将目标配置为 SWD 仿真模式并重新上电。接好 Link1D 后，从本目录执行：

```powershell
D:/Code/uv/uv.exe run stcforge list --swd
D:/Code/uv/uv.exe run stcforge swd-probe
D:/Code/uv/uv.exe run stcforge gdbserver --swd --once --port 3333
```

SWD 后端从目标读取代码和数据，可使用 8 个硬件断点槽。GDB 加载与板上程序对应的调试 ELF。
接线与验收步骤见 [Link1D SWD 调试](docs/link1d-swd.md)。目前通过模拟探针与真实 GDB 联调，待实板验收。

## 当前能力边界

| 能力 | 当前实现 |
| --- | --- |
| MCS-251 GDB 架构 | 29 个原始寄存器、46 字节大端布局、16 位 int、24 位指针 |
| GDB 通信 | 单客户端、all-stop、寄存器读取、内存读写、暂停、继续、单指令步进 |
| 断点 | USB-ICE 用 B9 软件断点；Link1D SWD 用硬件断点 |
| 调试符号 | 函数、源码行、简单整型全局/文件静态变量；实际转换统计为准 |
| 反汇编 | 目前只覆盖部分 source 映射指令；未知指令显式提示未解码 |
| 调用栈、局部变量、复杂类型 | 尚未实现；不伪造调用帧或变量地址 |
| 寄存器写回、复位、监视点 | 尚未实现，服务端明确返回不支持 |
| USB ICE 自动启动、烧录 | 尚未接入；不改动 stcgal |

GDB 可以查看当前帧；尚不能依赖 `next`、`finish` 或完整调用栈工作。
目标仍运行时断开连接会先暂停并恢复断点，当前不会自动继续运行。
客户端或服务进程被强制终止时，无法保证执行恢复逻辑；重新使用官方工具装载程序可以恢复代码。
软件断点对芯片 Flash/调试覆盖区的实际影响尚未确认。

## CLion

将工具链的自定义 GDB 指向 `dist/windows/stc-gdb.exe`。
Windows 版已经启用 Python；请保留 `dist/windows/` 中随附的 Python 运行库和
`share/gdb/python/`，完整复制该目录即可搬移，不需另配系统 Python。
先在终端启动 `stcforge gdbserver`，再创建 GDB Remote Debug 配置：

- GDB：使用上述自定义 GDB。
- 目标：`127.0.0.1:3333`。
- 符号文件：转换出的 `firmware.debug.elf`。
- 初始化命令：`set architecture mcs251`、`set endian big`。
- 源码路径不一致时，用 `set substitute-path 旧路径 新路径` 映射。

SDCC 的 CDB 有时只保留源码文件名。转换时可重复使用 `--source-dir Core/Src`、
`--source-dir Drivers/Src`、`--source-dir Hardware/Src`，将唯一匹配的源码绝对路径写入 ELF。
存在同名歧义时转换报错，避免打开其他例程的 `main.c`。
未显式解析源文件时，可用 GDB 的 `directory` 命令补充搜索目录。

STC32 模板的 Embedded GDB Server 入口包括 `STCForge_swd_debug`、`STCForge_usb_debug`
和 `STCForge_mock_debug`，使用 CLion 的 `MCS-251` 工具链中的自定义 GDB，
运行前构建 Debug 的 CDB/HEX 并生成调试 ELF；自动下载和复位均关闭。
模板的 `Misc/STCFORGE_DEBUG.md` 记录具体配置。SWD 入口要求连接 Link1D，USB 入口要求芯片已处于 USB-ICE 状态。

已验证模板实际生成的服务端命令和真实 GDB MI 接口的离线链路，尚未在 CLion 界面内完成硬件调试验收。

## 开发与复现

```powershell
D:/Code/uv/uv.exe run python -m unittest discover -s tools/tests -v
$env:STCFORGE_GDB = "$PWD/dist/windows/stc-gdb.exe"
$env:STCFORGE_SDCC = "D:/Code/c-env/SDCC/SDCC-4.6.0-MCS251/bin/sdcc.exe"
D:/Code/uv/uv.exe run python -m unittest discover -s tools/tests -v
```

构建方法见 [构建文档](docs/build.md)，寄存器和内存映射见 [架构说明](docs/architecture.md)。
GDB 端固定在 GNU GDB 16.3；Python 端固定 pyOCD 0.43.1，因为使用了它的内部报文接口。

STCForge 源码采用 GPL-3.0-or-later；构建出的 GDB 同样受 GNU GPL 约束。
第三方源码、依赖和来源见 [第三方说明](docs/third-party.md)。

## stc-isp ISP 下载程序

`stc-isp` 是基于 AiCube-ISP 6.97C 逆向结果重构的独立下载程序。当前 Windows 构建位于 [dist/windows/stc-isp.exe](dist/windows/stc-isp.exe)，源码和配置示例见 [docs/stc-isp.md](docs/stc-isp.md)。

```powershell
./dist/windows/stc-isp.exe --config docs/examples/stc32g144k246.toml
./dist/windows/stc-isp.exe --if usb --image firmware.hex --option cpu_mode=32 --option irc_hz=24000000
```

型号目录由逆向资料中的 1345 条记录生成，不代表所有型号都支持写入。运行 `--list-models` 查看目前已接入的 UART 和原生 USB 写入接口，详细分支见 [stc-isp 实现审计](docs/research/aicube-isp-v6.97a/stc-isp-port-audit-6.97c.md)。85 个配置族模板位于 [docs/examples/hardware-families](docs/examples/hardware-families)，Link1D 默认由探针断电上电。命令行参数会覆盖配置文件中的同名参数。
