# STC-USB Link1D SWD 调试

## 接线和目标设置

1. 用 `stc-isp --config docs/examples/stc32g144k246-swd-simulation.toml` 制作仿真芯片，或使用 AiCube-ISP 的「使用 SWD 口进行仿真」。按实际接线选引脚。`stc-isp` 制作会擦除程序区；制作完成后给目标重新上电。已经启用 SWD 时跳过此步。
2. 使用默认引脚时，Link1D 的 **S-P3.0 / SWDDAT** 接目标 **P3.0**，**S-P3.1 / SWDCLK** 接目标 **P3.1**，两端 GND 相连。按板卡电压选择供电方式。板卡已有独立供电时，避免连接 Link1D 的 S-Vcc 输出。[STC 官方接线说明](https://www.stcaimcu.com/plugin.php?action=gooddetail&gid=3&id=xiaomy_exchange%3Aexchange)
3. 在这块开发板上，P3.0/P3.1 同时接到目标 MCU 的 USB 接口。使用这组引脚做 SWD 时，拔掉板卡的 USB 数据线，保留电脑到 Link1D 的 USB 线。开始调试前关闭官方工具、Keil 和网页 IDE 中占用此探针的会话。

## 命令行

在 STCForge 目录运行：

```powershell
D:/Code/uv/uv.exe sync --extra usb
D:/Code/uv/uv.exe run stcforge list --swd
D:/Code/uv/uv.exe run stcforge swd-probe
D:/Code/uv/uv.exe run stcforge gdbserver --swd --once --port 3333
```

有多个探针时，从 `list --swd` 找到探针路径，将路径本身以引号包住，传给
`swd-probe` 或 `gdbserver` 的 `--device-path`。单个探针自动选用。
`swd-probe` 会连接并暂停目标，读出 PC、DPX、SPX、PSW、PSW1 后关闭连接。
`swd-probe` 和 `gdbserver --swd` 默认使用 600 kHz；可通过 `--swd-speed`
选择 `100`、`300`、`600` 或 `1000`（单位 kHz）。该参数不修改芯片的 `CKCON` 寄存器。

用 `stcforge swd-flash --image path/to/firmware.hex` 下载已启用 SWD 的
STC32G144K246。下载只接受 `FF0000..FFFFFF` 的程序区，按 512 字节处理
HEX 涉及的页；页内未指定字节按 `FF` 处理，其他页不擦除。相同的页不重写，
改动页擦写后逐字节回读。不修改 EEPROM 或下载设置。`--dry-run` 只检查 HEX。

另开终端运行 `./dist/windows/stc-gdb.exe -nx -q`，加载与板上程序对应的调试 ELF：

```gdb
set architecture mcs251
set endian big
file path/to/firmware.debug.elf
target remote 127.0.0.1:3333
info registers
x/8bx $pc
stepi
hbreak main
continue
```

将 `main` 换成接下来会执行的函数或源码位置。暂停后可以读当前寄存器、内存和 ELF
中带地址的变量。正常断开时服务端会清除本会话设置的硬件断点。
在 CLion 中重新加载 STC32 模板的 CMake。`STCForge_swd_debug` 直接连接，
`STCForge_swd_flash_debug` 构建后先通过 Link1D 下载、校验，再启动服务。
首次启用可显式运行 `stc_swd_enable`，其参数取自模板的 `Misc/stc-isp-swd.toml`。

## 协议与验证

- Link1D 使用 `34BF:1004` 或 `34BF:1005` 的 HID 接口。命令为 64 字节
  `5A + 命令 + 大端地址 + 长度 + 数据 + 填充 + 校验`，回复以 `A5` 起始。
  已用官方网页 IDE 的 SWD 模块核对命令和校验，并对照 Keil 的 `STCMON251.DLL`。
  [STC 网页 IDE](https://stcide.stcaimcu.com/)
- 启动时握手并确认目标停止，独立读取 PC 校验寄存器快照。继续后轮询运行状态，
  通过独立的硬件断点命令控制 8 个槽位。代码、RAM 和 SFR 从目标读取，调试 ELF 提供符号。
- 离线联调使用真实 `stc-gdb.exe` 和模拟 Link1D，覆盖寄存器、变量、单步、继续、
  硬件断点命中及清除。待用实物验证握手、停止状态、目标代码和变量回读、单步、断点及清理。
