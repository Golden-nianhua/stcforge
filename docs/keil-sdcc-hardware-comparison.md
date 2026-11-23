# Keil 与 SDCC 固件的实板对照

日期：2026-11-15。本记录延续 gdb-mi-async-fix.md；不是再次宣称 SDCC 运行失联已经修复。

## 同一 SDCC Simulation Test 固件

原生空间 5 回读与 HEX 的 1914 字节全部一致，镜像 SHA-256 为 2d7b7609bbd5a0db001d81588c9b78451ff212eebe34e396de283290a79755cf。独立 MI2 GDB 绕过 CLion 后，continue 收到运行确认，interrupt 已抵达服务端，但暂停等待 1000 ms 超时。日志：.cache/sdcc-independent-gdb-20261115-1904.jsonl。

直接使用官网原始 chunk-FDBPC2DQ.js 和 sim_core.wasm，经原生 Win32 HID 桥收发，亦在 full-run 确认后 300 ms 发暂停时超时。该路径不使用 IceSession、不经过 GDB/RSP/CLion。日志：.cache/sdcc-original-web-run-20261115-1913.jsonl。工具为 tools/diagnostics/probe_web_sim.mjs 和 tools/diagnostics/web_sim_transport.py。版本/寄存器只读测试通过。

官网 JS 及 WASM 的 SHA-256 与此前审阅样本一致；脚本固定校验样本后调用原始导出函数，没有将其重写成我们自己的报文编码器。此测试覆盖协议模块及原生传输，不等价于完整网页 UI 的全部副作用。

从复位运行到分段断点时，FF0042、FF0045、FF0047、FF004A、FF004D、FF0051、FF0055、FF0058 均可停止；FF005C 未观察到断点停止。该段位于运行库 XINIT 初始化，尚未进入应用时钟或 USB 配置。日志：.cache/sdcc-fromreset-xinit-checkpoints-20261115-1934.jsonl。

单步 FF005E 的 mov a,@dr4 从 FF0777 得到 3B；空间 5 的用户常量为 00。证明读取视图存在差异，尚不能据此认定全速运行根因、ICE RAM 冲突或所有原生间接读均不可用。

分段测试中通信失败导致过临时 B9 断点遗留。FF006C、FF005E 已分别重新连接并恢复，后一轮 FF005C 测试后用户重新下载了 Keil 固件；随后新固件完整字节核对通过。因此本记录结束时没有已知未恢复的测试断点。

## 用户重新下载的 Keil 固件

来源：模板 Misc/Keil Simulation Test/Objects/Keil Simulation Test.hex。该 HEX 使用低 16 位 CODE 地址，依据 L251 MAP 加 FF0000 得到测试镜像 .cache/keil-new-native-20261115.hex，未更改原文件、未下载新的固件。

空间 5 核对板内 1234 个有效字节全部一致。使用生产 stcforge gdbserver --usb 和发行版 stc-gdb.exe 的独立 MI2 客户端：

- 初始单步 FF0000 → FF03DB。
- 三轮 continue / MI interrupt / 寄存器读取成功，停止 PC 依次 FF0145、FF0137、FF013B。
- FF0478 的软件断点命中，GDB 报 breakpoint-hit。
- 删除断点后单步到 FF047A。
- detach 成功，服务端退出 0。
- 再次回读全部 1234 字节一致，断点字节恢复。

日志：.cache/keil-new-independent-gdb-20261115-1942.jsonl、.cache/keil-new-after-gdb-verify-20261115-1943.jsonl。本次没有 Keil 源码符号接入，验证的是寄存器/指令级调试，不声称 Keil 源码变量调试已支持。

## 用户补充的官方注意事项

制作仿真芯片后必须对目标重新断电上电，带自动断电上电电路的官方工具除外。枚举出 USB-ICE 不代替这个操作。本轮后用户明确表示已重新上电。

用户提供的说明指出串口/USB monitor 占用内部 xdata/edata 最后 768 字节，具体表格列举了若干系列。不能未经该型号依据核实，把其他系列的 RAM 末地址直接套给 STC32G144K246。若其 edata 为 16 KiB 且尾部 768 字节确为保留区，计算得到 003D00..003FFF；这里仅是条件计算，尚不是该型号保留区验收。当前 Keil MAP 使用至 000135，SDCC 已观察到栈约 000100..00010C，均不足以证明尾部保留区冲突。

完整 ISP 抓包未发现单独的 monitor 镜像下载：用户 HEX 与写入数据匹配；ICE 配置只改变 MSR3 bit7。监控功能来自芯片已有系统固件是当前证据支持的解释，但内部代码位于 ROM、受保护 Flash，或启动时如何复制到 RAM，仍未直接验证。保留 RAM 的工作内容不是掉电不变的固化常量。
