# GDB 默认 MI 异步修正与实板验收

日期：2026-11-15。用户确认网页调试器可正常使用后，在同一块当前连接的板卡上进行 GDB 对照。

## 确认修正的问题

原自定义 GDB 沿用上游 MI 同步默认值。真实 MI2 客户端发出 continue 后，MI interrupt 不会及时得到处理；服务端日志未收到 Ctrl-C。显式启用 mi-async 后，同一会话方案连续三轮继续/暂停成功。

tools/gdb/prepare_gdb.py 现将 GDB 16.3 的 mi_async 和 mi_async_1 默认值均设为 true；用户仍可显式 set mi-async off。该改变只涉及 MI 默认值，不改变命令行 CLI 的同步执行语义。覆盖层已应用到现有 WSL 交叉构建源码，增量构建并静态链接 Windows 二进制，保留内置 Python 与随包数据目录。

新的发行路径仍为 D:/Projects/stcforge/dist/windows/stc-gdb.exe，CLion 工具链路径与服务端启动参数保持一致。SHA-256：0C4C02A55A777A1F20DAB295114F6F912DACBA128A2E1D44D8ACF9534A600575。需要结束旧调试会话后再启动，才能使用新进程。

这证明并修正了一处 GDB 默认模式问题；没有从 CLion 原失败会话中取得完整 MI 指令日志，不能认定过去所有 USB 失联都由这个默认值单独造成。

## 当前板卡上的真实 GDB 结果

没有下载固件。为避免本地 HEX 与目标不符，先只读保存了 FF0000..FF03FF 的 1024 字节代码，生成 .cache/web-working-device-readback-20261115.hex，供本次 GDB 本地指令窗口使用。它不是新的发布固件。

使用生产 stcforge gdbserver --usb、hidapi、真实 Windows MCS-251 GDB 的 MI2 接口；不再显式设置 mi-async。

| 验收 | 结果 |
|---|---|
| 默认异步模式 | show mi-async 为 on |
| 初始单指令步进 | FF0000 → FF002C |
| 三轮继续、MI interrupt、读取 PC | 均返回 SIGINT 停止与寄存器 |
| 软件断点 | FF000D 命中，GDB 报 breakpoint-hit |
| 删除断点后单步 | FF000D → FF000F |
| 正常 detach | 成功，服务端退出码 0 |
| 调试后回读代码 | 1024 字节全部与此前读回镜像一致，断点原字节已恢复 |

日志依次为 .cache/gdb-web-device-before-fix-20261115.jsonl（同步 MI 中断未处理）、gdb-web-device-async-20261115.jsonl（显式开启异步的对照）、gdb-web-device-after-fix-20261115.jsonl（新默认值全流程）、gdb-web-device-restored-20261115.jsonl（断点恢复回读）。

独立原生 USB 对照中，网页的长 full-run 报文和 Keil 的短报文在当前固件上都能运行并暂停；特殊入口请求和两秒等待也通过。因此未仅凭网页报文长度不同就替换生产 run 指令。

## 回归与范围

完整 143 项 STCForge 测试通过，无跳过；包含实际 SDCC 编译、源码符号与真实 GDB 联调，以及新增的默认异步双轮中断测试。模板实际生成的 CLion 服务启动命令和真实 GDB 离线联调通过；验收脚本已改为按 token 和停止事件推进，不再把单步、detach、exit 一次性写进管道。

当前板内入口字节为 02 00 2C 75，与原简单 SDCC 工程的 02 00 1F 32 不同。本次实板成功属于当前固件及其读回镜像，不能据此声称原模板固件的全部源码、变量或启动初始化异常已经验收。源码级调试必须使用与板内固件一致的 HEX/CDB/ELF。此前 SDCC 固件单步时初始化常量读取视图差异仍保留独立排查记录。

