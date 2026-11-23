# 首版验收记录

日期：2026-11-15。此次所有验证均为离线或模拟目标测试，没有连接或写入真实芯片。

## 产物

- Windows x64 GDB：`dist/windows/stc-gdb.exe`，GNU GDB 16.3 + MCS-251 覆盖层。
- Python 服务端：`stcforge gdbserver`，复用 pyOCD 0.43.1 报文层。
- Python wheel / 源码包：`dist/stcforge-0.1.0-py3-none-any.whl`、`.tar.gz`。
- Linux GDB 也已在 WSL 完成构建和真实客户端测试；可通过构建脚本复现。

Windows 可执行文件 SHA-256：
`9bdf963319afbecfa01e5860fed293bab6e971142b1465eb3ad8dcbcd6fb5dbf`。
导入表包含随包分发的 `python312.dll` 和 Windows 系统库，没有 MinGW 运行库 DLL 依赖。
以下首版记录保留作为历史验证，当前 Python 修复验收见文末。

## 实际执行的检查

- Windows：99 项测试全部通过，启用了 `STCFORGE_GDB`、`STCFORGE_SDCC`。
- Linux：99 项中 98 项通过，真实 SDCC 编译用例因未配置 Linux SDCC 而跳过。
- Windows 构建脚本完整重跑成功，五个第三方源码归档 SHA-256 均通过校验。
- GDB 源码覆盖脚本重复执行成功；两个构建脚本通过 Bash 语法检查。
- Python `compileall`、wheel/源码包构建通过。
- 在隔离的 uv 环境安装 wheel，成功导入 STCForge 和服务端；不依赖项目的可编辑安装。

真实 GDB ↔ 模拟目标验证包括：寄存器布局、16 位 int、24 位指针、内存读写、
单指令步进、软件断点、正常断开后的断点恢复、Ctrl-C 暂停，以及错误校验包不执行。
另覆盖了单步 EA 处理、SFR 与 EDATA 分离、程序区普通写入拒绝和 USB 启动参数处理。

## 真实编译器与模板符号

使用安装的 SDCC MCS-251 编译 `docs/examples/firmware/main.c`，生成 CDB/HEX 后转换成 ELF。
由 Windows GDB 连接模拟目标，验证了：

- 16 位 `counter` 值为 `0x1234`，写入后读回 `0x5678`。
- 32 位 `ticks` 值为 `0x89abcdef`。
- IE 映射到独立 SFR 窗口，值为 `0x80`。
- 函数源码行可被 GDB 查询。

模板工程的真实 CDB/HEX 转换为 77 个函数、122 个全局变量（SFR）、14 个文件静态变量、
881 条源码行，来自 12 个文件。GDB 实际查询到：

- `main.c:6` → `0xff00bb`。
- `uptime_ms` → `unsigned long`，XDATA 地址 `0x10000`。
- IE → `0x100000a8`。
- 通过 `directory` 添加 `Core/Src`、`Hardware/Src` 后，可列出实际 `main.c` 源码。

发现并修正了函数末字节范围、最后一条源码行范围和同名静态变量歧义。
同名静态变量明确跳过并报告；不会任取某个地址作为变量位置。

## 验收边界

USB-ICE 编解码已用真实抓包样例和异常输入测试。尚未完成实际硬件上的暂停、
继续、内存访问、单步及断点验收；异步全零事件仍有无法仅凭内容消除的归属边界。
代码读取来自显式指定的本地 HEX，必须与目标固件一致。

自动装载仿真固件、ISP → ICE 切换由后续 stcgal 接入承担，本轮没有改动 stcgal。
局部变量、复杂类型、完整调用栈、完整反汇编、寄存器写回和复位仍未实现。
CLion 配置方法已记录，但本轮没有进行 CLion 界面内的真实硬件验收。

## CLion 模板接入补充

2026-11-15：新增 `--source-dir`，从显式目录唯一解析 CDB 源码名；重名和缺失均报错。
Windows 全套测试更新为 100 项通过，包含真实 SDCC 与 GDB。

模板 Debug 调试目标实际构建通过，ELF 内嵌 `Core/Src`、`Drivers/Src`、`Hardware/Src`
中的 12 个源码绝对路径。GDB 能直接列出 `Core/Src/main.c`，无需再手动设置 `directory`。
Debug、Release 配置先后重载后，两份调试入口均正确保留。

模板的 `tools/tests/test_stcforge_clion.py` 使用实际生成的 Embedded GDB Server XML 启动参数，
启动 mock 服务端并通过真实 GDB MI 接口确认架构、大端、源码行、寄存器读取、单指令步进与
断开后 `--once` 服务端退出。该测试通过；没有连接 USB，也没有操作 CLion 界面。

## CLion Python 初始化修复

2026-11-15：原 Windows GDB 使用 `--without-python`，CLion 初始化先后报告
`Python scripting is not supported` 和 `Undefined info command: pretty-printer`。
现已重新构建为嵌入 CPython 3.12.13，并随目录分发运行库、标准库、原生扩展和 GDB Python 模块。
Windows 默认数据目录优先定位到 EXE 同级的 `share/gdb`，不依赖开发机绝对路径。

- Windows 全套 102 项测试通过，包含真实 SDCC、真实 GDB 和新增 Python batch / MI2 测试。
- 从临时工作目录启动，移除 `PYTHONHOME`、`PYTHONPATH` 后，Python、GDB 模块及
  `ctypes`、`socket`、`ssl` 均可导入；MCS-251 的 int 为 2 字节、指针为 3 字节。
- 真实 MI2 交互执行 CLion 的 `python import gdb; print(gdb.VERSION)` 和
  `info pretty-printer`，没有 `^error`。
- 完整复制到含空格的路径，再次通过上述 Python 专项测试。
- 实际加载已安装 CLion 2026.1 的 `default.printers`、`default.commands`，
  注册打印器和辅助命令成功。
- 模板实际生成的 mock 启动命令与 GDB MI 联调再次通过。
- 正式 EXE 路径保持 `dist/windows/stc-gdb.exe`；旧版备份在 `.cache/stc-gdb-before-python.exe`。

测试期间发现 Windows 与 WSL 共用了工程 `.venv`，已将冲突环境移至
`.cache/venv-linux-conflict-20261115-1352`，并用 Windows uv 重建 Python 3.12.13 环境和 USB 依赖。
新增 `.python-version` 固定 3.12；WSL 测试必须使用单独的 `UV_PROJECT_ENVIRONMENT`。
当前只枚举确认 USB-ICE 接口存在，没有启动真实硬件调试会话。

## USB-ICE 首次实板连接与步进

2026-11-15：用户授权直接测试已连接的开发板，本节更新上述离线阶段的验收边界。
修复两项实际启动问题：

- HID 默认阻塞模式使旧事件清理的 `read(size, 0)` 永久等待，首次握手无法发出。
  现于打开句柄后设置非阻塞模式；设置失败会关闭句柄并报告错误。
- 设备已经暂停时不再确认暂停命令，旧服务端因此超时退出。
  现于确认超时后读取并严格验证完整 CPU 快照，状态不可读时仍失败。

实测设备返回 `V4.0`，USB 模式服务端成功监听 `127.0.0.1:3333`。
真实 Windows MCS-251 GDB 加载模板 Debug ELF，成功连接、读取 PC/SPX/PSW/PSW1 与 IE，
并将 PC 从 `FF001F` 单步到 `FF0029`，最后正常 detach，`--once` 服务端以 0 退出。
此前还以抓包中相同的零长度 PC 同步请求（保持当前 `FF0000`）和本地指令窗口，
验证单步 `FF0000 → FF001F`；该 PC 同步操作仍只限本次诊断，没有开放为通用 set_pc API。
代码字节显示仍来自本地 HEX，不能据此声称读回并核对了片内程序。

继续/暂停测试没有通过：设备确认 `08 00` 运行后，出现 HID 读错误或暂停及状态读取超时；
随后枚举或打开已知接口也可能阻塞。Windows 仍列出该 HID 节点，这不等于接口可以通讯。
目前不能确定是程序初始化、调试上下文还是其他设备行为导致，未归因于具体时钟配置。
主机进程已退出；后续实机验证需要重新让设备进入可响应的 ICE 状态。
未执行 ISP 烧录或断点代码补丁；全速继续、运行中暂停及软件断点仍未通过实板验收。

补充回归后 Windows 112 项测试通过，包括新的零超时读取、非阻塞配置失败清理、
暂停无确认时的合法快照确认，以及快照缺失/长度/校验/类型错误拒绝。
模板 CLion 启动等待由 1500 ms 调至 3000 ms，为握手及暂停状态确认预留时间。

## 连接后失联的时钟路径定位

2026-11-15：在用户本轮 CLion 会话失败后，板卡重新打开时可查询 `V4.0`，
CPU 快照仍为复位上下文 `PC=FF0000`。本轮没有复现完整 CLion UI 命令序列；
现有 idea.log 只记到连接后结束及 `-exec-interrupt` 超时，不包含正常的全部 MI/RSP 请求。
不能据此断定 CLion 具体在哪条启动命令触发失联。

使用当时匹配的 Debug HEX 和 IceTarget 逐指令执行：

- 从 `FF0000` 经 SDCC 启动代码，共约 151 步到达 `clock_init()` 的 `FF026D`，通信正常。
- 继续执行，旧镜像 `FF03A3` 切换 CPU 至 HPLL2/2，`FF03B0` 将 CLKDIV 写为 2（90 MHz）。
- 随后在 `FF03BB` 的 `mov a,@dpx` 单步请求处未收到回复；此时尚未执行 HSIO 选择写入。
  再次枚举接口也阻塞，诊断子进程受限时保护退出，没有遗留服务端。

证据将问题缩小到该时钟切换附近，没有证明 CPU 频率、Flash 等待、PLL 或 USB 时钟中的哪一项是根因。
资料核对未找到“USB-ICE 必须低于某主频”的明确限制，不把通用 EA/USB 中断说明当作 ICE 专用结论。

模板新增 `STC_USB_ICE_SAFE_CLOCK`（默认 ON，仅 Debug 生效）：CPU 改用与既有 Keil 测试
例程相同来源的 IRC48M / 1（48 MHz），Release 保留 90 MHz，HSIO 均保留 180 MHz。
定时器、UART7、IAP 随 SYSCLK 编译；Debug/Release 构建与调试 ELF 生成已通过。
此方案尚未下载或完成实板复测；芯片仍保留旧固件，必须恢复 ISP 并重新执行启用下载后再调试。
服务端补充异步通信异常的运行状态和最近 RSP 请求诊断，保留原异常，便于继续定位。
Windows 全套 113 项测试通过，包含运行中轮询断连的异常与清理回归；
模板实际生成的 mock 启动命令及 GDB MI 联调通过，源码包与 wheel 已更新。

## 官方驱动对照与独立 Win32 诊断

2026-11-15 后续：Debug 48 MHz 方案未解决用户报告的 continue 失联，不能视为修复。
新增 `tools/diagnostics/diagnose_usb_ice.py`，支持直接 Win32 overlapped HID 与 hidapi 对照，
记录逐条报文、时间和底层 Windows 错误码。native 查询版本和快照成功；
无 GDB、无断点运行后，暂停时实测 WinError 1167。补发特殊 PC 写、短暂等待后仍失败；
官方 2 秒等待的完整启动流程于后续恢复设备后补验，运行确认正常，随后暂停及状态查询仍超时。
因此该等待不足以修复故障。详细证据和复现方法见 `usb-ice-diagnosis.md`。
新增 6 项诊断回归，覆盖异步读取、Windows 错误码与特殊启动的 PC 限制；
Windows 全套 119 项测试通过，这些测试不代表硬件运行已通过。

继续排查时发现官方空间 5 的只读校验入口，新增诊断参数 `--verify-image`，
回读 HEX 中的已定义字节并比较，记录 SHA-256，发现差异后阻止后续运行。
新增 3 项回归覆盖线上报文、HEX 空洞、首个差异立即停止及地址校验。
当前接口随后不可用，尚未进行真实代码读回；未据此放开 GDB 后端的代码读取接口。
Windows 全套 122 项测试通过；本轮没有改写板上固件或生产调试服务器的行为。
