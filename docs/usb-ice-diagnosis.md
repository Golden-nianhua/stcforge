# USB-ICE 运行失联：分层诊断记录

记录日期：2026-11-15。当前结论是缩小故障范围，尚未修复全速运行/暂停。

## 已确认的官方实现

本机样本：`C:/Program Files (x86)/Keil/C251/BIN/STCMON251.DLL`。
32 位 PE，102400 字节，SHA-256：
`d9e71ce4b48e87e9c6852be1034c29485c0c7e6c8ca823e29bba8e41c4412aa8`。
以下均为相对 DLL 基址的 RVA。

| 环节 | 官方 DLL 证据 | 当前实现/核对结果 |
| --- | --- | --- |
| HID 打开 | `19C7..19D8`：读写权限、共享读写、OPEN_EXISTING、FILE_FLAG_OVERLAPPED | 诊断 native 通道使用相同打开参数 |
| 写报告 | `1C53..1C93`：清零 65 字节，首字节报告 ID 0，后 64 字节数据；`1CAA..1CB7` 等待异步完成 | hidapi 与 native 均写入 `00 + 64 字节报告` |
| 发起读取 | `1BB7..1BEC`：只在没有待完成请求时 ReadFile，长度 65 | native 保留同一请求，不反复取消重发 |
| 完成读取 | `1BF7..1C26`：GetOverlappedResult(bWait=FALSE)，未完成保留，下次再查；完成复制后 64 字节 | native 直接复现；正数超时不取消读取 |
| 报文编码 | `22F1..2355`：FF 5A、长度、负加和校验 | 与现有 IceSession 一致 |
| 自由运行入口 | `AG_GoStep(4)` → `48C2(-1)` → `2EA7` 发送 `08 00` | 协议命令相同；官方入口同步等到停止，GDB 服务异步等停止 |
| 条件 SFR 处理 | `5A77/5945` 的开头均检查 `[E04C] == 2`，不满足就直接返回 | 原生 USB-ICE 在 `1ACC` 设为模式 0，不能把这些 SFR 处理盲目移植过来 |
| 启动 PC 写 | `4602` → `2C28` → `2BAC(NULL, FF0000, 0, 0)`，非模式 2 随后等待 2000 ms，再读快照 | 生产入口已采用相同顺序；新实测初始化成功，运行后暂停仍超时 |

另外核对 hidapi 0.15.0 的 `windows/hid.c::hid_read_timeout()`：超时返回零，但保留
`read_pending` 和原 overlapped 读取。1 ms 轮询不等于每次取消、重建 USB 读请求。
不能仅凭“官方用 overlapped，Python 用 hidapi”断言传输方式不兼容。

Python cython-hidapi 0.15.0 的 `hid.pyx::read()` 在底层返回 -1 时只抛出
`IOError('read error')`，没有把 `hid_read_error()` 的细节带出来。因此这条错误本身不足以判因。

## 绕开 CLion/GDB 的实测

`tools/diagnostics/diagnose_usb_ice.py` 的 native 后端直接调用 Win32，复用 IceSession 编解码。
它绕过 CLion、GDB/RSP、hidapi，**没有绕过现有协议层**。

实际结果：

1. native 版本查询成功，返回 V4.0；读取完整快照成功，PC=FF0000。
2. native 发送 `08 00`，设备立即返回全零内容的 06 确认。
3. 运行约 100 ms 后发送暂停；底层读取在约 0.297 秒返回 Windows 错误 **1167**
   （ERROR_DEVICE_NOT_CONNECTED，设备没有连接）。该错误证明当时的句柄/设备不可用于该读取，
   不证明用户拔线，也不单独证明 MCU 复位、USB 重枚举或时钟故障。
4. 随后一次重新打开与查询又成功，快照 PC=FF0000。没有足够证据确定它为何回到此状态。
5. 另一次在运行前增加与官方 frame 11 相同的写请求：空间 0、地址 FF0000、数量 0。
   设备确认该请求，等待约 100 ms 后快照仍为 FF0000；运行后暂停和快照查询仍超时。
   这只说明补发请求尚未解决问题。官方还等待约 2 秒，本次没有完成该完整时序的验证，
   因而不能排除启动准备不足。暂不把它加入通用 PC 设置接口。
6. 随后诊断卡在枚举/打开阶段，受 8 秒进程保护退出。尝试用注册表记录的已知接口路径
   打开以补验 2 秒等待，返回 WinError 2；该次未能开始协议会话，不能算作协议测试结果。

以上运行测试执行的是板上现有程序，没有重新下载固件，没有写断点。
第 5 项只重放抓包中保持 FF0000 的特殊请求，不代表已经验证任意 PC 设置的语义。
当前本地 HEX 和板上 Flash 没有完成读取比对；不能把本地镜像当成片内代码已核实的证据。

本地原始日志位于 `.cache/`，每行保存时间、方向及完整 64 字节报告：

| 文件 | 内容 |
| --- | --- |
| `ice-native-query-20261115.jsonl` | native 版本与快照成功 |
| `ice-native-run-20261115.jsonl` | 运行确认、暂停、WinError 1167 |
| `ice-native-after-run-20261115.jsonl` | 重新查询成功，PC=FF0000 |
| `ice-native-official-start-20261115.jsonl` | 加入官方零数量 PC 写请求后，暂停仍超时 |

这些日志是本机诊断产物，不作为发布包中的固定文件。

## 恢复设备后的完整启动测试

2026-11-15 16:28，再次恢复到可查询的 ICE 状态后，实测序列如下：

| 日志内时间 | 操作 | 结果 |
| --- | --- | --- |
| 0.013 s | 版本与快照 | V4.0，PC=FF0000 |
| 0.017..0.041 s | FF0000/数量0 启动写 | 收到确认 |
| 2.042..2.044 s | 等待完整 2 秒后读取快照 | 完整快照，PC=FF0000 |
| 2.045..2.046 s | 运行 | 收到确认 |
| 2.148 s | 暂停 | 1000 ms 内没有回复 |
| 3.150 s | 后备快照查询 | 再次超时 |

原始日志：`.cache/ice-official-2s-20261115-162837.jsonl`。
后续重新打开同一接口，版本查询的 WriteFile 也超时，见
`.cache/ice-query-after-2s-20261115-162955.jsonl`。
本次没有出现 WinError 1167，表现为运行后接收及写入不再完成。
因此“补发启动请求并等待 2 秒”不足以解决本次故障。

16:35 准备只读核对代码时，原接口已无法打开（WinError 2），
随后 Win32_PnPEntity 查询没有列出 VID_34BF 设备。只读代码核对尚未开始，
不能把打开失败解释为空间 5 命令被设备拒绝。

## 官方只读代码校验入口

后续静态分析找到明确的设备代码读取路径，主代理已核对对应反汇编：

- `30ED` 检查下载校验选项；`315F` 压入空间 5，`3172` 直接调用 `2D92`。
- `2D92` 构造命令 `04 + space + addr32BE + count`，调用 `1F9D` 发出，再 `239B` 收数据。
  该路径没有主机缓存查询，能够用于只读核对。
- 普通代码读取 `3FF5` 先通过 `4010 → 4441` 查 Keil 缓存；未命中且允许设备访问时，
  才通过 `403A → 2D92(..., 5)` 回读。因此仅看 Keil 的反汇编窗口不能证明代码已回读。

例如设备地址 FF0000、4 字节的请求为：`FF 5A 08 04 05 00 FF 00 00 04 93`。
当前没有该读命令的 V4.0 实机成功结果；也尚不能区分设备返回的是物理 Flash
还是设备内部调试覆盖层。已有依据足以开展诊断，不足以声明生产代码读取已验收。

`--verify-image` 在运行前读取 HEX 明确定义的地址，每包最多 48 字节；跳过 HEX 空洞，
记录本地文件 SHA-256。首个字节不同就停止后续运行。该功能仅在诊断工具中开放，
GDB 后端仍按原方式从本地镜像提供代码，保持现有边界。

准备核对的本地 Debug HEX 为 26325 个定义字节，文件 SHA-256 为：
`111828b85c57b382bce8013b55cf0ffb62aa01757190f38df719215e13c0be2c`。
该值只标识当时的本地文件，没有证明板上固件相同。

同轮核对还纠正了 AG_Init 入口编号：`040D` 调用 `4602` 执行启动 PC 请求，
`040C` 关闭连接；不能互换。mode0 连接/启动至首次 run 的调用链及已有抓包中，
没有找到版本、启动 PC 写、快照之外的强制 USB 配置命令。

## 如何运行诊断

在 `D:/Projects/stcforge` 打开 PowerShell，使用 Windows uv 和本项目环境。
每次指定一个**尚不存在**的输出文件；脚本不会覆盖旧日志。

只查询版本和 CPU 快照：

```powershell
D:/Code/uv/uv.exe run --project D:/Projects/stcforge --no-sync python tools/diagnostics/diagnose_usb_ice.py --backend native --output .cache/ice-query-new.jsonl
```

运行板上已有固件 100 ms，再暂停并读取快照：

```powershell
D:/Code/uv/uv.exe run --project D:/Projects/stcforge --no-sync python tools/diagnostics/diagnose_usb_ice.py --backend native --run-ms 100 --output .cache/ice-run-new.jsonl
```

把 `--backend native` 改为 `--backend hidapi` 可对照生产后端。
native 仅支持 Windows，保留 Win32 错误码；hidapi 的 read error 仍受绑定的信息缺失限制。
脚本不烧录、不写寄存器或断点；`--run-ms` 会执行现有程序。
可额外传 `--official-start` 补验完整的官方启动等待：它只接受初始 PC=FF0000，
向相同地址发送特殊启动请求，等待 2 秒并读取快照；其他 PC 直接拒绝。
此选项有启动上下文副作用，仅限实验对照，不表示已实现或验证通用复位/PC 设置。

恢复 ICE 状态后，一次运行官方启动时序对照：

```powershell
D:/Code/uv/uv.exe run --project D:/Projects/stcforge --no-sync python tools/diagnostics/diagnose_usb_ice.py --backend native --official-start --run-ms 100 --output .cache/ice-official-start-new.jsonl
```

只读核对当前 Debug HEX（不添加 `--run-ms`）：

```powershell
D:/Code/uv/uv.exe run --project D:/Projects/stcforge --no-sync python tools/diagnostics/diagnose_usb_ice.py --backend native --verify-image D:/Code/CLionProjects/STC/STC32K144G246_32BIT_SDCC_Template/build/Debug/firmware/STC32G144K246_32BIT_SDCC_Template.hex --output .cache/ice-verify-new.jsonl
```

代码读取无响应、校验失败或镜像地址不合法均直接终止；不会据此自动下载或改写目标。

运行时默认设 20 秒进程保护，便于保留卡住前的日志；超时保护强制结束 Python，
并不表示已经暂停或复位了 MCU。查询也可能触发操作系统枚举接口。

## 下一次对照应控制的变量

下一次硬件验收前，先恢复设备到能稳定查询的 ICE 状态。
不再把更换 CPU 主频当作修复结果；Debug 48 MHz 分支仍只是未验收的实验配置。
完整 2 秒时序已经失败，下一次先做只读代码核对，确认镜像一致性后再安排运行测试。

静态分析还发现一个独立差异：官方 `48F5/4905` 会在当前 PC 是已有用户断点时先单步越过，
并在运行前安装、停止后移除断点。当前 Python 没有完整复现这个生命周期。
它可能影响从断点继续，但本次无断点的 native 测试也失败，不能用它解释全部现象。

必须对**同一份板上固件、同一初始状态**比较官方 Keil 与 native 的运行/暂停。
旧的 Keil 成功抓包对应独立的 Keil 测试固件，与当前 SDCC 模板不同，不能直接用于排除固件因素。
对照时只运行一个调试前端，记录官方完整 I/O 顺序，重点核实运行前的状态准备及暂停时机。

- 若同一 SDCC 固件在官方 Keil 中也失联：优先检查程序对 ICE 所依赖资源的修改，
  用已知正常的最小固件逐块加入初始化，而不是继续改 GDB。
- 若官方可以而 native 不可以：比较第一条有差异的报文及状态转换，修正协议实现后再回归。
- 若 native 可以而 GDB 服务不可以：再比较断点补丁、启动请求和事件归属。

当前结果只排除了“必须经由 CLion/GDB/hidapi 才会触发”的解释，
尚未排除协议初始化差异、板上程序、ICE 资源冲突和外部进程干扰等可能。

## 来源

- 官方 Keil DLL：上文路径与哈希，仅静态读取，不修改或分发 DLL。
- 用户抓包：模板工程 `Misc/Reference/usb-ice-analysis/transactions.json`；
  frame 7/9 版本、11/13 特殊 PC 写、15/17 快照、19/21 运行、23/25 暂停。
- hidapi 0.15.0：`https://github.com/libusb/hidapi/blob/hidapi-0.15.0/windows/hid.c`。
- cython-hidapi 0.15.0：`https://github.com/trezor/cython-hidapi/blob/0.15.0/hid.pyx`。
