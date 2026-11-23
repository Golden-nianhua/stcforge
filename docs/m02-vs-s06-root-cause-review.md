# M02 与 S06/S00：实际 HEX 静态根因复核

日期：2026-11-15。范围仅为本机已有源码、ASM/RST、MAP/CDB、HEX 和所用编译器安装中的 ABI/运行库资料；未访问设备、未烧录、未运行服务、未修改固件或测试器。

## 当前结论与证据边界

**本轮没有找到足够证据认定的错误 opcode 或 C 调用 ABI 缺陷。** 已将完整寄存器头污染汇编寄存器名、UART/Timer 参数不同、S06 未成功覆盖 external startup、普通函数混用 RET/ERET 等具体嫌疑逐项核对。最有价值的新证据是共用代码的机器码相等范围，及原例进入 main 后独有的一小段栈保存窗口；后者目前只是可定位的运行差异，不能写成编译器缺陷。

主代理提供的实板结果（本轮未自行复测）：M02 全 PASS；M01 三轮运行/暂停成功；S00～S07 首轮暂停失败；M00 第二轮 readerror。此结果不支持简单归因为“所有 SDCC 原生指令都坏了”或“开启 Timer1 就失败”。

最新主代理证据：在已核对的 M02 上，通过 ICE 单步窗口注入 S06 启动指令流，109 条后到达 S06 main `FF00BB`；24 字节初始化内容、`ERET -> FF0037`、栈 `00FF -> 0102 -> 00FF` 均正确；另 CMP DR12,#0 和 DEC DR12 单步正确。**这是监控单步路径的证据，不是 S06 全速执行证据。** 单步原生间接 code 读和 MOVC 的视图问题也不能直接归因于编译器生成错误。

## 输入及身份核对

矩阵根目录：`D:/Code/CLionProjects/STC/STC32K144G246_32BIT_SDCC_Template/Misc/Simulation Firmware Matrix/`。

| 镜像 | 定义字节数 | SHA-256 |
| --- | ---: | --- |
| `M02_led_uart_timer.hex` | 1375 | `242dc7332217845a4cf47972e1a7ae77927d43c51ed74d018cbe7b5e8da1874e` |
| `S06_manual_init.hex` | 2162 | `56bc3a99bab83d6ccd3c618742b099c4e1701c498893a09300996926fcbbabce` |
| `S00_sdcc_original.hex` | 1914 | `2d7b7609bbd5a0db001d81588c9b78451ff212eebe34e396de283290a79755cf` |

实际读取了各版本子目录中的 ASM、MAP/CDB、头文件与源码副本。S00 的原始重定位列表为：

`Misc/SDCC Simulation Test/build/Debug/CMakeFiles/STC32G144K246_Simulation_Test.dir/Core/Src/{main.c.rst,system_stc32.c.rst}`。

S00 与 S06 的 `FF00BB..FF0772` **连续 1720 字节完全一致**。因此原 S00 RST 在这个区间可用来给 S06 的相同字节定位，且核对时没有依赖 stc-gdb 的不完整解码。

## 1. 共用外围初始化不是抽象的“参数相同”，而是机器码相同

下表长度包含末尾返回指令，比较直接从 HEX 提取字节，并由 CDB 的函数开始/结束标记确定边界。

| 功能 | S06/S00 地址 | M02 地址 | 实际比较 |
| --- | --- | --- | --- |
| GPIO 的全部硬件访问 | `FF02F9..FF03E5` | `FF0123..FF020F` | 前 237 字节完全相等 |
| UART7 初始化 | `FF0453..FF0540` | `FF024E..FF033B` | 238 字节完全相等 |
| Timer1 初始化 | `FF0541..FF0566` | `FF042B..FF0450` | 38 字节完全相等 |
| 时钟初始化 | `FF03F1..FF0452` | `FF00C1..FF0122` | 98 字节中仅函数内 EJMP 的目标低两字节不同 |
| Timer1 ISR | `FF0567..FF05B7` | `FF03DA..FF042A` | 81 字节仅 4 个 tick 地址字节不同 |
| 毫秒原子快照 | `FF05D0..FF0615` | `FF0451..FF0496` | 70 字节仅 4 个 tick 地址字节不同 |

GPIO 剩余差异：M02 在硬件配置之后直接 `ERET`；S06 多执行 10 字节 `led_state=0`，然后 `ERET`。M02 早在 main 初始化了该变量。

时钟的两个差异在函数相对偏移 `+3A/+3B`：S06 的稳定等待回跳为 `8A FF 04 1B`，M02 为 `8A FF 00 EB`，均回到各自函数 `+2A` 的 IRC48M 状态读取。没有 CPU 模式差异可由此推出。

Timer1 的共同字节为：

```text
C2 8E C2 AB 53 8E BF 53 89 0F 53 8F FD
90 FE A1 75 84 7E 7F 7E E4 7A EB B0
75 8D F0 75 8B 60 C2 8F D2 AB D2 8E AA
```

对应停表/关 ET1、12T、模式0、关闭时钟输出、TM1PS=0、TH1/TL1=F060、清 TF1、开 ET1/TR1、ERET。这些指令已存在于全 PASS 的 M02 中，不能再把其本身列为 S06 特有的非法指令。

## 2. 完整寄存器头没有重定义 DR12/DR4/DPX

完整读取 S06 源码副本中的 `sources/Drivers/Inc/stc32g144k246_reg.h` 及 `compiler.h`，共识别到 122 个 SFR、128 个 SBIT 声明。

`compiler.h` 的实际 MCS251 分支展开为：

```c
#define SFR(name, addr) __sfr __at(addr) name
#define SBIT(name, addr, bit) __sbit __at((addr) + (bit)) name
#define __FAR __far
```

名称近似 CPU 特殊寄存器的声明为 SP、DPL、DPH、DPXL、SPH、PSW、PSW1、ACC、B。实际 ASM 生成 `_SP=0081`、`_DPL=0082`、`_DPH=0083`、`_DPXL=0084`、`_SPH=0085`、`_PSW=00D0`、`_PSW1=00D1`、`_ACC=00E0`、`_B=00F0`，均带前导下划线。

没有 `dr12/dr4/dpx/dptr/spx/rN/wrN` 的无下划线等值重定义，也没有这些名字的 C 宏覆盖。声明 USBCON/P3 本身只产生符号，不产生外设写指令。对三个 S06 代码单元的实际指令扫描未发现 `_AUXR2`、`_USBCON`、`_USBADR`、`_P3/_P30/_P31` 操作；M02 同样没有。

对应 M02 的实际使用地址逐项核对相等：

- SP/DPL/DPH/DPXL/SPH：`81/82/83/84/85`；WTST/CKCON：`E9/EA`；P_SW2：`BA`。
- EA/ET1/TR1/TF1 位地址：`AF/AB/8E/8F`。不要把 TR1 的**位地址** `8E` 与 AUXR 的**字节地址** `8E` 当成声明冲突。
- P9 配置、UART7、Timer7、时钟 XFR 与 M02 的自包含头全部同地址；上节逐机器码相等进一步覆盖了实际访问行为。

因此目前没有“完整头文件让汇编器错误解析 DR12/DR4/DPX”的证据。比较 XINIT 指令时也应遵守已有官方 A251 逐字节往返验证结果，不能再写成 CMP DR12 不受支持。

## 3. S06 的跳过初始化路径确实成立

M02/S06 的 `FF0029..FF003E` 共 22 字节，只有 ECALL 的钩子目标不同：

```text
共同前10字节：7E FC 00 07 75 81 FF 75 85 00
M02：9A FF 00 BB E5 82 60 04 8A FF 00 23
S06：9A FF 07 73 E5 82 60 04 8A FF 00 23
```

即 GSINIT0 的 SPX 占位初值、GSINIT1 将 SP/SPH 设为 00FF、ECALL external startup、读 DPL、JZ、EJMP program startup。S06 的 C 函数为双下划线 `__sdcc_external_startup`，链接为三下划线 `___sdcc_external_startup=FF0773`，没有符号名写错。

独立按 S06 实际 HEX 解出 hook 中的立即数赋值与 DPX 写入，恰好覆盖 `010000..010017`，24 个地址各写一次：

```text
010000..010017:
00 00 00 00 00 00 00 00 00 00 00 00 00 00 12 34
12 34 56 78 00 00 00 00
```

对应 heartbeat/rx/tx 三个计数、last_rx、led_state、watch16、watch32、tick_ms。没有溢出写到 USB XFR。尾部 `FF086B..FF086E = 75 82 01 AA`，返回 DPL=1；ERET 回 `FF0037` 后跳向 `FF0023`，再 ECALL main `FF00BB`。

M02 使用 XSEG 5 字节；S06/S00 使用 XISEG 24 字节。二者都从 `010000` 分配，S06 的初始化已显式写齐，并未漏初始化某个自身全局对象。**XISEG 与 XSEG 名称不同本身不能推出硬件地址空间不同，更不能推出 ICE RAM 重叠。**

MAP 两者均链接 `mcs251-large-stack-auto/mcs251.lib`，没有意外混用 mcs51 库或 small 库。安装中的 `lib/src/mcs251/Makefile` 明确将通用启动的 LCALL/LJMP/RET 转为 ECALL/EJMP/ERET，并将启动 SP 转为 SPX；最终机器码与之相符。

## 4. main 后最小可定位差异：首次返回值写栈窗口

S00/S06：

| 地址 | 字节 | 操作 |
| --- | --- | --- |
| `FF00BB` | `0B FE` | INC SPX,#4，保留 last_toggle 的4字节栈槽 |
| `FF00BD` | `9A FF 05 B8` | ECALL system_init |
| `FF00C1` | `9A FF 05 D0` | ECALL system_millis |
| `FF00C5` | `C0 E0` | PUSH ACC |
| `FF00C7` | `E5 82` | MOV A,DPL |
| `FF00C9` | `39 BF FF FF` | MOV @SPX-1,A |
| `FF00CD` | `D0 E0` | POP ACC |
| `FF00CF` | `C0 E0` | PUSH ACC |
| `FF00D1` | `E5 83` | MOV A,DPH |
| `FF00D3` | `39 BF FF FE` | MOV @SPX-2,A |
| `FF00D7` | `D0 E0` | POP ACC |
| `FF00D9` | `C0 E0` | PUSH ACC |
| `FF00DB` | `E5 F0` | MOV A,B |
| `FF00DD` | `39 BF FF FD` | MOV @SPX-3,A |
| `FF00E1` | `D0 E0` | POP ACC |
| `FF00E3` | `39 BF FF FD` | MOV @SPX-3,A |
| `FF00E7` | `9A FF 05 D0` | 进入主循环，下一次读取毫秒数 |

这段与 M02 的重要区别：M02 在开中断之前直接将本地 last_toggle 四字节清零；原例在 system_init 已开中断后，把首次 32 位返回值写到栈。

**这里不能因连续两次出现 @SPX-3 就认定覆盖错误。** 主函数当前 SPX=0106。每次 PUSH 暂时升到0107，所以 DPL/DPH/B 分别写0106/0105/0104；最后 POP 后 SPX=0106，A 写0103。最终栈对象 `0103..0106` 正是 `A:B:DPH:DPL` 的大端顺序。用原指令语义在 SPX=0106/01FF/0200、返回值0/1/12345678/FFFFFFFF 上做12组内存内核对，SP保持不变，结果均正确；这不模拟 ICE 或实板的中断行为。

原例与 M02 的后续 `now-last_toggle` 都有补码 SUBB 逐字节展开。额外做10000组固定种子32位输入的语义核对，结果均等于无符号32位差；未发现简单的减法方向或借位错误。

## 5. 中断、嵌套调用和寄存器活跃值

S06 system_init `FF05B8..FF05CF`：关 EA，开 P_SW2.XFR，按 GPIO/clock/UART7/Timer1 顺序调用；`FF05CD D2 AF` 开 EA，`FF05CF AA` ERET。M02 在 main 中直接做相同顺序，`FF04F0 D2 AF` 开 EA。因此原例多一个3字节 ECALL 帧；这是可测试的执行环境差异，不是已证明的返回帧错误。

两份 ISR 均为 PUSH ACC/B/DPL/DPH/PSW，再手工 PUSH DPXL；更新 tick 后按逆序 POP，最终 RETI。ISR 实际没有写 R0～R15、DR28，也不调用 C 函数，因此没有发现应当保护却遗漏的普通寄存器。PSW1 不在软件保存列表并不是两者的区别；若讨论它，应同时考虑实际中断模式的硬件帧，不能只凭缺少一条 PUSH 判定错误。

`system_millis` 与 M02 的快照函数仅 tick 地址不同，返回 ABI 都是低到高 DPL/DPH/B/A；保存 EA 到 R7、关 EA、读齐四字节、恢复 EA，然后组装返回值。原例中跨该调用活跃的 RX 字节有 PUSH/POP ar7 保护；UART 发送 timeout 路径的时间戳也有对应保护。

可定位的原例特有 UART 窗口：`FF06B6..FF06DB`，保存 ar7/ar6 和 R15/R14/R13/R12，ECALL system_millis，再逆序恢复。实际 native PUSH R15/R14/R13/R12 为 `CA F8 / CA E8 / CA D8 / CA C8`，POP 为 `DA C8 / DA D8 / DA E8 / DA F8`；与本机 instruction-forms.tsv 的合法 Rm 形式一致。**只有收到串口数据并进入发送轮询才会执行，不能在没有 UART 活动证据时拿它解释首次运行就失联。**

按本地 ABI 的3字节普通调用帧及既有4字节中断帧描述估算：原例启动 helpers 的最深 SPX=010C；IRQ 启用后首次快照约0109+10=0113；UART timeout 的最深快照约0112+10=011C。M02 同期约0113。这个量级远低于3FFF，静态未见栈容量溢出。该计算不包含未获证据的嵌套中断或 ICE 私有行为，也不把 EDATA0100 声称为已证明与 ICE 无冲突。

## 最小后续定位建议

不需要重复本轮已完成的 M02 注入初始化/CMP/DEC 探针。若后续换回完整 S06，应优先确认**真实全速路径首次在哪个已列窗口前后失去可停止性**，避免只验证单条 opcode 后推导整份固件正常。

1. 分界地址：`FF086B`（hook返回前）、`FF00BB`（main）、`FF05CD`（开EA前）、`FF00C1`（system_init返回）、`FF00C5`（首个快照返回）、`FF00E7`（栈保存完成）。地址本身不表示应一次布置全部断点；已有残留软件断点必须由主代理按其完整性流程处理。
2. 若能停在 `FF00C5` 与 `FF00E7`，核对 SPX应为0106；前者的 A:B:DPH:DPL 应等于后者 EDATA `000103..000106` 的4字节值。只需这些4字节和SP/返回寄存器即可检查最早特有栈窗口。EDATA 使用哪一原生空间编号由现有探针接口确认，不在这里猜测；space5仅用于代码镜像完整核对。
3. 若开EA后才失去暂停能力，优先对比相同ISR在不同调用深度的实际帧/恢复行为，而不是改 Timer1 参数或声称 CMP 不支持；若在开EA前即失败，则该 ISR/栈交错路径尚不可解释故障。

在获得上述全速分界之前，没有足够依据指定一个代码修复。本文保留明确排除证据及最短剩余检查窗口，不把猜测写成“已定位根因”。

## 本地资料索引

- 编译器：`D:/Code/c-env/SDCC/SDCC-4.6.0-MCS251/doc/zh-CN/chapters/11-mcs251-abi.md`（Source mode、大端、参数/返回、3字节调用帧、SPX、数据模型）。
- `doc/zh-CN/chapters/07-mcs251.md` 与 `12-mcs251-instruction-set.md`。
- `lib/src/mcs251/Makefile`、`lib/src/mcs51/crtstart.asm`、`lib/src/mcs251/crtxinit.asm`、`crtxclear.asm`。
- `D:/Projects/stcforge/.cache/instruction-forms.tsv`（仅用于已定位指令形式核对，不当作实板真值）。
