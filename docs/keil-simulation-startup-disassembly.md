# Keil Simulation Test：启动、初始化表、ISR 的机器码复核

日期：2026-11-15。任务范围仅为本节列出的 Keil 固件、链接映射、C 列表和本机官方资料。未访问 BSP_keil，未操作板卡、烧录或运行调试服务，未修改模板工程。本文件为本轮唯一工程内新增文件。用于重汇编的临时输入、OBJ、LST、ABS、HEX 均位于系统临时目录。

## 1. 可交给主代理的结论

1. **Keil 也使用原生 24 位间接读取初始化常量，不使用 MOVC。** `FF03EE/FF03F2` 将 `DR0` 设为 `00FF0499`；`FF03F6 0B 0A 40` 从 `@DR0` 读 16 位长度；`FF0407 7E 0B B0` 是 `MOV R11,@DR0`，R11 为 ACC。全 HEX 的 1234 个定义字节中，连原始字节 `93`、`83` 都没有，故不存在这两种 MOVC 指令。
2. **启动路径的实质差异是 EDATA/16 位目标和计数，对比主代理提供的 SDCC XDATA/32 位目标和计数。** Keil 源指针仍是 32 位寄存器承载的 24 位地址 `DR0`，目标为 `WR4`、计数为 `WR8`；SDCC 对应源 `DR4`、目标 DPX、计数 `DR12`。不能把差异写成原生读与 MOVC 的差异。
3. **Keil 本身并不回避 32 位 CMP。** `FF0145 BE 18 01 F4` 比较 `DR4` 与 500；`FF033F BE 18 00 05` 比较 `DR4` 与 5。同一固件也使用 `FF0332 BD 32` 的 16 位 `CMP WR6,WR4`。Keil 初始化表循环则通过 16 位 ANL/DEC 设置 Z，未用 CMP。
4. **STC 官方手册明确列出 `CMP DRk,#0DATA16`，不能只依据 Intel 推定。** 本机 2026-11-05 版 STC32G144K246 手册附录 A、印刷页 1233，给出 Source 模式 4 字节、`BE(u)8H`、影响 CY/OV/N/Z、不影响 AC；`DR12` 对应 `BE 38 00 00`。本次阅读的该条目及寻址标记未写 DR12 或立即数零的额外限制。官方 A251 也接受此形式。**文档支持及编码一致不证明 ICE 实板实现无异常**，更不能由此排除特定 DR12/零比较/调试路径问题。
5. **需撤回上一轮两项推断。** 原生 `@DRk` 不能读取 HCONST/code 的泛化判断不成立；本机 Keil HCONST 文档和本固件均有反证。`DR12=0x18` 与零比较之后 `JE` 应跳转的判断也不成立：按文档 Z=0，应顺序执行。SDCC 的实际行为由主代理单独复核。
6. 本次未找到足以认定 XDATA 与 ICE 保留 RAM 重叠的证据。Keil 不使用 XDATA 只能构成对比变量，不能证明其不用 XDATA 的原因是 ICE 占用。

## 2. 样本、地址基准与核验方法

### 固件与列表

| 输入 | 绝对路径 | SHA-256 |
| --- | --- | --- |
| HEX | `D:/Code/CLionProjects/STC/STC32K144G246_32BIT_SDCC_Template/Misc/Keil Simulation Test/Objects/Keil Simulation Test.hex` | `6a572bc409f7baaa694452be9ed1853992081f6ea097c57325815565b90dc5d0` |
| MAP | `D:/Code/CLionProjects/STC/STC32K144G246_32BIT_SDCC_Template/Misc/Keil Simulation Test/Listings/Keil Simulation Test.map` | `0d41e92d681905194c43ec072c851aef8887caba0e28040661cac16cf943fe12` |
| C 列表 | `D:/Code/CLionProjects/STC/STC32K144G246_32BIT_SDCC_Template/Misc/Keil Simulation Test/Listings/main.lst` | `1be49a291c84a08a943283606c043492b1949c474f001618d929465a2b1127c7` |

此 HEX 使用低 16 位偏移，解析得到原始地址 `0000..04D2`；必须按 MAP 的 CODE 基址 `FF0000` 对齐。以下所有 FF 地址是对齐后的 CPU 地址，不是声称 HEX 存有 `00FF` 扩展地址记录。定义字节共 1234；跨度 1235 字节，唯一空洞 `FF001A`。所有 HEX 记录校验和已通过。

MAP 首页给出：`CPU MODE: 251 SOURCE MODE`、`INTR FRAME: 4 BYTES SAVED ON INTERRUPT`、`MEMORY MODEL: XSMALL`；C 编译器为 C251 V5.60.0；所链库为 `C2SXS.LIB` 的 `?C_START`、`?C?INITEDATA`、`?C?INITEDATA_END`。

### 独立编码核验

没有使用 stc-gdb 的不完整反汇编器作为解码依据。先由原 HEX、官方手册、MAP 和 `.cache/instruction-forms.tsv` 建立候选指令，再在系统临时目录使用本机官方工具回编并逐字节比较：

```text
A251.EXE probe.a51 MODSRC
L251.EXE probe.obj TO probe.abs
OH251.EXE probe.abs HEXFILE(probe.hex)
```

工具版本：A251 V4.69.13.0、L251 V4.66.93.0、OH251 V1.47.0.0。最终三步全部成功，A251/L251 均为 0 警告、0 错误。OH251 生成的 H386 文件带实际 FF 地址，比较时对原 HEX 加 `FF0000`，不对回编 HEX 再加偏移。

| 回编范围 | 字节数 | 与原 HEX 比较 |
| --- | ---: | --- |
| `FF03DB..FF0419` | 63 | 全部一致，包括相对分支偏移 |
| `FF0003..FF0019` | 23 | 全部一致 |
| `FF0118..FF014A` | 51 | 全部一致 |
| `FF031E..FF0344` | 39 | 全部一致 |

临时核验目录：`C:/Users/Golde/AppData/Local/Temp/keil-startup-check-58b599b059754868bf713979b5115d17/`，输入 `probe.a51`，最终列表 `probe.lst`、镜像 `probe.hex`。共 176 个目标固件字节经过上述回编比较。本报告核心启动与 ISR 表中没有尚未证明的指令；没有在表外假装完成全固件解码。

另据主代理本轮提供的验证，SDCC `FF003F..FF006B` 的 45 字节亦已通过 A251 Source 模式、L251、OH251 完整回编对比；证据为其 `.cache/sdcc-runtime-roundtrip.a51/.lst/.hex`。这里引用为主代理提供的验证结果，未重复承担 SDCC 解码任务。

## 3. `FF03DB..FF0419`：逐条启动代码

### 清 EDATA 与初始化硬件栈

复位入口 `FF0000 02 03 DB` 为同一 code 段内的 `LJMP FF03DB`。

| 地址 | 原机器码 | 经官方 A251 回编确认的指令 | 作用 |
| --- | --- | --- | --- |
| `FF03DB` | `75 84 01` | `MOV DPXL,#01H` | 把 DPXL（SFR 84H）设为 XDATA 段号 1；不等于已向 XDATA 写数据。MAP 的 `?C?XDATASEG=1` 与此一致。 |
| `FF03DE` | `7E 44 04 1F` | `MOV WR8,#041FH` | 设置 16 位清零地址。 |
| `FF03E2` | `E4` | `CLR A` | R11/ACC=0。 |
| `FF03E3` | `7A 49 B0` | `MOV @WR8,R11` | 清一个 EDATA 字节。 |
| `FF03E6` | `1B 44` | `DEC WR8,#1` | 地址减 1，更新 Z。 |
| `FF03E8` | `78 F9` | `JNE FF03E3` | `FF03EA-7=FF03E3`。循环直到 WR8=0。 |
| `FF03EA` | `7E F8 00 35` | `MOV DR60,#0035H` | SPX=0x35，第一项栈写入从 EDATA 0x36 开始。不是仅修改 8 位 SP。 |

实际清零顺序为 `00:041F` 递减至 `00:0001`，共 `0x41F` 字节。最后一次 DEC 从 1 到 0 后结束，**不写地址 0**。不能把它写成“只清全局变量”或“清 0..041F（含 0）”。范围包含全局、静态局部和分配的栈，并超过 MAP 已分配的栈终点 0x135，但仍在本机手册列出的 16KB EDATA 中。此路径没有清 XDATA。

本机官方 `C:/Program Files (x86)/Keil/C251/LIB/START251.A51` 给出同一结构：`EDATALEN EQU 420H`，`MOV WR8,#EDATALEN-1`、`CLR A`、`MOV @WR8,R11`、`DEC WR8,#1`、`JNE`，然后 `MOV DR60,#WORD0(?STACK-1)`。本 HEX 是该结构的直接实例，不从这个通用源文件猜测 XDATA 有效长度。

### 逐记录复制 HCONST 到 EDATA

| 地址 | 原机器码 | 指令 | 作用 |
| --- | --- | --- | --- |
| `FF03EE` | `7E 04 00 FF` | `MOV WR0,#00FFH` | 设置 DR0 的高 16 位。 |
| `FF03F2` | `7E 14 04 99` | `MOV WR2,#0499H` | 设置 DR0 的低 16 位；合成 `DR0=00FF0499`。 |
| `FF03F6` | `0B 0A 40` | `MOV WR8,@DR0` | 原生间接读取 16 位记录长度。 |
| `FF03F9` | `5D 44` | `ANL WR8,WR8` | 长度不变，根据完整 16 位结果设置 Z。 |
| `FF03FB` | `68 1A` | `JE FF0417` | 长度为零时终止；`FF03FD+0x1A=FF0417`。 |
| `FF03FD` | `69 20 00 02` | `MOV WR4,@DR0+2` | 从记录头的后两字节读取 16 位 EDATA 目标地址。 |
| `FF0401` | `0B 0E` | `INC DR0,#4` | 跳过长度与地址这 4 字节记录头。 |
| `FF0403` | `0B 44` | `INC WR8,#1` | 为先减后判断的循环补偿一次。 |
| `FF0405` | `80 0A` | `SJMP FF0411` | 先去执行计数递减；`FF0407+0x0A=FF0411`。 |
| `FF0407` | `7E 0B B0` | `MOV R11,@DR0` | 从完整 24 位源地址读一个字节至 ACC；**不是 MOVC**。 |
| `FF040A` | `7A 29 B0` | `MOV @WR4,R11` | 将字节写到 16 位 EDATA 目标。 |
| `FF040D` | `0B 24` | `INC WR4,#1` | EDATA 目标地址加 1。 |
| `FF040F` | `0B 0C` | `INC DR0,#1` | 24 位源地址所在的双字寄存器加 1。 |
| `FF0411` | `1B 44` | `DEC WR8,#1` | 16 位剩余字节数减 1，设置 Z。 |
| `FF0413` | `78 F2` | `JNE FF0407` | `FF0415-0x0E=FF0407`，非零继续复制。 |
| `FF0415` | `80 DF` | `SJMP FF03F6` | `FF0417-0x21=FF03F6`，读下一记录。 |
| `FF0417` | `02 01 18` | `LJMP FF0118` | 进入 main；不是 CALL，因此本跳转不压 main 返回地址。 |

例如首记录长度 4：WR8 从 4 加到 5，先跳至 FF0411 减为 4，然后执行 4 次复制；第四次复制后减为 0，转到下一记录。对本表 8 条记录，累计复制 24 字节。终止时 DR0 指向 `FF04D1` 的零长度头，不是读完终止标记后的 `FF04D3`。

这里 WR8 与 WR4 是独立字寄存器；DR0 占用 WR0、WR2。不能因 DR0 是双字指针而把目标和计数也解成 32 位。

## 4. `FF0499..FF04D2`：逐记录初始化表

MAP 将整个范围定义为 HCONST `?C_INITEDATA`，总长 `0x3A=58` 字节，`?C?INITEDATA_END=FF04D1`。格式由实际读表机器码确定：

```text
uint16_be length
uint16_be edata_destination
byte payload[length]
...
uint16_be 0               ; 只有长度，没有后续目标字段
```

| 记录地址 | 完整机器字节/表字节 | 解释 |
| --- | --- | --- |
| `FF0499` | `00 04 00 08 12 34 56 78` | EDATA `0008..000B`：watch32=0x12345678。 |
| `FF04A1` | `00 02 00 0C 12 34` | EDATA `000C..000D`：watch16=0x1234。 |
| `FF04A7` | `00 01 00 0E 00` | EDATA `000E`：last_rx=0。 |
| `FF04AC` | `00 01 00 0F 00` | EDATA `000F`：led_state=0。 |
| `FF04B1` | `00 04 00 10 00 00 00 00` | EDATA `0010..0013`：heartbeat_count=0。 |
| `FF04B9` | `00 04 00 14 00 00 00 00` | EDATA `0014..0017`：tick_ms=0。 |
| `FF04C1` | `00 04 00 18 00 00 00 00` | EDATA `0018..001B`：rx_count=0。 |
| `FF04C9` | `00 04 00 1C 00 00 00 00` | EDATA `001C..001F`：tx_count=0。 |
| `FF04D1` | `00 00` | 零长度终止符。 |

58=8×4 字节记录头+24 字节数据+2 字节终止符。独立脚本已按上述规则解析全部记录，确认目的范围连续为 `0008..001F`、无重复写入、非零常量字节与 MAP/C 列表相符。此脚本验证表结构与值，不模拟 CPU，也不声称 ICE 实际读取视图已被验证。

## 5. EDATA、全局变量、静态局部与栈

| 地址 | MAP 对象 | 大小/含义 |
| --- | --- | --- |
| `0000..0007` | REG BANK 0 | 8 字节 DATA 映射。 |
| `0008..001F` | `?ED?MAIN` | 24 字节全局，具体对象见初始化表。 |
| `0020..0023` | main.last_toggle | 4 字节 EDATA。 |
| `0024..0027` | main.now | 4 字节 EDATA。 |
| `0028` | main.received | 1 字节 EDATA。 |
| `0029` | uart7_send.value | 1 字节 EDATA 参数槽。 |
| `002A..002D` | uart7_send.started | 4 字节 EDATA。 |
| `002E..002F` | uart7_send.spins | 2 字节 EDATA。 |
| `0030` | millis.saved_ea | 1 字节 EDATA。 |
| `0031..0034` | millis.snapshot | 4 字节 EDATA，非 4 字节对齐。 |
| `0035` | led_set.on | 1 字节 EDATA 参数槽。 |
| `0036..0135` | `?STACK` | 分配 0x100 字节，SPX 初值 0x35。 |

MAP 的 EDATA USED=`0x12E`，等于 `0x18+9+7+5+1+0x100`。HDATA 类虽限制在 `0..3FFF`，但没有已分配 HDATA 段；没有 XDATA 对象或 XDATA 初始化复制循环。C 列表总结 `edata size=46`，这是变量/局部 46 字节，另加 256 字节栈，勿把两个统计混为一谈。

本固件的普通局部变量使用静态 EDATA 槽；启动直接跳入 main，main 前缀也没有分配硬件栈局部帧。栈仍用于 LCALL/RET、ISR 现场保存等。`?STACK` 的 256 字节是链接分配，不是硬件自动施加的溢出保护。此布局本身没有出现变量与栈重叠。

## 6. `FF0003..FF0019`：Timer1 ISR 的逐条机器码

`FF001B 02 00 03` 是 Timer1 向量，执行 `LJMP FF0003`。`FF0003` 是本链接布局下的 ISR 函数位置；不要因地址恰好与 INT0 的标准向量槽相同就把函数认成 INT0 ISR。MAP 将其标为 `?PR?TIMER1_ISR?MAIN`，长度 `0x17`；C 列表第 110..114 行对应 `interrupt 3` 与 `++tick_ms`。

| 地址 | 机器码 | 指令 | 解释 |
| --- | --- | --- | --- |
| `FF0003` | `CA 1B` | `PUSH DR4` | 保存 4 字节工作寄存器。 |
| `FF0005` | `CA 0B` | `PUSH DR0` | 再保存 4 字节。 |
| `FF0007` | `7E 0F 00 14` | `MOV DR0,EDATA 0014H` | 32 位读取 tick_ms。此处是 dir16，不能擅自缩成不同编码的 dir8。 |
| `FF000B` | `7E 18 00 01` | `MOV DR4,#1` | 零扩展立即数至双字。 |
| `FF000F` | `2F 10` | `ADD DR4,DR0` | 执行一次完整 32 位加法。 |
| `FF0011` | `7A 1F 00 14` | `MOV EDATA 0014H,DR4` | 32 位写回 tick_ms。 |
| `FF0015` | `DA 0B` | `POP DR0` | 与保存顺序相反恢复。 |
| `FF0017` | `DA 1B` | `POP DR4` | 恢复 DR4。 |
| `FF0019` | `32` | `RETI` | 按配置的中断帧返回。 |

ISR 本体不调用函数、不修改 DPX/DPXL、不使用 ACC，也没有软件重装 TH1/TL1。软件压栈 8 字节；MAP 指定硬件中断帧 4 字节，因此每次此中断在被打断处 SPX 的基础上额外需要 12 字节。本机 STC 手册/Keil START251 的 INTR 描述为 PC 与 PSW1 的 4 字节帧；实际芯片模式是否与链接假定一致不能仅由 MAP 证明。

FF000B、FF0013 等其他标准向量槽位落在该函数体内。此 HEX 不是给所有中断都提供默认 RETI 的布局；这说明必须结合实际启用源讨论，不能自动认定全部向量都安全，也不能据此宣称已发现 ICE 向量冲突。

## 7. main 的启动流程与比较指令

MAP 定位 `main=FF0118`；C 列表第 167..174 行与下列机器码一一对应，`FF0118..FF014A` 全部已回编比较。

| 地址 | 机器码 | 行为 |
| --- | --- | --- |
| `FF0118` | `C3 C2 AF` | CLR C；CLR EA。 |
| `FF011B` | `43 BA 80` | ORL P_SW2,#80H，开放 XFR 访问。 |
| `FF011E` | `12 00 1E` | LCALL gpio_init（FF001E）。 |
| `FF0121` | `12 03 79` | LCALL clock_init（FF0379）。 |
| `FF0124` | `12 02 10` | LCALL uart7_init（FF0210）。 |
| `FF0127` | `12 04 4B` | LCALL timer1_init（FF044B）。 |
| `FF012A` | `D3 D2 AF` | SETB C；SETB EA。 |
| `FF012D` | `12 04 78` | LCALL millis。 |
| `FF0130` | `7A 1F 00 20` | MOV EDATA 0020H,DR4，保存 last_toggle。 |
| `FF0134` | `12 04 78` | 主循环开始，再读 millis。 |
| `FF0137` | `7A 1F 00 24` | 保存 now 至 EDATA。 |
| `FF013B` | `7E 0F 00 20` | DR0=last_toggle。 |
| `FF013F` | `7E 1F 00 24` | DR4=now。 |
| `FF0143` | `9F 10` | SUB DR4,DR0，计算无符号模 2^32 时间差。 |
| `FF0145` | `BE 18 01 F4` | CMP DR4,#000001F4H，**32 位比较**。立即数只编码 16 位不等于只比较 16 位。 |
| `FF0149` | `40 27` | JC FF0172；时间差小于 500 时跳过翻灯分支。 |

C 列表 clock_init 的次序为 CLKDIV=10、WTST=1、CKCON&=F8、开启并等待 IRC48M、选择 IRC48M、CLKDIV=1。它在 timer1_init 和最终 EA=1 之前执行。这里根据 C 列表解释源级顺序，不把 clock_init 全段冒充为逐机器码完整解码。

timer1_init 的 C 列表设置 Timer1 12T、模式 0 自动重载、TH1=F0、TL1=60、ET1/TR1=1；在进入 ISR 前初始化完成。millis 的机器码 `FF0483 7E 1F 00 14`、`FF0487 7A 1F 00 31`、`FF0494 7E 1F 00 31` 与 MAP/C 列表一致：关闭 EA 的临界区内将 tick_ms 读入 DR4，存入静态 snapshot，再恢复调用前 EA，最后通过 DR4 返回 32 位值。

### 同一固件的 16 位与 32 位 CMP

`FF031E..FF0344` 也已全部回编比较。关键位置如下：

| 地址 | 机器码 | 指令/宽度 | 用途 |
| --- | --- | --- | --- |
| `FF032C` | `6D 22` | XRL WR4,WR4，16 位 | WR4=0。 |
| `FF032E` | `7E 37 00 2E` | MOV WR6,EDATA 002EH，16 位 | 读取 spins。 |
| `FF0332` | `BD 32` | CMP WR6,WR4，16 位 | 判断 spins 是否为零。 |
| `FF0334` | `68 0F` | JE FF0345 | Z=1 才跳到返回 0 的分支。 |
| `FF0336` | `12 04 78` | LCALL millis | 返回时间在 DR4。 |
| `FF0339` | `7E 0F 00 2A` | MOV DR0,EDATA 002AH，32 位 | 读取 started。 |
| `FF033D` | `9F 10` | SUB DR4,DR0，32 位 | 计算发送等待时间。 |
| `FF033F` | `BE 18 00 05` | CMP DR4,#00000005H，32 位 | 判断是否超出 5ms。 |
| `FF0343` | `40 03` | JC FF0348 | 小于 5 时继续等待。 |

16 位 CMP+JE 已出现在 Keil 普通运行路径；32 位 CMP 立即数也已出现。Keil 初始化循环与 SDCC 初始化循环的区别是具体寄存器/计数方式及操作数，不是 Keil 完全不用 CMP、JE 或 32 位指令。

## 8. 官方指令依据与支持边界

### 本机 STC 手册，而非仅 Intel 指令表

原始官方 PDF：`D:/Golde/Downloads/DataSheet/STC32G144K246.pdf`，资料更新日期 2026-11-05。本次直接阅读已有完整文本提取 `C:/Users/Golde/AppData/Local/Temp/stc32-bsp-reference-20261114/manual.txt`，未执行新的 PDF 转换。该文本的来源路径由模板 `Misc/Reference/manual/manifest.json` 记载。注意章节 Markdown 提取仅覆盖部分章节；**本次 CMP 依据来自完整文本的附录 A**，不是只在章节 Markdown 中搜索后宣称未记载。

| 位置 | 可核对内容 |
| --- | --- |
| 印刷页 1205..1206，文本约 68819..68907 行 | Binary/Source 两种模式；@DRk 为 24 位间接地址；双字索引包含 DR0、DR4、DR12 等；`#0data16` 是高字填零的 32 位立即数。 |
| 印刷页 1231..1233，文本约 70473..70585 行 | CMP 影响 CY/OV/N/Z；WR 比较、DR 比较与立即数形式；`CMP DRk,#0DATA16` 的 Source 长度=4，Binary 长度=5。 |
| 文本 70559 行开始，印刷页 1233 | `BE(u)8H` 明确对应零扩展立即数形式；相邻 `BE(u)CH` 是高字填 1 的另一种形式，不能混淆。 |
| 文本 71392 行开始 | JE：Z=1 才跳；Source 操作码 68H、长度=2。 |
| 文本 71521 行开始 | JNE：Z=0 才跳；Source 操作码 78H、长度=2。 |
| 文本 72167 行开始 | `MOV Rm,@DRk`：Source 长度=3、编码 `7E(u)B(s)0H`，不改标志。 |

据此 `BE 38 00 00` 是合法的 **Source 编码候选**：DR12、零扩展的 0、全 32 位比较；官方 A251 在本次临时 probe 中也产生相同 4 字节。文档中的额外条件是正确的指令模式、寄存器选择及立即数扩展方式。没有找到“DR12 禁止”“与零比较另需配置”或“仅限 16 位”的说明。

这不是对 STC 芯片或 USB-ICE 的执行正确性验收。本次没有实板验证该指令，也没有找到具体芯片/ICE 版本的勘误或测试结果，不能把 A251、文档或 Intel 表当作实测替代品。也不能由本固件包含 `CMP DR4,#500/#5` 就证明 `CMP DR12,#0` 具有完全相同的 ICE 行为。

### HCONST 与 MOVC 的纠正

本机 `C:/Program Files (x86)/Keil/C251/HLP/a251.chm` 内：

- `a251_wp_code.htm`：CODE/CONST 的示例采用 `MOVC A,@A+DPTR`。
- **`a251_wp_hdata.htm`：HDATA/HCONST 可通过 DR0..DR28 与 DR56 访问；该页示例为 `MOV R4,@DR8`。**
- `a251_wp_expressionsexample.htm`：展示 `MOV R4,@DR0` 读取程序入口内容，同时说明 EDATA 类型转换用于强制 16 位直接寻址。
- `a251_modsrc.htm`：MODSRC 是提供给链接器/调试器的模式信息，不应把它误当成程序执行时写 CPU 模式寄存器的指令。

前两页必须一并看，不能摘 CODE/CONST 页面推导“任何代码地址只能 MOVC”。本固件初始化表是 HCONST，实码已证明使用 @DR0。R11=ACC 的别名也见本机 `HLP/Release_Notes.htm` 的 C251 参数传递示例；START251.A51 本身使用 CLR A 后 MOV @WR8,R11 的组合。

CPU 模式的最终证据层级：MAP 明确声明 SOURCE；实码和官方回编也符合 SOURCE 形式；启动段未包含切换 SOURCE/BINARY 的寄存器写。芯片实际选项及 ICE 下执行模式仍须由主代理另行核对，不能从链接声明推定已在硬件上设置成功。

## 9. 供主代理最终 SDCC 对比使用的精确变量

本表 SDCC 栏取自主代理提供的本轮定位/前文上下文，不代表本报告重新完整审计 SDCC 工程。

| 比较项 | 本 Keil 固件已证实 | SDCC 栏（主代理负责最终核对） | 能否据此下根因结论 |
| --- | --- | --- | --- |
| 源表 | HCONST FF0499，8 条记录 | CODE XINIT FF0777，连续 24 字节 | 表格式不同，不表示任一种本身错误。 |
| 源指针/读字节 | DR0；7E0BB0 | DR4；7E1BB0 | 都是原生 @DRk；不能再以 MOVC/原生分类。 |
| 源读表头 | 0B0A40：16 位 @DR0 | 无 Keil 式记录头 | 指针寄存器与读取宽度是可隔离变量。 |
| 复制目标 | WR4 的 EDATA 0008..001F | DPX 的 XDATA 010000..010017 | 存储区与寻址宽度均不同；没有 ICE 保留重叠证据。 |
| 计数/退出 | WR8，16 位 ANL/DEC 设置 Z 后 JE/JNE | DR12，32 位 CMP #0、DEC 后 JE/JNE | 应定点验证具体指令，不能推定 32 位 CMP 被 STC 禁止。 |
| 初始栈 | SPX=0035，首推0036；分配256字节 | SPX=00FF，首推0100 | 都在 EDATA；地址不同不自动构成冲突。 |
| main 入口 | LJMP FF0118，静态 EDATA 局部 | 主代理核对调用约定/栈局部 | 影响栈使用，不直接证明 ICE 失联原因。 |
| 32 位计算 | ISR ADD DR4,DR0，main SUB/CMP DR4 | 主代理核对 DR12/CMP #0 | Keil 的成功使用不能覆盖未测试的寄存器/立即数组合。 |
| 汇编编码 | 本报告启动63字节/ISR23字节回编一致 | 主代理提供启动45字节回编一致 | 两边均不能先归因于这些区域的汇编器编码错误。 |

如果后续重新测试 SDCC，应先恢复并核对该固件的实际字节，再隔离 CMP/寄存器/目标存储区；当前板内已换成 Keil，不能把旧 SDCC 地址的保存字节写回。这里仅列研究变量，不提出板卡操作，也不把本静态报告算作任何硬件验收结果。
