# Keil / SDCC Simulation Test：启动反汇编对照

核对日期：2026-11-15。对照磁盘中的两份实际 HEX、MAP、编译列表、官方 A251 回编结果及既有实板日志。本轮没有重新下载固件或修改编译器。

## 结论与边界

异常已能在 SDCC 进入 main 之前的全局变量初始化阶段复现；排查优先级应移到运行库启动路径与 USB-ICE 的交互。还不能认定 SDCC 产生了非法指令，或认定某条指令是最终根因。

- 两份程序的复位跳转均指向实际启动代码。
- 两份程序的 0x1234 / 0x12345678 初始化值均按大端排列，没有发现此处大小端不一致。
- SDCC 初始化循环的 45 字节经 Keil 官方 A251/L251/OH251 重建，与实际 HEX 完全一致，包括分支位移。
- Keil 也使用原生间接读程序区常量，也使用 32 位 CMP。不能将问题概括成这两类指令不受 STC 支持。
- 有明确差异的是数据模型、初始化循环的寄存器与计数方式，以及已观察到的 ICE 下读取视图差异。其因果关系还需控制变量实验。

## 1. 样本与地址

共同目录：`D:/Code/CLionProjects/STC/STC32K144G246_32BIT_SDCC_Template/Misc/`。

| 项目 | SDCC | Keil |
| --- | --- | --- |
| HEX 相对共同目录 | `SDCC Simulation Test/build/Debug/firmware/STC32G144K246_Simulation_Test.hex` | `Keil Simulation Test/Objects/Keil Simulation Test.hex` |
| 定义字节数 | 1914 | 1234 |
| HEX 地址解释 | 已含 FF0000 基址 | 按 MAP 给低 16 位地址加 FF0000 |
| main | FF00BB | FF0118 |
| 数据模型 | large；全局位于 XDATA | XSMALL；全局位于 EDATA |
| 24 字节初始化目的范围 | 010000..010017 | 000008..00001F |
| 栈初值 / 第一个压栈地址 | 0000FF / 000100 | 000035 / 000036 |

SHA-256：

```text
SDCC 2d7b7609bbd5a0db001d81588c9b78451ff212eebe34e396de283290a79755cf
Keil 6a572bc409f7baaa694452be9ed1853992081f6ea097c57325815565b90dc5d0
```

本次独立解析全部 HEX 记录并验证校验和。Keil 不是使用 FF0000 以外的启动区；其 HEX 地址格式与 SDCC 不同。

## 2. SDCC：连续复制 24 字节到 XDATA

复位从 FF0000 跳至 FF001F，再跳至 FF0029；设置栈、调用 external_startup 后，到达以下 XINIT 代码。目标地址与计数由链接值确定。

```asm
; 地址    机器码         指令
FF003F   90 07 77       MOV DPTR,#0777H
FF0042   75 84 FF       MOV DPXL,#0FFH
FF0045   7F 1E          MOV DR4,DR56       ; 源 = 00FF0777
FF0047   90 00 00       MOV DPTR,#0
FF004A   75 84 01       MOV DPXL,#1        ; 目的 DPX = 00010000
FF004D   7E 38 00 00    MOV DR12,#0
FF0051   7E 74 00 18    MOV WR14,#24
FF0055   7E D0 00       MOV R13,#0         ; DR12 = 00000018
FF0058   BE 38 00 00    CMP DR12,#0
FF005C   68 0E          JE  FF006C
FF005E   7E 1B B0       MOV R11,@DR4       ; ACC 读源字节
FF0061   7A EB B0       MOV @DR56,R11      ; 写目的字节
FF0064   0B 1C          INC DR4,#1
FF0066   0B EC          INC DR56,#1
FF0068   1B 3C          DEC DR12,#1
FF006A   78 F2          JNE FF005E
```

R11 是 ACC，DR56 对应这里的 DPX。DR12=24 时，与零比较应得到 Z=0，JE 不跳转，执行 FF005E；不能把顺序到达 FF005E 解读为错误跳转。

对应运行库源文件：`D:/Code/c-env/SDCC/SDCC-4.6.0-MCS251/lib/src/mcs251/crtxinit.asm`。这段是全局变量初始化运行库，不是应用里的 USB、LED 或时钟配置。

## 3. Keil：按记录复制到 EDATA

复位 FF0000 的 LJMP 指向 FF03DB。先用 16 位地址循环清 EDATA 0001..041F，再设 SPX=35H。然后初始化表源指针 DR0=00FF0499。

```asm
FF03EE   7E 04 00 FF    MOV WR0,#00FFH
FF03F2   7E 14 04 99    MOV WR2,#0499H    ; DR0 = 00FF0499
FF03F6   0B 0A 40      MOV WR8,@DR0      ; 读记录长度
FF03F9   5D 44         ANL WR8,WR8
FF03FB   68 1A         JE  FF0417
FF03FD   69 20 00 02   MOV WR4,@DR0+2    ; EDATA 目标
FF0401   0B 0E         INC DR0,#4
FF0403   0B 44         INC WR8,#1
FF0405   80 0A         SJMP FF0411
FF0407   7E 0B B0      MOV R11,@DR0      ; 同样是原生间接读
FF040A   7A 29 B0      MOV @WR4,R11
FF040D   0B 24         INC WR4,#1
FF040F   0B 0C         INC DR0,#1
FF0411   1B 44         DEC WR8,#1
FF0413   78 F2         JNE FF0407
FF0415   80 DF         SJMP FF03F6
FF0417   02 01 18      LJMP FF0118       ; main
```

其表记录为“大端 16 位长度、大端 16 位目的地址、数据”，末尾以零长度结束；8 条记录共复制 24 字节。Keil 的源指针仍用双字寄存器，只有目的地址与计数使用 16 位寄存器。

Keil 普通运行路径还存在：

```asm
FF0145   BE 18 01 F4   CMP DR4,#500
FF033F   BE 18 00 05   CMP DR4,#5
```

所以“Keil 不用 32 位比较”不成立。上述两条与 SDCC 的具体寄存器、立即数及所在路径仍有区别。

## 4. 变量、中断与大小端

SDCC 的 watch16 常量是 `12 34`，watch32 是 `12 34 56 78`；Keil 初始化表的对应数据完全相同。变量排列及所在地址不同不表示大小端不同。

Keil Timer1 ISR 在 FF0003，保存 DR4/DR0，以原生 32 位读写递增 EDATA tick_ms，再恢复并 RETI。SDCC ISR 在 FF0567，保存 ACC/B/DPL/DPH/PSW 及手工保存 DPXL，以字节 ADD/ADDC 递增 XDATA 010014..010017，再恢复并 RETI。两者代码风格和长度不同；现有启动阶段的异常发生在执行应用初始化之前，不能用 ISR 差异解释已复现的最早异常。

现有 MAP 与观察到的栈值没有证明 ICE 尾部保留 RAM 发生重叠。尤其不能把别的 STC 型号保留地址直接套用于本型号。

## 5. 已有实板证据如何对应

1. 同一 SDCC HEX 在独立 GDB/MI2 下运行后无法暂停；使用官方网页原始 JS/WASM 协议模块与原生 HID 桥亦复现运行后暂停超时。后者没有经过 GDB、RSP 或 CLion，但并不等价于完整网页 UI 的所有副作用。
2. 从协议初始化后的复位入口分别运行到断点：FF0042..FF0058 的已测检查点可命中；FF005C 未收到停止。该范围位于上述 SDCC XINIT。协议初始化并不等价于芯片真实冷复位；断点和监控器行为也可能影响结果，不能直接宣布 FF0058 的 CMP 是根因。
3. 单步执行 FF005E 时，DR4=00FF0777，ACC 读到 3B；原生空间 5 的用户常量首字节为 00，同地址空间 2 的首字节为 3B。确定存在读取视图差异，尚未证明该差异如何导致全速失联。单步已能越过 CMP/JE，也说明不能简单断言 CMP 完全不可执行。
4. 用户改下 Keil 固件后，全 1234 个定义字节核对一致。同一生产 GDB server 与 GDB 完成三轮运行/暂停、一次断点与单步，退出后再次全字节核对通过。此次是寄存器/指令级验证，没有声称接入 Keil 源码符号。

日志位于 `D:/Projects/stcforge/.cache/`：

- `sdcc-independent-gdb-20261115-1904.jsonl`
- `sdcc-original-web-run-20261115-1913.jsonl`
- `sdcc-fromreset-xinit-checkpoints-20261115-1934.jsonl`
- `sdcc-xinit-first-read-20261115-1918.jsonl`
- `ice-mini-sma-step-20261115.jsonl`
- `keil-new-independent-gdb-20261115-1942.jsonl`
- `keil-new-after-gdb-verify-20261115-1943.jsonl`

## 6. 核验与下一步实验

本轮主代理独立重读 HEX、校验记录、核对哈希，并复核 SDCC XINIT 45 字节、Keil startup 63 字节、Keil ISR 23 字节与官方回编 HEX 一致。Keil 其余已回编段及逐记录数据见 `keil-simulation-startup-disassembly.md`。

官方指令依据来自本机 STC 手册完整文本，附录 A 印刷页 1233：CMP DRk,#0DATA16 的 Source 编码是 BE(u)8H、四字节。依据不是仅看 Intel 文档推断。手册支持和回编一致均不能替代本芯片、本监控器的实测。

最有区分力的后续实验：在独立试验固件中只把初始化循环计数改成 16 位，保留源指针、XDATA 目的和应用不变；再分别改变源读取寄存器/方法及 EDATA/XDATA 布局。每次只变一个条件，比较脱离 ICE 的正常运行和 ICE 调试。这样才能区分运行库问题、特定指令/寄存器的监控兼容性与地址视图问题。本报告没有把这些实验当作已完成的修复。
