# 同源机器码对照：Keil C251 与 SDCC MCS-251

2026-11-16。本次把已经复现失败的 `04-split-timeout` 的应用逻辑交给 Keil C251 编译，不再用功能相近、结构不同的原 Keil `main.c` 推定编译器差异。Keil 同源 HDATA 版在实板也出现暂停失联；尚未定位是哪个执行条件造成失联。

## 输入与复现

基准源码位于 `.cache/m02-progression-20261116/08-main-first-timeout/review/baseline-04-rebuild`。从该源码重建的 SDCC HEX 与原04哈希一致。`make-keil-same-source.py` 先核对4个输入文件的 SHA256，再为 C251 生成两份输入：`61-keil-same-source`（`far` / HDATA）和 `62-keil-same-source-edata`（EDATA）。`ice_main.c` 逐字节相同；外设地址、初始化赋值、UART 双超时、灯控顺序及 `++tick_ms` 均不改变。适配内容是 SFR/sbit 声明、数据空间及中断关键字；去除 SDCC 专用启动钩子、ISR 的 DPXL 手动入栈/出栈，由 Keil 链接启动代码并按其实际指令保存上下文。未复用二进制对象或在同一固件混合两套 ABI。

Keil 用 C251 5.60，`XSMALL OPTIMIZE(0,SPEED) DEBUG CODE`，L251 `CLASSES(EDATA(0x0-0x3FFF),HDATA(0x10000-0x2FFFF))`，OH251 `H386`。两份均无编译或链接警告/错误。MAP/LST/HEX 均留存。SDCC 的等价重建有 `.rst`，对照下从实际 HEX 按地址读取字节，不使用 LST 中尚未重定位的占位字节。

## 同功能、不同生成方式

| 代码路径 | SDCC 04 | Keil 61（同源 HDATA） |
| --- | --- | --- |
| Timer1 向量、ISR | `FF001B: 8A FF 05 52`，`EJMP FF0552`。ISR 81 字节；软件保存 ACC/B/DPL/DPH/PSW/DPXL 共6字节，使用4次逐字节读写和 ADD/ADDC，最后 `32` RETI。 | `FF001B: 02 05 39`，`LJMP FF0539`。ISR 41 字节；保存 DR8/DR4/DR0 共12字节。经 DR0 地址做两次16位读、`2F 12` ADD DR4,DR8、两次16位写，最后同样 `32` RETI。 |
| `system_millis()` | `FF0370`，70字节；临时关闭 EA，DPX 分别读4个字节，按原值恢复 EA，经 A:B:DPH:DPL 返回，`AA` ERET。 | `FF050D`，44字节；同样保存/关闭/恢复 EA，DR0 间接读两个16位字，把值放在 EDATA 临时槽，经 DR4 返回，`22` RET。 |
| 无 UART 数据 | `FF03B6` 起用 DPX 读 `7EF7A0`，RI=0 跳至 `75 82 00` 返回 DPL=0，再 `EJMP FF0551` 到 ERET。 | `FF013B` 起用 DR4 读同一 XFR，RI=0 以 `E4` 返回 A=0，再 `LJMP FF0238` 到 RET。两个版本都不走发送等待分支。 |
| 主循环局部变量 | `now` 用 R12..R15，`last_toggle` 用 SPX 相对地址访问。命令比较用三条 `A5 BB imm rel`（CJNE R3）。 | `now`、`last_toggle` 都在静态 EDATA。命令比较用 `BE B0 imm` CMP R11 和 `78 rel` JNE。 |
| `(now-last_toggle)>=500` | `FF07B4..FF0800`，77字节。按低字节到高字节从 SPX 读，SUBB/CPL 处理借位，再用4条 SUBB 比较阈值，条件不满则 `EJMP FF06ED`。 | `FF0100..FF010F`，16字节。`7E 0F 00 0C 7E 1F 00 08 9F 10 BE 18 01 F4 40 9F`，读取两个32位 EDATA 对象，SUB DR4,DR0、CMP DR4,#500、JC 回跳。 |
| 内存布局 | tick `010001..010004`，watch16 `010005..010006`，watch32 `010007..01000A`；高字节在低地址。程序含2118个字节。 | tick `01000C..01000F`，watch16 `010005..010006`，watch32 `010000..010003`。仍是大端，不同的是对象排序、对齐和访问宽度。程序含1392个字节。 |

62 对照保持 Keil 源码逻辑，只改变8个应用全局变量的内存类；最终布局/机器码随之改变，不是二进制单字节对照。共1217个代码字节，tick 位于 EDATA `0014..0017`。ISR 位于 `FF0003..FF0019`，23字节：`CA 1B CA 0B 7E 0F 00 14 7E 18 00 01 2F 10 7A 1F 00 14 DA 0B DA 1B 32`。这是原成功 Keil K00 同样的 ISR 字节。现阶段仅构建和核对，尚未上板。

## 实板结论与恢复

- 已通过的03在直接调用官方 DLL 运行/暂停/等待/读PC/读状态/读RAM的对照中三轮通过。原 SDCC 04 在相同调用顺序、700ms运行时间下，暂停收到事件，但 DLL 在首笔读PC中超过12秒未返回。两次均恢复已备份扇区。
- Keil 61 通过实际程序空间回读核对1392字节，也收到运行确认；700ms后调用官方暂停函数，没有等到停止事件，外部12秒保护退出。此后 Windows 未再枚举 `34BF:1002`，两次恢复尝试均未打开设备，没有执行恢复擦写。故障点与同轮 SDCC 04 不完全相同，亦没有61的暂停快照或计数，不可声称已经证实同一芯片内根因。可以确定的是：这种暂停失联不以 SDCC 生成机器码为必要条件，不能把它单独归因于 SDCC 的 EJMP、A5 或 ABI。
- **当前待恢复为 `overlay-214254-358864`**，备份 `FF0000..FF07FF` 共2048字节，涉及03基线；未设置临时断点。设备重新上电出现 USB-ICE 后，普通恢复器验证备份身份以及板内字节，随后回读全部2048字节。不能用较早的2560字节记录代替这次备份。

```powershell
D:/Code/uv/uv.exe run --project D:/Projects/stcforge --no-sync python D:/Projects/stcforge/.cache/m02-progression-20261116/recover-erased-overlay.py D:/Projects/stcforge/.cache/m02-progression-20261116/overlay-214254-358864
```

Keil 61 HEX SHA256：`f0394d652c2f6a12668354d0aa4eeeba4a6ffc702e890a5086fefdbd7c90f9e7`。Keil 62 HEX SHA256：`0a7a9ec266dbcf48a902dd85eab21a14bb853a983d350e40152745c757c28062`。下一板测只跑62，核对实码并按 MAP 从空间1读取 EDATA。若62通过，先做 HDATA/EDATA 的重复对照，再分离存储器空间、访问编码和地址布局；若不通过，优先检查同源程序与原 K00 的实际执行结构差异。没有提交生产代码变更。
