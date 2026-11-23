# 原 S00/S06 应用代码语义核查

日期：2026-11-15。范围限定为原 main、system_millis、system_uart7_send 和 Timer1 ISR。M02 仅作生成代码对照。只创建本文档；未改固件、未访问硬件、未创建新矩阵。本轮不重查启动、CMP 或相同外设配置。

## 结论

**尚未找到可复现的应用代码编译器语义错误，没有足够依据给出固件修补。**

已核实：S00 与 S06 整个应用区 FF00BB..FF0772 共 1720 字节完全相同。原例与 M02 的 81 字节 ISR、70 字节毫秒快照函数都仅有四个 tick 地址字节不同；main 的 73 字节时间差计算完全相同。原例特有的首次返回值写栈、命令分支额外保存 R7、UART 超时路径六个活跃字节保存，按实际 SPX 增减与返回 ABI 核对均正确。

PSW1、DPX 高字节或普通寄存器保护方面，没有发现“被 ISR 改写、前台随后使用、且未恢复”的具体值。不能将缺少 PUSH PSW1、额外 MOV DR28,DPX 或较多栈操作直接定性为失联原因。

主代理补充的最新硬件证据：S00 已经空间 5 全量核对 1914 字节，无 B9，复位跳转单步后全速 100ms 仍暂停超时；当前等待物理上电。该实测由主代理完成，不是本轮静态审阅的测试结果。本文结论不表示原例全速通过。

## 输入、方法和字节范围

矩阵根目录：D:/Code/CLionProjects/STC/STC32K144G246_32BIT_SDCC_Template/Misc/Simulation Firmware Matrix。

- S00：根目录 S00_sdcc_original.hex，baselines/S00_sdcc_original.map 与 .cdb。
- S06：S06_manual_init 下的 HEX/MAP/CDB、main.asm、system_stc32.asm 及 sources 下的 C/头文件。
- M02：M02_led_uart_timer 下的 HEX、main.rst、main.asm、registers.h。
- 本地 ABI：D:/Code/c-env/SDCC/SDCC-4.6.0-MCS251/doc/mcs251/abi.md，Arguments and return values、Stack and startup。
- STC 手册：Misc/Reference/manual/chapters/ch12.md，12.2.4 及专用寄存器别名说明。
- 现有编码表：D:/Projects/stcforge/.cache/instruction-forms.tsv，push_rm/pop_rm、push_dir8/pop_dir8、mov_dr_dr。

通过 MAP 的 A$main$<汇编行号>、A$system_stc32$<汇编行号> 定位实际 HEX；没有使用不完整的 GDB 反汇编补齐未知指令。只读解析 HEX，检查 S00/S06 记录校验和并逐地址比较。

| 区段 | S00/S06 地址，含末字节 | 字节数 | 不同字节 |
| --- | --- | ---: | ---: |
| main | FF00BB..FF02F8 | 574 | 0 |
| Timer1 ISR | FF0567..FF05B7 | 81 | 0 |
| system_millis | FF05D0..FF0615 | 70 | 0 |
| system_uart7_send | FF0652..FF0772 | 289 | 0 |
| main 至 UART 末尾，含中间函数 | FF00BB..FF0772 | 1720 | 0 |

## main 的栈槽与活跃值

分配结果见 S06 main.asm:909 附近：last_toggle 在四字节栈槽，now 在 R15/R14/R13/R12（低到高），received 在 R7。32 位返回值低到高为 DPL/DPH/B/A，普通内存对象为大端。这两种排列是本地 ABI 的明确约定。

FF00C1 调用 system_millis，返回到 FF00C5。main 稳定 SPX 为 T=0106，包含三字节 main 调用帧和四字节局部对象；以下 T 始终表示临时 PUSH 之前的 SPX。

| 指令地址 | 操作 | 实际写槽 |
| --- | --- | --- |
| FF00C5..FF00CD | PUSH A；A=DPL；写 @SPX-1；POP A | T，即 0106 |
| FF00CF..FF00D7 | PUSH A；A=DPH；写 @SPX-2；POP A | T-1，即 0105 |
| FF00D9..FF00E1 | PUSH A；A=B；写 @SPX-3；POP A | T-2，即 0104 |
| FF00E3 | 写 @SPX-3,A，此时临时 PUSH 已撤销 | T-3，即 0103 |

返回值 12345678 时，A=12、B=34、DPH=56、DPL=78；最终 EDATA[0103..0106]=12 34 56 78，SPX 仍为 0106。前后两次 @SPX-3 的基准不同，不会写同一个字节。

FF00C5..FF00E6 的实际字节：

    C0 E0 E5 82 39 BF FF FF D0 E0
    C0 E0 E5 83 39 BF FF FE D0 E0
    C0 E0 E5 F0 39 BF FF FD D0 E0
    39 BF FF FD

离线按前增 PUSH、当前 SPX 相对寻址、后减 POP 核对 24 组：T=0106/01FF/0200，返回值=0/1/12345678/FFFFFFFF，有/无额外保存 R7。槽值与最终 SPX 全部正确。这是内存中的指令语义计算，不是完整 CPU 或 ICE 仿真。

接收路径 FF01C6 将字节放到 R7。更新 last_rx/rx_count 没有覆盖 R7。字符 0、1、L 分支分别在 FF022F、FF026E、FF02BD 保存 ar7，调用 LED/快照函数后恢复；FF02EB 将 R7 传入 DPL，FF02EE 调用发送函数。

保存 R7 后 SPX 多一字节，三次临时 PUSH 的写槽偏移变为 -2/-3/-4，最后 A 使用 -4，仍落在 T-3..T。例如字符 0 分支 FF0239..FF025A 写回 last_toggle，FF025B 恢复 R7；未发现对象写入接收字节的保存槽。

原例 FF00F6..FF013E 与 M02 FF0505..FF054D 的 73 字节时间差运算完全相同。它用 last-now-borrow 后取反构造 now-last，CPL C 配合下一字节借位。离线核对单字节恒等式 131072 组（256×256×2），四字节链核对 100169 组（13 个边界值的两两组合，加固定种子 251 的 100000 组随机数），均等于 (now-last_toggle) & FFFFFFFF。没有发现减法方向或借位错误。

## system_uart7_send 的保存恢复

FF0652 把参数 DPL 放入 R7。FF0655 C0 07 保存参数，FF0657 调用 system_millis，FF065B..FF0665 把返回值放入 R15/R14/R13/R12，FF0666 D0 07 恢复参数。system_millis 会用 R7 保存 EA，这里确实需要保护，实际没有遗漏。

value 已于 FF0689 写入 UART 数据寄存器，随后 R7/R6 才改用于 spins：低字节 R7=60，高字节 R6=EA，即 60000。FF06A4 先减 R7，仅当结果变 FF 时于 FF06AA 减 R6，符合 16 位减一。

时间检查时同时活跃的值：

| 值 | 所在寄存器，低到高 | 保护方式 |
| --- | --- | --- |
| started | R15/R14/R13/R12 | 四个单字节 native PUSH/POP |
| spins | R7/R6 | 两个 direct PUSH/POP |
| 新快照 now | DPL/DPH/B/A | 先转到 R5/R4/R3/R2，再恢复旧值 |

实际指令：

    FF06B6 C0 07       PUSH ar7
    FF06B8 C0 06       PUSH ar6
    FF06BA CA F8       PUSH R15
    FF06BC CA E8       PUSH R14
    FF06BE CA D8       PUSH R13
    FF06C0 CA C8       PUSH R12
    FF06C2 9A FF 05 D0 ECALL system_millis
    FF06C6..FF06D0    返回值转到 R5/R4/R3/R2
    FF06D1 DA C8       POP R12
    FF06D3 DA D8       POP R13
    FF06D5 DA E8       POP R14
    FF06D7 DA F8       POP R15
    FF06D9 D0 06       POP ar6
    FF06DB D0 07       POP ar7

CA/DA 是单字节寄存器形式，不是整个 DR12。现有编码表的 push_rm/pop_rm 与这些操作数编码一致。应用没有切换 RS0/RS1；direct ar6/ar7 按本程序 bank 0 使用，未发现应用内部 bank 不一致。

离线例：调用前 started=12345678、spins=EA60，快照返回 1234567E。六次保存、三字节调用帧进出、返回值转移、六次恢复后，started/spins 不变，now 在 R2..R5 为 12 34 56 7E。FF06DD..FF0701 得到差 6，后续与 5 比较应超时返回 0，未发现新返回值覆盖旧时间戳。

该路径只在 main 接收到字节后进入；不能仅凭这里指令更多解释没有 UART 活动时的失联。

## ISR、PSW1 和高 DPX 别名

原例 system_stc32.asm:1262，对应机器码：

    FF0567..FF0572 C0 E0 C0 F0 C0 82 C0 83 C0 D0 C0 84
                  PUSH ACC/B/DPL/DPH/PSW/DPXL
    FF05AB..FF05B7 D0 84 D0 D0 D0 83 D0 82 D0 F0 D0 E0 32
                  POP DPXL/PSW/DPH/DPL/B/ACC; RETI

主体只使用 A、DPTR、DPXL 和 ADD/ADDC 更新 tick，不调用其他 C 函数。

- ACC/B 分别别名 R11/R10，STC ch12.md:726..727 明确。ISR 会改它们，但均有 PUSH/POP；不能沿用“ISR 完全不写 R0..R15”的不精确说法。R0..R7、R12..R15 未被本 ISR 改写。
- DPX 是 DR56，不是 DR28。STC 手册位置 57/58/59 对应 DPXL/DPH/DPL；位置 56 未列可访问 SFR。ISR 改的三个可访问字节都保存了，没有发现遗漏保护另一个实际被写过的 DPX 高字节。
- 前台 MOV DR28,DPX（例如 FF01AF 的 7F 7E）复制到 R28..R31；后续访问仍是 @DPX。ISR 不写 DR28，应用也没有把该复制值作为跨 C 调用活跃值。它与 DPX 的 SFR 别名不是同一组寄存器。
- STC ch12.md:238..243 说明 PSW1 的 CY/AC/RS/OV 与 PSW 共用。PUSH/POP PSW 覆盖实际 ADDC/SUBB 链所需的 CY。N/Z 为 PSW1 独有，不能从 PSW 保存推导它们也被保存。
- 安装中的 doc/mcs251/research.md:306 描述四字节中断帧和 RETI 恢复 PSW1，abi.md 也要求四字节帧。本轮将它作为既有实现约定，不冒充 STC 实物独立验证；已读 STC 第 12 章足以证明寄存器别名，不能单独证明硬件帧细节。
- 对两份应用 ASM 扫描未发现 JE/JNE/JG/JGE/JL/JLE/JS/JNS 原生 N/Z 条件跳转。实际判断为 A 的 JZ/JNZ、位条件、CJNE、CY 的 JC/JNC。尚未找到本应用中会因独有 N/Z 未恢复而使用错误条件的消费者，不能直接以少 PUSH PSW1 定罪。

原 ISR FF0567..FF05B7 与 M02 FF03DA..FF042A，81 字节中仅四个 DPTR 立即数低字节不同：原例 010017/16/15/14，M02 010004/03/02/01。保存恢复及算术字节全部一致。

## XDATA 地址与返回值装配

| 原对象 | S00/S06 MAP 平坦地址 |
| --- | --- |
| heartbeat_count | 010000..010003 |
| rx_count | 010004..010007 |
| tx_count | 010008..01000B |
| last_rx / led_state | 01000C / 01000D |
| watch16 / watch32 | 01000E..01000F / 010010..010013 |
| tick_ms | 010014..010017 |

FF05D8 的 90 00 17、FF05DB 的 75 84 01、FF05DE 的 7E EB B0，形成 DPX=01:0017 并把最低有效字节读到 R15，随后按 010016/15/14 读到 R14/R13/R12。FF060A..FF0614 转回 DPL/DPH/B/A，符合大端对象 010014..17。

原快照 FF05D0..FF0615 与 M02 FF0451..FF0496 的 70 字节仅四个地址低字节不同。读取前关 EA，读齐后按原值恢复 EA。恢复后如发生 Timer1 ISR，其 DPL/DPH/B/ACC 保存覆盖返回值装配期间使用的别名寄存器；未发现快照返回值遗漏保护。

last_toggle 位于 EDATA 栈 0103..0106，与 flat XDATA 010003..010006 不同。未见生成代码把二者混用，也没有据此推断 XDATA 与 ICE 保留资源重叠。

## 收束与核查边界

没有确定错误，故没有最小固件补丁。可供主代理已有原固件执行隔离使用的具体不变量为：

1. 若 FF00C5 的 A:B:DPH:DPL=12:34:56:78，到 FF00E7 应见 SPX=0106、EDATA[0103..0106]=12 34 56 78。
2. FF06B6 前的 R6/R7、R12..R15 到 FF06DD 应恢复，新快照在 R5/R4/R3/R2。无接收字节时不进入这个窗口。
3. Timer1 ISR 返回后，被打断的 A、B、DPL、DPH、DPXL、CY、R12..R15 应保持，tick 增一。只有观察到具体值偏离，才能升级为保存恢复错误。

这些是已核对代码的预期结果，不是新增实验要求。本轮至此结束；未运行硬件、未验证 ICE 重入/总线时序，未把离线语义检查当作原固件通过。

