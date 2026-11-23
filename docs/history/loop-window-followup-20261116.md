# 主循环时序对照与本轮硬件状态

日期：2026-11-16。主线程独立处理，无子代理。没有生产协议修复。

更新：49已在下一轮开始完整恢复。最新状态及50/51/52结果见tail-window-and-fault-containment-20261116.md；以下“必须先恢复”是本页结束时的历史状态，最新待恢复记录已改为overlay-203858-116165。

## 当前必须先恢复的状态

最后测试49-sdcc-uart-call-bridge在首次700ms暂停失败，备份尚未恢复。覆盖记录为：

    D:/Projects/stcforge/.cache/m02-progression-20261116/overlay-202000-261081

恢复前现场读取超时；初始化收到46字节旧状态而不是5字节版本。随后有限次数排空/同步尝试取得V4.0，但入口请求没有零事件确认，仅又收到版本事件，因而没有继续擦写。日志为该目录recovery-resync.json。不能把取得版本文本等同于已经进入可安全恢复的停止状态。

需要目标板完整断电上电，随后优先执行普通恢复器：

    D:/Code/uv/uv.exe run --project D:/Projects/stcforge --no-sync python D:/Projects/stcforge/.cache/m02-progression-20261116/recover-erased-overlay.py D:/Projects/stcforge/.cache/m02-progression-20261116/overlay-202000-261081

备份范围FF0000..FF09FF，共2560字节；SHA256为075a2ec586320553c770882816ca7e9c4776d6e5dc88d32924c33eccb9eb2fc8。基线为03-led-commands。49失败发生在软件断点测试前，没有本轮登记的软件断点。

## 实板结果

原始04 HEX SHA256：14cc60afeb673a2094934cd4901279d27bae7cdcb7e364d7cd8b790ebeaa2495。除特别说明，使用真实GDB、三次700ms运行/暂停、watch16/watch32、软件断点命中与删除、删除后单步、退出时板内所有定义代码核对。所有候选写入后均经原生代码空间读回核对，再开始运行。

| 候选 | 唯一目的及范围 | 实板结果 | 覆盖记录 | 恢复 |
| --- | --- | --- | --- | --- |
| 43 | 前500ms原程序不变，FF0818改NOP/NOP/SJMP自身，EA/ET1持续开启 | PASS，使用--no-breakpoints，仅暂停/变量/退出核对 | overlay-200234-138248 | 同会话2560字节核对通过 |
| 33 | 按RST边界替换全部21处EJMP为LJMP+NOP，ISR不变 | 首次暂停后的状态查询read error | overlay-200256-811052 | 通过 |
| 44 | 65处A5前缀MOV Rn,A及MOV A,Rn换为等长原生7C编码；ISR不变 | 首次暂停失败，tick714、heartbeat1 | overlay-200828-280897 | 通过 |
| 45 | system_millis的MOV EA,C从返回值装载前移到其后，长度/地址不变 | 首次暂停失败，tick718、heartbeat1 | overlay-200941-142650 | 通过 |
| 46 | system_millis的CLR EA及MOV EA,C改NOP；仅诊断，快照不再保证原子性 | 首次暂停失败，tick720、heartbeat1 | overlay-201157-350882 | 通过 |
| 47 | UART调用经桥；主循环计算时CLR EA；循环末SETB EA+16NOP后返回 | 完整GDB上述各项PASS | overlay-201552-937922 | 同会话通过 |
| 48 | 与47相同布局，但桥中的CLR EA改为NOP/NOP，全程允许中断 | 完整GDB上述各项PASS | overlay-201746-810201 | 同会话通过 |
| 49 | 只保留UART调用桥，无循环末窗口；桥前NOP/NOP，中断不屏蔽 | 首次暂停失败 | overlay-202000-261081 | 尚未恢复 |

47、48保留原函数、完整ISR、所有计时及灯控操作；但当时测试工具只核对watch16/watch32，没有记录实际tick或heartbeat，因此不能把结构上的功能保留夸大成计时精度或灯控行为已验收。也没有施加UART输入，不能声称UART收发已测试。

43三次停止PC均为FF081A，确实进入自循环。它与41关闭EA后自循环都通过，因此不能把41通过归因于关中断。

## 解释边界

33表明单独替换所有EJMP不足以修复。44仅替换一组寄存器MOV编码，没有替换CJNE、算术等其他A5前缀指令，不能据此宣布所有前缀指令均已排除。

47通过后若只看单个结果，会误判为中断保护起效；48在相同布局不关中断仍通过，已否定这个单因素解释。49又说明仅移动UART调用点不足以达到48结果。当前最值得继续分离的是循环回跳路径与新增指令的时序影响，不能把NOP延时当作根因修复或直接合入模板。

## 已准备的下一项

50-sdcc-tail-window只改FF07FD和FF0854两处循环回跳，先到FF0870执行SETB EA、16NOP，再跳回原FF06ED。UART调用留在原处，不屏蔽EA；原ISR和其他代码保持。对应HEX SHA256为4e03d84f07c714545921928bd8fb5d635558130a2494086f3acf01ce1142a02f。

仅已离线生成并逐字节检查，尚未上板。下一次先恢复49，再测试50，不重复43/33或重新验证用户所说的上电就绪。

若50通过，应在同一候选中减小尾部窗口，区分额外跳转与NOP时序；如果50失败，应检查48中两段变化的组合，而不是立即把中断保护当修复。

## 测试工具改动

tools/diagnostics/test_usb_ice_matrix.py现对MAP中存在的_tick_ms、_heartbeat_count、_rx_count、_tx_count，在每轮已确认暂停后通过GDB读数并记入该轮check.counters。49在首次停止前失败，所以尚没有这些新增计数的实板证据。

同会话备份恢复已在43、47、48真实成功，均核对完整扇区后才记录恢复完成；它只改善诊断清理，不是暂停故障修复。相关工具49项单元测试通过，负例故意产生的错误日志不表示测试失败。
