# ICE 空间 5 代码装载实验的有效前提审阅

日期：2026-11-15。范围只覆盖 tools/diagnostics/probe_original_firmware.py 的空间 5 写码实验、IceSession 的写入/初始化/继续运行实现、已有本地官方网页 JS/WASM 复核和 Keil 驱动静态记录。未访问硬件、未改代码、未重新执行实验，也不重新审阅原应用语义。

## 阶段结论

主代理补充的事实是关键：S00 是通过 USB-ICE 空间 5 写入当前板，之后读回 1914 字节匹配；用户没有通过 ISP 烧录 S00。因此这个读回只能证明“空间 5 的读路径返回了与本地 HEX 相同的字节”，不能证明断电复位后 CPU 会从 S00 的非易失程序存储执行。

对当前实现可以给出两层结论：

- 作为“在已经建立的 ICE 会话中，向空间 5 写入临时代码，然后验证、单步并继续运行”的实验，探针具备基本协议前提：每个写包收到 06 事件确认，随后通过空间 5 读回验证，重新调用已验证的调试初始化，再执行单步和 resume。
- 作为“装载 S00 后等价于完整 ISP 烧录，能够证明冷启动执行 S00”的实验，前提不成立。当前探针没有执行 ISP 擦除/编程/提交流程，也没有本地证据证明空间 5 的写入会持久化到断电后的用户程序存储。

本地资料没有证明还需要某个未实现的“提交”或“代码缓存刷新”命令才能让空间 5 写入在同一 ICE 会话的全速执行中生效；同样也没有证明空间 5 写入本身一定会替换冷启动代码。应把这两个问题分开，不能由读回结果替代。

## 探针实际做了什么

probe_original_firmware.py 的精确路径如下：

1. 第 75 行调用 session.initialize_debug()。
2. 第 77..92 行先读出 FF0000..hi 的备份，然后把 HEX 中所有已定义地址按连续段分成最多 48 字节，调用 session.write_memory(5,start,chunk) 写入空间 5。
3. 第 93..96 行再次从空间 5 读 FF0000..hi，只对本地 HEX 已定义地址比较；得到 VERIFIED 后并没有进行 ISP 烧录或其他持久化步骤。
4. 第 100 行再次调用 session.initialize_debug()。
5. 若指定普通 SJMP 检查点，第 108..110 行再向空间 5 写 80 FE 并读回确认。
6. 第 111..118 行仅对 reset 入口做一次 target.step()，随后 target.resume()，等待后调用 target.halt()。
7. 第 125..135 行在确认暂停后恢复检查点字节并再次做空间 5 完整核对。

因此，探针日志语义“USB-ICE code writes, not ISP”是准确的；代码中的 LOADED/VERIFIED 不应解释成“已烧录”或“冷启动镜像已更换”。

## IceSession 能证明和不能证明的内容

### 空间 5 写入

src/stcforge/ice.py:604..643 的 write_memory：

- 允许空间 0..5，注释明确说空间 5 专门用于代码修改；
- 将请求编码为 space + address.to_bytes(4, big) + count + data；
- 调用 _event_exchange(CMD_WRITE, payload)；
- 将返回的 06 事件当作写确认，并清理后续事件。

该函数没有擦除、页编程、写保护解锁、校验提交、复位、Flash busy 等步骤。它也没有叫作 flush_code_cache 或 commit_code 的后续命令。

src/stcforge/ice.py:454..486 显示 _event_exchange 只负责发送一条 USB 命令并校验回复类型；06 事件确认的是协议命令完成，不是持久化介质提交的证明。

### 调试初始化和运行

src/stcforge/ice.py:490..524 的 initialize_debug：

- 查询 V4.0；
- 发送零长度空间 0 请求 FF5A08020000FF0000009E；
- 等待至少 2 秒；
- 读取完整状态并要求 PC 为 FF0000。

实现注释把它描述为“按 Keil 完整抓包建立新的调试会话”，并明确“此请求只用于启动 FF0000 的新会话，不开放通用 set_pc，也不先发暂停或自动运行”。现有实现没有把该请求定义成 Flash 提交或全片复位；它只能证明调试入口状态被建立并且 PC 回到 FF0000。

src/stcforge/ice.py:645..653 的 resume 只发送 CMD_CONTROL 的 00 运行请求并处理事件队列。它没有先提交空间 5 写入，没有代码缓存刷新，也没有 ISP 编程。

所以，探针随后全速运行时，代码路径只包含“空间 5 写、读回、初始化调试、短 run”。若设备把空间 5 视为当前调试代码覆盖层，这足以测试覆盖层；若设备要求另外的提交或复位才能切换执行视图，当前代码没有完成该要求，实验就不能判定新代码已执行。

## 官方网页 JS/WASM 的本地证据

样本目录：

- .cache/web-protocol-75XySu/chunks/chunk-FDBPC2DQ.js
- .cache/web-protocol-75XySu/sim_core.wasm
- 同内容的第二份样本在 .cache/web-protocol-RROQiO/。

chunk-FDBPC2DQ.js 的 buildFrame 分支明确区分：

- what=write：将数据放入 WASM dataPtr，调用 buildWrite(kind, addr, data.length)；
- what=erase：调用 buildErase(addr)；
- what=run：调用 buildRunStep 或 buildRunFull；
- what=reset：调用 buildReset；
- what=breakpoint：调用 buildSetBreak(addr)。

已有 docs/web-sim-protocol-review.md:161..168 对网页调用链的静态结论是：

- UI.download 和 FlashDiffer.download 支持 halt、扇区擦除、代码写入和默认读回校验；
- 下载后的自动运行会 writePc(host.codeBase)、readPc 核对，最多重试 5 次，然后 run；
- UI.reset 会 halt、清除断点、writePc(codeBase)、readPc、refreshRegs；
- WASM 可以构造擦除命令，例如 buildErase(FF0000)；构造导出本身不证明所有入口都会调用它；
- 已核对的 connect/run/step 调用链没有自动下载 monitor 或无条件替换用户代码。

这组证据支持一个精确区分：网页的“下载/自动运行”是包含擦除、代码写入、读回和 PC 准备的独立流程；网页的普通 full run 只是构造 run 帧。它没有证明 buildWrite 单独就完成 Flash 提交，也没有证明当前 STCForge 的空间 5 写入等价于网页的 download。

网页构造表见 docs/web-sim-protocol-review.md:37..54。buildReset 与 buildWritePc(FF0000) 在该样本中构造相同的零长度空间 0 请求。这个事实只能证明报文构造相同，不能把它升级为“已经完成 ISP 烧录”或“必然清除代码缓存”。

## Keil 驱动资料能证明的边界

根据 docs/keil-pause-review.md：

- DLL RVA 0x462E 负责软件断点安装/恢复；
- 停止后官方读取 PC，再恢复软件断点，然后读取完整状态；
- RVA 0x451F 清除的是宿主状态/内存缓存标记，调用 0x441B 处理缓存；已有逆向没有把它识别成目标芯片代码缓存刷新、Flash 提交或用户程序重烧；
- 运行入口 RVA 0x2EA7 发送 FF5A0308009C，然后等待事件。

官方抓包的运行前序列是查询版本、空间 0 零长度入口请求、等待约 2 秒、读取状态、run。该资料没有出现“写空间 5 后发送一个额外提交命令”的证据，因为抓包中的软件断点只是在停止时用空间 5 写 B9、随后恢复原字节；它不是完整固件下载记录。

因此可以确认：探针使用的 initialize_debug 和 run 形态接近已记录的 Keil 调试会话；不能确认它拥有 Keil/ISP 的完整程序下载语义。

## 对实验有效性的最终判断

| 要回答的问题 | 当前本地证据 | 判断 |
| --- | --- | --- |
| 每个空间 5 写请求是否被协议接受 | write_memory 收到 06 确认 | 有效 |
| 写入后的空间 5 读路径是否返回目标字节 | 探针 native_read 与本地 HEX 比较 | 对读路径有效 |
| 同一 ICE 会话中 resume 前是否有额外提交或 flush 实现 | IceSession 没有该步骤 | 未发现需要，但未证明设备不需要 |
| 新字节是否在当前调试执行视图生效 | 当前本地资料没有独立证明空间 5 写入的执行映射 | 未证明 |
| 断电后 PC=FF0000 是否执行刚写入 S00 | 没有 ISP 烧录，也没有冷启动后读回或执行证据 | 无效前提 |
| 当前板读回 S00 是否证明用户烧录了 S00 | 主代理说明 S00 是 ICE 写入 | 不能证明 |

最小静态结论是：probe_original_firmware.py 可用于记录“空间 5 临时代码写入并读回成功”，但其 resume/halt 结果只能解释为当前 ICE 会话中的执行尝试。它不能作为“原 S00 已通过完整烧录、冷启动运行后失联”的证据。

本轮没有修改实现，也没有提出硬件操作步骤；文档到此结束。

