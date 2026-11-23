# GDB Watch 与帧身份回归调查

## 2026-11-16 主代理修复与部署结果

以下原调查记录描述旧版，不再代表当前发行文件状态。主代理已修改 src/native/gdb/mcs251-tdep.c：有函数符号时用函数入口作为 unavailable-stack 帧 ID 的代码锚点，未知代码仍回退到当前 PC。同一函数内单步不再生成新身份；继续明确不支持调用栈展开，未声称具备完整递归帧识别。

旧版在同函数连续两次单步时都返回 WATCH_FRAME_SAME=False,False，新版返回 True,True；切到另一函数仍返回 WATCH_FRAME_OTHER=False,False,timer1_isr。三个全局变量同时创建、原对象跨单步更新也通过。完整测试运行163项，162项通过、1项因未设置编译器环境变量跳过；随后设置实际 SDCC 路径单独补跑该编译器/调试器联调测试通过。正式路径替换后，又对正式 EXE 跑了三个 Watch 回归，全部通过。全部验证仅使用回环 MockTarget，没有访问或写入开发板。

正式路径：D:/Projects/stcforge/dist/windows/stc-gdb.exe。SHA256：8f441e029f06e9fd7681d9748d6df5c22bc53dc02d00a6986046882a8229f43f。旧版备份：D:/Projects/stcforge/.cache/stc-gdb-before-watch-frame-20261116.exe。CLion 无需改工具链路径，重开调试会话加载新版。UI 中“只能添加一个”尚未复现，不能把本次帧修复写成用户全部现象已验证解决。

## 以下为子代理的旧版原始调查

日期：2026-11-15。子代理仅使用本地真实旧版 GDB、当前真实 ELF 和回环 MockTarget。子代理没有访问硬件、改固件、改生产 server/target 或 native 实现。

## 阶段结论

标准 MI 的“三个全局 Watch 同时创建、单步后更新”未复现用户描述的问题：watch16/watch32/tick_ms 都可创建；在复位地址与 main 内各连续两次 Mock 单步后，三个对象都保持 in_scope=true，更新值正确。数值不变时 changelist=[]，并不表示对象被删除。

独立的 Python Frame 身份问题已经由本测试复现：在 main 内仅前进一条 Mock NOP，先前保存的 gdb.Frame 就变为 is_valid=False，且不等于当前帧。连续第二步仍然如此。主代理已独立定位 src/native/gdb/mcs251-tdep.c 用 get_frame_pc 构建 unavailable-stack frame_id，计划改用 get_frame_func；该 native 分析及修复不属于本次改动。

主代理还报告：本机 CLion 原装 default.commands 的 cidr-var-create/read 两变量单步已正常。应区分“标准 Watch 未复现”和“帧 ID 缺陷已复现”；目前不能声称完全定位了用户 UI 中只能添加一个或变量消失的全部原因。

## 样本与复现命令

- GDB：D:/Projects/stcforge/dist/windows/stc-gdb.exe，GNU gdb 16.3，9387008 字节。
- GDB SHA256：0c4c02a55a777a1f20dab295114f6f912dacba128a2e1d44d8acf9534a600575。
- ELF：D:/Code/CLionProjects/STC/STC32K144G246_32BIT_SDCC_Template/Misc/SDCC Simulation Test/build/Debug/firmware/STC32G144K246_Simulation_Test.debug.elf，3736 字节。
- ELF SHA256：8a14fe4d9ef03397d5959ab2161b57396f1e44d499e4b5ea7da8b996517a7944。
- 测试：D:/Projects/stcforge/tools/tests/test_gdb_watch.py。

运行：

    D:/Code/uv/uv.exe run --project D:/Projects/stcforge --no-sync python -B -m unittest discover -s D:/Projects/stcforge/tools/tests -p test_gdb_watch.py -v

可用 STCFORGE_GDB 指定修复后的候选 GDB，用 STCFORGE_WATCH_ELF 指定相应 ELF。二者不存在时按既有集成测试约定跳过。设置 STCFORGE_WATCH_TRACE=1 可在终端输出 MI 记录；测试本身不写日志或固件文件。

## 标准 Watch 的真实 MI 响应

当前 ELF 中 watch16=010005（2 字节）、watch32=010007（4 字节）、tick_ms=010001（4 字节）；测试通过真实 GDB 查询地址和 sizeof，不硬编码地址。MockTarget 独立填入 1234、12345678、1000 的大端字节。

三个创建依次成功，节录初次复现的原始 token：

    > 12-var-create - * watch16
    12^done,name="var1",numchild="0",value="4660",type="unsigned int",has_more="0"
    > 14-var-create - * watch32
    14^done,name="var2",numchild="0",value="305419896",type="unsigned long",has_more="0"
    > 16-var-create - * tick_ms
    16^done,name="var3",numchild="0",value="1000",type="unsigned long",has_more="0"
    > 18-var-update --all-values *
    18^done,changelist=[]

设置十六进制显示并单步后，将 Mock RAM 中三个值各加一，真实更新返回：

    ^done,changelist=[{name="var3",value="0x3e9",in_scope="true",type_changed="false",has_more="0"},{name="var2",value="0x12345679",in_scope="true",type_changed="false",has_more="0"},{name="var1",value="0x1235",in_scope="true",type_changed="false",has_more="0"}]

第二次单步后同理返回 0x3ea、0x1234567a、0x1236，全部 in_scope=true。var-info-expression 和 var-evaluate-expression 对三个原对象也继续成功。没有重新创建对象来掩盖失效。

测试在 FF0000 和从 ELF 查询到的 main=FF0497 两处分别执行。MockTarget 只在自己的内存中放 NOP，逐字节前进；它不执行真实固件序言，也不模拟栈或 Timer1。真实 ELF 仅提供变量类型、位置和函数范围。

## Frame 身份回归及实际失败响应

新增 test_frame_identity_survives_steps_but_changes_function：

1. Mock 初始 PC 置于 ELF 的 main 入口；通过真实 GDB Python 保存 watch_saved_frame = gdb.selected_frame()。
2. main 内执行两次单步，每次要求原对象仍 is_valid() 且等于 gdb.selected_frame()。期望输出 WATCH_FRAME_SAME=True,True。
3. 重新保存当前 Frame，下一次 Mock step 直接把 PC 设到 ELF 中另一个真实函数 timer1_isr=FF03DA。不执行 ISR，只模拟换函数的停点事件。要求旧 Frame 失效且不等于当前帧，并确认当前名称为 timer1_isr。

当前发行版的实际响应：

    *stopped,reason="end-stepping-range",frame={addr="0x00ff0498",func="main",...}
    > -interpreter-exec console "python print(...saved frame validity and equality...)"
    ~"WATCH_FRAME_SAME=False,False\n"
    ^done

    *stopped,reason="end-stepping-range",frame={addr="0x00ff0499",func="main",...}
    ~"WATCH_FRAME_SAME=False,False\n"
    ^done

换函数的负向检查实际通过：

    ~"WATCH_FRAME_OTHER=False,False,timer1_isr\n"

因此回归不是简单要求所有帧使用常数 ID：修复后同函数内两步要保持，换到另一函数仍必须失效。测试不要求新增回溯支持，也不把函数入口 ID 当作完整递归栈展开能力。

## 验证结果与边界

在上述 GDB/ELF 指纹上，最终 unittest discovery 实跑：3 个测试，两个标准 MI Watch 测试通过；Frame 测试在两次同函数单步子用例上失败，换函数检查通过。输出为 Ran 3 tests，FAILED (failures=2)。失败断言保持严格预期，没有 expectedFailure 或放宽成接受旧缺陷。

测试复用 test_gdb_async.py 的有界 MI 读取和可取消回环 MockServer，按 token 匹配结果、按序列匹配停止事件；进程和服务都有超时清理。没有真实 GDB 以外的编译/部署步骤。主代理后续用新二进制运行本测试并部署；本报告不声明修复已经构建或发布。

