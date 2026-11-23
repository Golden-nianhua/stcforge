# 网页 USB 仿真协议独立复核

日期：2026-11-15。用户已经确认网页实板调试正常；这项观察作为当前背景接受，不再沿用旧文档中“网页尚未获用户确认”的说法。本任务只读检查公开静态资源与 sim_core.wasm，没有执行任何网页 JavaScript、没有打开浏览器或访问硬件，也没有修改 src/tests。

## 核心结论

1. 网页 full run 确实构造 FF5A0708000000000098。四个额外 00 在有效负载内，不是 64 字节报告的尾部填充；相对于 Keil 的 FF5A0308009C，LEN 从 03 变 07，校验从 9C 变 98。
2. 网页 step 的实参来自完整 state 解码的 PC，不来自读取的四字节指令。WASM 将该 32 位数按小端写进 step 负载：PC=FF0172 时得到 FF5A0708017201FF0025。它与 Keil 抓包的“4 字节指令窗口 + 尾部 00”在内容、长度和调用来源上均不同。仅凭构造结果不能证明设备端如何解释这些字节，更不能据此宣称 Keil 指令窗口方案错误。
3. state 中的 PC 仍按大端读取：46 字节数据的索引 42..45=00 FF 01 76，WASM 返回 PC=00FF0176。step 参数小端、state PC 大端、通用内存地址大端，必须分开处理。
4. 低层 USB connect 只有版本就绪探测，没有自动 FF0000 零数量写入或固定 2 秒等待；但 UI 连接后会做芯片型号读取，这条路径可能临时修改 CKCON。XFR 变量读取还可能置 P_SW2 bit7。因此“网页连接和查看数据完全不写寄存器”不成立。
5. 网页具备擦除/写程序和软件断点改写功能，它们有明确调用入口；没有发现 USB connect/freeRun/stepInto 自动安装另一份 monitor 或替换用户程序的路径。用户当次具体操作是否包含下载、reset、变量刷新，静态代码不能代替现场记录。

## 样本、指纹与方法

根地址：https://stcide.stcaimcu.com/ 。HTML 当前版本标记 stc-ide-77f9f185，入口 script 为 ./ide.js?v=1794681334183。

实际导入链：ide.js 动态导入 debug_ui-FGGZYT64.js；UI 的 ensureClient() 动态导入 public_client-5HSMHUJG.js；其 USB/串口仿真分支使用 chunk-FDBPC2DQ.js；后者 fetch sim_core.wasm。

| 根地址下的相对资源 | 字节数 | SHA-256 |
| --- | ---: | --- |
| ide.js | 982560 | bc9af65bdd4c3b0ac3bd011c7b86ca6681b6b7cf6a1a167ec281fc9eee45855f |
| chunks/debug_ui-FGGZYT64.js | 90025 | a9d94d9a2c6695392e2181f4f6fbeb155a159cd3b5dbc578f06288e29a21f704 |
| chunks/public_client-5HSMHUJG.js | 23268 | f7bd4cbd1a31c6cfed3807b9ae49d22f204100f7f960848e4f216cfd0b846e23 |
| chunks/chunk-FDBPC2DQ.js | 7634 | acefa782f917d17e154bdee15328f433c2f97f2166f331302b2a85ac20e1171f |
| chunks/chunk-HZQ3VFEK.js | 7545 | 4cede983d199653ad195d40f33b36754a891919eff771c499e77b761d1393be0 |
| chunks/chunk-FQPP636E.js | 20661 | 18971886fb4f5db7c4ad2af47714af29289b931233194c644936cc68001e60a6 |
| sim_core.wasm | 3176 | 99dde35ecc2329aaf782641b93c1f393fb9b972250400cf5ea539f21a64e64e2 |

网页 JS 只作为文本读取、检索；没有 import、eval、VM 执行或浏览器运行。WASM 验证使用本机 C:/Program Files/nodejs/node.exe，Node v24.15.0，独立进程在检查 WebAssembly.Module.imports(module) 为 [] 后，以空 imports 实例化。构造与解析只操作 WASM 线性内存，不存在通向 USB/文件/网络的 WASM 导入。

WASM 实测常量：modeUsb=1、modeSerial=0、VID=34BF、PID=1002、snapshotLen=46、snapRegCount=40、usbEnvelopeSize=64、maxPayload=56、maxWriteData=49、cmdTimeoutMs=500。内存指针 outPtr=1068、pktPtr=1132、respPtr=1196、dataPtr=1260。这些是本样本值，不是协议通用上限的证明。

## 运行报文：有效负载确实多四个零

直接调用 WASM 构造导出，再按包装层相同步骤 setMode(modeUsb())、wrapOut(n)。下表省略 64 字节包的尾部零填充；所有这些构造结果的有效区 sum8=0。

| WASM 调用 | 有效字节数 | 原始构造结果 |
| --- | ---: | --- |
| buildQueryFirmware() | 6 | FF5A030000A4 |
| buildQueryPause() | 6 | FF5A030002A2 |
| buildQueryRegs() | 6 | FF5A030001A3 |
| buildRunFull() | 10 | FF5A0708000000000098 |
| buildRunStep(0xFF0172) | 10 | FF5A0708017201FF0025 |
| buildWritePc(0xFF0000) | 11 | FF5A08020000FF0000009E |
| buildWrite(0,0xFF0000,0) | 11 | FF5A08020000FF0000009E |
| buildRead(0,0,4) | 11 | FF5A080400000000000497 |
| buildReset() | 11 | FF5A08020000FF0000009E |

full run 拆分：

	a) 网页：FF 5A | 07 | 08 | 00 | 00 00 00 00 | 98
	b) Keil：FF 5A | 03 | 08 | 00 | 9C

public_client 的 SimSession.freeRun() 只调用 request({what:"run",mode:"full"})，成功后设置本地 commandedRunning=true。chunk-FDBPC2DQ.js 的 buildFrame() 对 full 分支调用 buildRunFull()；exchangeFrame() 再把返回帧包成 64 字节传输。没有在这条调用链中额外写 PC、擦除代码、读取指令或添加初始化寄存器写。

Keil 原始帧 1745/1764 的短 run 已有成功停止记录，详见 docs/keil-pause-review.md。因此报文差异已确认，其在当前实板上的因果关系应由主代理 A/B 结果判断。

## step：调用方传 PC，WASM 原样编码该整数

public_client-5HSMHUJG.js 中实际源码：

    async stepInto(){let e=await this.readPc();await this.request({what:"run",mode:"step",pc:e}),this.commandedRunning=!1}

readPc() 调用 requestData({what:"registers"})，从解析结果 registers.pc 取数。它没有走空间 0 地址 0 的独立四字节 PC 读取，更没有从 code 空间读取四字节指令。

chunk-FDBPC2DQ.js 的 buildFrame() 对 step 调用：

    t.buildRunStep((e.pc??0)>>>0)

独立进程中的控制输入与输出：

| 传入整数 | step 报文 | 实参对应的四字节 |
| --- | --- | --- |
| 0x00FF0000 | FF5A0708010000FF0098 | 00 00 FF 00 |
| 0x00FF0172 | FF5A0708017201FF0025 | 72 01 FF 00 |
| 0x00FF0176 | FF5A0708017601FF0021 | 76 01 FF 00 |
| 0x12345678 | FF5A0708017856341283 | 78 56 34 12 |
| 0x7E34F7A0 | FF5A070801A0F7347E4E | A0 F7 34 7E |

控制输入仅用于内存内构造，没有向设备发送。四字节与传入整数的小端表示逐一对应；WASM 无 imports，不能自行从设备或宿主镜像取指令。网页这条 step 调用链也没有填充用户代码到 WASM dataPtr 的步骤。

同一 Keil 抓包在停止 PC=FF0172 后，于原始帧 1823 发送：

    FF5A0808017E34F7A0004D

其中 step 部分为 08 01 7E 34 F7 A0 00；网页针对 PC=FF0172 则为 08 01 72 01 FF 00，没有 Keil 的那个额外尾部 00。应把它记录为两种不同的主机实现，不能把网页的 PC 实参误写为“也是四字节指令”。

这不证明芯片端实际支持、要求或忽略何种 step 参数；用户确认网页实板正常，也不自动等于已对这一个 step 变体逐项完成线级验收。本任务没有网页实跑抓包。

## 状态解析与 PC、寄存器字节序

必须复现包装层的完整读取顺序：64 字节 USB IN → unwrapIn(64) → parseReply(返回长度)。直接将带 LEN 的 HID 报告交给 parseReply() 会格式失败，失败后继续调用 snapPc/snapReg 的结果不能作为证据。

用 46 字节数据依次填 00..2D，生成正确校验并补到 64 字节后，独立进程实测：

- unwrapIn 返回 48，移除了报告最前面的 LEN；解析输入为 02 + 46 字节数据 + 校验。
- parseReply 返回 0，respKind=1、respDataSize=46、respVerified=1。
- snapReg(0..39) 依次返回 0..39，即数据索引 0..39 的单字节；没有在这层转换为 WR/DR 数值。
- snapPsw=0x28、snapPsw1=0x29，分别对应数据索引 40、41。
- snapPc=0x2A2B2C2D，对应索引 42..45，按大端拼接。

再使用 Keil 原始帧 1759：

    300200005BCC0000F7A00000000100000000000000000000000000000000000000000001000000000035C1E000FF0176F2

按相同步骤得到 parseReply=0、kind=1、dataSize=46、PSW=C1、PSW1=E0、PC=00FF0176。单独置 PC 数据为 76 01 FF 00 时，解码得到 7601FF00，而非 FF0176。这排除了把 state PC 一律按小端处理的解释。

| 字段或操作 | 字节顺序/行为 |
| --- | --- |
| state 数据索引 0..31 | 按原始顺序提供 R0..R31 单字节 |
| state 数据索引 32..39 | WASM 作为 snapReg(32..39) 的单字节暴露；属于快照其余寄存器区 |
| state 数据索引 40、41 | PSW、PSW1 |
| state 数据索引 42..45 | 32 位 PC，大端 |
| step 输入整数 | 32 位整数，小端进入报文 |
| read/write 的地址 | 四字节大端，例如 buildRead(2,0x123456,4) → FF5A0804020012345604F9 |
| writePc 地址 | 大端，例如 buildWritePc(0x123456) → FF5A080200001234560001 |

还需避免 UI 假象：SimSession.readRegisters() 只复制 values 的前 32 字节，并直接返回 dpxl:0,dph:0,dpl:0,spx:0,sp:0。网页界面这些字段为零不等于设备快照值为零。UI 的 ACC 显示取 r0r31[11]，PC/PSW/PSW1 则使用解析结果；没有据此验证完整寄存器展示正确性。

## 读取 state 的实际流程与失败处理

以下为调用链确认的主机行为，不等于已经证明每一步是设备端必需条件。

- 连接：SimSession.connect() 的 USB 分支进行版本形状探测。UI 的 connectFlow() 随后 refreshRegs()，读取完整 state，再刷新变量；另有连接时的型号读取，见下节。
- step：先 requestData(registers) 取得完整 state/PC，再发 step。UI.step() 在成功后 refreshRegs()，再读一份完整 state。没有先读 code 的步骤。
- 手动 stop：UI.stop() 先 client.halt()，返回后 refreshRegs()，因此成功的常规路径是 pause → 状态读取。
- full run：低层 freeRun() 不读 state；它发 run、处理一条回复，然后仅改变本地 commandedRunning。
- SimSession.readStatus() 返回 {running:this.commandedRunning,breakpoint:false}，本身不发状态读取；不能把这个本地值当成实时设备 running 位。
- requestData() 最多循环两次调用 request()，若第一次得到 kind=0 事件，就再次发送同一个数据请求。它不是只等第二条 IN、不重发 OUT。外层 withRetry 另有重开与重试逻辑，不能把总重试次数一概说成两次。

USB halt 使用 25 ms 初次等待。超时且此前 commandedRunning=true 时，会尝试版本就绪探测；探测成功即可把本地 running 清零并返回。此前本地非运行状态时，25 ms 超时直接返回，不做版本探测。普通可解析的 pause 回复也把本地 running 清零。低层 halt 没有读快照；UI 在它返回后才 refreshRegs()。因此不要把“版本探测成功”重写成已从设备寄存器确认暂停。

WebHID transport 的 inputreport 回调只在 pending 存在时交付数据，没有额外事件队列；exchange() 在 await sendReport() 后才登记 pending。这里确认的是静态实现，不推断用户实跑时是否遇到过快回复或事件丢弃。

## 初始化：有条件的寄存器写需要与协议构造分开

低层 SimSession.connect()/freeRun()/stepInto() 中没有 Keil 启动专用零数量 PC 写，也没有固定 2000 ms 等待。WASM 的 buildReset/buildWritePc 能构造该报文，不代表 connect 调用了它。

但 UI.ensureConnected() 成功后会 detectChipModel()。其 readMcuid 来源于 chunk-FQPP636E.js，固定读取 kind=xdata、地址 0x7EFDE0、长度 2。UI 把 xdata 读取包装在 readXdmaGuarded()/withCkconGuardAsync() 中：

1. 读 SFR CKCON，地址 EA。
2. 若值为整数 1..7，直接读取目标地址。
3. 否则先写 CKCON=01，再读取数据，随后写回原 CKCON 并读回核对；错误路径也尝试恢复。

这个型号读取使用 xdata，不经过 ensureEaxfr。它可能产生临时 SFR 写，但没有证据证明它修复或改变了当前运行/暂停问题。

另外，变量访问 kind=xfr 时先经过同一 CKCON guard，然后 ensureEaxfr() 读 SFR P_SW2（BA）；若 bit7 未置位，写回 原值|80。该帮助函数没有恢复 P_SW2 的步骤。普通 xdata 变量读取不会自动执行这一步；不能把 xfr 条件写扩展为每次连接必写。

由 WASM 独立构造的相关报文示例：

| 操作 | 报文 |
| --- | --- |
| 读 CKCON | FF5A080404000000EA01AC |
| 写 CKCON=01 | FF5A090204000000EA0101AC |
| 读 P_SW2 | FF5A080404000000BA01DC |
| 写 P_SW2=80（仅原值为00的示例） | FF5A090204000000BA01805D |
| 读取芯片型号字节 0x7EFDE0..E1 | FF5A080402007EFDE0023C |

以上只是离线报文构造，不说明用户当次寄存器原值、条件分支或实际发送情况。没有对时钟、USB 外设或寄存器副作用作额外推断。

## 程序改写、入口写入与断点的边界

- UI.download() 与 FlashDiffer.download() 明确支持 halt、扇区擦除、代码写入及默认读回校验。不是所有调试操作都只读程序。
- 下载后自动运行分支会 writePc(host.codeBase())、readPc() 核对，最多 5 次、不匹配等待 80 ms，然后才 run；没有固定 2 秒等待。UI 的 #dbgRun 按钮明确绑定 this.run(true)，在 everDownloaded=false 时会先调用 download("diff")；之后是否直接返回取决于下载结果及自动运行设置。aiRun() 则调用默认 run(false)，因此不能把所有“运行”入口当作同一条不写程序的路径。
- UI.reset() 执行 halt、clearBreakpoint、writePc(codeBase)、readPc、refreshRegs；它不是只改前端状态。
- SimSession.setCodeBreak() 首次读取并保存目标代码原字节，再调用 buildSetBreak(addr) 写入 B9；清除时恢复保存字节。WASM 对 FF018F 构造 FF5A09020500FF018F01B94E，与 Keil 的 B9 断点写相同。
- WASM 可构造擦除命令，例如 buildErase(FF0000) → FF5A060600FF00009C；构造导出的存在不证明自动连接会调用它。
- 所核对的 USB connect/run/step 方法中没有内嵌 monitor 下载、无条件用户代码修补或自动替换初始化代码。下载、reset、软件断点、写变量以及上述 SFR guard 必须分别判断，不能笼统声称“网页完全不改程序/寄存器”。

## 最小复核方式与未确定项

报文构造可在本机 Node 中仅 fetch sim_core.wasm，检查无 imports 后运行下述核心代码；不需要、也不应 import 网页 JS：

    const module = await WebAssembly.compile(bytes);
    if (WebAssembly.Module.imports(module).length) throw Error("unexpected imports");
    const e = (await WebAssembly.instantiate(module, {})).exports;
    const n = e.buildRunStep(0xFF0172);
    const frame = new Uint8Array(e.memory.buffer).slice(e.outPtr(), e.outPtr() + n);
    // frame = FF5A0708017201FF0025

本次所有 WASM 构造和解析均已在独立 node.exe 进程运行；没有在 node_repl 内嵌 WASM 沙箱中执行。状态解析另外使用正确 USB 解封装和两类控制输入复核，成功后才读取字段。收尾断言检查通过：样本哈希和无 imports、7 组精确请求字节、64 字节封套、校验和与零填充，以及 Keil 原始快照的 PC/PSW/PSW1 解码；未使用设备。

仍未知：用户成功调试时使用的具体按钮序列、设置、变量/XFR 读取、现场 USB 报文与目标 monitor 版本。没有证据把四个零、step PC 编码、CKCON guard 中任何一项单独认定为根因。当前报告可给主代理提供精确 A/B 输入与注意事项，不代表已修复 STCForge 运行失联，也没有代替其硬件验收。

