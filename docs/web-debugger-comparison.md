# 网页调试器与暂停失败排查（2026-11-15）

## 网页公开实现的核对

用户提供入口：https://stcide.stcaimcu.com/ 。本次只读取公开静态资源，没有操作浏览器或连接网页中的设备。

沿 ide.js 的实际 import 核对了：

- chunks/debug_ui-FGGZYT64.js：调试界面。
- chunks/public_client-5HSMHUJG.js：区分 SWD、USB 仿真与串口仿真；USB 仿真通过独立 SimSession 实现，不经过 GDB。
- chunks/chunk-HZQ3VFEK.js：WebHID/WebUSB 传输，WebHID 使用 sendReport 与 inputreport。
- chunks/chunk-FDBPC2DQ.js：USB 仿真协议封装及暂停处理。
- sim_core.wasm：协议报文核心，3176 字节，无导入；使用独立 Node 实例在无设备、无宿主导入的条件下调用报文构造导出。

WASM SHA-256：99dde35ecc2329aaf782641b93c1f393fb9b972250400cf5ea539f21a64e64e2。public_client SHA-256：f7bd4cbd1a31c6cfed3807b9ae49d22f204100f7f960848e4f216cfd0b846e23。网页可能更新，应按样本指纹复核。

## 实际构造的 USB 仿真报文

WASM 给出的默认 VID/PID 为 34BF:1002，快照长度 46；以下省略补齐至 64 字节的零填充。

| 操作 | 网页 | STCForge / Keil 抓包 |
|---|---|---|
| 查询版本 | FF5A030000A4 | 相同 |
| 暂停 | FF5A030002A2 | 相同 |
| 完整状态 | FF5A030001A3 | 相同 |
| 全速运行 | FF5A0708000000000098 | FF5A0308009C |

全速运行的网页实现带额外四个零字节，长度和校验随之变化。这个差异真实存在，但 Keil 的短报文已有成功抓包，不能仅凭网页不同就认定短报文错误；此阶段未把网页变体替换进生产运行路径，也没有用当前固件未知的板卡试运行。

public_client 的 USB halt 使用约 25 ms 的首次等待，运行中超时后尝试版本探测；数据请求允许最多两次取得回复，处理 kind=0 的事件回复。它的失败处理和异步事件处理与 STCForge 不完全相同。WebHID 未登记 pending 时到达的 inputreport 没有队列保存；这也不能被当作可靠性已经经过实板验证的证明。

网页具备 USB 仿真实现，并不能证明它在用户当前同一份 SDCC 固件上已经完成继续/暂停验收。目前仍不能排除 STCForge 服务端的状态同步、回复归属和 GDB 交互问题。此前无 GDB 的 USB 测试失败只说明故障不要求 GDB 客户端参与，不等于我们自己的 USB 协议层无误。

## 本轮暂停失败处理修正

- 已知运行中的 halt 超时不再补发状态查询并据此宣称停止；保持停止未确认，保留首次超时。
- IceTarget 暂停失败后，退出清理不再再次请求暂停；有未恢复的软件断点时明确记录地址。
- Client/serve 清理的次生异常不再覆盖原始通信异常。
- Ctrl-C 被记录为实际请求 03；错误阶段区分请求暂停、等待停止事件和读取停止状态。

Windows uv 环境下 141 项回归全部通过，启用了真实 GDB 与 SDCC 的离线联调。上述修正处理失败路径，不表示硬件暂停已经修复。

## 后续只读硬件观察

系统仍列出 VID_34BF/PID_1002 设备；hidapi 查询未在限定时间内完成。使用已知 HID 路径直接走 Win32 后能打开设备：

- .cache/ice-pause-native-followup-20261115.jsonl：版本查询得到全零内容事件，不能当成版本回复。是否迟到确认尚未证实。
- .cache/ice-late-ack-probe-20261115.jsonl：下一次独立查询返回 V4.0，没有观察到额外回复。
- .cache/ice-web-reference-before-20261115.jsonl：完整状态可读取，PC=FF000F。
- .cache/ice-web-reference-image-20261115.jsonl：空间5读取 FF0000..FF0003 得到 02 00 2C 75，与本地简单 SDCC HEX 的 02 00 1F 32 不同；在首个差异 FF0002 停止后续核对及运行。

前一次完整校验曾匹配1914字节，本轮不能继续沿用该结论。该变化可能涉及板上固件或调试读取视图；未经进一步核对，不断言用户换过固件，也不把它直接认定为编译器或 GDB 根因。

