# AiCube-ISP 6.97C 静态逆向覆盖审计

本审计只检查主机程序中的代码、数据表、资源和已有本地抓包分析，不把逐型号上电测试作为完成条件。

| 功能 | 6.97C 入口或数据 | 资料 |
| --- | --- | --- |
| 全部型号目录 | `0x505468`，1345 条记录，85 个配置族 | `models-6.97c.json` |
| 配置界面选项 | `0x48BFF8`、85 个分发函数和描述表 | `models-6.97c.md` |
| 硬件选项组包 | `0x44B760` | `config-6.97c.asm`、`config-packer-map-6.97c.md` |
| 状态应答 | `0x43E1F0` | `status-6.97c.asm`、`status-parser-map-6.97c.md` |
| USB IRC 预置和选择 | `0x43EB30`、`0x43EFC0`，5 张频率表 | `irc-static-map-6.97c.md` |
| 串口 IRC 动态调节 | `0x4413F0`、`0x43F140`、`0x4402F0`、`0x43F920` | `irc-serial-static-map-6.97c.md` |
| 原生 USB HID 下载 | `0x44C800`、`0x44BB90`、`0x44BAB0` | `usb-flow.asm` |
| 另一 USB 下载封装 | `0x44D7F0` | `download-entry-6.97c.asm` |
| 串口和转接器下载 | `0x44E590` | `serial-flow.asm` |
| 程序区分块写入 | UART `0x443240`，64/128 字节及分版本地址头；原生 USB 单独分支 | `protocol-command-map-6.97c.md` |
| EEPROM 混合下载 | `12`、`32`，地址和连续块规则 | `capture-command-evidence-6.97c.md` |
| 用户系统区 | 项目数据、`04` 配置和程序缓冲区路径 | `project-and-offline-6.97c.md`、`download-entry-6.97c.asm` |
| 下载口令 | `05` 准备、`07` 更新 | `README.md`、`usb-flow.asm` |
| 用户密钥 | 256 字节分块、密钥文件封装 | `README.md`、`encode-ui.asm` |
| 固件加密 | `0x45C190`、`0x45C260` | `verify-routines.py`、`README.md` |
| 芯片 ID 绑定 | 芯片 ID 读取、变换和镜像写入路径 | `README.md`、`download-entry-6.97c.asm` |
| 用户命令复位到 ISP | `0x4A92C0`、`0x4C0997`、`0x4C0C25` | `reset-to-isp-6.97c.md` |
| 仿真、USB-ICE、SWD 选项 | 配置描述表、`04` 模式位和下载分支 | `f8d1-hardware-6.97c.md`、`hardware-page-6.97c.asm` |
| Link1D、Writer、U8W 辅助数据 | 模式 7、资源装载和 `42` / `62` | `project-and-offline-6.97c.md` |
| 普通离线编程器 | 模式 4、`F1–F4`、`46–49` | `project-and-offline-6.97c.md` |
| 项目保存和发布 EXE | `0x4BA010`、资源 184、ZipCrypto 资源 | `project-and-offline-6.97c.md` |
| 随附资源 | 93 个资源、哈希和型号族分支 | `resources-6.97c.md`、`resource-routes-6.97c.md` |

## 结果

这些是定位到的主机例程和数据，不是已移植的状态机清单。`models-6.97c.json` 和 `protocol-map-6.97c.json` 用于从型号派发到共享协议；C++ 中实际可执行的写入范围见 [stc-isp 实现审计](stc-isp-port-audit-6.97c.md)。

设备内部对某些状态字节的命名属于芯片固件语义。主机程序只使用这些字节参与计算和分支时，资料保留其偏移、变换和分支条件，不把没有出现在 AiCube-ISP 代码中的芯片内部名称伪造成静态逆向结果。
