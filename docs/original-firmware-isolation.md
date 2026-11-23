# 原 SDCC 例程的全速失联定位

当前目标：修复原 main.c + system_stc32.c 例程。M02 仅作为已通过测试的参照，不把替换成 M02 当作原例修复。

## 2026-11-15 原例重新装载实测

通过既有 USB-ICE 的空间5代码写入接口装载 S00，非ISP下载；未修改硬件选项、未另装监控固件。装载前从设备备份了完整 FF0000..FF078E 范围（包含原镜像空洞），备份和全部请求/回复位于：

    D:/Projects/stcforge/.cache/original-S00-20261115-225057-453441/

- code-before.bin：设备原始代码范围备份。
- backup.json：备份起址、大小与目标镜像。
- usb.jsonl：完整USB报文、代码装载与回读结果。

装载完成后，S00 的1914个定义字节全部回读匹配。入口初始化后通过生产 IceTarget 单步复位跳转 FF0000→FF001F，然后全速运行100ms。此次没有写B9或其他软件断点，仍然在请求暂停时超时，重新打开后读取状态也超时。

因此本轮确认原例的无断点全速失联仍在；早期B9断点异常不是这一现象的完整解释。不能因为这个重现就认定具体某条指令有错。

其后尝试装载S06的流程在版本查询阶段即失败，没有写入S06。当前最后核验过的调试代码镜像是S00，不能再以M02本地HEX启动GDB，也不能用M02恢复器改写此镜像。

## 后续检查不使用B9

工具 tools/diagnostics/probe_original_firmware.py 只接受已知原S00/S06镜像，支持 --checkpoint。检查点以普通 SJMP -2（80 FE）代替对应处两个字节。全速抵达检查点时CPU持续自循环，主机再用普通暂停命令读取PC。

该方法避免用B9作为“前面代码是否执行成功”的判断依据。它仍需实测，不能事先保证监控器在每个阶段都能暂停。

每个检查点的原始机器码已与两份实际HEX核对；成功暂停后先恢复原指令，再核对整份原程序。失败且停止状态未知时不继续修改运行中的代码，保留原始字节与未恢复标记。没有额外生成一套固件矩阵。

首先检查 after-xinit-compare（FF005C）：

    & D:/Code/uv/uv.exe run --project D:/Projects/stcforge --no-sync python D:/Projects/stcforge/tools/diagnostics/probe_original_firmware.py --variant S00 --checkpoint after-xinit-compare

后续根据结果选择 before-xinit-compare、main、before-interrupts、first-millis 或 main-loop，避免把所有检查都无差别重复一遍。S06绕过自动初始化，只用于区分运行库与原应用路径，不把它当成已修复版本。

原例构建目录 build/Debug-Original 的 stc_debug_build 已成功生成对应 main.c/system_stc32.c 的调试ELF；默认Debug的兼容例程未再次修改。

目前硬件会话无响应，需要目标完整断电再上电后才能继续上述原例定位。尚未确认原例根因，尚未实施声称能解决它的生产修复。
