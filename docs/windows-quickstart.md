# STCForge Windows x64

解压后保留完整目录结构。`bin/` 内置运行所需的 Python，不必安装 Python、uv 或 MinGW，也不用改系统 `PATH`。

| 命令 | 用途 |
| --- | --- |
| `bin/stc-isp.exe` | USB、UART 或 Link1D ISP 下载及芯片信息读取 |
| `bin/stcforge.exe` | SDCC 符号转换、CLion 启动及 GDB 服务 |
| `bin/stc-gdb.exe` | MCS-251 GDB 客户端 |

## ISP

从解压目录打开 PowerShell。参考 `examples/hardware-families/` 选择对应型号的 TOML。先检查配置，再接入芯片：

```powershell
.\bin\stc-isp.exe --help
.\bin\stc-isp.exe --config .\examples\stc32g144k246.toml --image .\firmware.hex --dry-run
```

将 `firmware.hex` 换成实际固件；去掉 `--dry-run` 会执行下载。只读设备信息用 `--info`。

## CLion

在 STC32 模板根目录 `CMakeLists.txt` 顶部，把 `STCFORGE_BIN` 指向本包的 `bin/`。在 CLion 的 `MCS-251` 工具链把自定义调试器选为同一目录的 `stc-gdb.exe`，然后重新加载 CMake。固件编译器 SDCC 仍需单独配置。

## 离线验证

在两个 PowerShell 窗口分别执行下面两组命令，不需要开发板：

```powershell
.\bin\stcforge.exe gdbserver --mock --once
```

```powershell
.\bin\stc-gdb.exe -nx -q --batch -ex "set architecture mcs251" -ex "target remote 127.0.0.1:3333" -ex "stepi" -ex "detach"
```
