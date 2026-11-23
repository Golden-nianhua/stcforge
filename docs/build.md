# 构建 MCS-251 GDB

当前维护独立覆盖层，基于固定的 GNU GDB 16.3 源码；没有把 MCS-251 伪装成 ARM。
`tools/gdb/prepare_gdb.py` 对锚点做唯一性检查，重复执行安全，源码版本不符时失败。
覆盖层包括 BFD 架构、配置入口、GDB 寄存器/数据模型和有限反汇编器。
Windows 另包含 EXE 同级 `share/gdb` 的默认数据目录定位，确保 Python 模块可随目录搬移。
MI 默认开启异步模式，使 CLion 能在目标运行期间发送中断；`set mi-async off` 仍可覆盖默认值。

当前函数帧使用函数入口作为身份锚点，避免每次单步因 PC 改变而使前端保存的帧失效。未知函数仍回退到 PC；这不扩展调用栈、递归帧或局部变量支持。tools/tests/test_gdb_watch.py 用真实 GDB 和回环 MockTarget 验证同函数单步、换函数及多变量更新。

## 准备源码

```powershell
D:/Code/uv/uv.exe run python tools/gdb/fetch_gdb.py --extract
D:/Code/uv/uv.exe run python tools/gdb/prepare_gdb.py .cache/gdb-16.3
```

GDB 源码归档 SHA-256：
`bcfcd095528a987917acf9fff3f1672181694926cc18d609c99d0042c00224c5`。
下载脚本会先校验再解压，编译目录和归档保留在 `.cache` 或指定的 WSL 工作目录中。

## Linux/WSL 原生版

安装 `g++ make libgmp-dev libmpfr-dev libexpat1-dev texinfo bison flex`。
在 WSL 中运行（将项目根目录替换为自己的路径）：

```bash
python3 /mnt/d/Projects/stcforge/tools/gdb/prepare_gdb.py /mnt/d/Projects/stcforge/.cache/gdb-16.3
bash /mnt/d/Projects/stcforge/tools/gdb/build_gdb.sh /mnt/d/Projects/stcforge/.cache/gdb-16.3 "$HOME/stcforge-build/linux"
```

输出为指定构建目录的 `gdb/gdb`。
建议源码和编译目录均放在 WSL 的 Linux 文件系统内，以减少跨文件系统开销。
脚本显式采用 GNU C17，兼容 GCC 15 默认切换 C 标准后仍使用旧式函数声明的上游代码。
如果更换了编译选项，使用新的构建目录，避免旧 `config.cache` 污染配置。

## Windows x64 版

在 WSL 中另需 `gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64`。

```bash
python3 /mnt/d/Projects/stcforge/tools/gdb/fetch_gdb.py
export STCFORGE_PYTHON_SDK=/mnt/d/Code/uv/python/cpython-3.12.13-windows-x86_64-none
bash /mnt/d/Projects/stcforge/tools/gdb/build_windows.sh
```

`STCFORGE_PYTHON_SDK` 指向 uv 管理的完整 Windows x64 CPython 3.12 安装，使用 WSL 路径。
可先在 Windows 执行 `uv python install 3.12`，再用 `uv python find --managed-python 3.12`
查询实际位置。SDK 必须包含 `include/Python.h` 和 `libs/python312.lib`；虚拟环境不是 SDK。
当前验收使用 CPython 3.12.13。SDK 路径请勿包含空格（Autoconf 的编译参数限制）；
生成的运行目录可以包含空格，也可以搬到其他位置。

脚本自动构建静态 GMP 6.3.0、MPFR 4.2.2、Expat 2.7.3 和 libiconv 1.18，再交叉编译 GDB。
归档 SHA-256 固定在 `tools/gdb/source-checksums.sha256`，下载后先校验再解压。
默认工作目录为 `$HOME/stcforge-build/windows`，可通过脚本的第一个参数指定。
显式指定 build/host，防止 WSL 的 Windows 程序互操作误导 Autoconf 的交叉编译检测。
成功后在 `.cache/build/gdb-windows/` 生成 `stc-gdb.exe` 和运行库；该目录是便携 ZIP 的组包输入。
libiconv 负责 Windows 字符集转换，避免缺少 CP1252/UTF-32 转换器时读取符号产生警告。
可设置 `STCFORGE_JOBS` 调整并行数，默认 4。

Windows 版启用 GDB Python，供 CLion 初始化、漂亮打印器及脚本使用。
`tools/gdb/python_windows_config.py` 只向交叉编译器提供 Windows SDK 信息；
`tools/gdb/package_windows_gdb.py` 打包 Python DLL、标准库、原生扩展及 GDB 自带的 Python 模块。
运行时通过同目录 `python312._pth` 定位，不依赖开发机的 Python 安装、环境变量或第三方包。
分发 GDB 时需将它的运行库和数据目录一起复制，不能只复制 EXE。CLion 的 GDB 路径可指向
便携包的 `bin/stc-gdb.exe`，不需要另外配置 Python 路径。已有本机 `dist/windows/stc-gdb.exe` 也可继续使用。
可用 `STCFORGE_PACKAGE_OUT` 指定暂存输出目录，验收后再替换正式版本。

工程 `.python-version` 固定为 3.12，Windows 服务端环境使用 `uv sync --extra usb` 准备。
Windows 和 WSL 不要共用工程 `.venv`；在 WSL 执行 uv 测试时，应另设例如
`UV_PROJECT_ENVIRONMENT="$HOME/stcforge-build/linux-venv"`，避免覆盖 Windows 调试服务端环境。

## Windows x64 发布包

先按上一节构建 GDB。可以在 WSL 中用 `STCFORGE_PACKAGE_OUT` 指定独立的 GDB 暂存目录，
避免覆盖已有调试器。组包使用与 GDB 运行库完全相同的 Windows x64 CPython 3.12 SDK，
依赖版本从 `uv.lock` 读取。

在 Windows PowerShell 中，从 STCForge 根目录运行：

```powershell
# SDK 根目录是 python.exe、include 和 libs 所在的完整安装目录，不是虚拟环境。
$sdk = "D:/Code/uv/python/cpython-3.12-windows-x86_64-none"
cmake -S . -B .cache/build/isp -G Ninja "-DSTCFORGE_PYTHON_SDK=$sdk"
cmake --build .cache/build/isp --target stc-isp stcforge-launcher
uv run --no-sync python tools/package/windows_release.py --sdk $sdk
uv run --no-sync python tools/package/smoke_windows_release.py dist/stcforge-0.1.0-windows-x64.zip
```

GDB 暂存目录不是 `.cache/build/gdb-windows` 时，用 `--gdb` 指定。默认 ZIP 输出到 `dist/`；
同名文件默认不覆盖，重新打包可传 `--replace`。所有依赖已缓存时可加 `--offline`。
解压后的 `bin/` 给模板使用，`lib/` 提供锁定的 Python 依赖。无需复制本机的虚拟环境。
公开分发前按[第三方说明](third-party.md)一并提供相应源码材料。

## 本机开发运行目录

在 STCForge 根目录、已配置好 CMake/Ninja 和 C++ 工具链的 PowerShell 中执行：

```powershell
cmake -S . -B .cache/build/isp -G Ninja
cmake --build .cache/build/isp
cmake -E make_directory dist/windows
cmake -E copy_if_different .cache/build/isp/stc-isp.exe dist/windows/stc-isp.exe
```

按上节构建的 `stc-gdb.exe` 及其运行文件也在这个目录。调试服务端只需安装一次：

```powershell
uv build --wheel --out-dir .cache/wheels
$wheel = (Get-ChildItem .cache/wheels -Filter 'stcforge-*.whl' |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
$python = (uv python find --managed-python 3.12).Trim()
$env:UV_TOOL_BIN_DIR = "$PWD/dist/windows"
$env:UV_TOOL_DIR = "$PWD/dist/.uv-tools"
uv tool install --python $python --reinstall --from "${wheel}[usb,uart]" stcforge
```

如果尚未安装 uv 管理的 Python，先运行 `uv python install 3.12`。环境变量指定安装位置，模板无需设置它们，也不用改系统 `PATH`。`stcforge.exe` 是本机 uv 环境的启动入口，不是独立打包的程序；换机器或移动目录后重新安装。更新源码后重新构建 wheel 并安装。

在模板中把 `STCFORGE_BIN` 指向 `dist/windows`，并在 CLion 工具链选择此目录下的 `stc-gdb.exe`。

## 验证

```powershell
./dist/windows/stc-gdb.exe -nx -q --batch -ex "set architecture mcs251" -ex "show architecture"
./dist/windows/stc-gdb.exe -nx -q --batch -ex "python import gdb; print(gdb.VERSION)" -ex "info pretty-printer"
$env:STCFORGE_GDB = "$PWD/dist/windows/stc-gdb.exe"
D:/Code/uv/uv.exe run python -m unittest discover -s tools/tests -v
```

设置 `STCFORGE_GDB` 后，测试会真正启动 GDB 并连接临时端口的模拟服务端；不会连接 USB。
