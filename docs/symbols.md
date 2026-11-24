# SDCC 符号转换说明

`stcforge.symbols` 把 SDCC MCS-251 生成的 `.cdb` 和 Intel HEX 转成供 GDB
读取的调试 ELF。当前状态是 **experimental**：目标是让新增的 MCS-251 GDB
端口具备最小源码行和全局变量支持，不是完整 SDCC 调试信息转换器。

```text
SDCC --debug -> firmware.cdb ─┐
                             ├─> stcforge symbols -> firmware.debug.elf
同一链接的 firmware.hex ─────┘                          │
                                                       v
                              stc-gdb + set architecture mcs251
```

输出 ELF 不能用于烧录。固件仍由原有 SDCC/HEX 流程生成，调试时加载的 ELF
只提供符号、源码行和本地代码视图。

## 命令和 API

推荐使用现有 CLI 入口：

```powershell
D:/Code/uv/uv.exe run stcforge symbols `
  --cdb path/to/firmware.cdb `
  --hex path/to/firmware.hex `
  --output build/firmware.debug.elf `
  --source-root path/to/project
```

需要完整统计时加 `--json`。也可以直接运行模块：

```powershell
D:/Code/uv/uv.exe run python -m stcforge.symbols `
  --cdb firmware.cdb --hex firmware.hex --output firmware.elf --source-root .
```

Python API：

```python
from pathlib import Path
from stcforge.symbols import convert

summary = convert(
    Path("firmware.cdb"),
    Path("firmware.hex"),
    Path("firmware.debug.elf"),
    source_root=Path("."),
)
```

`convert()` 返回 JSON 可序列化字典，包含输出路径、ELF 属性、代码范围、函数、
变量、行数、文件数、`known_ignored`、`skipped`、`duplicates`、
`file_static_ambiguities`、`samples` 和 `limitations`。无法安全转换时抛出
`SymbolConversionError`，不会为未知记录猜测地址。

`source_root` 写入 DWARF 编译单元的 `DW_AT_comp_dir`。默认保持 CDB 源码名。
如果 CDB 只有文件名，而源码位于子目录，可重复传入 `--source-dir`：

```powershell
D:/Code/uv/uv.exe run stcforge symbols --cdb firmware.cdb --hex firmware.hex `
  --output firmware.debug.elf --source-root . `
  --source-dir Core/Src --source-dir Drivers/Src --source-dir Hardware/Src
```

转换器只在这些指定目录中查找，并将唯一匹配的源码绝对路径写入行表。
找不到或存在多个匹配时直接报错，不递归搜索其他例程目录来猜测同名文件来源。
API 对应参数为 `source_dirs=[Path("Core/Src"), ...]`。
未传入此参数时仍可使用 GDB 的 `directory` 命令补充源码搜索目录。

## GDB 使用

ELF 是 32 位大端、`ET_EXEC`、`EM_NONE(0)`，必须由 MCS-251 GDB 显式选择架构：

```gdb
set architecture mcs251
file build/firmware.debug.elf
info sources
info line main.c:10
ptype counter
info address counter
break main
```

不要使用 `load` 装载这个 ELF。连接真实目标时，服务端应从与目标一致的 HEX
提供代码视图；ELF 与 HEX 必须来自同一次链接。

## 支持范围

| CDB 记录 | 当前处理 |
| --- | --- |
| `F:G$func$...` | 全局函数声明 |
| `F:Fmodule$func$...` | 文件静态函数声明 |
| `L:G$func$...:addr` / `L:XG$func$...:addr` | 全局函数起始/末字节地址 |
| `L:Fmodule$func$...:addr` / `L:XFmodule$func$...:addr` | 静态函数起始/末字节地址 |
| `L:C$file$line$scope...:addr` | 源码文件、行号、代码地址 |
| `S:G$name$...({1/2/4}SC/SI/SL:U/S)` + `L:G`/`L:F` | 基本整数全局变量 |
| `S:Fmodule$name$...` + `L:Fmodule$...` | 基本整数文件静态变量（仅名字全局唯一时） |
| `S:C` | 宏/常量，仅计数，不生成地址 |

支持的基本类型包括 `SC`、`SS`、`SI`、`SL`、`SB`、`SF`，并校验 CDB 声明的字节数与
类型一致。`S` 表示有符号，`U` 表示无符号；ELF/DWARF 中同时写出
`DW_AT_byte_size` 和对应的 `DW_AT_encoding`。

函数大小来自 `L:XG`/`L:XF`。这些记录给出的是函数最后一条指令的字节地址，
不是排他结束地址，所以 ELF `st_size` 为 `end - start + 1`。例如起始
`0xFC2800`、末字节 `0xFC2803` 的函数大小为 4 字节。

## 地址映射

| 存储类别 | CDB 地址 | GDB 虚拟地址 |
| --- | --- | --- |
| SFR，`I` | `0x80..0xFF` | `0x10000000 + raw`，即 `0x10000080..0x100000FF` |
| EDATA，`E` | `0x0000..0x3FFF` | 原值，`0x00000000..0x00003FFF` |
| XDATA，`F` | `0x010000..0x02FFFF` | 原值，绝对 XDATA 地址 |
| code | `0xFC2800..0xFFFFFF` | 原值，SDCC MCS-251 code 地址 |

SFR 的虚拟窗口只是为了避免与同数值 EDATA 地址混淆，不代表芯片具有 32 位
物理地址总线。EDATA 和 XDATA 必须保持为不同 GDB 地址，不能把 `0xA8` 的
普通 RAM 与 SFR `0xA8` 混为一谈。

HEX 小于 `0x10000` 的 Keil 地址不会被自动加 offset。当前转换器只接受
MCS-251 SDCC code 地址 `0xFC2800..0xFFFFFF`，其他地址直接失败。

## ELF 和 DWARF 产物

ELF 含有效节表及以下节：

- `.text`：从 HEX 最低 code 地址到最高 code 地址，代码空洞填 `0xFF`；
- `.symtab`、`.strtab`、`.shstrtab`：函数和变量符号；
- `.debug_abbrev`、`.debug_info`、`.debug_line`：最小 DWARF2；
- `.debug_loc`：可验证的栈和寄存器局部变量位置，按 PC 区间区分。

编译单元的 `DW_AT_producer` 为
`STCForge experimental SDCC CDB converter`。全局和唯一名字的文件静态整数
变量生成 `DW_TAG_variable`，位置为：

```text
DW_AT_location = DW_FORM_block1 { DW_OP_addr <4-byte big-endian address> }
```

代码连续跨度最多允许 16 MiB；超过时拒绝，避免异常 HEX 让进程分配巨量内存。
`.text` 的 `sh_size` 与实际代码跨度一致，空洞是明确的 `0xFF` 填充。

如果汇编函数只有 C 声明（如模板的 `system_idle()`），则从 `.cdb` 同名的链接
`.map` 补充函数入口，供 GDB 步过调用；不推断汇编函数的大小或源码行。

## 查看局部变量

CLion 模板的 Debug 构建会自动使用当前构建目录 `CMakeFiles/` 下的链接后 `.rst`。
单独运行 `stcforge symbols` 时，转换器会查找 `.cdb` 同目录的 `.rst`；
其他目录可用 `--listing-dir` 指定。不需要修改或重新烧录 HEX。

例如停在模板的 `debug_u32 = now;`，变量窗口会自动列出 `last_toggle` 和 `now`。
手动添加的监视是独立条目；CLion 调试窗口的布局选项 `Separate watches` 可以把两类条目分开。

栈位置支持函数体最外层、有固定栈槽并能确认初始化的局部变量；寄存器位置支持
带可识别初始化、保存在 `R0–R15` 的局部变量。同一个值在多条寄存器
中时按芯片字节序组装。指令字节须与 HEX 一致。声明所在源码块可以确定时，最后一次
引用后也继续跟踪；调用后可从已验证的保存槽恢复寄存器字节，在栈与寄存器之间切换。
值已被覆盖、尚未初始化或无法确认位置时，GDB 显示不可用，不读取猜测的值。

全局、文件静态和位置可验证的局部变量可以使用定长数组、多维数组、结构体、联合体、
位域和浮点类型。`p frame.payload[0]`、`p word.real` 等表达式可直接使用。
指针使用编译器记录的宽度：DATA/IDATA 为 1 字节，CODE/XDATA 和通用指针为 3 字节。
请搭配同一套工具构建的 `stc-gdb`；旧 GDB 不能正确区分同一元素类型的两种指针宽度。

## 输入校验

HEX 读取是严格的：

- 每条记录必须校验长度和 checksum；
- type 04 扩展线性地址只取高 16 位，type 02 扩展段地址按 16 字节段换算；
- 数据不得越过 16 位 offset 边界；
- 地址不得重叠，不得超出 24 位空间；
- 必须存在唯一 EOF 记录，EOF 后不得再有数据；
- 开始地址记录必须是合法的 4 字节记录，但不作为程序字节导入。

CDB 的重复声明按 `(scope, module, name)` 去重。数千条重复寄存器声明不会
被同名误合并；同名但地址或类型冲突会直接报错。文件静态符号始终按
`(module, name)` 配对地址，模块名允许包含 `$`。

单 CU 下，GDB 按裸变量名解析 DWARF。若两个模块都有名为 `same` 的文件静态
变量，保留两个 DIE 会让 `p same` 产生歧义。本阶段采用
`skip_all_same_name`：跨模块同名的静态变量全部跳过，并计入
`skipped.ambiguous_file_statics` 和 `file_static_ambiguities`；名字唯一的
静态变量仍正常生成。多 CU 支持以后再恢复这些符号。
静态变量与全局变量或函数裸名相同的情况也会跳过静态变量，保留原全局符号。

## 已知限制

- 不生成独立的位变量/位寄存器；结构体位域不受此限制；
- 不补猜 CDB 缺失的信息，例如枚举器名称、被擦除的类型限定或函数指针参数列表；
- CDB 对结构体和联合体使用相同标记；多成员联合体按零偏移重叠布局识别，无法区分的单成员类型按结构体显示；
- 不转换函数参数、寄存器中部分仍有效的值或无法验证的局部变量位置；
- 不生成调用栈展开信息；局部变量支持限于停住的当前函数；
- `S:C` 宏不生成地址；`L:A` 汇编地址和 `L:L` 局部地址只记为已知忽略；
- 不支持多编译单元、内联函数、模板或 C++ 名称修饰；
- 不接入 stcgal，不操作硬件，不开发 DAP；
- 不把 ELF 的 `EM_NONE` 伪装成 ARM/x86，也不提供独立于 MCS-251 GDB 的加载器。

转换器会把这些限制写入返回值的 `limitations`，同时用 `skipped`、`samples`
给出具体计数和示例。看到非零计数时应按实际调试需求判断是否接受，而不是
把它当作完整 CDB 已全部转换。

## 测试状态

专项测试 `tools/tests/test_symbols.py` 使用临时极小 CDB/HEX，检查：

- ELF32 大端、`EM_NONE`、有效节表和 `.text` 空洞；
- 函数末字节语义、全局/静态变量地址映射；
- 跨模块同名静态变量不生成 ELF/DWARF 符号；
- DWARF 基本类型、变量位置和行表；
- HEX checksum、重叠、EOF、边界和低地址拒绝；
- 已安装 `dist/windows/stc-gdb.exe` 时的真实离线 GDB 查询。

当前专项 10 项测试通过，其中真实 GDB 用例支持 `STCFORGE_GDB` 指定客户端。另用真实
`STC32G144K246_32BIT_SDCC_Template.cdb/.hex` 离线验证：

- 77 个函数、122 个全局变量、14 个文件静态变量、881 条源码行；
- GDB 能查询 `main.c` 行号、`uptime_ms` 类型和 XDATA 地址；
- 函数末字节与下一函数起始地址正确衔接。

尚未完成真实硬件上的调试符号联调；USB 后端和断点行为仍需上板验收。该验证
不代表任意 `next`、`finish` 或完整调用栈已可用。局部变量和复合类型另有真实
SDCC 编译产物与 GDB 的离线联调测试。
