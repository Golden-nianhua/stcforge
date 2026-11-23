# stc-isp

stc-isp 是 STCForge 中独立的 ISP 命令行程序。协议实现以
docs/research/aicube-isp-v6.97a 中对 AiCube-ISP 6.97C 的静态逆向和现有
STC32G144K246 抓包为依据。

当前可执行版本覆盖以下主流程：

- USB HID ISP 34BF:1001
- STC32G144K246 的程序区和 EEPROM 混合下载
- STC8H8K64U、AI8H8K64U 族的 16 位 USB ISP 地址布局和 USB 配置载荷
- 00 状态读取、01 初始化、05 口令准备、03 擦除、02/32 数据块、04 硬件配置、07 新口令和 FF 退出
- STC32G144K246 的 USB 预置 IRC 表和 46 字节配置载荷
- Windows 原生 HID，Linux/macOS 使用 hidapi
- Windows 和 POSIX 串口传输，以及 Link1D HID-UART1
- 软件 USB（5354:4312）的控制传输与部分机型的联机下载
- 离线编程器镜像打包、上传和清除
- 配置文件和命令行逐项覆盖
- 应用侧 HID、USB-CDC 和普通串口复位命令的传输入口
- 85 个 AiCube-ISP 6.97C 配置族模板，位于 docs/examples/hardware-families

写入程序区和 EEPROM 时，终端会显示单行进度条、完成百分比、已写入字节数、实时写入速度和预计剩余时间。速度统计从开始写入数据块时计算，不包含前面的擦除和握手时间。

编译：

    cmake -S . -B .cache/build/isp -G Ninja -DCMAKE_CXX_COMPILER="D:/Code/c-env/mingw64/x86_64-15.2.0-release-posix-seh-ucrt-rt_v13-rev1/bin/g++.exe"
    cmake --build .cache/build/isp

执行：

    .cache/build/isp/stc-isp.exe --config docs/examples/stc32g144k246.toml
    .cache/build/isp/stc-isp.exe --if usb --image firmware.hex --option cpu_mode=32 --option irc_hz=24000000
    .cache/build/isp/stc-isp.exe --if usb --info

`--image` 支持 Intel HEX 和 BIN。HEX 使用文件里记录的地址，可在支持的型号上同时包含程序和 EEPROM。BIN 从目标的程序区起点写入，程序会在擦除前检查当前分区容量。

`--info` 从设备识别型号，并显示当前实现能解码的硬件选项。未移植的字段不套用其他族的布局；有些型号目前只能识别，不能显示硬件配置。

配置硬件选项时，程序先读目标状态，再按该下载分支的布局组包。硬件选项写入没有全量移植；配置族模板中的 AiCube 选项不代表当前都能写入。

型号目录从逆向资料的 1345 条记录和 85 个配置族生成。`--list-models` 中 `uart-write`、`usb-write` 分别标明已接入的程序写入接口，`simulation-make` 标明独立仿真制作模式。记录数包含别名。这些标记不是对所有 BSL 版本、硬件选项或实板验证的承诺。

## Link1D 联机下载

```powershell
stc-isp.exe --list-link1d
stc-isp.exe --if link1d --info
stc-isp.exe --if link1d --model STC32G144K246 --image firmware.hex
```

`--if link1d` 默认通过探针 HID 控制 S-VCC 断电、重新上电并握手。目标板必须由 S-VCC 供电，或以其他方式确保能完整掉电；独立供电不会被探针断开。`--info` 不擦写 Flash，但默认也会重新上电。`--list-link1d` 仅枚举探针，不改变供电。接了多个探针时用 `--device-path` 选择其中一个。

`--link1d-auto-power false` 改用探针的 **UART1 虚拟串口**，不发 HID 电源命令。启动后手动重新给目标板上电，`--timeout-ms` 可延长等待。早期 STC89 使用无校验 UART，建议指定型号。

```powershell
stc-isp.exe --if link1d --link1d-auto-power false --port COM30 --timeout-ms 10000 --info
```

默认下载成功后持续给目标供电。`--link1d-keep-power false` 可关闭这个行为，不影响下载前的自动断电和上电。两项都可在 TOML 顶层设置，也可以用命令行覆盖：

```toml
if = "link1d"
link1d_auto_power = true
link1d_keep_power = true
```

Link1D 转接的是目标侧 UART ISP。`uart-write=yes` 当前标记 1340 条型号记录，包含别名。STC89/STC90 和 STC10/11/12 按握手中的 BSL 版本切换协议。新版 8 位 UART 需要 BSL 6.2 或更新；旧 STC15 的选择器 3、STC15E/EA 与两款 IRC15x207A 的程序写入路径支持 BSL 6.0 起，硬件选项另有版本要求。支持 EEPROM 的旧 STC10/11/12 及新版 8 位路径都可以从同一份 HEX 写入程序与尾部 EEPROM 数据；BIN 本身不携带 EEPROM 地址。

使用 1T/4T 定时器换速的下载路径会按目标时钟选择可用的传输波特率，并在与 `--baud` 不同时显示实际值。初始握手仍使用 `--handshake-baud`。

`usb-write=yes` 当前标记 67 条记录。STC8 原生 USB 路径在 BSL ≥ 7.4 时支持带尾部 EEPROM 数据的 HEX，按 7.5 前后选择块头。STC8U、AI8051U 和 AI32 的下载配置分别组包。

`--if usb-soft` 用于软件模拟 USB ISP，与 `--if usb` 的原生 HID 不同。Windows 使用已安装的 USBSCAN 驱动；Linux/macOS 编译时需要 libusb。该接口从设备识别型号，目前接入不超过 64 KiB 的程序布局、基础擦写、加密镜像、用户密钥、UID 名单及绑定、追加测试参数和部分 8 位硬件选项。旧 STC15 的选择器 3 路径及 STC10/11/12 路径可写 64 字节配置包，保留当前频率和修调值；软件 USB 不执行 UART 动态校准。STC12 的软件 USB 配置包不传低压检测门槛，改这项请用 UART。不支持的硬件选项会在擦写前报错。原生 HID 型号不要使用这个接口。

```powershell
stc-isp.exe --if usb-soft --info
stc-isp.exe --if usb-soft --model STC8H1K08 --image firmware.hex
```

AI/STC32G12 已接入 BSL 7.4.3 起的下载；AiCube 标记有 USB 下载问题的 7.4.12 批次仍须用 UART 或 Link1D。G8 和 F12 目前要求 BSL ≥ 7.5。原生 USB 仅开放给型号表中标有 USB ISP 的记录。G12 的传输基址为 `FE0000`，程序从 EEPROM 末尾开始，固定分区的 G12K64 从 `FF0000` 开始。G8 和 F12 的程序从 `FF0000` 开始。HEX 可同时包含程序区和 EEPROM 数据。修改 G12 的 `eeprom_kib` 时，HEX 必须按新程序起点链接；BIN 自动放到新起点。缩小 EEPROM 会使让出的扇区进入程序区，原数据不保留。

AI16F40K128-Beta 和 STC16F40K128-Beta 的 UART 与原生 USB 路径要求 BSL ≥ 7.5。HEX 使用 `0000..FFFF`，烧录完整的 120 KiB 程序可以使用从地址 `0000` 开始的 BIN。擦除范围按设备报告的边界和镜像长度计算。

AI/STC8051U 支持 BSL 7.4.12 起的联机下载；与 G12 一样，受影响的 7.4.12 批次只走 UART 或 Link1D。HEX 从 `FF0000` 开始，可以同时包含程序和 EEPROM 数据。`irc_adjust_mode=dynamic` 与 `irc_hz` 可在已接入的 UART 校准分支中执行测量；USB 下载不会走这个测量流程。

新版 STC8U、AI8051U、AI32 和 AI16 原生 USB 在调节 IRC 时会按型号选基频和分频，并使用设备状态中的修调值。并非所有串口可用频率都能用 USB 合成。AI16 Beta 的 `usb_isp_clock_source` 另行选择下次 USB ISP 使用的时钟，不是用户程序的 IRC 频率。

支持本次填充的旧系列可用 `eeprom_fill_ff = true`；STC12C54 系列也可用 `eeprom_fill_zero = true`。这会覆盖整个 EEPROM，不能与镜像自带的 EEPROM 数据同时使用，且不受 `modify_hardware_options` 开关控制。`append_test_parameters` 则将芯片的测试参数写入程序区尾部，适用范围见各型号模板。

`--user-key-file`（TOML：`user_key_file`）可在已接入该命令的 STC32G144K246、AI/STC8051U、AI32 和 AI16 路径上写入用户密钥。可传入 AiCube 导出的 `.k` 文件，也可传入 256 字节原始密钥表（每个字节值恰好出现一次）。密钥在擦除后、程序块之前写入；该参数不对镜像内容进行加密。

`--encrypted-image`（TOML：`encrypted_image = true`）用于下载已加密的 HEX 或 BIN。它切换目标的写块命令，不转换镜像内容；目标须使用与镜像相配的密钥。

可用 `stc-isp --encrypt-bin firmware.bin --key-file key.k --output firmware-encrypted.bin` 离线生成加密 BIN。`--key-file` 接受与 `--user-key-file` 相同的格式；转换不访问设备，也不覆盖已有输出文件。

`--uid-allowlist`（TOML：`uid_allowlist`）接受文本名单，每行一个 7 字节 UID，例如 `01 02 03 04 05 06 07`。名单只允许匹配的芯片继续写程序。和 AiCube 一样，UID 取自擦除应答，**名单不匹配时程序区可能已经被擦除**。不接受仅擦除模式或不支持这类 UID 应答的旧 UART 下载路径。

`--uid-bind 0xFF0080=xor:0x55,add:1` 将 7 字节 UID 逐字节运算后写到指定固件地址。地址用该型号在 HEX 中的地址；只指定地址则写原始 UID。最多四个地址，每处最多四步，可选 `add`、`mul`、`div`、`xor`，操作数为 `0..255`，除数不能为 0。不允许覆盖复位入口或用于预加密镜像。配置文件可在 `[uid_bind]` 段下写 `"0xFF0080" = "xor:0x55,add:1"`。

可在支持的 H8U 上使用 `--if link1d --model STC8H8K64U --image firmware.hex --option modify_hardware_options=false`。完整的分支及待移植范围见 [AiCube 6.97C → stc-isp 实现审计](research/aicube-isp-v6.97a/stc-isp-port-audit-6.97c.md)。

STC32G144K246 可附带 `--option modify_hardware_options=false --option simulation_mode=swd --option swd_pins=p3.0-p3.1` 下载程序并写入 SWD 仿真配置。探针和供电时序目前通过本地 AiCube 6.97C 反汇编及模拟回包核对，尚未实板烧录验证。

## 离线编程器

先使用 AiCube 导出的硬件配置 `.cfg` 和固件打包，再使用 `--if usb`（编程器 HID）或 `--if serial`（编程器串口）上传。`--offline-resources` 指向本地从 6.97C 解出的资源目录；程序按型号和编程器连接方式选取辅助数据。`--erase-offline` 清除的是编程器里的离线任务，不是目标芯片 Flash。

```powershell
stc-isp.exe --offline-profile board.cfg --image firmware.hex --offline-output offline.bin
stc-isp.exe --if usb --offline-image offline.bin --offline-resources docs/research/aicube-isp-v6.97a/resources
stc-isp.exe --if serial --port COM3 --offline-image offline.bin --offline-resources docs/research/aicube-isp-v6.97a/resources
```

三条命令都可先加 `--dry-run`。目标硬件选项来自 `.cfg`，不是联机下载的 TOML 硬件项。普通上传和清除不自动更新编程器固件。主机组包和通信已通过原例程对照及模拟回包，未在实物离线编程器上执行。

打包支持 `--uid-bind`，实际 UID 由离线编程器在烧录时填入。程序区和 EEPROM 可以各配置一个自动增量，例如 `--option offline_program_counter=hex,0x0020,4,0001,1` 和 `--option offline_eeprom_counter=dec,0xFE02,2,100,1`。依次填写格式（`hex`、`dec`、`ascii`）、HEX 地址、长度（1–16 字节）、起始值、步进值。失败也递增可设置 `offline_increment_on_failure=true`，默认关闭。生成数据的地址不能占用复位入口或彼此重叠。

## 工具主控制作

`--make-tool` 会擦写工具主控，和向离线编程器上传用户程序、更新运行中的探针固件是不同的操作。`USB-Link1D`、`AiUSB-Link1D`、`USB-Writer1`、`AiUSB-Writer1` 使用原生 HID 和本地原始 `res65.bin`。`U7-5V`、`U7-3V`、`U8-5V`、`U8-3V`、`U8W` 使用普通串口和本地原始 `res11.bin`，要求 BSL 7.1.3 或更新。先用 `--dry-run` 检查资源、型号和参数：

```powershell
stc-isp.exe --if usb --model USB-Link1D --make-tool --tool-resources docs/research/aicube-isp-v6.97a/resources --dry-run
stc-isp.exe --if serial --port COM3 --model U8W --make-tool --tool-resources docs/research/aicube-isp-v6.97a/resources --dry-run
```

`tool_rx1`、`tool_rx2` 可选 `high_impedance`（默认）或 `quasi_pullup`。`tool_tx1_idle`、`tool_tx2_idle`、`tool_tx1_active`、`tool_tx2_active` 可选 `open_drain`（默认）或 `push_pull`。通过 `--option` 或 `[hardware]` 配置。此路径已对照原始数据块，未对实物工具执行擦写。

## 独立制作仿真芯片

`--make-simulation` 会擦除程序区；如果芯片当前配置在下载时擦除 EEPROM，用户 EEPROM 也可能被擦除。命令要求 `--model`，不接受 `--image`。串口仿真和 SWD 的通用 BSL 下限为 7.1.3，USB 仿真至少需要 7.4，STC32G144K246 需要 7.5。`--dry-run` 不连接设备，只检查型号、接口、参数和所需文件。

`--if` 选择**进入 ISP 的接口**；`simulation_mode` 选择**制作后的仿真模式**。`--list-models` 的 `simulation-make` 列按型号显示可选模式。通常可通过 `serial` 或 `link1d` 制作，具备原生 USB ISP 的型号也可用 `--if usb` 制作非 SWD 模式。USB-2UART 只能通过原生 USB ISP 连接。G12 和 AI8051U 受影响的 7.4.12 批次需通过串口或 Link1D 连接，即使制作的是 USB 仿真。

```powershell
stc-isp.exe --if usb --model STC32G144K246 --make-simulation --option simulation_mode=usb
stc-isp.exe --if link1d --model STC8H8K64U --make-simulation --option simulation_mode=uart --option uart_simulation_pins=p1.6-p1.7
stc-isp.exe --if usb --model AI8051U-34K64 --make-simulation --option simulation_mode=usb
stc-isp.exe --if link1d --model AI32G12K128 --make-simulation --option simulation_mode=swd --option swd_pins=p3.0-p3.1
stc-isp.exe --config docs/examples/stc32g144k246-swd-simulation.toml
stc-isp.exe --config docs/examples/iap15-uart-simulation.toml --dry-run
```

支持换脚的型号可选 `p3.0-p3.1`、`p3.6-p3.7`、`p1.6-p1.7` 或 `p4.3-p4.4`；其余串口仿真型号使用固定的 P3.0/P3.1。新增分支不接受通用下载硬件选项；它根据状态报文写回 IRC、低压、看门狗和 EEPROM 等可还原字段。启用了下载 RS485 方向控制的设备会在擦除前被拒绝。

旧 IAP15F/L2K61S2、IAP15W4K58S4（含 Student）和 IAP15W4K61S4 要写入原版监控镜像。用 `--simulation-resources` 或配置中的 `simulation_resources` 指向从本地 AiCube 6.97C 提取的资源目录，程序会在连接前校验 `res2.bin` 和对应型号的 `res6.bin`、`res30.bin` 或 `res31.bin`。可用仓库内的 `docs/research/aicube-isp-v6.97a/inspect-project.py <AiCube-ISP-v6.97C.exe> --extract-resources <新目录>` 提取。其他型号不需要资源文件。

制作完成后重新上电，再由对应调试器写入用户程序。

## 应用侧自动复位

AiCube-ISP 的自动复位不是 ISP 命令。stc-isp 会先向应用固件发送最多 32 字节的用户命令，应用固件识别命令后自行跳转到 ISP。

HID 模式使用应用侧 VID/PID，写出 65 字节报告。USB-CDC 和普通串口使用同一组串口参数，数据位固定为 8，支持校验位、停止位、DTR 和 RTS。写出后等待 50 ms，再进入 ISP 握手。

```toml
reset_transport = "serial"
reset_port = "COM5"
reset_baud = 115200
reset_parity = "none"
reset_stop_bits = 1
reset_dtr = false
reset_rts = false
reset_command = "hex:4053544349535023"
```

## 配置族模板

docs/examples/hardware-families 中每个模板对应 AiCube-ISP 6.97C 的一个配置族。模板使用功能名称作为键名，并在每项旁边写明作用、可选值、每个值的含义和默认值。

`usb` 表示原生 USB ISP/HID，`serial` 表示 UART 或 USB-CDC 转出的串口。`link1d` 是由 Link1D 探针转接的目标侧 UART ISP。模板按每个型号的 USB 标志注明支持范围；`usb_isp_enabled` 是下次启动设置，不用来判断接口能力。模板包含尚未移植的选项，实际写入覆盖以 `--list-models` 和上文为准。

STC32G144K246 的 AiCube 页面会将串口仿真控件置灰，因此模板和程序都不提供 `uart_simulation_pins`。串口 ISP 下载仍然可用，它与串口仿真是两个独立功能。

STC32 模板顶部的 IRC 说明分成两组：USB 自动选择的预置 IRC 频率是 AiCube 内嵌的 10 项静态候选表；IRC 输入框候选频率是用户可以直接填写或选择的完整候选列表，不能把两组列表当成同一组。当前已知的 17 个输入频点中，18.432MHz、49.152MHz 和 55.296MHz 只保留作串口动态调节候选，USB 成功下载尚未确认。

`irc_adjust_mode` 的三个值对应 AiCube 的实际分支：`dynamic` 动态调节；`internal_preset` 使用内置频率表；`last_trim` 沿用芯片上一次保存的修调值。后两种模式都会忽略 `irc_hz`，模板中的默认 24MHz 只服务于动态调节模式。

## 配置文件与命令行覆盖

程序先读取 `--config` 指定的 TOML，再按命令行出现的参数覆盖配置文件中的同名值。`--image`、`--model`、`--if`、`--port`、波特率、口令、复位参数和重复出现的 `--option` 都遵循这个顺序。

例如：

```powershell
stc-isp.exe --config docs/examples/stc32g144k246.toml --image build/Release/firmware.hex --option irc_hz=24000000
```

命令行中的镜像会覆盖 TOML 的 `image`，命令行中的 IRC 选项会覆盖 `[hardware]` 中的 `irc_hz`。
