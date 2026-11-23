from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DB = ROOT / 'docs/research/aicube-isp-v6.97a/models-6.97c.json'
CORE_VOLTAGES = json.loads(DB.with_name('stc15-core-voltage-mv.json').read_text(encoding='utf-8'))
OUT = ROOT / 'docs/examples/hardware-families'
IRC_TABLES = {
    0x51ABF0: [22118400, 24000000, 18432000, 20000000, 27000000],
    0x51AC18: [22118400, 24000000, 20000000, 27000000, 30000000, 33177600, 35000000, 36864000, 40000000, 45000000],
    0x51AC68: [22118400, 24000000, 27000000, 30000000, 33177600, 35000000, 36864000, 40000000, 44236800, 45158400],
    0x51ACB8: [22118400, 24000000, 40000000, 45158400, 48000000, 50803200, 52000000, 56000000, 60000000, 64000000],
    0x51AD08: [22118400, 24000000, 40000000, 45158400, 48000000, 50803200, 52000000, 56000000, 60000000, 64000000],
}

# USB 自动选择使用的内置表，不等于“输入用户程序运行时的 IRC 频率”
# 控件的全部候选。STC32G144K246 的用户输入框还包含串口动态调节
# 使用的频点；其中三个频点在用户提供的 USB 抓包中未完成成功下载。
STC32_INPUT_IRC_VALUES = [
    5529600, 6000000, 11059200, 12000000, 18432000, 20000000,
    22118400, 24000000, 30000000, 32000000, 40000000, 45158400,
    48000000, 49152000, 50803200, 55296000, 60000000,
]
STC32_UART_ONLY_IRC_VALUES = [18432000, 49152000, 55296000]

# control 是 6.97C 的内部控件编号，用来给所有配置族共享稳定的用户键名。
# 这些编号不会写入模板，只在生成阶段用于还原语义。
BOOLEAN = {
    0x0606: ('eeprom_erase_enabled', '下次下载用户程序时擦除用户 EEPROM 区', 'true=擦除，false=保留'),
    0x0607: ('cold_start_p32_p33_required', '下次冷启动时要求 P3.2/P3.3 同时为低电平才能下载', 'true=要求，false=不要求'),
    0x0608: ('cold_start_p10_p11_required', '下次冷启动时要求 P1.0/P1.1 同时为低电平才能下载', 'true=要求，false=不要求'),
    0x0609: ('oscillator_gain_high', '振荡器使用高放大增益', 'true=高增益，false=低增益'),
    0x060A: ('reset2_voltage_reset_enabled', 'RESET2 电压低于 1.33V 时复位芯片', 'true=启用，false=禁用'),
    0x060B: ('ale_as_p45', 'ALE 脚用作 P4.5', 'true=用作 P4.5，false=保持 ALE'),
    0x060C: ('watchdog_poweroff_only', '看门狗只有断电后才能停止', 'true=只有断电停止，false=任何复位都可停止'),
    0x060D: ('cpu_6t_enabled', '使用 6T 双倍速模式', 'true=6T，false=12T'),
    0x060E: ('cpu_6t_enabled', '使用 6T 双倍速模式', 'true=6T，false=12T'),
    0x060F: ('oscillator_gain_reduced', '降低振荡器的放大增益以降低功耗', 'true=降低增益，false=不降低增益'),
    0x0610: ('xram_enabled', '使用 MCU 内部扩展 RAM', 'true=可用，false=不可用'),
    0x0611: ('por_reset_delay_long', '上电复位使用较长延时', 'true=较长延时，false=普通延时'),
    0x0612: ('eeprom_disabled', '禁用 EEPROM 功能', 'true=禁用，false=启用'),
    0x0613: ('modify_hardware_options', '本次下载修改硬件选项', 'true=修改，false=保留当前配置'),
    0x0614: ('irc_adjust_enabled', '本次下载调节 IRC 频率', 'true=调节，false=不调节'),
    0x0616: ('reset_pin_as_io', '复位脚用作 I/O 口', 'true=用作 I/O，false=保持复位脚'),
    0x0617: ('low_voltage_reset_enabled', '允许低压复位并禁止低压中断', 'true=允许低压复位，false=不允许'),
    0x0618: ('eeprom_disabled_at_low_voltage', '低压时禁止 EEPROM 操作', 'true=禁止，false=允许'),
    0x0619: ('watchdog_por_enabled', '上电复位时由硬件自动启动看门狗', 'true=自动启动，false=不自动启动'),
    0x061A: ('watchdog_stop_idle', '空闲状态时停止看门狗计数', 'true=停止，false=继续计数'),
    0x061D: ('append_test_parameters', '在程序区末尾追加芯片测试参数（占用程序 Flash）', 'true=追加，false=不追加'),
    0x061F: ('uid_in_code_enabled', '在程序区最后写入芯片全球唯一 ID', 'true=写入，false=不写入'),
    0x0621: ('uart1_p37_push_pull', 'UART1 的 P3.7 使用推挽输出', 'true=推挽，false=普通模式'),
    0x0623: ('uart1_remap', 'UART1 数据线切换到 P3.6/P3.7', 'true=切换，false=保持默认引脚'),
    0x0624: ('reset_pwm_port_open_drain', '复位脚关联 PWM 端口使用开漏模式', 'true=开漏，false=普通模式'),
    0x0625: ('usb_simulation_enabled', '使能 USB 仿真功能', 'true=使能，false=禁用'),
    0x0626: ('swd_enabled', '使能 SWD 仿真功能', 'true=使能，false=禁用'),
    0x0627: ('usb_auto_calibration_enabled', '使用 USB 自动校准功能', 'true=使用，false=不使用'),
    0x0678: ('usb_isp_enabled', '下次下载时使能 USB-ISP 模式', 'true=使能，false=禁用'),
    0x0679: ('preserve_flash_ff', '自动保留 Flash 目标区域为 FF', 'true=保留，false=不保留'),
    0x06F3: ('p54_as_p12', 'P5.4 切换为 P1.2', 'true=切换，false=保持默认功能'),
    0x06F4: ('swap_p10_p11', '交换 P1.0 和 P1.1 的管脚位置', 'true=交换，false=保持原位置'),
    0x06F5: ('user_system_enabled', '使能用户系统区功能', 'true=使能，false=禁用'),
    0x06F6: ('verify_system_code', '下次下载时校验系统代码完整性', 'true=校验，false=不校验'),
    0x06F7: ('checksum_user_code', '下次下载时计算用户整个代码区校验和', 'true=计算，false=不计算'),
}

SEMANTIC = {
    0x0415: ('irc_hz', '用户程序运行时的 IRC 频率', '填写顶部列出的频率值，单位 Hz；选择内置预置或上次调节时忽略此值'),
    0x0416: ('isp_rs485_wait_time', 'ISP 等待 RS485 下载命令的时间', '0=不等待；现有逆向资料未恢复其它固定时间档位'),
    0x0418: ('uart_simulation_pins', '串口仿真的通信引脚', 'p3.0-p3.1、p3.6-p3.7、p1.6-p1.7 或 p4.3-p4.4'),
    0x0419: ('swd_pins', 'SWD 仿真的通信引脚', 'p3.0-p3.1、p3.6-p3.7、p1.6-p1.7 或 p4.3-p4.4'),
    0x041A: ('usb_isp_clock_source', 'USB ISP 使用的时钟源', '0=外部 12 MHz 晶振，1=外部 24 MHz 晶振，2=内部专用 48 MHz IRC，3=内部系统 24 MHz IRC'),
    0x041B: ('low_voltage_threshold', '低压检测门槛电压', '0=2.0V，1=2.4V，2=2.7V，3=3.0V'),
    0x041D: ('watchdog_prescale', '看门狗定时器分频系数', '2、4、8、16、32、64、128 或 256'),
    0x041F: ('oscillator_stable_delay', '等待振荡器稳定的时钟数', '4096、8192、16384 或 32768 个时钟'),
    0x0421: ('core_voltage', 'CPU 内核最高工作电压，单位 mV', ''),
    0x0423: ('eeprom_kib', '用户 EEPROM 容量', '填写 2..246 KiB 之间的偶数，例如 2、4、8、16'),
    0x0425: ('flash_blank_value', 'Flash 空白区域的填充值', '0x00=填充 00，0xFF=填充 FF'),
    0x0453: ('irc_adjust_mode', 'IRC 调节模式', 'dynamic=总是动态调节，internal_preset=使用内部预置频率，last_trim=使用上一次调节后的频率'),
    0x0454: ('cpu_mode', 'CPU 指令模式', '8=8 位模式，32=32 位模式'),
    0x0455: ('user_system_kib', '用户系统区大小', '0=禁用，否则填写芯片支持的偶数 KiB'),
    0x0456: ('wtst_initial_value', '用户模式 WTST 初始值', '0=不等待，1=等待 1 个 Flash 读取时钟，2=等待 2 个，3=等待 3 个，4=等待 4 个'),
    0x0620: ('uart1_remap_p37_level', 'UART1 切换到 P3.6/P3.7 后的 P3.7 电平', '0=低电平，1=高电平'),
    0x0628: ('reset_pin_level', '复位脚上电复位电平', '0=低电平，1=高电平'),
    0x062A: ('eeprom_fill_zero', '本次将整个 EEPROM 区填充为 00；不可同时提供 EEPROM 数据', 'true=填充，false=不填充'),
    0x062C: ('eeprom_fill_ff', '本次将整个 EEPROM 区填充为 FF；不可同时提供 EEPROM 数据', 'true=填充，false=不填充'),
    0x0630: ('fast_download_enabled', '选择校准时使用的 ISP 时钟，不改变用户程序的 IRC 目标频率', 'true=22.1184 MHz，false=11.0592 MHz'),
    0x0638: ('internal_irc_clock', '系统使用内部 IRC 时钟', 'true=内部 IRC，false=外部时钟'),
}

# 当前工具没有实现把芯片全球唯一 ID 写入程序区，模板不暴露这个选项。
HIDDEN_KEYS = {'uid_in_code_enabled'}

# 这些控件虽然出现在静态选项描述表中，但具体型号或当前页面不会把
# 它们作为用户可选控件开放。flags=0 的条目也是 AiCube 的内部/隐藏项。
HIDDEN_BY_FAMILY = {
    89: {0x0418},
}

HIDDEN_DESCRIPTOR_FLAGS = {0}

SIMULATION_KEYS = {
    'uart_simulation_pins', 'usb_simulation_enabled', 'swd_enabled', 'swd_pins',
}


def semantic(option: dict) -> tuple[str, str, str]:
    control = option['control']
    if control in BOOLEAN:
        return BOOLEAN[control]
    if control in SEMANTIC:
        return SEMANTIC[control]
    return 'device_specific_option', option['label'], '0=默认设置；其他值仅在该型号手册明确说明时使用'


def core_voltages(family_id: int) -> list[int]:
    return CORE_VOLTAGES[min(max(family_id - 34, 0), 4) if family_id != 32 else 5]


def default_value(option: dict, key: str, family_id: int) -> str:
    value = option['default']
    if key == 'watchdog_prescale':
        return str(2 ** (value + 1))
    if key == 'eeprom_kib':
        if family_id == 88:
            return str((1, 2, 4, 8, 16, 32, 64)[value])
        return str((value + 1) * 2)
    if key == 'oscillator_stable_delay':
        return str(4096 << value)
    if key == 'core_voltage':
        return str(core_voltages(family_id)[value])
    if key == 'cpu_mode':
        return '32' if value else '8'
    if key == 'low_voltage_threshold':
        return str(value)
    if key == 'irc_hz':
        return '0'
    if key.startswith(('hardware_setting_', 'device_specific_option', 'cpu_core_voltage', 'core_voltage_level')):
        return str(value)
    if key == 'flash_blank_value':
        # AiCube 的控件默认索引为 0，主机下载路径把它解释为 FF。
        return '0xFF' if value == 0 else '0x00'
    if key in {'eeprom_fill_zero', 'eeprom_fill_ff'}:
        return 'true' if value else 'false'
    if key in {'uart_simulation_pins', 'swd_pins'}:
        return ('p3.0-p3.1', 'p3.6-p3.7', 'p1.6-p1.7', 'p4.3-p4.4')[value]
    if key == 'irc_adjust_mode':
        return ('dynamic', 'internal_preset', 'last_trim')[value] if value in (0, 1, 2) else 'dynamic'
    if key == 'usb_isp_clock_source':
        return str(value)
    if key == 'fast_download_enabled':
        return 'true' if value else 'false'
    if key in {v[0] for v in BOOLEAN.values()} or key in {'internal_irc_clock'}:
        return 'true' if value else 'false'
    return str(value)


def toml_value(value: str) -> str:
    if value in {'true', 'false'} or value.startswith(('0x', '0X')) or value[:1].isdigit():
        return value
    return json.dumps(value, ensure_ascii=False)


def choices_for(option: dict, family_id: int, choices: str) -> str:
    control = option['control']
    if control == 0x0421:
        return '、'.join(map(str, core_voltages(family_id)))
    if control == 0x0423:
        if family_id == 88:
            return '1、2、4、8、16、32 或 64 KiB'
        if family_id == 89:
            return '2、4、6、8...246 KiB，按 2 KiB 递增'
    if control == 0x0455:
        if family_id == 88:
            return '0=禁用；0.5、1、1.5...64 KiB，按 0.5 KiB 递增'
        return '0=禁用；2、4、6、8...246 KiB，按 2 KiB 递增'
    if control == 0x041B:
        if option['mask'] == 0x40:
            return '0=低门槛电压，1=高门槛电压'
        if option['mask'] == 0x03:
            if family_id in (61, 86, 87, 88, 89, 90):
                return '0=2.0V，1=2.4V，2=2.7V，3=3.0V'
            return '0、1、2、3 四档固定低压检测值'
        if option['mask'] == 0x07:
            return '0=最低门槛，1=较低门槛，2=中低门槛，3=中等门槛，4=中高门槛，5=较高门槛，6=高门槛，7=最高门槛'
        if option['mask'] == 0x0F:
            return '0..15=从最低到最高的 16 档低压检测门槛'
    return choices


def irc_comment(family_id: int, irc_table: int) -> tuple[str, str]:
    """Return the static USB list and the user-input list for a template."""
    usb_values = IRC_TABLES.get(irc_table, [])
    if family_id == 89:
        return (
            ', '.join(str(value) for value in usb_values),
            ', '.join(str(value) for value in STC32_INPUT_IRC_VALUES),
        )
    text = ', '.join(str(value) for value in usb_values)
    return text, text


def simulation_modes(model: dict) -> list[str]:
    flags, family_id = model['flags'], model['family']
    if flags & 0x11 != 0x11:
        return []
    modes = []
    if family_id != 89:
        modes.append('uart')
    if flags & 0x4000:
        modes.append('usb')
    if family_id != 88 and flags & 0x3000 == 0x1000:
        modes.append('swd')
    return modes


def main() -> None:
    data = json.loads(DB.read_text(encoding='utf-8'))
    OUT.mkdir(parents=True, exist_ok=True)
    index_lines = [
        '# AiCube-ISP 6.97C 配置族模板', '',
        '模板使用面向用户的语义键名。每项包含作用、可选值及各值含义、默认值。',
        '85 个配置族的型号列表和连接方式说明也保留在各自文件顶部。',
        '芯片全球唯一 ID 写入尚未接入，因此没有放入模板。', '',
    ]
    for family in data['families']:
        family_id = family['family']
        models = [m for m in data['models'] if m['family'] == family_id]
        supported_models = [m['name'] for m in models]
        usb_models = [m['name'] for m in models if m['flags'] & 0x4000]
        uart_models = [m['name'] for m in models if m['magic'] != 0xF78F]
        # 4BDDA0 gates the native USB interface on each selected model.
        # The 0678 control sets the device's next boot preference.
        name = family['first_model']
        representative = next(model for model in models if model['name'] == name)
        native_usb = name in usb_models
        default_transport = 'usb' if native_usb else 'serial'
        if len(usb_models) == len(models):
            transport_note = '原生 USB ISP 用 "usb"；UART ISP 用 "serial"，或用 "link1d" 经探针转接。'
        elif usb_models:
            transport_note = 'UART ISP 用 "serial" 或 "link1d"；支持原生 USB ISP 的型号见下一行。'
        else:
            transport_note = 'UART ISP 用 "serial" 或 "link1d"；本族型号不支持原生 USB ISP。'
        interface_details = []
        if usb_models and len(usb_models) != len(models):
            interface_details.append('# 支持原生 USB ISP 的型号：' + '、'.join(usb_models))
        if len(uart_models) != len(models):
            interface_details.append('# USB-2UART 只能用 "usb"，不支持 UART ISP。')
        if any(m['magic'] in {0xF7EE, 0x77EE, 0xF7EF, 0x77EF} for m in models):
            interface_details.append('# USB-Link1D、USB-Writer1 及其 Ai 别名需要专用工具固件流程。')
        safe = re.sub(r'[^A-Za-z0-9._-]+', '_', name)[:48]
        filename = f'family-{family_id:02d}-{safe}.toml'
        flags = family['flags'][0]
        layout = family['config_layout']['layout']
        irc_table = family['irc_table']['tables'][0]
        has_irc_mode = any(
            option['control'] == 0x0453 and option['flags'] not in HIDDEN_DESCRIPTOR_FLAGS
            for option in family['options']
        )
        has_irc_adjustment = has_irc_mode or any(
            option['control'] == 0x0614 and option['flags'] not in HIDDEN_DESCRIPTOR_FLAGS
            for option in family['options']
        )
        usb_irc_values, input_irc_values = irc_comment(family_id, irc_table)
        irc_scope_note = (
            '# 对 STC32G144K246，'
            + '、'.join(f'{value / 1_000_000:g}MHz' for value in STC32_UART_ONLY_IRC_VALUES)
            + ' 保留为串口动态调节候选，USB 成功下载尚未确认。'
            if family_id == 89 else
            '# 若本族同时支持串口动态校准，输入频率范围可能大于 USB 自动选择预置表；以本族实际界面为准。'
        )
        lines = [
            '# AiCube-ISP 6.97C 配置族模板',
            f'# 配置族：0x{family_id:02X}，示例型号：{name}',
            '# 支持型号：' + '、'.join(supported_models),
            '# 连接接口：' + transport_note,
            *interface_details,
            f'# {"支持 USB-ISP 的型号使用的 IRC 预置频率" if usb_models else "AiCube 内置 IRC 预置频率"}：{usb_irc_values or "由该型号频率表决定"}',
            f'# IRC 输入框候选频率：{input_irc_values or "按型号和连接方式决定"}',
            '# IRC 频率可直接填写 Hz；上面两组列表分别对应 USB 自动选择预置值和用户输入候选值。',
            irc_scope_note,
            '#',
            '# 下面的硬件选项已经填入默认值，按需修改或删除即可。',
            '# 以上为 AiCube 的接口说明。stc-isp 实际写入支持请查 --list-models。',
            '# 只下载程序、保留当前硬件选项时可设 modify_hardware_options = false。',
            '',
            'model = ' + json.dumps(name, ensure_ascii=False),
            f'if = "{default_transport}"',
            '# 仅用于 if = "link1d"：true 由探针断电上电；false 用 port 指定 UART1，手动上电。',
            'link1d_auto_power = true',
            '# 普通串口或 Link1D 手动上电时填写端口，例如 COM3 或 /dev/ttyUSB0。',
            'port = ""',
            'image = "firmware.hex"',
            '',
            '[hardware]',
        ]
        used = set()
        written_count = 0
        simulation_options = []
        for option in family['options']:
            key, description, choices = semantic(option)
            if (key in HIDDEN_KEYS or option['flags'] in HIDDEN_DESCRIPTOR_FLAGS or
                    option['control'] in HIDDEN_BY_FAMILY.get(family_id, set())):
                continue
            if key == 'eeprom_kib' and not (representative['flags'] & 8):
                # 48D27E skips this control for fixed partitions.
                continue
            if key in used:
                key = f'{key}_{option["index"]:02d}'
            used.add(key)
            if key in SIMULATION_KEYS:
                simulation_options.append((key, description, choices, option))
                continue
            value = default_value(option, key, family_id)
            if key == 'irc_hz' and has_irc_adjustment:
                # 0453/0614 的 AiCube 默认都打开了调节路径，因此不能再给
                # 一个无意义的 0 Hz。24 MHz 是所有已逆向 IRC 静态表都包含、
                # 且 STC32 已有抓包参数的公共频点。
                value = '24000000'
                if has_irc_mode:
                    description = '动态调节时的目标 IRC 频率；选择内部预置或上一次调节时忽略'
                else:
                    description = '启用 IRC 调节时的目标频率；关闭调节时忽略'
            choices = choices_for(option, family_id, choices)
            if key == 'eeprom_kib' and 45 <= family_id <= 52:
                nominal = representative['total_size'] - representative['code_size']
                value = format(nominal / 1024, 'g')
                choices = '仅可调分区型号支持；按 0.25 KiB 递增，须留出可表示的程序区'
            lines += [
                f'# {key}',
                f'# 作用：{description}。',
                f'# 可选值：{choices}。',
                f'# 默认：{value}',
                f'{key} = {toml_value(value)}',
                '',
            ]
            written_count += 1
        modes_by_model = {model['name']: simulation_modes(model) for model in models}
        candidate_modes = ['uart', 'usb', 'swd']
        modes = [mode for mode in candidate_modes if any(mode in values for values in modes_by_model.values())]
        if modes:
            used.add('simulation_mode')
            labels = {
                'none': '不制作仿真', 'usb': 'USB 仿真',
                'swd': 'SWD 仿真', 'uart': '串口仿真',
            }
            mode_text = '、'.join(f'{mode}={labels[mode]}' for mode in ['none', *modes])
            lines += [
                '# 仿真方式',
                '# 作用：选择一种仿真方式。制作会擦除程序区；使用 --make-simulation 和单独的制作配置。',
                f'# 可选值：{mode_text}。',
            ]
            for mode in modes:
                names = [model for model, allowed in modes_by_model.items() if mode in allowed]
                if len(names) != len(models):
                    lines.append(f'# {labels[mode]}支持型号：' + '、'.join(names))
            if family_id in (29, 38):
                lines.append('# 旧 IAP15 串口仿真需要 simulation_resources；见 ../iap15-uart-simulation.toml。')
            lines += [
                '# 默认：none',
                'simulation_mode = "none"',
                '',
            ]
            written_count += 1
            switchable = {
                'uart_simulation_pins': [m['name'] for m in models if
                                        m['flags'] & 0x4000 and 'uart' in modes_by_model[m['name']]],
                'swd_pins': [m['name'] for m in models if 'swd' in modes_by_model[m['name']]],
            }
            descriptors = {key: (description, choices, option) for key, description, choices, option in simulation_options}
            for control in (0x0418, 0x0419):
                key, description, choices = SEMANTIC[control]
                if not switchable[key]:
                    continue
                value = 'p3.0-p3.1'
                if key in descriptors:
                    description, choices, option = descriptors[key]
                    value = default_value(option, key, family_id)
                    choices = choices_for(option, family_id, choices)
                if len(switchable[key]) != len(models):
                    lines.append('# 可换脚型号：' + '、'.join(switchable[key]))
                lines += [
                    f'# {key}',
                    f'# 作用：{description}。',
                    f'# 可选值：{choices}。',
                    f'# 默认：{value}',
                    f'{key} = {toml_value(value)}',
                    '',
                ]
                written_count += 1
        (OUT / filename).write_text('\n'.join(lines) + '\n', encoding='utf-8')
        index_lines.append(f'- [{filename}]({filename})，{name}，{written_count} 项')
    (OUT / 'README.md').write_text('\n'.join(index_lines) + '\n', encoding='utf-8')
    print(f'generated {len(data["families"])} family templates in {OUT}')


if __name__ == '__main__':
    main()
