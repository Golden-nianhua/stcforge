import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "docs/research/aicube-isp-v6.97a/models-6.97c.json"
TARGET = ROOT / "src/isp/isp_hardware_options_generated.inc"
HIDDEN_CONTROLS = {0x061F}
HIDDEN_BY_FAMILY = {89: {0x0418}}
INFO_HIDDEN_CONTROLS = {
    0x0416,  # ISP 等待 RS485 命令的时间
    0x0425,  # Flash 镜像空白区域填充值
    0x0613,  # 本次下载是否修改配置
    0x0614,  # 本次下载是否调节 IRC
    0x061D,  # 下载时追加测试参数
    0x062A,  # 本次 EEPROM 填充 00
    0x062C,  # 本次 EEPROM 填充 FF
    0x0630,  # 本次使用快速下载
    0x0679,  # 下载时保留 Flash 空白区域
}


def cpp_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def main() -> None:
    data = json.loads(SOURCE.read_text(encoding="utf-8"))
    lines = []
    for family in data["families"]:
        family_id = family["family"]
        for option in family["options"]:
            # flags=0 是逆向表中的内部项或隐藏项，不是用户实际能选择的配置。
            if (option["flags"] == 0 or option["control"] in HIDDEN_CONTROLS or
                    option["control"] in INFO_HIDDEN_CONTROLS or
                    option["control"] in HIDDEN_BY_FAMILY.get(family_id, set())):
                continue
            lines.append(
                "    {"
                f"{family_id}, 0x{option['control']:04X}, "
                f"{cpp_string(option['label'])}, {option['raw_offset']}, "
                f"0x{option['mask']:02X}, {option['default']}, {option['flags']}"
                "},"
            )
    TARGET.write_text(
        "// Generated from docs/research/aicube-isp-v6.97a/models-6.97c.json.\n"
        + "\n".join(lines)
        + "\n",
        encoding="utf-8",
    )
    print(f"generated {len(lines)} visible hardware options")
    voltages = json.loads(SOURCE.with_name("stc15-core-voltage-mv.json").read_text(encoding="utf-8"))
    assert len(voltages) == 6 and all(len(row) == 32 for row in voltages)
    TARGET.with_name("isp_core_voltage_generated.inc").write_text(
        "// AiCube 6.97C: 48C60D selects a row from 559DCC.\n"
        + "\n".join("    {" + ", ".join(map(str, row)) + "}," for row in voltages)
        + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
