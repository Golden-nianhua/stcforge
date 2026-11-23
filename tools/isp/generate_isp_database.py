"""Generate the compiled model catalogue from the AiCube-ISP reverse database."""

from __future__ import annotations

import json
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    database = json.loads((root / "docs/research/aicube-isp-v6.97a/models-6.97c.json").read_text(encoding="utf-8"))
    rows = ["// Generated from models-6.97c.json. Do not edit by hand."]
    test_families = {
        family["family"] for family in database["families"]
        if any(o["control"] == 0x061D and o["flags"] and o["mask"] == 2 and o["raw_offset"] == 15
               for o in family["options"])
    }
    eeprom_fill_families = {
        family["family"] for family in database["families"]
        if any(o["control"] in {0x062A, 0x062C} and o["flags"] for o in family["options"])
    }
    for model in database["models"]:
        alternate = model["alternate_magic"]
        variant = (model["field28"] >> 8) & 0xFF
        test_parameters = model["family"] in test_families
        family, flags = model["family"], model["flags"]
        legacy_stc12 = (7 <= family <= 14 or 19 <= family <= 24) and (
            (flags >> 9) & 7) == 2 and ((flags >> 6) & 7) <= 1
        eeprom_size = model["field16"] if legacy_stc12 or family in eeprom_fill_families else 0
        record_eeprom = model["field16"]
        record_reserve = model["field28"] & 0xFF
        extra = f", 0x{alternate:04X}, {variant}" if (
            alternate or variant or test_parameters or eeprom_size or record_eeprom or record_reserve
        ) else ""
        if test_parameters:
            extra += f", {model['field28'] & 0xFF}"
        elif eeprom_size or record_eeprom or record_reserve:
            extra += ", std::nullopt"
        if eeprom_size or record_eeprom or record_reserve:
            extra += f", 0x{eeprom_size:X}"
        if record_eeprom or record_reserve:
            extra += f", 0x{record_eeprom:X}, {record_reserve}"
        rows.append(
            "        {" + json.dumps(model["name"], ensure_ascii=True) +
            f", 0x{model["magic"]:04X}, 0x{model["code_size"]:X}, "
            f"0x{model["total_size"]:X}, 0x{model["flags"]:X}, {model["family"]}{extra}}},"
        )
    output = root / "src/isp/isp_database_generated.inc"
    output.write_text("\n".join(rows) + "\n", encoding="utf-8")
    print(f"generated {len(rows) - 1} model records at {output}")


if __name__ == "__main__":
    main()
