"""Build the machine-readable host-side protocol map for AiCube-ISP 6.97C."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


F8D1_USB_COMMANDS = {
    "00": {"direction": "out/in", "out_length": 1, "in_length": 54, "meaning": "initial status query"},
    "01": {"direction": "out/in", "out_length": 8, "in_length": 1, "meaning": "status preparation"},
    "02": {"direction": "out/in", "out_length": 133, "in_length": 2, "meaning": "128-byte program or data block"},
    "03": {"direction": "out/in", "out_length": 5, "in_length": 8, "meaning": "erase flash"},
    "04": {"direction": "out/in", "out_length": 46, "in_length": 2, "meaning": "hardware options"},
    "05": {"direction": "out/in", "out_length": 5, "in_length": 1, "meaning": "download password preparation"},
    "12": {"direction": "out", "out_length": 133, "meaning": "EEPROM continuation block in F8D1 captures"},
    "32": {"direction": "out", "out_length": 133, "meaning": "EEPROM first block in F8D1 captures"},
    "FF": {"direction": "out", "out_length": 1, "meaning": "leave ISP"},
}


def build(models: dict) -> dict:
    counts = Counter((model["flags"] >> 6) & 7 for model in models["models"])
    return {
        "source": {
            "program": "AiCube-ISP-v6.97C.exe",
            "sha256": "d857b147f2f4e527c5566a2dd40e63f875c94f4e344fa5ce800ab13a770db420",
            "image_base": "0x00400000",
        },
        "entry_points": {
            "download_task": "0x004C0250",
            "usb_hid": "0x0044C800",
            "usb_wrapper": "0x0044D7F0",
            "serial_or_adapter": "0x0044E590",
            "send_usb": "0x0044BDC0",
            "receive_usb": "0x0044BCE0",
            "send_uart_or_link1d": "0x0043D0D0",
            "receive_uart_or_link1d": "0x0043D240",
            "status_parser": "0x0043E1F0",
            "usb_irc_select": "0x0043EB30",
            "usb_irc_pack": "0x0043EFC0",
            "serial_irc": "0x004413F0",
            "hardware_option_pack": "0x0044B760",
            "reset_command_parser": "0x004A92C0",
            "reset_command_writer": "0x004C0997",
        },
        "transport_mode": {
            "1": "0x0044D7F0",
            "2": "0x0044C800",
            "other": "0x0044E590",
        },
        "f8d1_native_usb": {
            "commands": F8D1_USB_COMMANDS,
            "memory_block": {
                "address_formula": "0xFC2800 + (payload[4] << 16) + (payload[1] << 8) + payload[2]",
                "data_offset": "0x05",
                "data_length": 128,
            },
        },
        "uart": {
            "selector": "(flags >> 6) & 7",
            "selector_counts": dict(sorted(counts.items())),
            "baud_timer_selector": "(flags >> 9) & 7",
            "effective_selector": "status[17] >= 0x72 and selector < 3 ? 5 : selector",
            "frame_checksum": "8-bit additive for effective selector 0; 16-bit additive otherwise",
            "frame_checksum_branch": "0x0043D16C",
            "program_block_size": "128 if raw selector < 2 and family not in [25,27,28,32,33], otherwise 64",
            "program_block_size_branch": "0x0043E324",
            "baud_entry": "0x004416C0",
            "modern_prepare_packet": "0x00442B54",
            "modern_erase_packet": "0x00442C82",
            "legacy_stc89_erase_packet": "0x0044293B",
            "program_block_entry": "0x00443240",
            "h8u_bsl_75_program_write_header": "[22/02, address>>8, address, address>>24, address>>16]",
        },
        "status_offsets": {
            "hardware_options": ["0x01", "0x10"],
            "bsl_major": "0x11",
            "bsl_minor": "0x12",
            "status_parameter": "0x13",
            "model_magic_be": ["0x14", "0x15"],
            "family_parameters": ["0x16", "0x23", "0x2B", "0x34"],
        },
        "irc_tables": {
            "legacy": {"address": "0x51AC68", "entries": 10},
            "short": {"address": "0x51ABF0", "entries": 5},
            "normal": {"address": "0x51AC18", "entries": 10},
            "40_60": {"address": "0x51ACB8", "entries": 10},
            "40_64": {"address": "0x51AD08", "entries": 10},
        },
        "model_catalog": {
            "file": "models-6.97c.json",
            "model_count": models["model_count"],
            "family_count": models["family_count"],
        },
        "evidence": [
            "capture-command-evidence-6.97c.md",
            "commands-01-baseline-with-options/summary.json",
            "commands-02-hardware-options-24-cases/summary.json",
            "commands-03-irc-modes-and-user-system-area/summary.json",
            "commands-04-boot-pin-p32-p33-toggle/summary.json",
            "commands-05-eeprom-fc2800-single-block/summary.json",
            "commands-06-eeprom-fc2800-two-blocks/summary.json",
            "commands-07-irc-frequency-sweep/summary.json",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--models",
        type=Path,
        default=Path(__file__).resolve().parent / "models-6.97c.json",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    models = json.loads(args.models.read_text(encoding="utf-8"))
    args.output.write_text(json.dumps(build(models), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"model_count": models["model_count"], "family_count": models["family_count"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
