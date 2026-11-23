"""Decode STC USBPcap HID ISP frames without assuming one download session."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import subprocess


FIELDS = [
    "frame.number",
    "frame.time_relative",
    "usb.device_address",
    "usb.endpoint_address",
    "usb.capdata",
    "usbhid.data",
]


def tshark_reports(capture: Path, tshark: Path) -> list[dict]:
    command = [str(tshark), "-r", str(capture), "-T", "fields"]
    for field in FIELDS:
        command += ["-e", field]
    output = subprocess.run(command, capture_output=True, text=True, check=True).stdout
    reports = []
    for line in output.splitlines():
        columns = line.split("\t") + [""] * len(FIELDS)
        frame, time, device, endpoint, capdata, hiddata = columns[: len(FIELDS)]
        data = capdata or hiddata
        if not data:
            continue
        reports.append(
            {
                "frame": int(frame),
                "time": float(time),
                "device": device,
                "endpoint": endpoint,
                "data": bytes.fromhex(data.replace(":", "")),
            }
        )
    return reports


def decode_frames(reports: list[dict]) -> tuple[list[dict], list[dict]]:
    streams = {}
    frames = []
    errors = []
    for report in reports:
        if report["endpoint"] not in ("0x04", "0x84"):
            continue
        key = report["device"], report["endpoint"]
        state = streams.setdefault(key, {"data": bytearray(), "reports": []})
        if not state["data"] and not report["data"].startswith(b"\x46\xb9"):
            errors.append({"frame": report["frame"], "error": "unframed payload"})
            continue
        state["data"].extend(report["data"])
        state["reports"].append(report)
        if len(state["data"]) < 5:
            continue
        end = int.from_bytes(state["data"][3:5], "big") + 2
        if end < 9:
            errors.append({"frame": report["frame"], "error": "invalid length"})
            state["data"].clear()
            state["reports"].clear()
            continue
        if len(state["data"]) < end:
            continue
        packet = bytes(state["data"][:end])
        direction = "OUT" if key[1] == "0x04" else "IN"
        payload = packet[5:-3]
        checksum_ok = (sum(packet[2:-3]) & 0xFFFF) == int.from_bytes(packet[-3:-1], "big")
        direction_ok = packet[2] == (0x6A if direction == "OUT" else 0x68)
        valid = checksum_ok and direction_ok and packet[-1] == 0x16
        frames.append(
            {
                "first_frame": state["reports"][0]["frame"],
                "last_frame": report["frame"],
                "time": state["reports"][0]["time"],
                "direction": direction,
                "command": f"{payload[0]:02X}" if payload else "",
                "length": len(payload),
                "payload": payload.hex(),
                "reports": len(state["reports"]),
                "valid": valid,
            }
        )
        if not valid:
            errors.append({"frame": report["frame"], "error": "checksum, direction or trailer"})
        state["data"].clear()
        state["reports"].clear()
    for state in streams.values():
        if state["data"]:
            errors.append({"error": "incomplete frame", "data": bytes(state["data"]).hex()})
    return frames, errors


def summarize(capture: Path, reports: list[dict], frames: list[dict], errors: list[dict]) -> dict:
    command_counts = Counter(f"{frame['direction']} {frame['command']}" for frame in frames)
    lengths = defaultdict(Counter)
    unique_payloads = defaultdict(set)
    for frame in frames:
        key = f"{frame['direction']} {frame['command']}"
        lengths[key][frame["length"]] += 1
        unique_payloads[key].add(frame["payload"])
    config_payloads = sorted(
        {frame["payload"] for frame in frames if frame["direction"] == "OUT" and frame["command"] == "04"}
    )
    writes = []
    for frame in frames:
        if frame["direction"] != "OUT" or frame["command"] not in {"02", "12", "32"}:
            continue
        payload = bytes.fromhex(frame["payload"])
        if len(payload) != 133 or payload[3] != 0:
            continue
        address = 0xFC2800 + (payload[4] << 16) + (payload[1] << 8) + payload[2]
        writes.append(
            {
                "frame": frame["first_frame"],
                "command": frame["command"],
                "address": f"0x{address:06X}",
                "length": 128,
            }
        )
    return {
        "capture": str(capture.resolve()),
        "sha256": hashlib.sha256(capture.read_bytes()).hexdigest(),
        "payload_reports": len(reports),
        "isp_frames": len(frames),
        "valid_frames": sum(frame["valid"] for frame in frames),
        "errors": errors,
        "command_counts": dict(sorted(command_counts.items())),
        "lengths": {key: dict(value) for key, value in sorted(lengths.items())},
        "unique_payload_count": {key: len(value) for key, value in sorted(unique_payloads.items())},
        "config_payloads": config_payloads,
        "writes": writes,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("capture", type=Path)
    parser.add_argument("--tshark", type=Path, default=Path("C:/Program Files/Wireshark/tshark.exe"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    reports = tshark_reports(args.capture, args.tshark)
    frames, errors = decode_frames(reports)
    summary = summarize(args.capture, reports, frames, errors)
    (args.output / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (args.output / "frames.json").write_text(json.dumps(frames, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (args.output / "reports.tsv").write_text(
        "frame\ttime\tdevice\tendpoint\tdata\n"
        + "".join(
            f"{report['frame']}\t{report['time']:.6f}\t{report['device']}\t{report['endpoint']}\t{report['data'].hex()}\n"
            for report in reports
        ),
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
