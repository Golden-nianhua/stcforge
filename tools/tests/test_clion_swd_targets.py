import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock

from stcforge import clion


class ClionSwdTests(unittest.TestCase):
    def test_swd_entries_share_one_target_and_replace_the_legacy_scheme(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            settings = dict(simulation_mode="swd", warmup_ms=3000, port=3333)
            inputs = (root, "stcforge", "test", root / "config.toml", root / "test.hex",
                      "Debug", "MCS-251", Path("stc-isp"))
            configs = root / ".idea/runConfigurations"
            legacy = configs / "STC32_Auto_STCForge_debug.xml"
            direct = configs / "STC32_Auto_STCForge_swd_attach.xml"
            flash = configs / "STC32_Auto_STCForge_swd_flash.xml"

            def read(path):
                return ET.parse(path).getroot().find("configuration")

            clion.write_configuration(settings, *inputs, legacy, "STCForge_swd")
            clion.write_configurations(settings, *inputs)
            self.assertFalse(legacy.exists())
            self.assertEqual(read(direct).get("name"), "STCForge_swd_attach")
            self.assertEqual(read(direct).get("TARGET_NAME"), "test")
            self.assertEqual(read(flash).get("name"), "STCForge_swd_flash")
            self.assertEqual(read(flash).get("TARGET_NAME"), "test")
            self.assertEqual(read(direct).get("folderName"), "Debug")
            self.assertEqual(read(flash).get("folderName"), "Debug")
            self.assertEqual(read(flash).get("PROGRAM_PARAMS"),
                             read(direct).get("PROGRAM_PARAMS") + " --swd-load")
            self.assertEqual(read(flash).find("custom-gdb-server").get("download-type"), "ALWAYS")
            self.assertEqual(read(direct).find("custom-gdb-server").get("download-type"), "NONE")
            clion.write_configurations({**settings, "simulation_mode": "usb"}, *inputs)
            self.assertEqual(read(legacy).get("name"), "STCForge_debug")
            self.assertFalse(direct.exists())
            self.assertFalse(flash.exists())

    def test_only_explicit_sync_subcommand_can_download(self):
        settings = dict(simulation_mode="swd", swd_speed_khz=600, swd_device_path="Probe", port=3333)
        args = ["--config", "config.toml"]
        image = ["--image", "test.ihx"]
        with mock.patch.object(clion, "read_config", return_value=settings), \
             mock.patch.object(clion.subprocess, "run",
                               return_value=subprocess.CompletedProcess([], 7)) as run:
            self.assertEqual(clion.main(args + ["prepare"] + image + [
                "--root", ".", "--output", "test.debug.elf"]), 7)
            run.assert_called_once()
            self.assertEqual(run.call_args.args[0][3], "symbols")
            run.reset_mock()
            self.assertEqual(clion.main(args + ["serve", "--swd-load"] + image), 7)
            run.assert_called_once()
            self.assertEqual(run.call_args.args[0][3:], [
                "gdbserver", "--swd", "--once", "--host", "127.0.0.1", "--port", "3333",
                "--swd-speed", "600", "--device-path", "Probe", "--swd-load", "--image", "test.hex"])
            run.reset_mock()
            settings["simulation_mode"] = "usb"
            self.assertEqual(clion.main(args + ["serve", "--swd-load"] + image), 1)
            run.assert_not_called()
