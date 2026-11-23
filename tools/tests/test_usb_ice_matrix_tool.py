"""USB测试器的固件核对和失败退出边界；只用注入对象，不枚举设备。"""
from contextlib import redirect_stdout
import importlib.util
from io import StringIO
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("matrix_test_tool", Path(__file__).resolve().parents[2] / "tools/diagnostics/test_usb_ice_matrix.py")
TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOL)


class Journal:
    def __init__(self):
        self.rows = []

    def log(self, event, **fields):
        self.rows.append({"event": event, **fields})


class SameSessionRestoreTests(unittest.TestCase):
    def fixture(self, root):
        saved=bytes([0x02,0,0])+bytes(509)
        replacement=bytes([0x02,0,0])+bytes([0x55])*509
        baseline=root/'baseline.hex';baseline.write_text('baseline',encoding='ascii')
        image=root/'candidate.hex';image.write_text('candidate',encoding='ascii')
        (root/'code-before.bin').write_bytes(saved)
        (root/'replacement.bin').write_bytes(replacement)
        meta=dict(erase_sectors=True,base=0xff0000,size=512,
            backup_sha256=hashlib.sha256(saved).hexdigest(),
            replacement_sha256=hashlib.sha256(replacement).hexdigest(),
            candidate_hex_sha256=TOOL.digest(image),baseline=str(baseline),
            baseline_hex_sha256=TOOL.digest(baseline),restored=False)
        return saved,replacement,image,meta

    def run_restore(self, change=None, corrupt_current=False, corrupt_readback=False):
        with TemporaryDirectory() as temp:
            root=Path(temp)
            saved,replacement,image,meta=self.fixture(root)
            if change:change(meta,root)
            (root/'result.json').write_text(json.dumps(meta),encoding='utf-8')
            class Session:
                memory=bytearray(replacement)
                writes=[]
                erased=False
                def read_state(self):return SimpleNamespace(pc=0xff081a)
                def _data_exchange(self, command, payload, expected_data_length):
                    address=int.from_bytes(payload[1:5],'big')-0xff0000
                    data=bytes(self.memory[address:address+expected_data_length])
                    if corrupt_readback and self.erased and address==0:data=bytes([255])+data[1:]
                    return SimpleNamespace(data=data)
                def _event_exchange(self, command, payload):
                    self.erased=True;self.writes.append(('erase',int.from_bytes(payload,'big')))
                def write_memory(self,space,address,data):
                    self.writes.append(('write',address))
                    offset=address-0xff0000;self.memory[offset:offset+len(data)]=data
            session=Session()
            if corrupt_current:session.memory[-1]^=1
            from stcforge import symbols
            with patch.object(symbols,'read_hex',return_value={0xff0000:2}):
                try:
                    count=TOOL.restore_overlay_in_session(session,image,root,Journal())
                except Exception:
                    self.last_writes=session.writes
                    self.last_marker=(root/'same-session-restored.json').exists()
                    raise
            self.assertEqual(bytes(session.memory),saved)
            marker=json.loads((root/'same-session-restored.json').read_text())
            self.assertTrue(marker['verified']);self.assertEqual(marker['bytes'],512)
            self.assertTrue(json.loads((root/'result.json').read_text())['restored'])
            return count,session.writes

    def test_complete_backup_is_restored_and_verified(self):
        count,writes=self.run_restore()
        self.assertEqual(count,512)
        self.assertEqual(writes[0],('erase',0xff0000))

    def test_invalid_scope_or_identity_never_writes(self):
        changes=[lambda m,r:m.update(base=0xfe0000),lambda m,r:m.update(size=4097),
                 lambda m,r:m.update(erase_sectors=False),
                 lambda m,r:m.update(backup_sha256='0'*64),
                 lambda m,r:m.update(candidate_hex_sha256='0'*64),
                 lambda m,r:m.update(baseline_hex_sha256='0'*64)]
        for change in changes:
            with self.subTest(change=change),self.assertRaises(TOOL.TestFailure):
                self.run_restore(change=change)
            self.assertEqual(self.last_writes,[])
            self.assertFalse(self.last_marker)

    def test_unknown_gap_byte_refuses_erase(self):
        with self.assertRaisesRegex(TOOL.TestFailure,'完整扇区与候选不一致'):
            self.run_restore(corrupt_current=True)
        self.assertEqual(self.last_writes,[])

    def test_failed_readback_never_marks_restored(self):
        with self.assertRaisesRegex(TOOL.TestFailure,'回读不符'):
            self.run_restore(corrupt_readback=True)
        self.assertFalse(self.last_marker)


class InterruptContextTests(unittest.TestCase):
    def context(self, pc=0xFF0552, spx=0x10A, frame=bytes.fromhex('A4 FF 00 06')):
        return dict(pc=pc, spx=spx, dpx=0x7EF7A0, psw=0x80, psw1=0xA4, frame=frame,
                    registers={n: 0 for n in range(29)})

    def test_registers_are_saved_before_a_stack_read_failure(self):
        state = self.context()
        values = dict.fromkeys(range(29), 0)
        values.update({24: state['dpx'], 25: state['spx'], 26: state['psw'],
                       27: state['psw1'], 28: state['pc']})
        reply = '^done,register-values=[' + ','.join(
            f'{{number="{n}",value="0x{v:x}"}}' for n, v in values.items()) + ']'
        journal = Journal()
        def fail_read(*args):
            self.assertEqual(journal.rows[0]['event'], 'isr_registers')
            raise TOOL.TestFailure('stack read failed')
        gdb = SimpleNamespace(command=lambda command: reply, read_bytes=fail_read)
        with self.assertRaisesRegex(TOOL.TestFailure, 'stack read failed'):
            TOOL.interrupt_context(gdb, journal, 'entry')
        self.assertEqual(journal.rows[0]['spx'], 0x10A)

    def test_registers_and_stack_use_actual_edata_addresses(self):
        values = dict.fromkeys(range(29), 0)
        values.update({24: 0x7EF7A0, 25: 0x10A, 26: 0x80, 27: 0xA4, 28: 0xFF0552})
        reply = '^done,register-values=[' + ','.join(
            f'{{number="{n}",value="0x{v:x}"}}' for n, v in values.items()) + ']'
        reads = []
        def read(address, count):
            reads.append((address, count))
            return bytes(12) + bytes.fromhex('A4 FF 00 06')
        gdb = SimpleNamespace(command=lambda command: reply, read_bytes=read)
        state = TOOL.interrupt_context(gdb, Journal(), 'entry')
        self.assertEqual(reads, [(0xFB, 16)])
        self.assertEqual(state['frame'], bytes.fromhex('A4 FF 00 06'))

    def trace(self, contexts, image):
        commands = []
        gdb = SimpleNamespace(stops=[], command=lambda command, **kwargs: commands.append(command),
                              stop_event=lambda: None)
        journal = Journal()
        with patch.object(TOOL, 'interrupt_context', side_effect=contexts):
            TOOL.trace_entry_isr(gdb, journal, image)
        return journal.rows, commands

    def test_balanced_push_pop_and_four_byte_reti_return(self):
        contexts = [self.context(), self.context(pc=0xFF0554, spx=0x10B),
                    self.context(pc=0xFF0556), self.context(pc=0xFF0600, spx=0x106)]
        image = {0xFF0552: 0xC0, 0xFF0554: 0xD0, 0xFF0556: 0x32, 0xFF0600: 0}
        rows, commands = self.trace(contexts, image)
        self.assertEqual(commands, ['-exec-step-instruction'] * 3)
        self.assertEqual(rows[-1]['event'], 'isr_return_verified')
        self.assertEqual(rows[-1]['pc'], 0xFF0600)
        self.assertEqual(rows[-1]['spx'], 0x106)

    def test_wrong_return_pc_or_stack_cannot_pass(self):
        for after in (self.context(pc=0xFF0601, spx=0x106),
                      self.context(pc=0xFF0600, spx=0x108)):
            with self.subTest(after=after), self.assertRaisesRegex(TOOL.TestFailure, 'RETI前后'):
                self.trace([self.context(), after], {0xFF0552: 0x32, 0xFF0600: 0})

    def test_software_stack_must_be_balanced_before_reti(self):
        contexts = [self.context(), self.context(pc=0xFF0554, spx=0x10B),
                    self.context(pc=0xFF0600, spx=0x106)]
        with self.assertRaisesRegex(TOOL.TestFailure, 'RETI前后'):
            self.trace(contexts, {0xFF0552: 0xC0, 0xFF0554: 0x32, 0xFF0600: 0})

    def test_invalid_entry_frame_does_not_step(self):
        with self.assertRaisesRegex(TOOL.TestFailure, '入口栈'):
            self.trace([self.context(frame=bytes(4))], {0xFF0552: 0x32})

    def test_restored_pc_does_not_hide_a_corrupted_dpx_or_psw1(self):
        for register in (24, 27):
            after = self.context(pc=0xFF0600, spx=0x106)
            if register == 24:
                after['registers'][24] = 1
            else:
                after['psw1'] ^= 0x80
            with self.subTest(register=register), self.assertRaisesRegex(TOOL.TestFailure, '未恢复'):
                self.trace([self.context(), after], {0xFF0552: 0x32, 0xFF0600: 0})

    def test_no_reti_is_bounded_to_64_instructions(self):
        states = [self.context(pc=0xFF0552 + i) for i in range(65)]
        image = {state['pc']: 0 for state in states}
        image[0xFF0600] = 0
        with self.assertRaisesRegex(TOOL.TestFailure, '64条指令'):
            self.trace(states, image)


class BreakpointAddressTests(unittest.TestCase):
    def select_from_map(self, text, variant="M02_led_uart_timer"):
        with TemporaryDirectory() as temp:
            matrix = Path(temp)
            if variant.startswith("S00"):
                path = matrix / "baselines" / "S00_sdcc_original.map"
            else:
                path = matrix / variant / (variant + ".map")
            path.parent.mkdir(parents=True)
            path.write_text(text, encoding="utf-8")
            return TOOL.breakpoint_address(matrix, {"id": variant}, False)

    def test_global_candidates_keep_original_priority_over_map_order(self):
        symbols = ("_system_millis", "_millis_snapshot", "_led_toggle", "_software_delay")
        for first in range(len(symbols)):
            with self.subTest(first=symbols[first]):
                entries = [f"C:   {0xFF0100 + i:08X}  {symbols[i]}  board\n"
                           for i in reversed(range(first, len(symbols)))]
                self.assertEqual(self.select_from_map("".join(entries)), 0xFF0100 + first)

    def test_lower_priority_global_still_precedes_all_static_candidates(self):
        text = (
            "C:   00FF0451  Ftimer$system_millis$0$0  timer\n"
            "C:   00FF0211  Fmain$led_toggle$0$0  main\n"
            "C:   00FF0300  _software_delay  exported\n"
        )
        self.assertEqual(self.select_from_map(text), 0xFF0300)

    def test_static_candidates_use_function_priority_not_map_order(self):
        text = (
            "C:   00FF0211  Fmain$led_toggle$0$0  main\n"
            "C:   00FF024D  XFmain$led_toggle$0$0  main\n"
            "C:   00FF0451  Fmain$millis_snapshot$0$0  main\n"
            "C:   00FF0496  XFmain$millis_snapshot$0$0  main\n"
        )
        self.assertEqual(self.select_from_map(text), 0xFF0451)

    def test_static_entries_accept_arbitrary_module_and_compact_code_prefix(self):
        for module in ("main", "timer_7", "board.uart"):
            for function in ("system_millis", "millis_snapshot", "led_toggle", "software_delay"):
                with self.subTest(module=module, function=function):
                    text = f"  C:00ff03be  F{module}${function}$0$0"
                    self.assertEqual(self.select_from_map(text, "M01_led_uart"), 0xFF03BE)

    def test_static_end_labels_and_symbol_prefixes_are_not_entries(self):
        text = (
            "C:   00FF0496  XFmain$millis_snapshot$0$0  main\n"
            "C:   00FF024D  XFother$led_toggle$0$0  other\n"
            "C:   00FF0100  Fother$system_millis$0$0_extra  other\n"
            "C:   00FF0110  Fother$millis_snapshot_extra$0$0  other\n"
            "C:   00FF0120  Fother$led_toggle$1$0  other\n"
            "C:   00FF0130  _system_millis_extra  other\n"
            "D:   00FF0140  Fother$system_millis$0$0  other\n"
            "C:   00FF03BE  Fdelay$software_delay$0$0  delay\n"
        )
        self.assertEqual(self.select_from_map(text, "M01_led_uart"), 0xFF03BE)

    def test_watch_variables_require_data_entries_not_exported_function_names(self):
        text = (
            "C:   00FF0C00  _watch16  main\n"
            "C:   00FF0C04  _watch32  main\n"
            "D:   00000C  _watch16  main\n"
            "D:   000008  _watch32  main\n"
        )
        self.assertEqual(TOOL.map_watch_symbols(text), {"_watch16": 0x0C, "_watch32": 0x08})

    def test_only_static_end_labels_raise_instead_of_selecting_return_address(self):
        with self.assertRaises(TOOL.TestFailure):
            self.select_from_map("C:   00FF0496  XFmain$millis_snapshot$0$0  main\n")

    def test_s00_still_reads_baseline_map(self):
        self.assertEqual(self.select_from_map("C:   00FF0240  _system_millis  system\n",
                                              "S00_sdcc_original"), 0xFF0240)

    def test_keil_and_mock_keep_verified_addresses_without_reading_map(self):
        with patch.object(Path, "read_text", side_effect=AssertionError("Unexpected MAP read")):
            self.assertEqual(TOOL.breakpoint_address(Path("missing"), {"id": "K00_keil_reference"}, False),
                             0xFF0478)
            self.assertEqual(TOOL.breakpoint_address(Path("missing"), {"id": "M02_led_uart_timer"}, True),
                             0xFF0000)
            self.assertEqual(TOOL.breakpoint_address(Path("missing"), {"id": "K00_keil_reference"}, True),
                             0xFF0000)


class FirmwareSourceTests(unittest.TestCase):
    def args(self, **values):
        base = dict(matrix=Path("matrix"), variant=None, image=None, elf=None, map=None,
                    breakpoint_address=None)
        base.update(values)
        return SimpleNamespace(**base)

    def test_no_arguments_keep_k00_default(self):
        with TemporaryDirectory() as temp:
            matrix = Path(temp)
            (matrix / "manifest.json").write_text(json.dumps({"variants": [{"id": "K00_keil_reference"}]}),
                                                    encoding="utf-8")
            image = matrix / "k00.hex"
            image.write_bytes(b"hex")
            with patch.object(TOOL, "load_variant", return_value=({"id": "K00_keil_reference"}, image, None)):
                selection = TOOL.select_firmware(self.args(matrix=matrix))
        self.assertEqual(selection.row["id"], "K00_keil_reference")

    def test_variant_with_image_or_side_files_is_rejected(self):
        for overrides in ({"image": Path("firmware.hex")},
                          {"elf": Path("firmware.debug.elf")},
                          {"map": Path("firmware.map")}):
            with self.subTest(overrides=overrides), self.assertRaises(TOOL.TestFailure):
                TOOL.choose_files(self.args(variant="M02", **overrides))

    def test_elf_or_map_without_image_is_rejected(self):
        for overrides in ({"elf": Path("firmware.debug.elf")}, {"map": Path("firmware.map")}):
            with self.subTest(overrides=overrides), self.assertRaisesRegex(TOOL.TestFailure, "显式--image"):
                TOOL.choose_files(self.args(**overrides))

    def test_image_infers_same_stem_debug_elf_and_map(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            image = root / "M02_count.hex"
            elf = root / "M02_count.debug.elf"
            map_path = root / "M02_count.map"
            for path in (image, elf, map_path):
                path.write_bytes(b"x")
            selected_image, selected_elf, selected_map = TOOL.choose_files(self.args(image=image))
        self.assertEqual(selected_image, image.resolve())
        self.assertEqual(selected_elf, elf.resolve())
        self.assertEqual(selected_map, map_path.resolve())

    def test_explicit_side_files_override_inference(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            image = root / "current.hex"
            elf = root / "other.elf"
            map_path = root / "other.map"
            for path in (image, elf, map_path):
                path.write_bytes(b"x")
            self.assertEqual(TOOL.choose_files(self.args(image=image, elf=elf, map=map_path)),
                             (image.resolve(), elf.resolve(), map_path.resolve()))

    def test_custom_image_allows_missing_map_with_explicit_breakpoint(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            image = root / "current.hex"
            image.write_bytes(b"hex")
            selection = TOOL.select_firmware(self.args(image=image, breakpoint_address=0xFF0451))
            self.assertIsNone(selection.map)
            self.assertIsNone(selection.breakpoint)

    def test_explicit_missing_map_is_rejected_even_in_mock_mode(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            image = root / "current.hex"
            image.write_bytes(b"hex")
            args = self.args(image=image, map=root / "missing.map", mock=True)
            with self.assertRaisesRegex(TOOL.TestFailure, "找不到MAP文件"):
                TOOL.choose_files(args)

    def test_custom_image_allows_no_breakpoints_without_map(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            image = root / "current.hex"
            image.write_bytes(b"hex")
            args = self.args(image=image)
            args.no_breakpoints = True
            selection = TOOL.select_firmware(args)
            self.assertIsNone(selection.breakpoint)

    def test_custom_map_without_function_candidate_allows_automatic_skip(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            image = root / "current.hex"
            map_path = root / "current.map"
            image.write_bytes(b"hex")
            map_path.write_text("D:   00000C  _watch16  main\n", encoding="utf-8")
            selection = TOOL.select_firmware(self.args(image=image))
            self.assertIsNone(selection.breakpoint)
            self.assertEqual(selection.symbols, {"_watch16": 0x0C})

    def test_custom_map_uses_explicit_address_when_no_function_candidate(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            image = root / "current.hex"
            map_path = root / "current.map"
            image.write_bytes(b"hex")
            map_path.write_text("D:   00000C  _watch16  main\n", encoding="utf-8")
            selection = TOOL.select_firmware(self.args(image=image, breakpoint_address=0xFF0999))
            self.assertEqual(selection.breakpoint, 0xFF0999)

    def test_custom_explicit_breakpoint_wins_even_with_map_candidate(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            image = root / "current.hex"
            map_path = root / "current.map"
            image.write_bytes(b"hex")
            map_path.write_text("C:   00FF0451  Fmain$millis_snapshot$0$0  main\n", encoding="utf-8")
            selection = TOOL.select_firmware(self.args(image=image, breakpoint_address=0xFF0999))
            self.assertEqual(selection.breakpoint, 0xFF0999)

    def test_custom_selection_records_inputs_and_hashes(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            image = root / "M02.hex"
            elf = root / "M02.debug.elf"
            map_path = root / "M02.map"
            image.write_bytes(b"hex")
            elf.write_bytes(b"elf")
            map_path.write_text(
                "D:   00000C  _watch16  main\n"
                "D:   000008  _watch32  main\n"
                "C:   00FF0010  _main  main\n"
                "C:   00FF0451  Fmain$millis_snapshot$0$0  main\n", encoding="utf-8")
            selection = TOOL.select_firmware(self.args(image=image))
            report = selection.report()
            actual_hash = TOOL.digest(image)
        self.assertEqual(report["input"], {"hex": str(image.resolve()), "elf": str(elf.resolve()),
                                           "map": str(map_path.resolve())})
        self.assertEqual(report["symbols"], {"_watch16": "00000C", "_watch32": "000008"})
        self.assertEqual(selection.breakpoint, 0xFF0451)
        self.assertEqual(report["hex_sha256"], actual_hash)


class WorkerArgumentTests(unittest.TestCase):
    def test_worker_argv_parser_accepts_custom_file_selection(self):
        parser = TOOL.parser()
        options = parser.parse_args([
            "--worker", "--image", "M02.hex", "--elf", "M02.debug.elf",
            "--map", "M02.map", "--image-sha256", "0" * 64,
            "--elf-sha256", "1" * 64, "--map-sha256", "2" * 64, "--log-dir", "logs"])
        self.assertEqual(options.image, Path("M02.hex"))
        self.assertEqual(options.variant, None)
        self.assertIsNotNone(options.elf)
        self.assertIsNotNone(options.map)
        self.assertEqual(options.elf_sha256, "1" * 64)
        self.assertEqual(options.map_sha256, "2" * 64)

    def test_worker_command_passes_same_image_elf_map_and_hash(self):
        selection = SimpleNamespace(
            image=Path("D:/firmware/M02.hex"), elf=Path("D:/firmware/M02.debug.elf"),
            map=Path("D:/firmware/M02.map"),
            hashes={"hex": "a" * 64, "elf": "b" * 64, "map": "c" * 64})
        args = SimpleNamespace(matrix=Path("D:/matrix"), mock=False, device_path="hid-1")
        command = TOOL.worker_command(args, selection, Path("D:/logs"))
        self.assertEqual(command[command.index("--image") + 1], str(selection.image))
        self.assertEqual(command[command.index("--image-sha256") + 1], "a" * 64)
        self.assertEqual(command[command.index("--elf") + 1], str(selection.elf))
        self.assertEqual(command[command.index("--elf-sha256") + 1], "b" * 64)
        self.assertEqual(command[command.index("--map") + 1], str(selection.map))
        self.assertEqual(command[command.index("--map-sha256") + 1], "c" * 64)
        self.assertNotIn("--variant", command)

    def test_worker_command_keeps_matrix_provenance_separate(self):
        selection = SimpleNamespace(image=Path("D:/matrix/K00.hex"), elf=Path("D:/matrix/K00.elf"),
                                    map=None, hashes={"hex": "b" * 64, "elf": "c" * 64})
        args = SimpleNamespace(matrix=Path("D:/matrix"), mock=True, device_path=None)
        command = TOOL.worker_command(args, selection, Path("D:/logs"))
        self.assertIn("--mock", command)
        self.assertNotIn("--variant", command)
        self.assertNotIn("--map", command)

    def test_worker_uses_the_parent_selected_image_and_hash(self):
        from stcforge import ice, server, symbols, transport
        with TemporaryDirectory() as temp:
            root = Path(temp)
            image = root / "M02.hex"
            elf = root / "M02.debug.elf"
            map_path = root / "M02.map"
            image.write_bytes(b"hex")
            elf.write_bytes(b"elf")
            map_path.write_text("C:   00FF0451  Fmain$millis_snapshot$0$0  main\n", encoding="utf-8")
            seen = []

            class DummyTransport:
                def __init__(self, path):
                    pass

                def open(self):
                    pass

                def close(self):
                    pass

            class DummySession:
                def __init__(self, wrapped):
                    self.transport = wrapped

                def initialize_debug(self):
                    return "V4.0", SimpleNamespace(pc=0xFF0000)

                def _data_exchange(self, command, payload, expected_data_length):
                    return SimpleNamespace(data=b"\x02\0\x1F")

            def serve(target, **kwargs):
                seen.append(True)
                target.close()

            args = SimpleNamespace(log_dir=root, mock=False, matrix=root, variant=None, image=image,
                                   elf=elf, map=map_path, device_path=None, no_breakpoints=False,
                                   breakpoint_address=None,
                                   image_sha256=TOOL.digest(image), elf_sha256=TOOL.digest(elf),
                                   map_sha256=TOOL.digest(map_path))
            with patch.object(symbols, "read_hex",
                              side_effect=lambda path: seen.append(("hex", Path(path).resolve())) or {0xFF0000: 2, 0xFF0001: 0, 0xFF0002: 0x1F}), \
                 patch.object(transport, "HidTransport", DummyTransport), \
                 patch.object(ice, "IceSession", DummySession), \
                 patch.object(server, "serve", side_effect=serve), redirect_stdout(StringIO()):
                code = TOOL.worker(args)
            events = [json.loads(line) for line in (root / "usb.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual(code, 0)
        self.assertIn(("hex", image.resolve()), seen)
        self.assertIn("preflight_verified", [event["event"] for event in events])

    def test_worker_refuses_changed_hash_before_opening_usb(self):
        from stcforge import symbols, transport
        with TemporaryDirectory() as temp:
            root = Path(temp)
            image = root / "M02.hex"
            image.write_bytes(b"hex")
            args = SimpleNamespace(log_dir=root, mock=False, matrix=root, variant=None, image=image,
                                   elf=None, map=None, device_path=None, image_sha256="0" * 64)
            with patch.object(transport, "HidTransport", side_effect=AssertionError("USB opened")), \
                 patch.object(symbols, "read_hex", side_effect=AssertionError("HEX read")), \
                 redirect_stdout(StringIO()):
                code = TOOL.worker(args)
        self.assertEqual(code, 1)

    def worker_with_changed_side_file(self, field, filename, hash_field):
        from stcforge import symbols, transport
        with TemporaryDirectory() as temp:
            root = Path(temp)
            image = root / "M02.hex"
            side = root / filename
            image.write_bytes(b"hex")
            side.write_bytes(b"side")
            values = dict(log_dir=root, mock=False, matrix=root, variant=None, image=image,
                          elf=None, map=None, device_path=None, image_sha256=TOOL.digest(image),
                          elf_sha256=None, map_sha256=None)
            values[field] = side
            values[hash_field] = "0" * 64
            opened, read = [], []

            def forbid_open(*args, **kwargs):
                opened.append(True)
                raise AssertionError("USB opened")

            def forbid_read(*args, **kwargs):
                read.append(True)
                raise AssertionError("HEX read")

            with patch.object(transport, "HidTransport", side_effect=forbid_open), \
                 patch.object(symbols, "read_hex", side_effect=forbid_read), \
                 redirect_stdout(StringIO()):
                code = TOOL.worker(SimpleNamespace(**values))
            events = [json.loads(line) for line in (root / "usb.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual(code, 1)
        self.assertFalse(opened)
        self.assertFalse(read)
        self.assertEqual(events[-1]["event"], "worker_failed")
        self.assertIn("摘要不一致", events[-1]["error"])

    def test_worker_refuses_changed_elf_hash_before_reading_hex_or_opening_usb(self):
        self.worker_with_changed_side_file("elf", "M02.debug.elf", "elf_sha256")

    def test_worker_refuses_changed_map_hash_before_reading_hex_or_opening_usb(self):
        self.worker_with_changed_side_file("map", "M02.map", "map_sha256")


class RunPcTests(unittest.TestCase):
    def test_reset_entry_cannot_count_as_successful_application_run(self):
        with self.assertRaisesRegex(TOOL.TestFailure, '复位入口'):
            TOOL.validate_run_pc(0xFF0000, {0xFF0000: 0x02})

    def test_pc_in_hex_hole_is_rejected(self):
        with self.assertRaisesRegex(TOOL.TestFailure, '已定义代码'):
            TOOL.validate_run_pc(0xFF0004, {0xFF0000: 0x02, 0xFF001F: 0x8A})

    def test_known_m02_pause_address_is_accepted(self):
        TOOL.validate_run_pc(0xFF046D, {0xFF046D: 0x7C})


class MatrixToolTests(unittest.TestCase):
    def test_native_read_uses_real_session_codec_without_space5_public_api(self):
        from stcforge.ice import IceSession
        from stcforge.transport import TransportTimeout
        payload = b"\x02\0\x1F"

        class Wire:
            def __init__(self):
                self.sent = []
                self.reply = None

            def write_report(self, report, **kwargs):
                self.sent.append(report)
                content = b"\x02" + payload
                self.reply = (bytes((len(payload) + 2,)) + content + bytes((-sum(content) & 255,))).ljust(64, b"\0")

            def read_report(self, timeout_ms):
                if self.reply is None:
                    raise TransportTimeout("empty")
                reply, self.reply = self.reply, None
                return reply

        wire = Wire()
        TOOL.native_verify(IceSession(wire), {0xFF0000 + i: value for i, value in enumerate(payload)}, Journal(), "before")
        self.assertEqual(len(wire.sent), 1)
        self.assertEqual(wire.sent[0][:11].hex(), "ff5a08040500ff00000394")

    def test_code_verification_reads_actual_space5_and_preserves_holes(self):
        image = {0xFF0000 + i: i & 255 for i in range(110)}
        image[0xFF0100] = 0xAA
        reads = []

        def read(command, payload, expected_data_length):
            self.assertEqual(command, 4)
            space, address, count = payload[0], int.from_bytes(payload[1:5], "big"), payload[5]
            self.assertEqual(count, expected_data_length)
            reads.append((space, address, count))
            return SimpleNamespace(data=bytes(image[address + i] for i in range(count)))

        journal = Journal()
        TOOL.native_verify(SimpleNamespace(_data_exchange=read), image, journal, "before")
        self.assertEqual(reads, [(5, 0xFF0000, 48), (5, 0xFF0030, 48), (5, 0xFF0060, 14), (5, 0xFF0100, 1)])
        self.assertEqual(journal.rows[-1]["bytes"], 111)

    def run_worker_with_reads(self, replies):
        from stcforge import ice, server, symbols, transport
        image = {0xFF0000: 2, 0xFF0001: 0, 0xFF0002: 0x1F}
        payload = bytes(image.values())
        received = iter(payload if value == "good" else b"\xB9\0\x1F" for value in replies)
        calls = []
        closed = []

        class DummyTransport:
            def __init__(self, path):
                pass

            def open(self):
                pass

            def close(self):
                closed.append(True)

        class DummySession:
            def __init__(self, wrapped):
                self.transport = wrapped

            def initialize_debug(self):
                return "V4.0", SimpleNamespace(pc=0xFF0000)

            def _data_exchange(self, command, payload, expected_data_length):
                return SimpleNamespace(data=next(received))

        def serve(target, **kwargs):
            calls.append(True)
            target.close()

        with TemporaryDirectory() as temp:
            image_path = Path(temp) / "sample.hex"
            image_path.write_bytes(b"hex")
            args = SimpleNamespace(log_dir=Path(temp), mock=False, matrix=Path(temp), variant=None,
                                   image=image_path, elf=None, map=None, device_path=None,
                                   image_sha256=TOOL.digest(image_path))
            with patch.object(TOOL, "select_firmware", return_value=SimpleNamespace(
                     row={}, image=image_path, elf=None, map=None, hashes={"hex": "0" * 64})), \
                 patch.object(symbols, "read_hex", return_value=image), \
                 patch.object(transport, "HidTransport", DummyTransport), \
                 patch.object(ice, "IceSession", DummySession), \
                 patch.object(server, "serve", side_effect=serve), \
                 redirect_stdout(StringIO()):
                code = TOOL.worker(args)
            rows = [json.loads(line) for line in (Path(temp) / "usb.jsonl").read_text(encoding="utf-8").splitlines()]
        return code, rows, calls, closed

    def test_image_mismatch_refuses_to_start_gdb_server(self):
        code, rows, calls, closed = self.run_worker_with_reads(["bad"])
        self.assertEqual(code, 1)
        self.assertFalse(calls)
        self.assertTrue(closed)
        self.assertIn("image_mismatch", [row["event"] for row in rows])

    def test_cleanup_mismatch_cannot_be_reported_as_success(self):
        code, rows, calls, closed = self.run_worker_with_reads(["good", "bad"])
        self.assertEqual(code, 1)
        self.assertTrue(calls)
        self.assertTrue(closed)
        events = [row["event"] for row in rows]
        self.assertIn("cleanup_failed", events)
        self.assertNotIn("worker_complete", events)
        self.assertNotIn("cleanup_verified", events)

    def test_success_requires_preflight_and_cleanup_reads(self):
        code, rows, calls, closed = self.run_worker_with_reads(["good", "good"])
        self.assertEqual(code, 0)
        self.assertTrue(calls)
        self.assertTrue(closed)
        events = [row["event"] for row in rows]
        self.assertIn("preflight_verified", events)
        self.assertIn("cleanup_verified", events)
        self.assertIn("worker_complete", events)

    def test_pc_accepts_decimal_and_hex_mi_values(self):
        mi = object.__new__(TOOL.MI)
        for value in ("16711680", "0xff0000"):
            mi.command = lambda command: '1^done,value="' + value + '"'
            self.assertEqual(mi.pc(), 0xFF0000)


if __name__ == "__main__":
    unittest.main()
