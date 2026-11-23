"""Test an extracted Windows release without the build environment or a target board."""

import argparse
import os
from pathlib import Path
import queue
import subprocess
import tempfile
import threading
import zipfile


def smoke(archive: Path) -> None:
    system = Path(os.environ["SystemRoot"])
    env = {key: value for key, value in os.environ.items()
           if not key.upper().startswith(("PYTHON", "UV_", "CONDA", "VIRTUAL_ENV"))}
    env["PATH"] = os.pathsep.join((str(system / "System32"), str(system)))
    # Invalid host settings must not affect the bundled interpreters.
    env["PYTHONHOME"] = r"Z:\unavailable\python"
    env["PYTHONPATH"] = r"Z:\unavailable\packages"

    with tempfile.TemporaryDirectory(prefix="STCForge \u4fbf\u643a ") as folder:
        work = Path(folder)
        extracted = work / "Release"
        with zipfile.ZipFile(archive) as bundle:
            bundle.extractall(extracted)
        root, = extracted.iterdir()
        bin_dir = root / "bin"

        def check(executable: str, *args: str) -> str:
            result = subprocess.run(
                [str(bin_dir / executable), *args], cwd=work, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                encoding="utf-8", errors="replace", timeout=20,
            )
            if result.returncode:
                raise RuntimeError(f"{executable} {args} failed:\n{result.stdout}")
            return result.stdout

        check("python.exe", "-c",
              "import pathlib, sys, hid, serial, pyocd, stcforge;"
              " root = pathlib.Path(sys.executable).parent.parent;"
              " assert sys.flags.isolated and all(pathlib.Path(p).is_relative_to(root) for p in sys.path);"
              " assert all(pathlib.Path(p.__file__).is_relative_to(root)"
              " for p in (hid, serial, pyocd, stcforge))")
        check("stcforge.exe", "--help")
        gdb_check = check("stc-gdb.exe", "-nx", "-q", "--batch",
                          "-ex", "set architecture mcs251",
                          "-ex", "python import gdb; print('GDB Python', gdb.VERSION)",
                          "-ex", "info pretty-printer")
        if "GDB Python 16.3" not in gdb_check:
            raise RuntimeError(gdb_check)

        image = work / "sample firmware.hex"
        image.write_text(":0200000400FFFB\n:03000000000000FD\n:00000001FF\n", encoding="ascii")
        image.with_suffix(".cdb").write_text(
            "M:main\nF:G$main$0_0$0({3}DF,SV:S),C,0,0,0,0,0\n"
            "L:G$main$0$0:FF0000\nL:XG$main$0$0:FF0002\n"
            "L:C$main.c$1$0_0$1:FF0000\n", encoding="ascii",
        )
        (work / "main.c").write_text("void main(void) {}\n", encoding="ascii")
        config = work / "debug.toml"
        config.write_text('[stcforge]\nmodel="STC32G144K246"\nsimulation_mode="usb"\n'
                          'port=3333\nwarmup_ms=3000\n', encoding="ascii")
        elf = image.with_suffix(".debug.elf")
        isp_config = work / "\u4e0b\u8f7d\u9009\u9879.toml"
        isp_config.write_text('model="STC32G144K246"\nif="usb"\n', encoding="ascii")
        check("stc-isp.exe", "--config", str(isp_config), "--image", str(image), "--dry-run")
        check("stcforge.exe", "clion", "--config", str(config), "prepare",
              "--image", str(image), "--output", str(elf), "--root", str(work))
        with elf.open("rb") as stream:
            if stream.read(4) != b"\x7fELF":
                raise RuntimeError("CLion prepare did not produce an ELF.")

        with subprocess.Popen(
            [str(bin_dir / "stcforge.exe"), "gdbserver", "--mock", "--once", "--port", "0"],
            cwd=work, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8",
        ) as server:
            lines: queue.Queue[str | None] = queue.Queue()

            def collect() -> None:
                for line in server.stdout:
                    lines.put(line)
                lines.put(None)

            reader = threading.Thread(target=collect, daemon=True)
            reader.start()
            try:
                startup = []
                while (line := lines.get(timeout=15)) is not None:
                    if line.startswith("STCForge GDB server: "):
                        endpoint = line.partition(": ")[2].strip()
                        break
                    startup.append(line)
                else:
                    raise RuntimeError("Could not start release server:\n" + "".join(startup))
                output = check("stc-gdb.exe", "-nx", "-q", "--batch",
                               "-ex", "set architecture mcs251", "-ex", f"target remote {endpoint}",
                               "-ex", "stepi", "-ex", "print/x $pc", "-ex", "detach")
                if "0xff0001" not in output or server.wait(timeout=5):
                    raise RuntimeError("Debugger did not finish a mock step:\n" + output)
            finally:
                if server.poll() is None:
                    server.kill()
                    server.wait(timeout=5)
                reader.join(timeout=2)
    print("PASS: bundled dependencies, ISP dry-run, CLion symbols, GDB Python, mock step.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    smoke(parser.parse_args().archive)
