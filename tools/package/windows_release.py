"""Assemble the Windows x64 release using the GDB bundle and locked Python dependencies."""

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib
import zipfile


ROOT = Path(__file__).resolve().parents[2]
GDB_FILES = (
    "stc-gdb.exe", "python3.dll", "python312.dll", "python312.zip",
    "vcruntime140.dll", "vcruntime140_1.dll",
)
GDB_DIRS = ("DLLs", "share/gdb", "licenses")


def sha256(path: Path) -> bytes:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").digest()


def package(args: argparse.Namespace) -> Path:
    if os.name != "nt":
        raise ValueError("Build the release on Windows x64.")
    python = args.sdk / "python.exe"
    if not python.is_file() or sha256(args.sdk / "python312.dll") != sha256(args.gdb / "python312.dll"):
        raise ValueError("--sdk must match the Python runtime in --gdb.")
    subprocess.run(
        [str(python), "-I", "-c",
         "import sys, sysconfig; assert sysconfig.get_platform() == 'win-amd64'"
         " and sys.version_info[:2] == (3, 12) and sys.prefix == sys.base_prefix"],
        check=True,
    )

    with (ROOT / "pyproject.toml").open("rb") as stream:
        version = tomllib.load(stream)["project"]["version"]
    name = f"stcforge-{version}-windows-x64"
    archive = args.output / f"{name}.zip"
    if archive.exists() and not args.replace:
        raise FileExistsError(f"{archive} exists; use --replace to rebuild it.")
    args.output.mkdir(parents=True, exist_ok=True)
    temp_base = ROOT / ".cache/build"
    temp_base.mkdir(parents=True, exist_ok=True)

    uv = [str(args.uv)]
    offline = ["--offline"] if args.offline else []
    ignore_cache = shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo")
    with tempfile.TemporaryDirectory(prefix="windows-release-", dir=temp_base) as folder:
        work = Path(folder)
        bundle = work / name
        bin_dir = bundle / "bin"
        bin_dir.mkdir(parents=True)
        shutil.copy2(args.isp, bin_dir / "stc-isp.exe")
        shutil.copy2(args.launcher, bin_dir / "stcforge.exe")
        shutil.copy2(python, bin_dir / "python.exe")
        for filename in GDB_FILES:
            shutil.copy2(args.gdb / filename, bin_dir / filename)
        for dirname in GDB_DIRS:
            shutil.copytree(args.gdb / dirname, bin_dir / dirname, ignore=ignore_cache)
        (bin_dir / "python312._pth").write_text(
            "python312.zip\nDLLs\n../lib/python\n", encoding="ascii"
        )

        requirements = work / "requirements.txt"
        subprocess.run(
            uv + ["export", "--locked", "--no-header", "--no-emit-project",
                  "--extra", "usb", "--extra", "uart", "--output-file", str(requirements)] + offline,
            cwd=ROOT, stdout=subprocess.DEVNULL, check=True,
        )
        installed = work / "installed"
        subprocess.run(
            uv + ["pip", "install", "--python", str(python), "--target", str(installed),
                  "--require-hashes", "--only-binary", ":all:", "--link-mode", "copy",
                  "-r", str(requirements)] + offline,
            cwd=ROOT, check=True,
        )
        lib = bundle / "lib/python"
        lib.mkdir(parents=True)
        for item in sorted(installed.iterdir()):
            # No console-script launchers with paths back to the build SDK.
            if item.name in {"bin", "Scripts", ".lock", "__pycache__"}:
                continue
            if item.is_dir():
                shutil.copytree(item, lib / item.name, ignore=ignore_cache)
            elif item.suffix not in {".pyc", ".pyo", ".pth"}:
                shutil.copy2(item, lib / item.name)
        shutil.copytree(ROOT / "src/stcforge", lib / "stcforge", ignore=ignore_cache)

        examples = bundle / "examples"
        examples.mkdir()
        for template in sorted((ROOT / "docs/examples").glob("*.toml")):
            shutil.copy2(template, examples / template.name)
        shutil.copytree(ROOT / "docs/examples/hardware-families", examples / "hardware-families")
        shutil.copy2(ROOT / "docs/windows-quickstart.md", bundle / "README.md")
        shutil.copy2(ROOT / "docs/third-party.md", bundle / "THIRD-PARTY.md")
        shutil.copy2(ROOT / "LICENSE", bundle / "LICENSE")

        with tempfile.NamedTemporaryFile(dir=args.output, suffix=".tmp", delete=False) as fp:
            pending = Path(fp.name)
        try:
            with zipfile.ZipFile(pending, "w", compression=zipfile.ZIP_DEFLATED) as output:
                for path in sorted(bundle.rglob("*")):
                    if path.is_file():
                        output.write(path, path.relative_to(work).as_posix())
            pending.replace(archive)
        finally:
            pending.unlink(missing_ok=True)
    return archive


def path(text: str) -> Path:
    return Path(text).resolve()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", required=True, type=path)
    parser.add_argument("--uv", default=Path(shutil.which("uv") or "uv"))
    parser.add_argument("--gdb", default=ROOT / ".cache/build/gdb-windows", type=path)
    parser.add_argument("--isp", default=ROOT / ".cache/build/isp/stc-isp.exe", type=path)
    parser.add_argument("--launcher", default=ROOT / ".cache/build/isp/stcforge.exe", type=path)
    parser.add_argument("--output", default=ROOT / "dist", type=path)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--replace", action="store_true")
    print(package(parser.parse_args()))
