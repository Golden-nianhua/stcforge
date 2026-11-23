"""下载并校验固定 GDB 源码；--extract 解压，随后调用 prepare_gdb.py。"""
import argparse
import hashlib
from pathlib import Path
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
SHA256 = "bcfcd095528a987917acf9fff3f1672181694926cc18d609c99d0042c00224c5"

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--extract", action="store_true")
    args = parser.parse_args()
    cache = ROOT / ".cache"
    cache.mkdir(exist_ok=True)
    archive = cache / "gdb-16.3.tar.xz"
    if not archive.exists():
        temporary = archive.with_suffix(".part")
        with urllib.request.urlopen("https://sourceware.org/pub/gdb/releases/gdb-16.3.tar.xz", timeout=60) as response:
            with temporary.open("wb") as output:
                while block := response.read(1024 * 1024): output.write(block)
        if hashlib.sha256(temporary.read_bytes()).hexdigest() != SHA256:
            raise ValueError("GDB 下载校验不匹配，保留 .part 供排查")
        temporary.replace(archive)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != SHA256:
        raise ValueError("GDB 源码归档 SHA-256 不匹配")
    if args.extract and not (cache / "gdb-16.3").exists():
        with tarfile.open(archive) as source:
            source.extractall(cache, filter="data")
    print(f"已校验：{archive}")

if __name__ == "__main__": main()
