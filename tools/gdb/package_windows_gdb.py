"""打包可搬移的 Windows GDB、CPython 运行库及 GDB Python 模块。"""
import argparse
from pathlib import Path
import re
import shutil
import zipfile


def package(sdk: Path, source: Path, executable: Path, output: Path):
    header = (sdk / 'include/patchlevel.h').read_text()
    major = re.search(r'#define PY_MAJOR_VERSION\s+(\d+)', header)[1]
    minor = re.search(r'#define PY_MINOR_VERSION\s+(\d+)', header)[1]
    version = f'{major}{minor}'
    if (major, minor) != ('3', '12'):
        raise ValueError('当前验证的嵌入运行库为 CPython 3.12，请使用 uv 的完整 3.12 SDK')
    output.mkdir(parents=True, exist_ok=True)
    shutil.copy2(executable, output / 'stc-gdb.exe')
    for name in (f'python{version}.dll', 'python3.dll',
                 'vcruntime140.dll', 'vcruntime140_1.dll'):
        shutil.copy2(sdk / name, output / name)
    dlls = output / 'DLLs'
    dlls.mkdir(exist_ok=True)
    for path in sorted((sdk / 'DLLs').iterdir()):
        if path.name.startswith(('_test', '_ctypes_test', '_tkinter', 'tcl', 'tk')):
            continue
        if path.suffix.lower() in ('.pyd', '.dll'):
            shutil.copy2(path, dlls / path.name)
    excluded = {'site-packages', '__pycache__', 'test', 'tests', 'idlelib',
                'tkinter', 'turtledemo', 'ensurepip'}
    with zipfile.ZipFile(output / f'python{version}.zip', 'w',
                         compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted((sdk / 'Lib').rglob('*')):
            relative = path.relative_to(sdk / 'Lib')
            if (path.is_file() and not excluded.intersection(relative.parts)
                    and path.suffix not in ('.pyc', '.pyo')):
                archive.write(path, relative.as_posix())
    # 既不搜索开发机 Python，也不加载用户 site-packages。
    (output / f'python{version}._pth').write_text(
        f'python{version}.zip\nDLLs\n.\n', encoding='utf-8')
    python_modules = output / 'share/gdb/python'
    python_modules.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source / 'gdb/python/lib/gdb', python_modules / 'gdb',
                    dirs_exist_ok=True, ignore=shutil.ignore_patterns('__pycache__'))
    licenses = output / 'licenses'
    licenses.mkdir(exist_ok=True)
    shutil.copy2(sdk / 'LICENSE.txt', licenses / 'Python.txt')
    shutil.copy2(source / 'COPYING3', licenses / 'GDB.txt')
    print(f'Windows GDB + CPython 3.12: {output}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--executable', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    package(args.sdk.resolve(), args.source.resolve(), args.executable.resolve(),
            args.output.resolve())
