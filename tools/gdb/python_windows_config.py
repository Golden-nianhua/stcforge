#!/usr/bin/env python3
"""给 GDB 的交叉编译配置提供 Windows CPython SDK 信息。"""
import os
from pathlib import Path
import sys


def main():
    sdk = Path(os.environ['STCFORGE_PYTHON_SDK']).resolve()
    if any(character.isspace() for character in str(sdk)):
        raise SystemExit('交叉编译使用的 CPython SDK 路径不能包含空白字符')
    if not (sdk / 'include/Python.h').is_file():
        raise SystemExit(f'缺少 CPython 开发头文件: {sdk}')
    # 版本由 SDK 头文件决定，禁止误链接构建机的 Linux libpython。
    import re
    header = (sdk / 'include/patchlevel.h').read_text()
    major = re.search(r'#define PY_MAJOR_VERSION\s+(\d+)', header)[1]
    minor = re.search(r'#define PY_MINOR_VERSION\s+(\d+)', header)[1]
    if (major, minor) != ('3', '12'):
        raise SystemExit('当前 Windows 构建需要 CPython 3.12 SDK')
    library = f'python{major}{minor}.lib'
    if not (sdk / 'libs' / library).is_file():
        raise SystemExit(f'缺少 Windows CPython 导入库: {library}')
    option = sys.argv[-1]
    if option == '--includes':
        print(f'-I{sdk}/include')
    elif option == '--ldflags':
        print(f'-L{sdk}/libs -l:{library}')
    elif option == '--exec-prefix':
        # 空前缀使 GDB 不固化 SDK 安装位置；运行时由同目录的 _pth 定位。
        print('')
    else:
        raise SystemExit(f'不支持的 python-config 参数: {option}')


if __name__ == '__main__':
    main()
