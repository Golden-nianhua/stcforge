"""向固定的 GDB 16.3 源码应用 STCForge 架构覆盖层。重复执行安全。"""
import argparse
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[2]

def replace(root, file, old, new):
    path = root / file
    text = path.read_text(encoding="utf-8")
    if new in text:
        return
    if text.count(old) != 1:
        raise RuntimeError(f"源码锚点不匹配: {file}: {old!r}")
    path.write_text(text.replace(old, new), encoding="utf-8", newline="\n")

def prepare(root):
    if '16.3' not in (root / 'gdb/version.in').read_text():
        raise RuntimeError("仅支持固定版本 GDB 16.3")
    # 自定义 GDB 面向 CLion 的 MI 会话：默认允许运行期间处理 interrupt。
    # 上游默认同步 MI，continue 后不会处理 MI interrupt，直到目标自己停止。
    # 保留 set mi-async off 开关，命令行 CLI 的同步执行行为不受此默认值影响。
    replace(root, 'gdb/mi/mi-main.c', 'static bool mi_async = false;',
            'static bool mi_async = true;')
    replace(root, 'gdb/mi/mi-main.c', 'static bool mi_async_1 = false;',
            'static bool mi_async_1 = true;')
    replace(root, 'config.sub', '| moxie \\\n', '| mcs251 \\\n\t\t\t| moxie \\\n')
    replace(root, 'bfd/archures.c', '.  bfd_arch_moxie,', '.  bfd_arch_mcs251,\n.  bfd_arch_moxie,')
    replace(root, 'bfd/bfd-in2.h', '  bfd_arch_moxie,', '  bfd_arch_mcs251,\n  bfd_arch_moxie,')
    replace(root, 'bfd/archures.c', 'extern const bfd_arch_info_type bfd_moxie_arch;',
            'extern const bfd_arch_info_type bfd_mcs251_arch;\nextern const bfd_arch_info_type bfd_moxie_arch;')
    replace(root, 'bfd/archures.c', '    &bfd_moxie_arch,', '    &bfd_mcs251_arch,\n    &bfd_moxie_arch,')
    for file in ('bfd/Makefile.am', 'bfd/Makefile.in'):
        for suffix in ('lo', 'c'):
            old = f'\tcpu-moxie.{suffix} \\\n'
            replace(root, file, old, f'\tcpu-mcs251.{suffix} \\\n' + old)
    replace(root, 'bfd/config.bfd', '  moxie-*-elf |',
            '  mcs251-*-*)\n    targ_defvec=elf32_be_vec\n    ;;\n\n  moxie-*-elf |')
    replace(root, 'gdb/configure.tgt', 'moxie-*-elf |',
            'mcs251-*-*)\n\tgdb_target_obs="mcs251-tdep.o"\n\t;;\n\nmoxie-*-elf |')
    replace(root, 'gdb/Makefile.in', '\tmoxie-tdep.o \\\n', '\tmcs251-tdep.o \\\n\tmoxie-tdep.o \\\n')
    # Windows 分发保留 stc-gdb.exe 路径，数据目录随 EXE 放置。
    # GNU 路径重定位会把同级 bindir 的末尾组件算作一次上跳，显式优先寻找随包目录。
    # 后续命令行 --data-directory 仍可覆盖此默认值。
    datadir = ('  gdb_datadir = relocate_gdb_directory (GDB_DATADIR,\n'
               '\t\t\t\t\tGDB_DATADIR_RELOCATABLE);')
    replace(root, 'gdb/main.c', datadir, datadir + '''

#ifdef __MINGW32__
  /* STCForge ships its Python modules beside the Windows executable.  */
  {
    std::string bundled_datadir = ldirname (gdb_program_name) + "/share/gdb";
    struct stat bundled_stat;
    if (stat (bundled_datadir.c_str (), &bundled_stat) == 0
        && S_ISDIR (bundled_stat.st_mode))
      gdb_datadir = relocate_gdb_directory (bundled_datadir.c_str (), false);
  }
#endif''')
    replace(root, 'gdb/python/python.c',
            '      gdbpy_ref<> pythondir (PyUnicode_FromString (gdb_pythondir.c_str ()));',
            '''#ifdef _WIN32
      /* The narrow Windows entry point returns paths in the active code page.  */
      gdbpy_ref<> pythondir (PyUnicode_DecodeMBCS (gdb_pythondir.c_str (),
\t\t\t\t\t\t gdb_pythondir.size (), nullptr));
#else
      gdbpy_ref<> pythondir (PyUnicode_FromString (gdb_pythondir.c_str ()));
#endif''')
    for file in ('opcodes/configure.ac', 'opcodes/configure'):
        replace(root, file, '\tbfd_moxie_arch)', '\tbfd_mcs251_arch) ;; # STCForge decoder lives in GDB tdep.\n\tbfd_moxie_arch)')
    shutil.copyfile(ROOT / 'src/native/gdb/cpu-mcs251.c', root / 'bfd/cpu-mcs251.c')
    shutil.copyfile(ROOT / 'src/native/gdb/mcs251-tdep.c', root / 'gdb/mcs251-tdep.c')
    print(f'MCS-251 overlay prepared: {root}')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    prepare(parser.parse_args().source.resolve())
