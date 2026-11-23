#!/usr/bin/env bash
# Linux/WSL 原生构建。Windows 交叉构建见 docs/build.md。
set -euo pipefail
src=$(realpath "${1:?GDB source directory}")
out=$(realpath -m "${2:?build directory}")
mkdir -p "$out"
cd "$out"
"$src/configure" --target=mcs251-none-elf --disable-binutils --disable-gas \
  --disable-ld --disable-gprof --disable-sim --disable-gdbserver --disable-nls \
  --without-python --without-guile --without-debuginfod --without-intel-pt \
  --with-expat --with-gdb-datadir="$out/share/gdb" CFLAGS='-O2 -g0 -std=gnu17' CXXFLAGS='-O2 -g0'
make -j"${STCFORGE_JOBS:-4}" all-gdb
