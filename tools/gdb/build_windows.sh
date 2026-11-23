#!/usr/bin/env bash
# 在 WSL/Linux 中生成可直接在 Windows 运行的 stc-gdb.exe。
# 源码和构建目录保留供复现；MinGW 静态链接，CPython 随目录分发。
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
work=${1:-"$HOME/stcforge-build/windows"}
jobs=${STCFORGE_JOBS:-4}
export STCFORGE_PYTHON_SDK=${STCFORGE_PYTHON_SDK:?请设置 uv 管理的 Windows CPython 3.12 SDK 的 WSL 路径}
package_out=${STCFORGE_PACKAGE_OUT:-"$root/.cache/build/gdb-windows"}
chmod +x "$root/tools/gdb/python_windows_config.py"
mkdir -p "$work/sources" "$work/prefix" "$root/.cache" "$package_out"
work=$(realpath "$work")
prefix="$work/prefix"
python3 "$root/tools/gdb/fetch_gdb.py"
fetch_extract() {
  local url=$1 archive=$2 folder=$3
  if [ ! -f "$root/.cache/$archive" ]; then
    curl --fail --location --retry 2 "$url" -o "$root/.cache/$archive"
  fi
  local expected
  expected=$(awk -v name="$archive" '$2 == name { print $1 }' "$root/tools/gdb/source-checksums.sha256")
  test -n "$expected"
  printf '%s  %s\n' "$expected" "$root/.cache/$archive" | sha256sum -c -
  if [ ! -d "$work/sources/$folder" ]; then
    tar -xf "$root/.cache/$archive" -C "$work/sources"
  fi
}
fetch_extract https://ftp.gnu.org/gnu/gmp/gmp-6.3.0.tar.xz gmp-6.3.0.tar.xz gmp-6.3.0
fetch_extract https://ftp.gnu.org/gnu/mpfr/mpfr-4.2.2.tar.xz mpfr-4.2.2.tar.xz mpfr-4.2.2
fetch_extract https://github.com/libexpat/libexpat/releases/download/R_2_7_3/expat-2.7.3.tar.xz expat-2.7.3.tar.xz expat-2.7.3
fetch_extract https://ftp.gnu.org/gnu/libiconv/libiconv-1.18.tar.gz libiconv-1.18.tar.gz libiconv-1.18
export CC=x86_64-w64-mingw32-gcc-posix
export CXX=x86_64-w64-mingw32-g++-posix
export CC_FOR_BUILD=gcc
export CXX_FOR_BUILD=g++
for pkg in gmp-6.3.0 mpfr-4.2.2 expat-2.7.3 libiconv-1.18; do
  mkdir -p "$work/$pkg"
  cd "$work/$pkg"
  if [ ! -f .stcforge-installed ]; then
    extra=()
    case "$pkg" in
      gmp-*) extra=(--disable-assembly);;
      mpfr-*) extra=(--with-gmp="$prefix");;
      expat-*) extra=(--without-docbook --without-xmlwf --without-tests --without-examples);;
    esac
    "$work/sources/$pkg/configure" --build="$(gcc -dumpmachine)" --host=x86_64-w64-mingw32 --prefix="$prefix" \
      --disable-shared --enable-static "${extra[@]}"
    make -j"$jobs"
    make install
    touch .stcforge-installed
  fi
done
if [ ! -d "$work/sources/gdb-16.3" ]; then
  tar -xf "$root/.cache/gdb-16.3.tar.xz" -C "$work/sources"
fi
python3 "$root/tools/gdb/prepare_gdb.py" "$work/sources/gdb-16.3"
mkdir -p "$work/gdb"
cd "$work/gdb"
"$work/sources/gdb-16.3/configure" --build="$(gcc -dumpmachine)" --host=x86_64-w64-mingw32 --target=mcs251-none-elf \
  --disable-binutils --disable-gas --disable-ld --disable-gprof --disable-sim \
  --disable-gdbserver --disable-nls --with-python="$root/tools/gdb/python_windows_config.py" --without-python-libdir --without-guile \
  --prefix=/stcforge --bindir=/stcforge --with-gdb-datadir=/stcforge/share/gdb \
  --without-debuginfod --without-intel-pt --without-lzma --without-zstd \
  --with-gmp="$prefix" --with-mpfr="$prefix" --with-libexpat-prefix="$prefix" \
  --with-libiconv-prefix="$prefix" \
  --with-expat --with-static-standard-libraries --disable-source-highlight \
  CFLAGS='-O2 -g0 -std=gnu17' CXXFLAGS='-O2 -g0' LDFLAGS='-static'
make -j"$jobs" all-gdb
# Libtool 的 -static 仅约束 libtool 库，-all-static 才能确保线程运行库静态链接。
make -C gdb -W mcs251-tdep.o gdb.exe \
  LDFLAGS='-all-static -static-libstdc++ -static-libgcc -Wl,--stack,12582912'
x86_64-w64-mingw32-strip gdb/gdb.exe -o "$work/stc-gdb.exe"
python3 "$root/tools/gdb/package_windows_gdb.py" \
  --sdk "$STCFORGE_PYTHON_SDK" --source "$work/sources/gdb-16.3" \
  --executable "$work/stc-gdb.exe" --output "$package_out"
