#!/bin/sh
set -eu

target="${1:-}"
if [ -z "$target" ]; then
	echo "usage: $0 linux_arm64" >&2
	exit 1
fi

case "$target" in
	linux_arm64)
		triplet="aarch64-linux-gnu"
		compiler="${AARCH64_CC:-aarch64-linux-gnu-gcc}"
		;;
	*)
		echo "unsupported target: $target" >&2
		exit 1
		;;
esac

version="${LIBSECCOMP_VERSION:-2.6.0}"
repo_root="${PWD}"
sysroot_dir="${repo_root}/.goreleaser-sysroot/${target}"
pkgconfig_dir="${sysroot_dir}/lib/pkgconfig"
pkgconfig_file="${pkgconfig_dir}/libseccomp.pc"
header_file="${sysroot_dir}/include/seccomp.h"
library_file="${sysroot_dir}/lib/libseccomp.so"

if [ -f "$pkgconfig_file" ] && [ -f "$header_file" ] && [ -f "$library_file" ]; then
	exit 0
fi

build_root="${repo_root}/.goreleaser-build/libseccomp-${target}"
src_dir="${build_root}/libseccomp-${version}"
archive="${build_root}/libseccomp-${version}.tar.gz"
url="https://github.com/seccomp/libseccomp/releases/download/v${version}/libseccomp-${version}.tar.gz"

rm -rf "$build_root"
mkdir -p "$build_root" "$sysroot_dir"

curl -fsSL -o "$archive" "$url"
tar -xzf "$archive" -C "$build_root"

cd "$src_dir"
CC="$compiler" ./configure \
	--host="$triplet" \
	--prefix="$sysroot_dir" \
	--libdir="$sysroot_dir/lib" \
	--includedir="$sysroot_dir/include"

jobs="${MAKEJOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"
make -j"$jobs"
make install
