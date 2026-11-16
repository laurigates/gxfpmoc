#!/usr/bin/env bash
# Build gxfpmoc on a Debian/Ubuntu host (Pop!_OS 22.04): mbedtls 3.6 into a private prefix,
# the userspace tools against it, and the kernel module against the running kernel.
# Usage: tools/laptop-build.sh   (run from the repo root on the target machine)
set -euo pipefail

prefix="${GXFP_PREFIX:-$HOME/.local/gxfp}"
mbedtls_tag="${MBEDTLS_TAG:-mbedtls-3.6.7}"
src="$(cd "$(dirname "$0")/.." && pwd)"
work="${GXFP_WORK:-$HOME/.cache/gxfp-build}"

# Build dependencies; idempotent.
sudo -n apt-get install -y --no-install-recommends \
  build-essential cmake git python3-jsonschema python3-jinja2 \
  "linux-headers-$(uname -r)" >/dev/null

# mbedtls 3.6 LTS (the distro ships 2.28, whose API differs).
if [ ! -f "$prefix/lib/cmake/MbedTLS/MbedTLSConfig.cmake" ]; then
  mkdir -p "$work"
  rm -rf "$work/mbedtls"
  git clone -q --depth 1 --branch "$mbedtls_tag" --recurse-submodules --shallow-submodules \
    https://github.com/Mbed-TLS/mbedtls.git "$work/mbedtls"
  cmake -S "$work/mbedtls" -B "$work/mbedtls/build" -DCMAKE_INSTALL_PREFIX="$prefix" \
    -DENABLE_TESTING=OFF -DENABLE_PROGRAMS=OFF -DUSE_SHARED_MBEDTLS_LIBRARY=ON \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON >/dev/null
  cmake --build "$work/mbedtls/build" -j"$(nproc)" >/dev/null
  cmake --install "$work/mbedtls/build" >/dev/null
fi

# Userspace library and tools.
cmake -S "$src" -B "$src/build" -DCMAKE_PREFIX_PATH="$prefix" \
  -DCMAKE_BUILD_RPATH="$prefix/lib" >/dev/null
cmake --build "$src/build" -j"$(nproc)"

# Kernel module against the running kernel.
make -C "$src/kernel"

ls -l "$src/build"/gxfp_* "$src/kernel"/*.ko
