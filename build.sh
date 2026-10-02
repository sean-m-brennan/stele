#!/usr/bin/env bash
# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ******************
#
# Build Stele's native layer: the AT C core with at-stele linked in (steled) and
# libstele_shim, into $BUILD_DIR (default native/build).
#
#   ./build.sh                      # Release into native/build
#   BUILD_DIR=/tmp/stele-build ./build.sh
#   BUILD_TYPE=Debug ./build.sh
#   STELE_CLEAN=1 ./build.sh        # remove the build dir first
#
# Like Agora's, it builds with the SYSTEM toolchain: a conda environment on PATH
# is stripped for the duration (STELE_KEEP_CONDA=1 to keep it).
set -euo pipefail
cd "$(dirname "$0")"
BUILD_DIR="${BUILD_DIR:-native/build}"
BUILD_TYPE="${BUILD_TYPE:-Release}"

if [ -n "${CONDA_PREFIX:-}" ] && [ "${STELE_KEEP_CONDA:-0}" != "1" ]; then
  echo "==> conda detected; stripping it for a system-toolchain build"
  PATH="$(printf '%s' "$PATH" | tr ':' '\n' | grep -viE 'conda|miniforge|mamba' | paste -sd: -)"
  unset CC CXX CFLAGS CXXFLAGS LDFLAGS CPPFLAGS PKG_CONFIG_PATH PKG_CONFIG_LIBDIR \
        CONDA_PREFIX CMAKE_PREFIX_PATH || true
  export PATH
fi
if [ "${STELE_CLEAN:-0}" = "1" ]; then
  echo "==> STELE_CLEAN=1: removing $BUILD_DIR"
  rm -rf "$BUILD_DIR"
fi

cmake -S native -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE="$BUILD_TYPE"
cmake --build "$BUILD_DIR" --target steled stele_shim -j"$(nproc 2>/dev/null || echo 4)"
echo "==> built: $BUILD_DIR/steled, $BUILD_DIR/libstele_shim.so"
