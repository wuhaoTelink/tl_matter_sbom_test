#!/usr/bin/env bash
#
# Copyright (c) 2026 Project CHIP Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Build a single Telink Matter example with the Zephyr build system and emit an
# SPDX bill of materials for it.
#
# This must be invoked through scripts/run_in_build_env.sh so that the Matter
# (pigweed) build environment is active -- the Zephyr CMake integration for
# Matter shells out to GN/ninja/python from that environment:
#
#   ./scripts/run_in_build_env.sh \
#       "bash scripts/tools/telink/build_with_sbom.sh <board> <app-dir> <build-dir> <sbom-dir>"
#
# The SPDX generation relies on Zephyr's built-in `west spdx` command (zspdx),
# which walks the CMake file-based API codemodel. That query file has to exist
# *before* CMake configures, which is why `west spdx --init` runs first.

set -euo pipefail

BOARD="${1:?board required, e.g. tl3238x}"
APP_DIR="${2:?app source dir required, e.g. examples/lighting-app/telink}"
BUILD_DIR="${3:?build dir required, e.g. out/tl3238x-lighting}"
SBOM_DIR="${4:?sbom output dir required, e.g. out/sbom}"

: "${TELINK_ZEPHYR_BASE:?TELINK_ZEPHYR_BASE is not set -- run this inside the Telink build container}"

# Same environment wiring the Matter Telink builder uses
# (see scripts/build/builders/telink.py:get_cmd_prefixes).
export ZEPHYR_TOOLCHAIN_VARIANT=zephyr
export ZEPHYR_BASE="$TELINK_ZEPHYR_BASE"
if [[ -n "${TELINK_ZEPHYR_SDK_DIR:-}" ]]; then
    export ZEPHYR_SDK_INSTALL_DIR="$TELINK_ZEPHYR_SDK_DIR"
fi

# shellcheck disable=SC1091
source "$ZEPHYR_BASE/zephyr-env.sh"

# --- Reproducible builds -----------------------------------------------------
#
# Two builds of the same commit currently produce different hashes for five
# artifacts -- libapp.a, libzephyr.a, libopenthread-ftd.a, zephyr.elf and
# zephyr_pre0.elf -- while all 561 source files hash identically. ar embeds
# member mtimes and the linker stamps a build-id, so a customer cannot verify a
# shipped binary against the SBOM.
#
# SOURCE_DATE_EPOCH is the standard lever: binutils and GCC read it instead of
# the wall clock. Pin it to the commit timestamp, which is the only value that
# is both fixed per revision and meaningful in the output.
#
# Deliberately not doing -ffile-prefix-map here. CI always builds at
# /__w/tl_matter/tl_matter, so paths already agree between runs; that flag
# matters for reproducing a build on a different machine, which is a separate
# question. Measure before adding more.
if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
    SOURCE_DATE_EPOCH="$(git -C "$PWD" log -1 --format=%ct 2>/dev/null || true)"
fi
if [[ -n "${SOURCE_DATE_EPOCH:-}" ]]; then
    export SOURCE_DATE_EPOCH
    echo "=== SOURCE_DATE_EPOCH: $SOURCE_DATE_EPOCH ($(date -u -d "@$SOURCE_DATE_EPOCH" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo unknown))"
else
    echo "=== WARNING: could not determine SOURCE_DATE_EPOCH; build will not be reproducible"
fi

# Resolve to absolute paths so `west spdx` and `west build` agree on the build
# directory regardless of what the caller's cwd was.
BUILD_DIR="$(realpath -m "$BUILD_DIR")"
SBOM_DIR="$(realpath -m "$SBOM_DIR")"
APP_DIR="$(realpath "$APP_DIR")"
mkdir -p "$SBOM_DIR"

echo "=== board      : $BOARD"
echo "=== app dir    : $APP_DIR"
echo "=== build dir  : $BUILD_DIR"
echo "=== sbom dir   : $SBOM_DIR"
echo "=== zephyr base: $ZEPHYR_BASE"
echo

# Step 1: enable the CMake file-based API *before* configuring.
echo "=== [1/3] west spdx --init"
west spdx --init --build-dir="$BUILD_DIR"

# Step 2: build.
#
# CONFIG_BUILD_OUTPUT_META=y is what makes the build emit the meta file that
# zspdx requires. Without it Zephyr's top-level CMakeLists.txt actively deletes
# it ("Prevent spdx to use invalid data"), and `west spdx` then bails with
# "cannot find a valid zephyr_meta.yml required for SPDX generation".
# This mirrors Zephyr's own SBOM test, which sets exactly this one option:
#   tests/application_development/software_bill_of_materials/prj.conf
echo "=== [2/3] west build -b $BOARD"
west build -d "$BUILD_DIR" -b "$BOARD" "$APP_DIR" -- -DCONFIG_BUILD_OUTPUT_META=y

# The file is NOT called zephyr_meta.yml -- that is only the wording of zspdx's
# error message. Zephyr computes KERNEL_META_NAME=${KERNEL_NAME}.meta in
# cmake/modules/kernel.cmake, so the real artifact is <build_dir>/zephyr.meta.
# Read the path back out of the CMake cache, which is exactly what zspdx does,
# instead of hardcoding a guess.
META_PATH="$(sed -n 's/^KERNEL_META_PATH:[^=]*=//p' "$BUILD_DIR/CMakeCache.txt" | head -1)"
if [[ -z "$META_PATH" || ! -s "$META_PATH" ]]; then
    echo "ERROR: KERNEL_META_PATH is unset or its file is missing (got: '${META_PATH:-<unset>}')." >&2
    echo "       CONFIG_BUILD_OUTPUT_META=y did not take effect." >&2
    exit 1
fi
echo "=== meta file: $META_PATH"

# Step 3: generate the SBOM from the compile graph.

# zspdx in this Zephyr revision (4.1.0 line) crashes on any target that has no
# build product on disk:
#
#   walker.py, collectTargetDependencies:
#     rd.ownerFileAbspath = pkg.targetBuildFile.abspath
#     AttributeError: 'NoneType' object has no attribute 'abspath'
#
# pkg.targetBuildFile is only assigned by addBuildFile(), which returns None
# when a target has no artifacts or its artifact is missing after the build --
# yet collectTargetDependencies() is called unconditionally. Newer Zephyr
# rewrote this code and guards the same spot with `if component.target_build_file:`,
# so skipping is the intended semantics: with no build file there is no
# build-file relationship to record.
#
# Patch it at runtime rather than forking the SDK. The check is written to fail
# loudly if the surrounding source ever changes, instead of silently no-op'ing.
patch_zspdx_walker() {
    local walker="$TELINK_ZEPHYR_BASE/scripts/west_commands/zspdx/walker.py"
    if [[ ! -f "$walker" ]]; then
        echo "ERROR: zspdx walker not found at $walker" >&2
        return 1
    fi

    python3 - "$walker" <<'PY'
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as f:
    src = f.read()

target = "            rd.ownerFileAbspath = pkg.targetBuildFile.abspath\n"
guard = ("            if pkg.targetBuildFile is None:\n"
         "                continue\n")

if guard + target in src:
    print("zspdx walker: guard already present, nothing to do")
elif target in src:
    with open(path, "w", encoding="utf-8") as f:
        f.write(src.replace(target, guard + target, 1))
    print("zspdx walker: patched missing None guard")
else:
    sys.exit("ERROR: could not locate the expected line in zspdx walker.py; "
             "the pinned Zephyr revision may have changed")
PY
}

echo "=== patching zspdx walker"
patch_zspdx_walker

echo "=== [3/3] west spdx"
west spdx \
    --build-dir="$BUILD_DIR" \
    --spdx-dir="$SBOM_DIR" \
    --namespace-prefix "${SBOM_NAMESPACE_PREFIX:-https://github.com/Aaronlu1/tl_matter}"

echo
echo "=== SPDX documents produced:"
ls -la "$SBOM_DIR"

# Fail loudly rather than uploading an empty artifact set.
for doc in app.spdx zephyr.spdx build.spdx modules-deps.spdx; do
    if [[ ! -s "$SBOM_DIR/$doc" ]]; then
        echo "ERROR: expected SPDX document '$doc' is missing or empty" >&2
        exit 1
    fi
done

echo
echo "=== SBOM generation OK"
