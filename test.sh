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
# Run Stele's tests: AT's conformance run with stele plugged in, each pytest
# directory, and the browser extension's node tests. None of them need
# ./build.sh; the live cohorts (test/cohort/) are host-only and not run here.
#
#   ./test.sh
#   AT_ROOT=/path/to/autonomous_trust ./test.sh
#
# The conformance and pytest steps run in the autonomous_trust conda env when it
# exists, else in the current environment. Every step runs even if an earlier one fails, and
# a PASS/FAIL summary is printed at the end. Exits non-zero if any step failed.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

CONDA_BIN="${CONDA_BIN:-$(command -v mamba || command -v conda || command -v micromamba || true)}"
CONDA_RUN=()
if [[ -n "$CONDA_BIN" ]]; then
    CONDA_RUN=("$CONDA_BIN" run)
    # conda captures output until the command exits unless told not to.
    if "$CONDA_BIN" run --help 2>&1 | grep -q -- --no-capture-output; then
        CONDA_RUN+=(--no-capture-output)
    fi
fi

# Run a command in the named conda env if it exists, else in the current one.
in_env() {
    local name=$1 prefix=""
    shift
    if [[ -n "$CONDA_BIN" ]]; then
        prefix=$("$CONDA_BIN" env list 2>/dev/null \
            | awk -v n="$name" '$NF ~ ("/envs/" n "$") {print $NF; exit}')
    fi
    if [[ -n "$prefix" ]]; then
        "${CONDA_RUN[@]}" -p "$prefix" "$@"
    else
        "$@"
    fi
}

RESULTS=()
FAILED=0

# step LABEL CMD...: run CMD and record whether it passed.
step() {
    local label=$1
    shift
    echo ""
    echo "=== stele test: $label ==="
    if "$@"; then
        RESULTS+=("PASS  $label")
    else
        RESULTS+=("FAIL  $label")
        FAILED=1
    fi
}

step "conformance" in_env autonomous_trust at-stele/test-conformance.sh
# Each pytest directory holds its own `tests` package, so run them one at a time.
for d in at-stele/python/tests tools/tests verifier/tests viewer/tests; do
    step "pytest $d" in_env autonomous_trust python -m pytest "$d"
done
step "extension" node --test extension/tests/panel.test.mjs extension/tests/background.test.mjs

echo ""
echo "=== stele test summary ==="
printf '  %s\n' "${RESULTS[@]}"
exit "$FAILED"
