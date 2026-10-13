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
# run_all.sh — run every Stele live cohort, one after another, and summarize.
#
# Run it as yourself; it re-runs itself under sudo, keeping your PATH (the
# `sudo -E env "PATH=$PATH"` every cohort needs). It also appends /usr/sbin
# and /sbin, which a user PATH often lacks and root tools live in.
#
# Each script's output goes to its own log under .coh/run-all-<pid>/ (owned by
# you, not root) and to the terminal. By default every test runs whatever the
# others did, and the exit status is the number that failed.
#
# Usage:
#   ./test/cohort/run_all.sh                       # everything
#   ./test/cohort/run_all.sh redteam relay_redteam # only these (names without stele_ / .sh)
#   ./test/cohort/run_all.sh --skip team_redteam
#   ./test/cohort/run_all.sh --fail-fast           # stop at the first failure
#   ./test/cohort/run_all.sh --list                # print the run order and exit
#   FORGE=1 ./test/cohort/run_all.sh               # env passes through to every script
#
# A new stele_*.sh is picked up automatically, after the ones below.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STELE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$STELE_DIR/native/build}"

# In phase order: the basic cohort first, so a broken build shows up early.
ORDER=(cohort redteam team_redteam relay_redteam)

script_of() { echo "$SCRIPT_DIR/stele_${1}.sh"; }

all_tests() {
  local t f n seen=" ${ORDER[*]} "
  for t in "${ORDER[@]}"; do [ -f "$(script_of "$t")" ] && echo "$t"; done
  for f in "$SCRIPT_DIR"/stele_*.sh; do
    n="$(basename "$f" .sh)"; n="${n#stele_}"
    case "$seen" in *" $n "*) ;; *) echo "$n" ;; esac
  done
}

usage() { sed -n '18,36p' "$0" | sed 's/^# \{0,1\}//'; }

ARGS=("$@")
FAIL_FAST=0 LIST=0 SKIP="" ONLY=()
while [ $# -gt 0 ]; do
  case "$1" in
    --fail-fast) FAIL_FAST=1 ;;
    --list)      LIST=1 ;;
    --skip)      shift; SKIP="${1:-}" ;;
    --skip=*)    SKIP="${1#--skip=}" ;;
    -h|--help)   usage; exit 0 ;;
    -*)          echo "run_all: unknown option $1" >&2; usage >&2; exit 2 ;;
    *)           t="${1%.sh}"; ONLY+=("${t#stele_}") ;;
  esac
  shift
done

mapfile -t AVAILABLE < <(all_tests)
TESTS=()
if [ ${#ONLY[@]} -gt 0 ]; then
  for t in "${ONLY[@]}"; do
    if [ -f "$(script_of "$t")" ]; then TESTS+=("$t")
    else echo "run_all: no cohort named '$t' (try --list)" >&2; exit 2; fi
  done
else
  TESTS=("${AVAILABLE[@]}")
fi
if [ -n "$SKIP" ]; then
  kept=()
  for t in "${TESTS[@]}"; do
    case ",$SKIP," in *",$t,"*|*",stele_$t,"*) ;; *) kept+=("$t") ;; esac
  done
  TESTS=("${kept[@]}")
fi

if [ "$LIST" = 1 ]; then printf '%s\n' "${TESTS[@]}"; exit 0; fi
[ ${#TESTS[@]} -gt 0 ] || { echo "run_all: nothing to run" >&2; exit 2; }

# Root, keeping the caller's PATH. Done after parsing so --list and --help
# never ask for a password.
if [ "$(id -u)" -ne 0 ]; then
  exec sudo -E env "PATH=$PATH" BUILD_DIR="$BUILD_DIR" "$0" "${ARGS[@]}"
fi
case ":$PATH:" in *:/usr/sbin:*) ;; *) PATH="$PATH:/usr/sbin" ;; esac
case ":$PATH:" in *:/sbin:*) ;; *) PATH="$PATH:/sbin" ;; esac
export PATH BUILD_DIR

if [ ! -x "$BUILD_DIR/steled" ]; then
  echo "run_all: $BUILD_DIR/steled is missing; run ./build.sh first (as yourself)." >&2
  exit 2
fi

LOGS="$STELE_DIR/.coh/run-all-$$"
mkdir -p "$LOGS"
OWNER="${SUDO_USER:-}"
own() { [ -n "$OWNER" ] && chown -R "$OWNER": "$LOGS" 2>/dev/null; true; }

declare -A RESULT SECS
failed=0
for t in "${TESTS[@]}"; do
  echo
  echo "################ $t ################"
  start=$(date +%s)
  # Each script finds the stele dir itself. PIPESTATUS keeps the script's own
  # status through tee.
  bash "$(script_of "$t")" 2>&1 | tee "$LOGS/$t.log"
  rc=${PIPESTATUS[0]}
  SECS[$t]=$(( $(date +%s) - start ))
  if [ "$rc" -eq 0 ]; then RESULT[$t]=PASS
  else RESULT[$t]="FAIL ($rc)"; failed=$((failed + 1)); fi
  own
  if [ "$rc" -ne 0 ] && [ "$FAIL_FAST" = 1 ]; then
    echo "run_all: stopping at $t (--fail-fast)"
    break
  fi
done

echo
echo "================ cohort summary ================"
for t in "${TESTS[@]}"; do
  printf '  %-18s %-10s %s\n' "$t" "${RESULT[$t]:-not run}" \
    "${SECS[$t]:+${SECS[$t]}s}"
done
echo "  logs: $LOGS"
if [ "$failed" -eq 0 ]; then echo "==> ALL PASS"; else echo "==> $failed FAILED"; fi
own
exit "$failed"
