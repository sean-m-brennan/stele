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
# stele_cohort.sh — Stele Phase 0 live check: a CVE finding lowers a repository
# owner's AutonomousTrust reputation, verifiably, off the owner's hand.
#
# Three real steled nodes on one virtual L2 segment (bridge + netns):
#
#   owner    — publishes a repository (a Go module pinning a vulnerable
#              golang.org/x/net) and advertises it with a signed repo ad
#   verifier — scans the owner's commit with osv-scanner from its OWN clone and
#              attests the finding: a verifier-attested score about the owner,
#              on the `probe` channel
#   observer — co-signs the attestation as admissible, and afterwards checks,
#              from its own persisted evidence and the three nodes' public
#              keys alone, that the entry is in a quorum-signed checkpoint
#
# What it proves, in order:
#   1. Discovery: three nodes, one group.
#   2. The verifier stands above the attestation floor (AT_ATTEST_MIN_REP,
#      0.5) in the owner's and the observer's views, from AT's own background
#      probes. (The owner's view is not needed -- its signature never counts --
#      but it is reported.)
#   3. The owner advertises its repository at a commit; the verifier holds the
#      ad.
#   4. The verifier scans that commit (FORGE=1: a push to Forgejo fires the
#      webhook to verifier/stele_hook.py; otherwise the same scan runs on a
#      local clone) and attests: 20 vulnerabilities, score 0.3. The quorum
#      round commits it on the verifier and the observer WITHOUT the owner's
#      signature.
#   5. OFF THE OWNER'S HAND: after a checkpoint, `stele_ctl.py verify` on the
#      observer finds the attested entry inside the quorum-signed checkpoint,
#      with a certificate the owner did not sign; the observer's score for the
#      owner is reported before and after.
#   6. THE OWNER CANNOT FORK IT AWAY: the owner restarts with its chain wiped;
#      catch-up brings the certified entry back into its own evidence.
#
# NETNS ONLY, on a HOST (not the agent sandbox). Requirements: root + iproute2,
# python3 (with pynacl), git, and the built native layer (../../build.sh).
# osv-scanner and its offline Go database are fetched into the run directory
# unless OSV_SCANNER / OSV_DB name them. FORGE=1 also needs forge/up.sh run first.
#
# Usage:
#   sudo -E env "PATH=$PATH" ./test/cohort/stele_cohort.sh
#   FORGE=1 KEEP=1 sudo -E env "PATH=$PATH" ./test/cohort/stele_cohort.sh
#
# Env knobs: WAIT (per-phase timeout, default 180), WARM_WAIT (phase 2, default
#   600), CHECKPOINT_SEC (AT_REP_CHECKPOINT_SEC, default 20), RESCORE_SEC
#   (AT_REP_RESCORE_SEC, default 5), SETTLE_SEC / SETTLE_EPS (phase 2: the
#   owner's score must move less than SETTLE_EPS, default 0.003, over
#   SETTLE_SEC, default 15), ATTEST_MIN_REP (the
#   floor, default AT's 0.5; lowering it weakens what phase 2 shows and is
#   reported), SUBNET (default 10.9.12), BUILD_DIR, LOG_LEVEL, KEEP=1, FORGE=1.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STELE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$STELE_DIR/native/build}"
STELED="$BUILD_DIR/steled"
SHIM="$BUILD_DIR/libstele_shim.so"
ATCORE="$BUILD_DIR/at_core"
CTL="$STELE_DIR/tools/stele_ctl.py"
HOOK="$STELE_DIR/verifier/stele_hook.py"

WAIT="${WAIT:-180}"
WARM_WAIT="${WARM_WAIT:-600}"
CHECKPOINT_SEC="${CHECKPOINT_SEC:-20}"
RESCORE_SEC="${RESCORE_SEC:-5}"
SETTLE_SEC="${SETTLE_SEC:-15}"
SETTLE_EPS="${SETTLE_EPS:-0.003}"
LOG_LEVEL="${LOG_LEVEL:-2}"
SUBNET="${SUBNET:-10.9.12}"
PREFIX=24
MIN_REP="${ATTEST_MIN_REP:-0.5}"

NODES=(owner verifier observer)
declare -A IP NS V VB ROOT PID
i=11
for n in "${NODES[@]}"; do
  IP[$n]="$SUBNET.$i"; NS[$n]="agst$n"; V[$n]="agst${n:0:4}"; VB[$n]="agst${n:0:4}b"
  i=$(( i + 1 ))
done
BR=agbr12

RUN="${AGORA_COHORT_RUN:-$STELE_DIR/.coh/st-$$}"
for n in "${NODES[@]}"; do ROOT[$n]="$RUN/$n"; PID[$n]=""; mkdir -p "${ROOT[$n]}"; done

log()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m  OK\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31mERR:\033[0m %s\n' "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

# --------------------------------------------------------------------------- #
# Preflight
# --------------------------------------------------------------------------- #
for t in python3 git ip; do have "$t" || { err "$t not found."; exit 1; }; done
for f in "$STELED" "$SHIM"; do
  [ -e "$f" ] || { err "missing $f; build first: (cd '$STELE_DIR' && ./build.sh)"; exit 1; }
done
python3 -c "import nacl" 2>/dev/null || { err "python3 needs pynacl (pip install pynacl)"; exit 1; }
if [ "$(id -u)" -ne 0 ]; then err "needs root (network namespaces)."; exit 1; fi
if ! ip netns add _stele_probe 2>/dev/null; then
  err "this kernel refuses network namespaces; run on a host."; exit 1
fi
ip netns del _stele_probe 2>/dev/null
for n in "${NODES[@]}"; do
  need=$(( ${#ROOT[$n]} + 24 ))
  [ "$need" -le 108 ] || { err "socket path too long under ${ROOT[$n]}; set AGORA_COHORT_RUN=/tmp/st-\$\$"; exit 1; }
done

OSV_SCANNER="${OSV_SCANNER:-}"
OSV_DB="${OSV_DB:-}"
if [ -z "$OSV_SCANNER" ]; then
  log "fetching osv-scanner 2.6.0 into the run directory"
  mkdir -p "$RUN/osv"
  curl -fsSL -o "$RUN/osv/osv-scanner" \
    https://github.com/google/osv-scanner/releases/download/v2.6.0/osv-scanner_linux_amd64 \
    && chmod +x "$RUN/osv/osv-scanner" || { err "could not fetch osv-scanner"; exit 1; }
  OSV_SCANNER="$RUN/osv/osv-scanner"
fi
if [ -z "$OSV_DB" ]; then
  log "fetching the OSV Go database snapshot"
  mkdir -p "$RUN/osv/db/osv-scalibr/Go"
  curl -fsSL -o "$RUN/osv/db/osv-scalibr/Go/all.zip" \
    https://storage.googleapis.com/osv-vulnerabilities/Go/all.zip \
    || { err "could not fetch the OSV database"; exit 1; }
  OSV_DB="$RUN/osv/db"
fi

# --------------------------------------------------------------------------- #
# Network and node primitives (from apps/agora/test/cohort)
# --------------------------------------------------------------------------- #
net_reset() {
  local n
  for n in "${NODES[@]}"; do
    ip netns del "${NS[$n]}" 2>/dev/null
    ip link del "${VB[$n]}" 2>/dev/null
  done
  ip link del "$BR" 2>/dev/null
  return 0
}

net_up() {
  net_reset
  log "Creating bridge $BR and ${#NODES[@]} namespaces on $SUBNET.0/$PREFIX"
  ip link add "$BR" type bridge && ip link set "$BR" up || return 1
  local n
  for n in "${NODES[@]}"; do
    ip netns add "${NS[$n]}" || return 1
    ip link add "${V[$n]}" type veth peer name "${VB[$n]}" || return 1
    ip link set "${V[$n]}" netns "${NS[$n]}" || return 1
    ip link set "${VB[$n]}" master "$BR" || return 1
    ip link set "${VB[$n]}" up || return 1
    ip -n "${NS[$n]}" addr add "${IP[$n]}/$PREFIX" dev "${V[$n]}" || return 1
    ip -n "${NS[$n]}" link set "${V[$n]}" up || return 1
    ip -n "${NS[$n]}" link set lo up || return 1
  done
  if [ -e /proc/sys/net/bridge/bridge-nf-call-iptables ]; then
    echo 0 > /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null || true
  fi
  for n in "${NODES[@]:1}"; do
    ip netns exec "${NS[owner]}" ping -c1 -W2 "${IP[$n]}" >/dev/null 2>&1 \
      || { err "no L2 path from owner to $n"; return 1; }
  done
  log "L2 segment ready"
}

node_start() { # name
  local n="$1"
  local floor=()
  [ -n "${ATTEST_MIN_REP:-}" ] && floor=(AT_ATTEST_MIN_REP="$ATTEST_MIN_REP")
  ip netns exec "${NS[$n]}" env \
    AUTONOMOUS_TRUST_ROOT="${ROOT[$n]}" \
    AT_PEER_NAME="$n" AT_PEER_SEED="stele-$n" \
    AT_REP_CHECKPOINT_SEC="$CHECKPOINT_SEC" \
    AT_REP_RESCORE_SEC="$RESCORE_SEC" \
    "${floor[@]}" \
    LD_LIBRARY_PATH="$ATCORE:${LD_LIBRARY_PATH:-}" \
    "$STELED" extern_to_at at_to_extern "$LOG_LEVEL" \
    >"${ROOT[$n]}/node.log" 2>&1 &
  PID[$n]=$!
}

node_stop() { # name
  [ -z "${PID[$1]}" ] && return 0
  kill "${PID[$1]}" 2>/dev/null; sleep 2; kill -9 "${PID[$1]}" 2>/dev/null
  PID[$1]=""
}

HOOK_PID=""
SAMPLER_PID=""
dump_logs() {
  local n
  for n in "${NODES[@]}"; do
    [ -f "${ROOT[$n]}/node.log" ] || continue
    echo "--- $n ---"
    tail -n 30 "${ROOT[$n]}/node.log"
  done
  [ -f "$RUN/hook.log" ] && { echo "--- stele_hook ---"; tail -n 20 "$RUN/hook.log"; }
}

cleanup() {
  local rc="${1:-0}" n
  [ -n "$HOOK_PID" ] && kill "$HOOK_PID" 2>/dev/null
  [ -n "$SAMPLER_PID" ] && kill "$SAMPLER_PID" 2>/dev/null
  for n in "${NODES[@]}"; do node_stop "$n"; done
  if [ "${KEEP:-0}" = "1" ] || [ "$rc" != "0" ]; then
    log "Leaving the network and $RUN in place (exit $rc). Tear down with:"
    for n in "${NODES[@]}"; do log "  ip netns del ${NS[$n]}"; done
    log "  ip link del $BR"
    return
  fi
  net_reset
  rm -rf "$RUN"
}
trap 'cleanup $?' EXIT
trap 'cleanup 130' INT TERM

ctl() { STELE_SHIM="$SHIM" LD_LIBRARY_PATH="$ATCORE:${LD_LIBRARY_PATH:-}" python3 "$CTL" "$@"; }
saw() { grep -q "$2" "${ROOT[$1]}/node.log" 2>/dev/null; }
count() { grep -c "$2" "${ROOT[$1]}/node.log" 2>/dev/null || echo 0; }
fail() { err "FAIL ($1) — $2"; dump_logs; exit 1; }
wait_for() { # timeout cmd...
  local deadline=$(( SECONDS + $1 )); shift
  until "$@"; do [ "$SECONDS" -ge "$deadline" ] && return 1; sleep 2; done
}
# A node's stored reputation for a peer (its own view), or "" when unrated.
rep_of() { # node uuid
  python3 - "${ROOT[$1]}/etc/at/reputation.cfg.json" "$2" <<'P' 2>/dev/null
import json, sys
try:
    cur = (json.load(open(sys.argv[1])) or {}).get('current') or {}
except (OSError, ValueError):
    cur = {}
print(next((v for k, v in cur.items() if sys.argv[2] in str(k)), ''))
P
}
above() { # node uuid floor
  local r; r="$(rep_of "$1" "$2")"
  [ -n "$r" ] && python3 -c "import sys; sys.exit(0 if float('$r') >= float('$3') else 1)"
}

net_up || exit 1

# --------------------------------------------------------------------------- #
# Phase 1 — discovery
# --------------------------------------------------------------------------- #
# One at a time, as Agora's partition_cohort.sh does: the owner founds the group
# and each later node joins everyone already running before the next starts.
# Started 4 s apart, two nodes could each self-bootstrap a group; the observer
# then joined both and merged, but the two founders were never introduced and
# never peered (st-284840: owner never added verifier).
# "Network: added peer <name>" is the one line every join path logs; the
# identity layer's "confirmed peer" only appears on some (an admitted peer
# logs "peer acceptance confirmed from" instead).
log "Phase 1: starting ${NODES[*]} one at a time"
started=()
for n in "${NODES[@]}"; do
  node_start "$n"
  sleep 3
  kill -0 "${PID[$n]}" 2>/dev/null || fail "phase 1" "$n died at start"
  if [ "${#started[@]}" -eq 0 ]; then
    wait_for "$WAIT" saw "$n" "self-bootstrapping a fresh group" \
      || fail "phase 1" "$n never founded a group"
  else
    for m in "${started[@]}"; do
      wait_for "$WAIT" saw "$n" "Network: added peer $m " \
        || fail "phase 1" "$n never added $m at the network layer"
    done
  fi
  started+=("$n")
done
for n in "${NODES[@]}"; do
  for m in "${NODES[@]}"; do
    [ "$m" = "$n" ] && continue
    wait_for "$WAIT" saw "$n" "Network: added peer $m " \
      || fail "phase 1" "$n never added $m at the network layer"
  done
done
declare -A U PK
for n in "${NODES[@]}"; do
  U[$n]="$(ctl uuid "${ROOT[$n]}")" || fail "phase 1" "no identity for $n"
  PK[$n]="$(ctl pubkey "${ROOT[$n]}")" || fail "phase 1" "no key for $n"
done
KEYS=()
for n in "${NODES[@]}"; do KEYS+=(--key "${U[$n]}=${PK[$n]}"); done
ok "phase 1: three nodes, each confirmed the other two"

# --------------------------------------------------------------------------- #
# Phase 2 — the verifier stands above the attestation floor
# --------------------------------------------------------------------------- #
log "Phase 2: waiting for the verifier to stand >= $MIN_REP in the observer's view (AT's own probes; up to ${WARM_WAIT}s)"
wait_for "$WARM_WAIT" above observer "${U[verifier]}" "$MIN_REP" \
  || fail "phase 2" "the observer holds the verifier at '$(rep_of observer "${U[verifier]}")', below $MIN_REP"
# And the observer's view of the OWNER must have stopped climbing, or phase 5
# cannot see the finding: a cold cohort's scores rise from the probes' early
# 0.5s toward ~0.87 by ~0.3, and the attestation moves the owner ~0.012.
# st-543900 attested 26 s after start, with the owner at 0.55; the owner then
# rose to 0.859 (0.868 on its evidence without the attested entry, 0.857 with
# it), and phase 5 compared that to 0.55.
log "Phase 2: and for the observer's view of the owner to settle (moves < $SETTLE_EPS over ${SETTLE_SEC}s)"
prev="" cur="" settled=0 deadline=$(( SECONDS + WARM_WAIT ))
while [ "$SECONDS" -lt "$deadline" ]; do
  cur="$(rep_of observer "${U[owner]}")"
  if [ -n "$prev" ] && [ -n "$cur" ] && python3 -c \
      "import sys; sys.exit(0 if abs(float('$cur') - float('$prev')) < float('$SETTLE_EPS') else 1)"; then
    settled=1; break
  fi
  prev="$cur"; sleep "$SETTLE_SEC"
done
[ "$settled" = 1 ] || fail "phase 2" "the observer's view of the owner never settled (last '$cur', before '$prev')"
ok "phase 2: observer holds the verifier at $(rep_of observer "${U[verifier]}") (owner: '$(rep_of owner "${U[verifier]}")')$([ -n "${ATTEST_MIN_REP:-}" ] && echo "  [floor LOWERED to $ATTEST_MIN_REP]")"

# --------------------------------------------------------------------------- #
# Phase 3 — the owner advertises its repository
# --------------------------------------------------------------------------- #
REPO="$RUN/repo"
cp -r "$STELE_DIR/forge/seed" "$REPO"
mkdir -p "$REPO/.forgejo/workflows"
cp "$STELE_DIR/forge/workflows/osv.yml" "$REPO/.forgejo/workflows/"
git -C "$REPO" init --quiet -b main
git -C "$REPO" -c user.name=owner -c user.email=owner@stele add .
git -C "$REPO" -c user.name=owner -c user.email=owner@stele commit --quiet -m "seed"
COMMIT="$(git -C "$REPO" rev-parse HEAD)"
if [ "${FORGE:-0}" = "1" ]; then
  [ -f "$STELE_DIR/forge/.forge.env" ] || fail "phase 3" "FORGE=1 but forge/.forge.env is missing; run forge/up.sh"
  # shellcheck disable=SC1091
  . "$STELE_DIR/forge/.forge.env"
  CLONE_URL="$REPO_URL"
else
  CLONE_URL="file://$REPO"
fi
log "Phase 3: owner advertises demo @ ${COMMIT:0:12} ($CLONE_URL)"
advertised() { saw verifier "stele repo demo@${COMMIT:0:12}"; }
for _ in 1 2 3 4 5; do
  ctl advertise "${ROOT[owner]}" demo "$CLONE_URL" main "$COMMIT" 1 >/dev/null
  wait_for 15 advertised && break
done
advertised || fail "phase 3" "the verifier never held the owner's repo ad"
ok "phase 3: the verifier holds the owner's signed ad for ${COMMIT:0:12}"

# --------------------------------------------------------------------------- #
# Phase 4 — the verifier scans and attests; the round commits
# --------------------------------------------------------------------------- #
[ -n "$(rep_of observer "${U[owner]}")" ] || fail "phase 4" "the observer holds no score for the owner to lower"
# The observer's score of the owner, once a second, so phase 5 can compare
# against the reading just before the commit rather than one taken before a
# scan of unknown length (FORGE=1: push, webhook, clone, scan).
SAMPLES="$RUN/owner-rep.samples"
( while :; do
    r="$(rep_of observer "${U[owner]}")"
    [ -n "$r" ] && echo "$(date +%s.%N) $r"
    sleep 1
  done ) >"$SAMPLES" 2>/dev/null &
SAMPLER_PID=$!
if [ "${FORGE:-0}" = "1" ]; then
  log "Phase 4: pushing to Forgejo; the webhook drives the verifier's scan"
  python3 - "$RUN/hook.json" "$HOOK_SECRET" "$OSV_SCANNER" "$OSV_DB" "$CLONE_URL" "${U[owner]}" <<'P'
import json, sys
out, secret, osv, db, url, owner = sys.argv[1:]
json.dump({'secret': secret, 'osv_scanner': osv, 'osv_db': db, 'repos': {url: owner}},
          open(out, 'w'))
P
  STELE_SHIM="$SHIM" python3 "$HOOK" --root "${ROOT[verifier]}" --config "$RUN/hook.json" \
    >"$RUN/hook.log" 2>&1 &
  HOOK_PID=$!
  sleep 2
  PUSH_URL="${FORGE_URL/http:\/\//http://$FORGE_USER:$FORGE_PASS@}/$FORGE_USER/demo.git"
  git -C "$REPO" push --quiet --force "$PUSH_URL" main || fail "phase 4" "push to Forgejo failed"
  wait_for "$WAIT" grep -q "attested ${COMMIT:0:12}" "$RUN/hook.log" \
    || fail "phase 4" "the webhook never produced an attestation"
else
  log "Phase 4: the verifier scans its own clone of ${COMMIT:0:12} and attests"
  STELE_SHIM="$SHIM" LD_LIBRARY_PATH="$ATCORE:${LD_LIBRARY_PATH:-}" python3 - \
    "$HOOK" "${ROOT[verifier]}" "${U[owner]}" "$COMMIT" "$CLONE_URL" "$OSV_SCANNER" "$OSV_DB" <<'P' \
    || fail "phase 4" "the scan or the attest verb failed"
import importlib.util, sys
hook_path, root, owner, commit, url, osv, db = sys.argv[1:]
spec = importlib.util.spec_from_file_location('stele_hook', hook_path)
hook = importlib.util.module_from_spec(spec); spec.loader.exec_module(hook)
report = hook.scan_commit(url, commit, osv, db)
sys.exit(hook.attest(root, owner, commit, report, {'osv_scanner': osv, 'osv_db': db}))
P
fi
for n in verifier observer; do
  wait_for "$WAIT" saw "$n" "attested score committed" \
    || fail "phase 4" "$n never committed the attested score"
done
saw owner "co-signed attest_propose" && fail "phase 4" "the owner co-signed an attestation about itself"
ok "phase 4: the attested score committed on the verifier and the observer, without the owner"

# --------------------------------------------------------------------------- #
# Phase 5 — off the owner's hand
# --------------------------------------------------------------------------- #
log "Phase 5: waiting for a checkpoint to cover the entry, then verifying on the observer"
verified() { ctl verify "${ROOT[observer]}" "${U[owner]}" "${KEYS[@]}" >"$RUN/verify.json" 2>&1; }
wait_for "$WAIT" verified || { cat "$RUN/verify.json"; fail "phase 5" "the observer's evidence does not verify the attestation"; }
# The exit criterion itself: the finding LOWERS the owner's standing in the
# observer's view. The attested commit marks the owner due, and the rescore
# sweep (AT_REP_RESCORE_SEC: 60 s by default, RESCORE_SEC=5 here, as Agora's
# cohorts use) folds it in, so the score is read after a sweep, not at the
# commit. Two passing host runs read it too early and printed the same value
# twice. The fast sweep matters: one 0.3 among ~50 entries lowers the mean by
# ~0.012, and every 0.9 probe after it claws a little of that back. BEFORE is
# the last sample taken before the observer logged the commit, on a score
# phase 2 saw settle. (A score at or below AT_REP_PERSIST_THRESHOLD, 0.5,
# leaves the snapshot, so '' there means lowered past it.)
BEFORE="$(python3 - "${ROOT[observer]}/node.log" "$SAMPLES" <<'PY'
import datetime, re, sys
log = open(sys.argv[1], errors='replace').read()
m = re.search(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+)Z[^\n]*attested score committed', log)
if m is None:
    sys.exit(0)
t = datetime.datetime.strptime(m.group(1), '%Y-%m-%dT%H:%M:%S.%f') \
    .replace(tzinfo=datetime.timezone.utc).timestamp()
best = ''
for line in open(sys.argv[2]):
    parts = line.split()
    if len(parts) == 2 and float(parts[0]) <= t:
        best = parts[1]
print(best)
PY
)"
[ -n "$BEFORE" ] || fail "phase 5" "no sample of the owner's score before the observer's commit (see $SAMPLES)"
lowered() {
  local r; r="$(rep_of observer "${U[owner]}")"
  [ -z "$r" ] && return 0
  python3 -c "import sys; sys.exit(0 if float('$r') < float('$BEFORE') else 1)"
}
wait_for "$WAIT" lowered \
  || fail "phase 5" "the observer still holds the owner at '$(rep_of observer "${U[owner]}")' (was '$BEFORE')"
AFTER="$(rep_of observer "${U[owner]}")"
python3 - "$RUN/verify.json" <<'P'
import json, sys
r = json.load(open(sys.argv[1]))
for a in r['attested']:
    print(f"    entry {a['index']}: score {a['score']} on {a['channel']}, "
          f"{a['cosigners']} co-signer(s), certified={a['certified']}, "
          f"in checkpoint={a['in_checkpoint']}, evidence {a['evidence_digest'][:12]}")
P
ok "phase 5: certified, checkpointed, and the observer LOWERED the owner from $BEFORE to ${AFTER:-below the persist threshold}"

# --------------------------------------------------------------------------- #
# Phase 6 — the owner cannot fork it away
# --------------------------------------------------------------------------- #
log "Phase 6: the owner restarts with its chain wiped"
node_stop owner
rm -f "${ROOT[owner]}/etc/at/reputation-history.cfg.json" "${ROOT[owner]}/etc/at/reputation.cfg.json"
node_start owner
sleep 4
kill -0 "${PID[owner]}" 2>/dev/null || fail "phase 6" "the owner died on restart"
owner_has_it() { ctl verify "${ROOT[owner]}" "${U[owner]}" "${KEYS[@]}" >"$RUN/verify-owner.json" 2>&1; }
wait_for "$WAIT" owner_has_it || { cat "$RUN/verify-owner.json"; fail "phase 6" "the owner's caught-up chain lacks the certified entry"; }
ok "phase 6: the owner's own evidence holds the certified entry again"

log "PASS: stele — a finding lowered the owner's standing, certified by a quorum the owner was not part of"
exit 0
