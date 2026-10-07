# shellcheck shell=bash
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
#
# lib.sh — primitives shared by Stele's netns cohorts (sourced, never run).
# Taken from stele_cohort.sh, which keeps its own copy until it is next
# changed on a host; stele_redteam.sh uses these.
#
# The caller sets, before sourcing:
#   NODES (every node that may run), IP NS V VB ROOT PID (associative, per
#   node), BR SUBNET PREFIX RUN STELED SHIM ATCORE CTL LOG_LEVEL
#   CHECKPOINT_SEC RESCORE_SEC WAIT, and optionally LIBDIR (per node: a
#   directory searched before ATCORE, for a node run on other libraries).

log()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m  OK\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31mERR:\033[0m %s\n' "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

preflight() {
  local t f n need
  for t in python3 git ip curl; do have "$t" || { err "$t not found."; exit 1; }; done
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
    [ "$need" -le 108 ] || { err "socket path too long under ${ROOT[$n]}; set STELE_COHORT_RUN=/tmp/rt-\$\$"; exit 1; }
  done
}

# OSV_SCANNER / OSV_DB, fetched into the run directory unless given.
fetch_osv() {
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
}

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
  local first="${NODES[0]}"
  for n in "${NODES[@]:1}"; do
    ip netns exec "${NS[$first]}" ping -c1 -W2 "${IP[$n]}" >/dev/null 2>&1 \
      || { err "no L2 path from $first to $n"; return 1; }
  done
  log "L2 segment ready"
}

node_start() { # name
  local n="$1" libs="$ATCORE"
  local floor=()
  [ -n "${ATTEST_MIN_REP:-}" ] && floor=(AT_ATTEST_MIN_REP="$ATTEST_MIN_REP")
  [ -n "${LIBDIR[$n]:-}" ] && libs="${LIBDIR[$n]}:$ATCORE"
  ip netns exec "${NS[$n]}" env \
    AUTONOMOUS_TRUST_ROOT="${ROOT[$n]}" \
    AT_PEER_NAME="$n" AT_PEER_SEED="stele-$n" \
    AT_REP_CHECKPOINT_SEC="$CHECKPOINT_SEC" \
    AT_REP_RESCORE_SEC="$RESCORE_SEC" \
    "${floor[@]}" \
    LD_LIBRARY_PATH="$libs:${LD_LIBRARY_PATH:-}" \
    "$STELED" extern_to_at at_to_extern "$LOG_LEVEL" \
    >>"${ROOT[$n]}/node.log" 2>&1 &
  PID[$n]=$!
}

node_stop() { # name
  [ -z "${PID[$1]:-}" ] && return 0
  kill "${PID[$1]}" 2>/dev/null; sleep 2; kill -9 "${PID[$1]}" 2>/dev/null
  PID[$1]=""
}

ctl() { STELE_SHIM="$SHIM" LD_LIBRARY_PATH="$ATCORE:${LD_LIBRARY_PATH:-}" python3 "$CTL" "$@"; }
saw() { grep -q "$2" "${ROOT[$1]}/node.log" 2>/dev/null; }
# grep -c prints 0 AND exits 1 on no match, so "|| echo 0" would print it twice.
count() { local n; n="$(grep -c "$2" "${ROOT[$1]}/node.log" 2>/dev/null)"; echo "${n:-0}"; }
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
# The effective tier a node's roster (roster.cfg.json) records for a peer.
tier_at_least() { # node uuid tier
  python3 - "${ROOT[$1]}/etc/at/roster.cfg.json" "$2" "$3" <<'P' 2>/dev/null
import json, sys
m = (json.load(open(sys.argv[1])).get('members') or {}).get(sys.argv[2]) or {}
sys.exit(0 if int(m.get('tier', -1)) >= int(sys.argv[3]) else 1)
P
}
in_roster() { # node uuid
  python3 - "${ROOT[$1]}/etc/at/roster.cfg.json" "$2" <<'P' 2>/dev/null
import json, sys
m = (json.load(open(sys.argv[1])).get('members') or {}).get(sys.argv[2]) or {}
sys.exit(0 if m.get('member') else 1)
P
}

# The standing a viewer node folds for CLONE_URL, checked against specs:
#   state=S  commit=C  has=SCANNER:CHANNEL:VERDICT  agree=SCANNER:CHANNEL:N
#   counted=SCANNER:CHANNEL:UUID:yes|no  rebutted=SCANNER
standing_is() { # viewer label spec...
  local viewer="$1" label="$2"; shift 2
  ctl standing "${ROOT[$viewer]}" "$CLONE_URL" >"$RUN/standing-$label.json" 2>/dev/null
  python3 - "$RUN/standing-$label.json" "$@" <<'P'
import json, sys
try:
    st = json.load(open(sys.argv[1]))
except (OSError, ValueError):
    sys.exit(1)
checks = {(c['scanner'], c['channel']): c for c in st.get('checks') or []}
for spec in sys.argv[2:]:
    k, _, v = spec.partition('=')
    if k == 'state' and st.get('state') != v:
        sys.exit(1)
    if k == 'commit' and (st.get('repo') or {}).get('commit') != v:
        sys.exit(1)
    if k == 'has':
        scanner, channel, verdict = v.split(':')
        c = checks.get((scanner, channel))
        if c is None or c['verdict'] != verdict:
            sys.exit(1)
    if k == 'agree':
        scanner, channel, n = v.split(':')
        c = checks.get((scanner, channel))
        if c is None or int(c.get('agreement', 0)) < int(n):
            sys.exit(1)
    if k == 'counted':
        scanner, channel, who, yes = v.split(':')
        c = checks.get((scanner, channel)) or {}
        got = [x for x in c.get('verifiers') or [] if x['verifier'] == who]
        if not got or bool(got[0]['counted']) != (yes == 'yes'):
            sys.exit(1)
    if k == 'rebutted' and not any(c['scanner'] == v and c.get('rebuttal')
                                   for c in checks.values()):
        sys.exit(1)
P
}
show_standing() { # label
  python3 - "$RUN/standing-$1.json" <<'P'
import json, sys
st = json.load(open(sys.argv[1]))
print(f"    {st['repo']['name']} @ {st['repo']['commit'][:12]}: {st['state']}, score {st.get('score')}")
for c in st.get('checks') or []:
    print(f"      [{c.get('state')}] {c['reason']}")
P
}
