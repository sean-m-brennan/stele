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
# stele_relay_redteam.sh — Stele Phase 4's discovery relays: a reader finds a
# repository in ANOTHER AT group through a relay, and believes nothing about it
# but what verifies under the group anchor of a polity it follows (Ethne D43).
#
# Three L2 segments joined by a router (discovery stays on its segment; the
# relay is reached over TCP):
#
#   group A  — owner, verifier, auditor: a team whose polity mints the anchor
#   group B  — viewer, b1, b2: the reader's own group
#   relay    — an AT relay serving the stl_ family (AT_RELAY=1, AT_STELE_RELAY=1),
#              alone on its segment; every node names it in AT_USE_RELAY
#
# What it proves, in order:
#   1. Two groups and a relay: neither group holds the other's nodes.
#   2. The verifier and the auditor reach tier 3 in group A.
#   3. A confirmed finding in group A: the verifier's scan, the auditor's
#      replication, archived under a checkpoint.
#   4. The polity mints its group anchor from the owner's roster (every node
#      consenting) and the owner publishes it; the viewer follows the polity.
#   5. OMISSION: the owner publishes its ad and leaves the finding out. The
#      viewer reads the repository through the relay as unknown, never green.
#   6. ANYONE PUBLISHES: the auditor publishes what it holds; the viewer reads
#      failing, agreed by 2, under the polity's anchor.
#   7. THE RELAY'S WORD: a node of group B files a clean attestation it made up
#      itself; the relay counts it, labelled as its word, and the viewer still
#      reads failing.
#   8. FORGERY: an anchor edited after signing is not followed, and a record
#      edited after it was certified does not verify.
#   9. UNFOLLOWED: once the viewer stops following the polity, the repository
#      is listed and unverified ("group not followed").
#
# NETNS ONLY, on a HOST. Requirements as stele_redteam.sh (root, iproute2,
# python3 + pynacl, git, curl, ../../build.sh). osv-scanner and its Go database
# are fetched unless OSV_SCANNER / OSV_DB name them.
#
# Usage:
#   sudo -E env "PATH=$PATH" ./test/cohort/stele_relay_redteam.sh
#   KEEP=1 sudo -E env "PATH=$PATH" ./test/cohort/stele_relay_redteam.sh
#
# Env knobs: WAIT (default 180), WARM_WAIT (phase 2, default 900),
#   CHECKPOINT_SEC (default 20), RESCORE_SEC (default 5), TIER_REP (default
#   0.80), NET (the first two octets, default 10.9; segments .15 .16 .17),
#   BUILD_DIR, LOG_LEVEL, KEEP=1.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STELE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$STELE_DIR/native/build}"
STELED="$BUILD_DIR/steled"
SHIM="$BUILD_DIR/libstele_shim.so"
ATCORE="$BUILD_DIR/at_core"
CTL="$STELE_DIR/tools/stele_ctl.py"
HOOK="$STELE_DIR/verifier/stele_hook.py"
TEAM="$STELE_DIR/tools/stele_team.py"

WAIT="${WAIT:-180}"
WARM_WAIT="${WARM_WAIT:-900}"
CHECKPOINT_SEC="${CHECKPOINT_SEC:-20}"
RESCORE_SEC="${RESCORE_SEC:-5}"
TIER_REP="${TIER_REP:-0.80}"
LOG_LEVEL="${LOG_LEVEL:-2}"
NET="${NET:-10.9}"
PREFIX=24

GROUP_A=(owner verifier auditor)
GROUP_B=(viewer b1 b2)
NODES=(relay owner verifier auditor viewer b1 b2)
declare -A IP NS V VB ROOT PID LIBDIR U SEG EXTRA
declare -A SEGNET=([a]="$NET.15" [b]="$NET.16" [r]="$NET.17")
declare -A SEGBR=([a]=agbr15 [b]=agbr16 [r]=agbr17)
for n in "${GROUP_A[@]}"; do SEG[$n]=a; done
for n in "${GROUP_B[@]}"; do SEG[$n]=b; done
SEG[relay]=r
i=31
for n in "${NODES[@]}"; do
  IP[$n]="${SEGNET[${SEG[$n]}]}.$i"; NS[$n]="agrl$n"; V[$n]="agrl${n:0:4}"; VB[$n]="agrl${n:0:4}b"
  i=$(( i + 1 ))
done
ROUTER_NS=agrlrouter
RELAY_PORT=27790
RELAY_EP="${IP[relay]}:$RELAY_PORT"
for n in "${GROUP_A[@]}" "${GROUP_B[@]}"; do
  # Only what each node files when it registers, and what it is told to: the
  # phases decide who publishes when.
  EXTRA[$n]="AT_USE_RELAY=$RELAY_EP AT_STELE_RELAY_REFILE_SEC=100000"
done
EXTRA[relay]="AT_RELAY=1 AT_RELAY_PORT=$RELAY_PORT AT_STELE_RELAY=1"
BR="${SEGBR[r]}"   # lib.sh's net_reset removes one bridge; this script removes all three

RUN="${STELE_COHORT_RUN:-$STELE_DIR/.coh/rl-$$}"
for n in "${NODES[@]}"; do ROOT[$n]="$RUN/$n"; PID[$n]=""; mkdir -p "${ROOT[$n]}/etc/at"; done

# shellcheck source=lib.sh
. "$SCRIPT_DIR/lib.sh"

preflight
fetch_osv

dump_logs() {
  local n
  for n in "${NODES[@]}"; do
    [ -f "${ROOT[$n]}/node.log" ] || continue
    echo "--- $n ---"
    tail -n 30 "${ROOT[$n]}/node.log"
  done
}
fail() { err "FAIL ($1) — $2"; dump_logs; exit 1; }

net_down() {
  local n s
  for n in "${NODES[@]}"; do
    ip netns del "${NS[$n]}" 2>/dev/null
    ip link del "${VB[$n]}" 2>/dev/null
  done
  ip netns del "$ROUTER_NS" 2>/dev/null
  for s in a b r; do ip link del "${SEGBR[$s]}" 2>/dev/null; done
  return 0
}

# Three bridges, one per segment, and a router namespace with a leg on each
# (.1), so TCP crosses segments and discovery's broadcasts do not.
net_up3() {
  net_down
  log "Creating three segments ($NET.15/16/17.0/$PREFIX) and a router"
  local s n
  ip netns add "$ROUTER_NS" || return 1
  # Not sysctl, which a sudo PATH may lack: /proc/sys/net is the netns's own.
  ip netns exec "$ROUTER_NS" sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward' || return 1
  ip -n "$ROUTER_NS" link set lo up
  for s in a b r; do
    ip link add "${SEGBR[$s]}" type bridge && ip link set "${SEGBR[$s]}" up || return 1
    ip link add "agrlrt$s" type veth peer name "agrlrt${s}b" || return 1
    ip link set "agrlrt$s" netns "$ROUTER_NS" || return 1
    ip link set "agrlrt${s}b" master "${SEGBR[$s]}" && ip link set "agrlrt${s}b" up || return 1
    ip -n "$ROUTER_NS" addr add "${SEGNET[$s]}.1/$PREFIX" dev "agrlrt$s" || return 1
    ip -n "$ROUTER_NS" link set "agrlrt$s" up || return 1
  done
  for n in "${NODES[@]}"; do
    s="${SEG[$n]}"
    ip netns add "${NS[$n]}" || return 1
    ip link add "${V[$n]}" type veth peer name "${VB[$n]}" || return 1
    ip link set "${V[$n]}" netns "${NS[$n]}" || return 1
    ip link set "${VB[$n]}" master "${SEGBR[$s]}" && ip link set "${VB[$n]}" up || return 1
    ip -n "${NS[$n]}" addr add "${IP[$n]}/$PREFIX" dev "${V[$n]}" || return 1
    ip -n "${NS[$n]}" link set "${V[$n]}" up && ip -n "${NS[$n]}" link set lo up || return 1
    ip -n "${NS[$n]}" route add default via "${SEGNET[$s]}.1" || return 1
  done
  if [ -e /proc/sys/net/bridge/bridge-nf-call-iptables ]; then
    echo 0 > /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null || true
  fi
  for n in owner viewer; do
    ip netns exec "${NS[$n]}" ping -c1 -W2 "${IP[relay]}" >/dev/null 2>&1 \
      || { err "no route from $n to the relay"; return 1; }
  done
  log "segments and router ready"
}

cleanup() {
  local rc="${1:-0}" n
  for n in "${NODES[@]}"; do node_stop "$n"; done
  if [ "${KEEP:-0}" = "1" ] || [ "$rc" != "0" ]; then
    log "Leaving the network and $RUN in place (exit $rc). Tear down with:"
    for n in "${NODES[@]}"; do log "  ip netns del ${NS[$n]}"; done
    log "  ip netns del $ROUTER_NS; ip link del ${SEGBR[a]}; ip link del ${SEGBR[b]}; ip link del ${SEGBR[r]}"
    return
  fi
  net_down
  rm -rf "$RUN"
}
trap 'cleanup $?' EXIT
trap 'cleanup 130' INT TERM

joined() { saw "$1" "Network: added peer $2 "; }
start_and_join() { # node others...
  local n="$1" m; shift
  node_start "$n"
  sleep 3
  kill -0 "${PID[$n]}" 2>/dev/null || fail "start" "$n died at start"
  for m in "$@"; do
    wait_for "$WAIT" joined "$n" "$m" || fail "start" "$n never added $m at the network layer"
  done
}

# What the viewer makes of the relays' answer about URL, against specs:
#   state=S  anchored=yes|no  agree=SCANNER:CHANNEL:N  reason=TEXT  green=no
relay_is() { # label url spec...
  local label="$1" url="$2"; shift 2
  ctl relay-standing "${ROOT[viewer]}" "$url" >"$RUN/relay-$label.json" 2>/dev/null
  python3 - "$RUN/relay-$label.json" "$@" <<'P'
import json, sys
try:
    out = json.load(open(sys.argv[1]))
except (OSError, ValueError):
    sys.exit(1)
st = out.get('standing') or {}
checks = {(c['scanner'], c['channel']): c for c in st.get('checks') or []}
for spec in sys.argv[2:]:
    k, _, v = spec.partition('=')
    if k == 'state' and st.get('state') != v:
        sys.exit(1)
    if k == 'anchored' and bool(st.get('anchored_by')) != (v == 'yes'):
        sys.exit(1)
    if k == 'agree':
        scanner, channel, n = v.split(':')
        c = checks.get((scanner, channel))
        if c is None or int(c.get('agreement', 0)) < int(n):
            sys.exit(1)
    if k == 'reason' and out.get('reason') != v:
        sys.exit(1)
    if k == 'green' and st.get('state') == 'verified-safe':
        sys.exit(1)
P
}
show_relay() { # label
  python3 - "$RUN/relay-$1.json" <<'P'
import json, sys
out = json.load(open(sys.argv[1]))
st = out.get('standing') or {}
a = st.get('anchored_by') or {}
print(f"    via {len(out.get('relays') or [])} relay(s): {st.get('state')}"
      + (f"  [anchor of {a.get('polity')}, seq {a.get('seq')}]" if a else '')
      + (f"  ({out['reason']})" if out.get('reason') else ''))
for c in st.get('checks') or []:
    print(f"      [{c.get('state')}] {c['reason']}")
P
}
# The relay search as the viewer folds it: name=N:clean>=K:state=S
results_is() { # label text spec...
  local label="$1" q="$2"; shift 2
  ctl relay-results "${ROOT[viewer]}" "$q" >"$RUN/results-$label.json" 2>/dev/null
  python3 - "$RUN/results-$label.json" "$@" <<'P'
import json, sys
try:
    out = json.load(open(sys.argv[1]))
except (OSError, ValueError):
    sys.exit(1)
for spec in sys.argv[2:]:
    name, _, rest = spec.partition(':')
    e = next((e for e in out.get('results') or [] if (e.get('repo') or {}).get('name') == name), None)
    if e is None:
        sys.exit(1)
    for cond in rest.split(':') if rest else []:
        if cond.startswith('clean>='):
            if max((r.get('clean', 0) for r in e['relays']), default=0) < int(cond[7:]):
                sys.exit(1)
        if cond.startswith('state='):
            if (e.get('verified') or {}).get('state') != cond[6:]:
                sys.exit(1)
P
}

net_up3 || exit 1

# --------------------------------------------------------------------------- #
# Phase 1 — two groups and a relay
# --------------------------------------------------------------------------- #
log "Phase 1: the relay, then group A and group B, each on its own segment"
node_start relay
wait_for "$WAIT" saw relay "Stele relay: serving discovery" \
  || fail "phase 1" "the relay never served the stl_ family (a steled built before Phase 4?)"
start_and_join owner
start_and_join verifier owner
start_and_join auditor owner verifier
start_and_join viewer
start_and_join b1 viewer
start_and_join b2 viewer b1
for n in "${NODES[@]}"; do U[$n]="$(ctl uuid "${ROOT[$n]}")" || fail "phase 1" "no identity for $n"; done
sleep $(( CHECKPOINT_SEC * 2 ))
in_roster viewer "${U[owner]}" && fail "phase 1" "the groups merged: the viewer holds the owner"
in_roster owner "${U[viewer]}" && fail "phase 1" "the groups merged: the owner holds the viewer"
ok "phase 1: group A and group B stay apart; both reach the relay at $RELAY_EP"

# --------------------------------------------------------------------------- #
# Phase 2 — group A's verifiers at tier 3
# --------------------------------------------------------------------------- #
log "Phase 2: the verifier and the auditor reach $TIER_REP (tier 3) in group A (up to ${WARM_WAIT}s)"
for pair in "verifier auditor" "auditor verifier" "owner verifier" "owner auditor"; do
  set -- $pair
  wait_for "$WARM_WAIT" above "$1" "${U[$2]}" "$TIER_REP" \
    || fail "phase 2" "$1 holds $2 at '$(rep_of "$1" "${U[$2]}")', below $TIER_REP"
done
for v in verifier auditor; do
  wait_for "$WARM_WAIT" tier_at_least owner "${U[$v]}" 3 \
    || fail "phase 2" "the owner's roster does not record $v at tier 3"
done
ok "phase 2: the owner's roster holds the verifier and the auditor at tier 3"

# --------------------------------------------------------------------------- #
# Phase 3 — a confirmed finding in group A
# --------------------------------------------------------------------------- #
REPO="$RUN/repo"
cp -r "$STELE_DIR/forge/seed" "$REPO"
git -C "$REPO" init --quiet -b main
git -C "$REPO" -c user.name=owner -c user.email=owner@stele add .
git -C "$REPO" -c user.name=owner -c user.email=owner@stele commit --quiet -m "seed"
C1="$(git -C "$REPO" rev-parse HEAD)"
URL="file://$REPO"
python3 - "$RUN/hook.json" "$OSV_SCANNER" "$OSV_DB" <<'P'
import json, sys
json.dump({'osv_scanner': sys.argv[2], 'osv_db': sys.argv[3], 'scanners': ['osv-scanner']},
          open(sys.argv[1], 'w'))
P
log "Phase 3: the owner advertises demo @ ${C1:0:12}; the verifier scans, the auditor replicates"
# Each try at a higher seq, and only the ad just advertised counts: a verifier
# attests about the newest ad it holds, which the auditor must hold too to
# replicate it (rl-2763743 attested an ad the auditor never received).
AD=""
held() { local n; for n in verifier auditor; do saw "$n" "stele repo demo@${C1:0:12} .*(ad ${AD:0:12})" || return 1; done; }
for seq in 1 2 3 4 5; do
  ctl advertise "${ROOT[owner]}" demo "$URL" main "$C1" "$seq" --description "a demo for the relays" >/dev/null
  sleep 1
  AD="$(grep -a -o "advertised stele repo demo@${C1:0:12} (ad [0-9a-f]*)" "${ROOT[owner]}/node.log" | tail -1 | sed 's/.*(ad \([0-9a-f]*\))/\1/')"
  [ -n "$AD" ] && wait_for 15 held && break
done
{ [ -n "$AD" ] && held; } || fail "phase 3" "group A never held the owner's newest ad (${AD:-none})"
STELE_SHIM="$SHIM" LD_LIBRARY_PATH="$ATCORE:${LD_LIBRARY_PATH:-}" python3 - \
  "$HOOK" "${ROOT[verifier]}" "${U[owner]}" "$C1" "$URL" "$RUN/hook.json" >>"$RUN/hook.log" 2>&1 <<'P' \
  || fail "phase 3" "the verifier's scan or attest failed"
import importlib.util, json, sys
hook_path, root, owner, commit, url, cfg_path = sys.argv[1:]
spec = importlib.util.spec_from_file_location('stele_hook', hook_path)
hook = importlib.util.module_from_spec(spec); spec.loader.exec_module(hook)
cfg = json.load(open(cfg_path))
report = hook.scan_commit(url, commit, cfg['osv_scanner'], cfg['osv_db'])
sys.exit(hook.attest(root, owner, commit, report, cfg, 'osv-scanner', url))
P
wait_for "$WAIT" saw auditor "stele attestation .* from verifier" \
  || fail "phase 3" "the auditor never held the verifier's attestation"
STELE_SHIM="$SHIM" LD_LIBRARY_PATH="$ATCORE:${LD_LIBRARY_PATH:-}" \
  python3 "$HOOK" replicate --root "${ROOT[auditor]}" --config "$RUN/hook.json" >>"$RUN/hook.log" 2>&1
archived() { [ "$(find "${ROOT[auditor]}/etc/at/attested" -name '*.json' 2>/dev/null | wc -l)" -ge 2 ]; }
wait_for "$WAIT" archived || fail "phase 3" "the auditor never archived both entries under a checkpoint"
ok "phase 3: the finding and its replication are archived in group A"

# --------------------------------------------------------------------------- #
# Phase 4 — the polity's group anchor; the viewer follows it
# --------------------------------------------------------------------------- #
log "Phase 4: the polity mints its group anchor from the owner's roster; the viewer follows it"
SPEC="$RUN/polity.json"
python3 - "$SPEC" "$RUN" "${ROOT[owner]}" "${ROOT[verifier]}" "${ROOT[auditor]}" <<'P'
import json, sys
spec, run, owner, ver, aud = sys.argv[1:]
json.dump({'root': run + '/polity.key', 'members': {'owner': owner, 'verifier': ver,
                                                    'auditor': aud},
           'officers': [], 'anchor_from': owner, 'anchor_seq': 1}, open(spec, 'w'))
P
python3 "$TEAM" anchor "$SPEC" "$RUN/polity.anchor" 2>>"$RUN/team.log" \
  || fail "phase 4" "stele_team.py could not mint the anchor"
ctl anchor-publish "${ROOT[owner]}" "$RUN/polity.anchor" >"$RUN/anchor-publish.json" \
  || fail "phase 4" "the owner would not publish the anchor"
python3 -c "import json,sys; d=json.load(open(sys.argv[1]))['publishing']; sys.exit(0 if d['members']==3 else 1)" \
  "$RUN/anchor-publish.json" || { cat "$RUN/anchor-publish.json"; fail "phase 4" "the anchor does not list all three of group A"; }
ctl anchor-follow "${ROOT[viewer]}" "$RUN/polity.anchor" >/dev/null \
  || fail "phase 4" "the viewer refused the polity's anchor"
ok "phase 4: the anchor lists group A's three nodes; the viewer follows the polity"

# --------------------------------------------------------------------------- #
# Phase 5 — OMISSION: the owner leaves the finding out
# --------------------------------------------------------------------------- #
log "Phase 5: the owner publishes its ad and anchor, with the finding left out"
mkdir -p "$RUN/withheld"
mv "${ROOT[owner]}/etc/stele/attestations" "$RUN/withheld/attestations" 2>/dev/null
mv "${ROOT[owner]}/etc/at/attested" "$RUN/withheld/attested" 2>/dev/null
ctl relay-publish "${ROOT[owner]}" || fail "phase 5" "relay-publish failed on the owner"
sleep 3
mv "$RUN/withheld/attestations" "${ROOT[owner]}/etc/stele/attestations" 2>/dev/null
mv "$RUN/withheld/attested" "${ROOT[owner]}/etc/at/attested" 2>/dev/null
wait_for "$WAIT" relay_is omitted "$URL" state=unknown green=no \
  || { cat "$RUN/relay-omitted.json"; fail "phase 5" "the owner's ad alone read as anything but unknown"; }
show_relay omitted
ok "phase 5: with the finding left out, the repository reads unknown, never green"

# --------------------------------------------------------------------------- #
# Phase 6 — ANYONE PUBLISHES: the auditor files the finding
# --------------------------------------------------------------------------- #
log "Phase 6: the auditor publishes what it holds"
ctl relay-publish "${ROOT[auditor]}" || fail "phase 6" "relay-publish failed on the auditor"
wait_for "$WAIT" relay_is finding "$URL" state=failing anchored=yes agree=osv-scanner:probe:2 \
  || { cat "$RUN/relay-finding.json"; fail "phase 6" "the auditor's records did not make it failing under the anchor"; }
show_relay finding
ok "phase 6: failing, agreed by 2, verified under the polity's anchor"

# --------------------------------------------------------------------------- #
# Phase 7 — THE RELAY'S WORD
# --------------------------------------------------------------------------- #
log "Phase 7: b1 files a clean attestation it made up; the relay counts it, the viewer does not"
python3 - "${ROOT[owner]}/etc/stele/ads" "${ROOT[b1]}/etc/stele" "${U[b1]}" "$C1" <<'P' \
  || fail "phase 7" "could not make the forged attestation"
import glob, json, os, sys
ads, out, me, commit = sys.argv[1:]
ad_path = next(p for p in sorted(glob.glob(ads + '/*.json'))
               if json.load(open(p)).get('commit') == commit)
os.makedirs(out + '/ads', exist_ok=True)
os.makedirs(out + '/attestations', exist_ok=True)
ad = json.load(open(ad_path))
open(out + '/ads/' + os.path.basename(ad_path), 'w').write(json.dumps(ad))
at = {'verifier': me, 'repo_ad_id': os.path.basename(ad_path)[:-5], 'commit': commit,
      'scanner': 'osv-scanner', 'scanner_version': '2.6.0', 'db_digest': 'cd' * 32,
      'findings_digest': '00' * 32, 'verdict': 'clean', 'count': 0, 'max_severity': '',
      'ts': 1790000000, 'sig': '00' * 64}
open(out + '/attestations/forged.json', 'w').write(json.dumps(at))
P
ctl relay-publish "${ROOT[b1]}" || fail "phase 7" "relay-publish failed on b1"
wait_for "$WAIT" results_is word "relays" "demo:clean>=1:state=failing" \
  || { cat "$RUN/results-word.json"; fail "phase 7" "the relay's clean word was missing or moved the viewer"; }
ok "phase 7: the relay counts b1's made-up clean scan as its word; the viewer reads failing"

# --------------------------------------------------------------------------- #
# Phase 8 — FORGERY
# --------------------------------------------------------------------------- #
log "Phase 8: an edited anchor is not followed; an edited record does not verify"
python3 - "$RUN/polity.anchor" "$RUN/edited.anchor" <<'P'
import json, sys
outer = json.load(open(sys.argv[1]))
outer['body'] = outer['body'].replace('"tier":1', '"tier":4').replace('"tier":2', '"tier":4')
json.dump(outer, open(sys.argv[2], 'w'))
P
if ctl anchor-follow "${ROOT[viewer]}" "$RUN/edited.anchor" >/dev/null 2>&1; then
  fail "phase 8" "the viewer followed an anchor edited after signing"
fi
python3 - "${ROOT[viewer]}/etc/stele/relay" "$RUN/edited-bundle.json" <<'P' \
  || fail "phase 8" "no fetched bundle to edit"
import glob, json, sys
doc = json.load(open(sorted(glob.glob(sys.argv[1] + '/fetch-*.json'))[-1]))
b = next(r['answer']['bundle'] for r in doc['relays'] if r['answer'].get('bundle'))
assert b['records']
for r in b['records']:
    r['entry']['p1_score'] = 0.8
json.dump(b, open(sys.argv[2], 'w'))
P
ctl standing "${ROOT[viewer]}" "$URL" --bundle "$RUN/edited-bundle.json" >"$RUN/edited-standing.json" 2>/dev/null
python3 -c "import json,sys; d=json.load(open(sys.argv[1]))['bundle']; sys.exit(0 if d['verified']==0 and len(d['unverified'])>0 else 1)" \
  "$RUN/edited-standing.json" || { cat "$RUN/edited-standing.json"; fail "phase 8" "an edited record verified"; }
ok "phase 8: the edited anchor refused, the edited records unverified"

# --------------------------------------------------------------------------- #
# Phase 9 — UNFOLLOWED
# --------------------------------------------------------------------------- #
log "Phase 9: the viewer stops following the polity"
ISSUER="$(python3 "$TEAM" issuer "$SPEC")"
ctl anchor-unfollow "${ROOT[viewer]}" "$ISSUER" >/dev/null
wait_for "$WAIT" relay_is unfollowed "$URL" anchored=no reason="group not followed" green=no \
  || { cat "$RUN/relay-unfollowed.json"; fail "phase 9" "the repository still verified with the polity unfollowed"; }
show_relay unfollowed
ok "phase 9: listed, and nothing about it verified, once the polity is not followed"

log "PASS: stele relay red team — another group's repository found through a relay and verified only under the anchor of a polity the viewer follows; an omitted finding read unknown until anyone published it; the relay's word labelled and never believed; forged anchors and records refused"
exit 0
