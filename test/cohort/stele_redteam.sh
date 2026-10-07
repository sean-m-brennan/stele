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
# stele_redteam.sh — Stele Phase 2's exit: each of the four owner attacks of
# CODE_SHARING_PLAN §5 fails on a hostile instance, and no single verifier is
# authoritative.
#
# Real steled nodes on one virtual L2 segment (bridge + netns):
#
#   owner    — HOSTILE: publishes a repository with a known CVE and then tries
#              every way it has to show a green standing anyway
#   verifier — scans the owner's commit and attests the finding (`probe`)
#   auditor  — a second verifier: re-runs the verifier's check and attests what
#              it got (`replication`); tier 3 in its co-signers' view
#   observer — the viewer: co-signs as admissible, and its stele_view folds the
#              standing the trust panel shows
#   shill    — the owner's sybil, started late: a fresh node the owner controls
#   rogue    — a modified build (libautonomous_trust with bytes appended),
#              which reports its own, different, package hash
#
# Every node but the rogue runs the same build, and each holds an allowlist
# (etc/at/package_hashes.cfg.json) naming that build's hash, which the founder
# reports in its log before anyone joins.
#
# What it proves, in order:
#   1. Discovery: owner, verifier, auditor and observer form one group.
#   2. The verifier and the auditor reach tier 3 in each co-signer's view, and
#      in the observer's roster.
#   3. ATTACK 4, a patched build: the rogue asks to join and is refused as a
#      counterfeit, and never enters the observer's roster. (A build patched
#      to report the HONEST hash would get in; that is the owner below, who
#      runs the honest binary and attacks from outside it.)
#   4. The finding, confirmed: the verifier attests osv-scanner's finding; the
#      auditor replicates it. The observer's standing is failing, agreed by 2.
#   5. ATTACK 1½, refusing to countersign: the owner signed neither entry, and
#      both committed.
#   6. ATTACK 1, a green badge: the owner serves a forged bundle (its own key,
#      a group of one, "clean") and a tampered one (the real records with the
#      finding edited out). The observer's stele_view verifies neither against
#      its own roster, while the real bundle verifies; the standing stays
#      failing. FORGE=1 serves the forged bundle from Forgejo as
#      .stele/standing.json, the path the extension reads.
#   7. ATTACK 2, stripping the finding: the owner rewrites the finding in its
#      own history and restarts; the observer's records still verify and its
#      standing stays failing. The owner's shill joins and attests a clean
#      probe and a clean replication: the replication is refused below tier
#      3, the shill is not counted, and the standing is still failing, not
#      disputed. The owner's attestation about itself never commits.
#   8. ATTACK 3, firing the auditor: in a solo repository's group the owner
#      cannot expel anyone, so it withdraws: its node stops. The auditor
#      attests a further finding, which commits on the others' quorum. (A
#      team expelling its auditor is Phase 3, Ethne.)
#   9. The answer is evidence: the owner fixes the commit; one verifier's clean
#      scan is single-source, and with the auditor's replication it is
#      verified-safe, the only green there is.
#
# NETNS ONLY, on a HOST. Requirements as stele_cohort.sh (root, iproute2,
# python3 + pynacl, git, curl, readelf, ../../build.sh). osv-scanner and its Go
# database are fetched unless OSV_SCANNER / OSV_DB name them. FORGE=1 also
# needs forge/up.sh run first.
#
# Usage:
#   sudo -E env "PATH=$PATH" ./test/cohort/stele_redteam.sh
#   FORGE=1 KEEP=1 sudo -E env "PATH=$PATH" ./test/cohort/stele_redteam.sh
#
# Env knobs: WAIT (per phase, default 180), WARM_WAIT (phase 2, default 900),
#   CHECKPOINT_SEC (default 20), RESCORE_SEC (default 5), TIER_REP (the tier-3
#   floor phase 2 waits for, default 0.80), SUBNET (default 10.9.13),
#   BUILD_DIR, LOG_LEVEL, KEEP=1, FORGE=1, VIEW_PORT (default 18199).

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STELE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$STELE_DIR/native/build}"
STELED="$BUILD_DIR/steled"
SHIM="$BUILD_DIR/libstele_shim.so"
ATCORE="$BUILD_DIR/at_core"
CTL="$STELE_DIR/tools/stele_ctl.py"
HOOK="$STELE_DIR/verifier/stele_hook.py"
FORGER="$SCRIPT_DIR/forge_bundle.py"
VIEWER="$STELE_DIR/viewer/stele_view.py"

WAIT="${WAIT:-180}"
WARM_WAIT="${WARM_WAIT:-900}"
CHECKPOINT_SEC="${CHECKPOINT_SEC:-20}"
RESCORE_SEC="${RESCORE_SEC:-5}"
TIER_REP="${TIER_REP:-0.80}"
LOG_LEVEL="${LOG_LEVEL:-2}"
SUBNET="${SUBNET:-10.9.13}"
PREFIX=24
VIEW_PORT="${VIEW_PORT:-18199}"

MEMBERS=(owner verifier auditor observer)
NODES=(owner verifier auditor observer shill rogue)
declare -A IP NS V VB ROOT PID LIBDIR U
i=31
for n in "${NODES[@]}"; do
  IP[$n]="$SUBNET.$i"; NS[$n]="agrt$n"; V[$n]="agrt${n:0:4}"; VB[$n]="agrt${n:0:4}b"
  i=$(( i + 1 ))
done
BR=agbr13

RUN="${STELE_COHORT_RUN:-$STELE_DIR/.coh/rt-$$}"
for n in "${NODES[@]}"; do ROOT[$n]="$RUN/$n"; PID[$n]=""; mkdir -p "${ROOT[$n]}/etc/at"; done

# shellcheck source=lib.sh
. "$SCRIPT_DIR/lib.sh"

preflight
have readelf || { err "readelf not found (binutils)."; exit 1; }
fetch_osv

VIEW_PID=""
dump_logs() {
  local n
  for n in "${NODES[@]}"; do
    [ -f "${ROOT[$n]}/node.log" ] || continue
    echo "--- $n ---"
    tail -n 30 "${ROOT[$n]}/node.log"
  done
  [ -f "$RUN/view.log" ] && { echo "--- stele_view ---"; tail -n 20 "$RUN/view.log"; }
}
fail() { err "FAIL ($1) — $2"; dump_logs; exit 1; }

cleanup() {
  local rc="${1:-0}" n
  [ -n "$VIEW_PID" ] && kill "$VIEW_PID" 2>/dev/null
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

joined() { # node peer
  saw "$1" "Network: added peer $2 "
}
start_and_join() { # node others...
  local n="$1" m; shift
  node_start "$n"
  sleep 3
  kill -0 "${PID[$n]}" 2>/dev/null || fail "start" "$n died at start"
  for m in "$@"; do
    wait_for "$WAIT" joined "$n" "$m" || fail "start" "$n never added $m at the network layer"
  done
}
records_about() { # node subject -> count of verified records
  ctl verify "${ROOT[$1]}" "$2" >"$RUN/records-$1.json" 2>/dev/null
  python3 -c "import json,sys; print(sum(r['verified'] for r in json.load(open(sys.argv[1]))['records']))" \
    "$RUN/records-$1.json" 2>/dev/null || echo 0
}
committed_on() { # node -> how many attested scores it committed
  count "$1" "attested score committed"
}

net_up || exit 1

# --------------------------------------------------------------------------- #
# Phase 1 — discovery, under an allowlist of the honest build
# --------------------------------------------------------------------------- #
log "Phase 1: the owner founds the group and reports its package hash"
node_start owner
wait_for "$WAIT" saw owner "Identity: package hash c:" \
  || fail "phase 1" "the owner never reported its package hash (an AT built before Phase 2?)"
HONEST="$(grep -o 'Identity: package hash c:[0-9a-f]*' "${ROOT[owner]}/node.log" | head -1 | awk '{print $4}')"
[ "${#HONEST}" -eq 66 ] || fail "phase 1" "unexpected package hash '$HONEST'"
wait_for "$WAIT" saw owner "self-bootstrapping a fresh group" || fail "phase 1" "the owner never founded a group"
for n in "${NODES[@]}"; do
  printf '{"accepted": ["%s"]}\n' "$HONEST" >"${ROOT[$n]}/etc/at/package_hashes.cfg.json"
done
log "  allowlist: $HONEST"
start_and_join verifier owner
start_and_join auditor owner verifier
start_and_join observer owner verifier auditor
for n in "${MEMBERS[@]}"; do
  for m in "${MEMBERS[@]}"; do
    [ "$m" = "$n" ] && continue
    wait_for "$WAIT" joined "$n" "$m" || fail "phase 1" "$n never added $m"
  done
done
for n in "${MEMBERS[@]}"; do
  U[$n]="$(ctl uuid "${ROOT[$n]}")" || fail "phase 1" "no identity for $n"
done
ok "phase 1: four nodes, one group, all on the allowlisted build"

# --------------------------------------------------------------------------- #
# Phase 2 — two verifiers at tier 3
# --------------------------------------------------------------------------- #
log "Phase 2: waiting for the verifier and the auditor to reach $TIER_REP (tier 3) in every co-signer's view (up to ${WARM_WAIT}s)"
for pair in "observer verifier" "observer auditor" "verifier auditor" "auditor verifier"; do
  set -- $pair
  wait_for "$WARM_WAIT" above "$1" "${U[$2]}" "$TIER_REP" \
    || fail "phase 2" "$1 holds $2 at '$(rep_of "$1" "${U[$2]}")', below $TIER_REP"
done
for v in verifier auditor; do
  wait_for "$WARM_WAIT" tier_at_least observer "${U[$v]}" 3 \
    || fail "phase 2" "the observer's roster does not record $v at tier 3"
done
ok "phase 2: observer holds verifier at $(rep_of observer "${U[verifier]}"), auditor at $(rep_of observer "${U[auditor]}"); both tier 3 in its roster"

# --------------------------------------------------------------------------- #
# Phase 3 — ATTACK 4: a patched build asks to join
# --------------------------------------------------------------------------- #
NEEDED="$(readelf -d "$STELED" | sed -n 's/.*Shared library: \[\(libautonomous_trust[^]]*\)\].*/\1/p' | head -1)"
[ -n "$NEEDED" ] || fail "phase 3" "steled does not load libautonomous_trust dynamically; patch it differently"
LIBDIR[rogue]="$RUN/patched"
mkdir -p "${LIBDIR[rogue]}"
cp -L "$ATCORE/$NEEDED" "${LIBDIR[rogue]}/$NEEDED" || fail "phase 3" "could not copy $NEEDED"
printf 'stele red team: a modified build\n' >>"${LIBDIR[rogue]}/$NEEDED"
log "Phase 3: the rogue, on a modified $NEEDED, asks to join"
node_start rogue
wait_for "$WAIT" saw rogue "Identity: package hash c:" || fail "phase 3" "the rogue never started"
ROGUE_HASH="$(grep -o 'Identity: package hash c:[0-9a-f]*' "${ROOT[rogue]}/node.log" | head -1 | awk '{print $4}')"
[ "$ROGUE_HASH" != "$HONEST" ] || fail "phase 3" "the modified library hashes the same as the honest one"
refused_somewhere() {
  local n
  for n in "${MEMBERS[@]}"; do saw "$n" "Counterfeit .*rogue.* refused" && return 0; done
  return 1
}
wait_for "$WAIT" refused_somewhere || fail "phase 3" "no member refused the rogue as a counterfeit"
U[rogue]="$(ctl uuid "${ROOT[rogue]}")"
sleep $(( CHECKPOINT_SEC * 2 + 10 ))
in_roster observer "${U[rogue]}" && fail "phase 3" "the rogue is in the observer's roster"
node_stop rogue
ok "phase 3: the modified build (${ROGUE_HASH:0:14}…) was refused and never joined"

# --------------------------------------------------------------------------- #
# Phase 4 — the finding, and its replication
# --------------------------------------------------------------------------- #
REPO="$RUN/repo"
cp -r "$STELE_DIR/forge/seed" "$REPO"
git -C "$REPO" init --quiet -b main
git -C "$REPO" -c user.name=owner -c user.email=owner@stele add .
git -C "$REPO" -c user.name=owner -c user.email=owner@stele commit --quiet -m "seed"
C1="$(git -C "$REPO" rev-parse HEAD)"
if [ "${FORGE:-0}" = "1" ]; then
  [ -f "$STELE_DIR/forge/.forge.env" ] || fail "phase 4" "FORGE=1 but forge/.forge.env is missing; run forge/up.sh"
  # shellcheck disable=SC1091
  . "$STELE_DIR/forge/.forge.env"
  CLONE_URL="$REPO_URL"
  PUSH_URL="${FORGE_URL/http:\/\//http://$FORGE_USER:$FORGE_PASS@}/$FORGE_USER/demo.git"
  git -C "$REPO" push --quiet --force "$PUSH_URL" main || fail "phase 4" "push to Forgejo failed"
else
  CLONE_URL="file://$REPO"
fi
python3 - "$RUN/hook.json" "$OSV_SCANNER" "$OSV_DB" <<'P'
import json, sys
json.dump({'osv_scanner': sys.argv[2], 'osv_db': sys.argv[3], 'scanners': ['osv-scanner']},
          open(sys.argv[1], 'w'))
P
advertise() { # commit seq
  local c="$1" seq="$2" n
  held() { local n; for n in verifier auditor observer; do saw "$n" "stele repo demo@${c:0:12}" || return 1; done; }
  for _ in 1 2 3 4 5; do
    ctl advertise "${ROOT[owner]}" demo "$CLONE_URL" main "$c" "$seq" >/dev/null
    wait_for 15 held && return 0
  done
  return 1
}
scan_and_attest() { # verifier-node commit
  STELE_SHIM="$SHIM" LD_LIBRARY_PATH="$ATCORE:${LD_LIBRARY_PATH:-}" python3 - \
    "$HOOK" "${ROOT[$1]}" "${U[owner]}" "$2" "$CLONE_URL" "$RUN/hook.json" <<'P'
import importlib.util, json, sys
hook_path, root, owner, commit, url, cfg_path = sys.argv[1:]
spec = importlib.util.spec_from_file_location('stele_hook', hook_path)
hook = importlib.util.module_from_spec(spec); spec.loader.exec_module(hook)
cfg = json.load(open(cfg_path))
report = hook.scan_commit(url, commit, cfg['osv_scanner'], cfg['osv_db'])
sys.exit(hook.attest(root, owner, commit, report, cfg, 'osv-scanner', url))
P
}
# Phase 2 saw tier 3 once. A standing near the floor can sink below it by
# the time the replication is proposed, and then every co-signer declines it
# (rt-1865809, 2026-10-07), so check again in each co-signer's view first.
replicator_at_tier() { # replicator-node phase
  local n
  for n in verifier observer; do
    [ "$n" = "$1" ] && continue
    wait_for "$WARM_WAIT" above "$n" "${U[$1]}" "$TIER_REP" \
      || fail "$2" "$n holds $1 at '$(rep_of "$n" "${U[$1]}")', below $TIER_REP, before its replication"
  done
}
replicate() { # replicator-node -> prints the pass's JSON
  STELE_SHIM="$SHIM" LD_LIBRARY_PATH="$ATCORE:${LD_LIBRARY_PATH:-}" \
    python3 "$HOOK" replicate --root "${ROOT[$1]}" --config "$RUN/hook.json" 2>>"$RUN/hook.log" \
    | tail -1
}

log "Phase 4: the owner advertises demo @ ${C1:0:12}; the verifier scans and attests, the auditor replicates"
advertise "$C1" 1 || fail "phase 4" "the members never held the owner's ad"
before="$(committed_on observer)"
scan_and_attest verifier "$C1" >>"$RUN/hook.log" 2>&1 || fail "phase 4" "the verifier's scan or attest failed"
wait_for "$WAIT" saw auditor "stele attestation .* from verifier" \
  || fail "phase 4" "the auditor never held the verifier's attestation"
replicator_at_tier auditor "phase 4"
REPL="$(replicate auditor)"
python3 -c "import json,sys; d=json.loads(sys.argv[1]); sys.exit(0 if 'vuln' in d.values() else 1)" "$REPL" \
  || fail "phase 4" "the auditor's replication pass did not reproduce the finding: $REPL"
two_more() { [ "$(committed_on observer)" -ge $(( before + 2 )) ]; }
wait_for "$WAIT" two_more || fail "phase 4" "the observer did not commit both the probe and its replication"
wait_for "$WAIT" standing_is observer c1 commit="$C1" state=failing agree=osv-scanner:probe:2 \
  || { cat "$RUN/standing-c1.json"; fail "phase 4" "the observer's standing is not a confirmed finding"; }
show_standing c1
ok "phase 4: failing, confirmed by two verifiers"

# --------------------------------------------------------------------------- #
# Phase 5 — ATTACK 1½: the owner's signature is not needed
# --------------------------------------------------------------------------- #
saw owner "co-signed attest_propose" && fail "phase 5" "the owner co-signed an attestation about itself"
python3 - "${ROOT[observer]}/etc/at/attested" "${U[owner]}" <<'P' || fail "phase 5" "a record carries the owner's signature"
import glob, json, sys
for path in glob.glob(sys.argv[1] + '/*.json'):
    rec = json.load(open(path))
    if rec['entry'].get('subject_id') == sys.argv[2] and sys.argv[2] in (rec['entry'].get('attest_sigs') or {}):
        sys.exit(1)
P
ok "phase 5: both entries committed and archived without the owner's signature"

# --------------------------------------------------------------------------- #
# Phase 6 — ATTACK 1: the owner serves a green badge
# --------------------------------------------------------------------------- #
log "Phase 6: the owner forges a bundle; the observer's stele_view is asked to believe it"
ctl bundle "${ROOT[observer]}" "$CLONE_URL" >"$RUN/real.json" || fail "phase 6" "no real bundle to forge from"
python3 "$FORGER" "$RUN/real.json" "$RUN/forgery" >"$RUN/forger.log" 2>&1 \
  || { cat "$RUN/forger.log"; fail "phase 6" "the forger failed"; }
sed 's/^/    /' "$RUN/forger.log"
for f in forged tampered; do
  [ -s "$RUN/forgery/$f.json" ] || fail "phase 6" "the forger wrote no $f.json"
done
python3 "$VIEWER" --root "${ROOT[observer]}" --port "$VIEW_PORT" >"$RUN/view.log" 2>&1 &
VIEW_PID=$!
wait_for 20 curl -fs "http://127.0.0.1:$VIEW_PORT/health" -o /dev/null \
  || fail "phase 6" "stele_view never answered on 127.0.0.1:$VIEW_PORT"
ENC="$(python3 -c "import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=''))" "$CLONE_URL")"
post() { # file label
  curl -fs -X POST -H 'Content-Type: application/json' --data-binary "@$1" \
    "http://127.0.0.1:$VIEW_PORT/verify?url=$ENC" -o "$RUN/verify-$2.json"
}
judge() { # label min-verified max-verified state
  python3 - "$RUN/verify-$1.json" "$2" "$3" "$4" <<'P'
import json, sys
r = json.load(open(sys.argv[1]))
lo, hi, state = int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
ok = lo <= r['verified'] <= hi and r['standing'].get('state') == state
print(f"    {sys.argv[1].rsplit('/', 1)[-1]}: {r['verified']} verified, "
      f"{len(r['unverified'])} refused, standing {r['standing'].get('state')}")
for u in r['unverified'][:2]:
    print(f"      refused: {'; '.join(u['reasons'])}")
sys.exit(0 if ok else 1)
P
}
post "$RUN/real.json" real || fail "phase 6" "POST /verify (real) failed"
judge real 2 99 failing || fail "phase 6" "the real bundle did not verify"
post "$RUN/forgery/forged.json" forged || fail "phase 6" "POST /verify (forged) failed"
judge forged 0 0 failing || fail "phase 6" "the forged bundle was believed"
post "$RUN/forgery/tampered.json" tampered || fail "phase 6" "POST /verify (tampered) failed"
judge tampered 0 0 failing || fail "phase 6" "the tampered bundle was believed"
if [ "${FORGE:-0}" = "1" ]; then
  mkdir -p "$REPO/.stele"
  cp "$RUN/forgery/forged.json" "$REPO/.stele/standing.json"
  git -C "$REPO" -c user.name=owner -c user.email=owner@stele add .stele
  git -C "$REPO" -c user.name=owner -c user.email=owner@stele commit --quiet -m "a green badge"
  git -C "$REPO" push --quiet --force "$PUSH_URL" main || fail "phase 6" "push to Forgejo failed"
  RAW="$FORGE_URL/$FORGE_USER/demo/raw/branch/main/.stele/standing.json"
  wait_for 30 curl -fs "$RAW" -o "$RUN/served.json" || fail "phase 6" "Forgejo does not serve $RAW"
  post "$RUN/served.json" served || fail "phase 6" "POST /verify (served) failed"
  judge served 0 0 failing || fail "phase 6" "the bundle served by the forge was believed"
fi
kill "$VIEW_PID" 2>/dev/null; VIEW_PID=""
ok "phase 6: the forged and tampered bundles verify against nothing the observer holds; the real one does; still failing"

# --------------------------------------------------------------------------- #
# Phase 7 — ATTACK 2: strip the finding
# --------------------------------------------------------------------------- #
log "Phase 7: the owner rewrites the finding in its own history and restarts"
NREC="$(records_about observer "${U[owner]}")"
node_stop owner
HIST="${ROOT[owner]}/etc/at/reputation-history.cfg.json"
if [ -f "$HIST" ]; then
  python3 - "$HIST" <<'P'
import json, sys
doc = json.load(open(sys.argv[1]))
for e in doc.get('chain') or []:
    if e.get('attested'):
        e['p1_score'] = 0.8
json.dump(doc, open(sys.argv[1], 'w'))
P
else
  log "  (the owner kept no history file; it restarts with none)"
fi
node_start owner
sleep 4
kill -0 "${PID[owner]}" 2>/dev/null || fail "phase 7" "the owner died on restart"
sleep $(( CHECKPOINT_SEC * 2 ))
[ "$(records_about observer "${U[owner]}")" -ge "$NREC" ] || fail "phase 7" "the observer's verified records fell"
standing_is observer c1b commit="$C1" state=failing agree=osv-scanner:probe:2 \
  || { cat "$RUN/standing-c1b.json"; fail "phase 7" "the owner's rewrite moved the observer's standing"; }
ok "phase 7a: the owner's rewrite moved nothing the observer holds ($NREC record(s) verify)"

log "Phase 7: the owner's shill joins and vouches for the repository"
# The owner hands its shill everything it holds (its ad, the attestations
# about it), so the shill's verbs reach AT rather than stopping at Stele's
# "not a held attestation".
mkdir -p "${ROOT[shill]}/etc/stele"
cp -r "${ROOT[owner]}/etc/stele/ads" "${ROOT[owner]}/etc/stele/attestations" "${ROOT[shill]}/etc/stele/" \
  || fail "phase 7" "the owner holds no Stele store to hand over"
node_start shill
wait_for "$WAIT" joined observer shill || fail "phase 7" "the shill never joined"
U[shill]="$(ctl uuid "${ROOT[shill]}")"
echo '{"results": []}' >"$RUN/clean-osv.json"
read -r DBD VER < <(python3 - "$STELE_DIR/verifier" "$RUN/hook.json" <<'P'
import json, sys
sys.path.insert(0, sys.argv[1])
import scanners
cfg = json.load(open(sys.argv[2]))
print(scanners.db_digest_of('osv-scanner', cfg), scanners.version_of('osv-scanner', cfg))
P
)
ORIG="$(python3 - "${ROOT[observer]}/etc/stele/attestations" "${U[verifier]}" "$C1" <<'P'
import glob, json, sys
for path in glob.glob(sys.argv[1] + '/*.json'):
    a = json.load(open(path))
    if a.get('verifier') == sys.argv[2] and a.get('commit') == sys.argv[3] \
            and a.get('channel', 'probe') == 'probe' and a.get('scanner') == 'osv-scanner':
        print(path.rsplit('/', 1)[-1][:-5]); break
P
)"
[ -n "$ORIG" ] || fail "phase 7" "no verifier attestation to replicate"
ctl attest "${ROOT[shill]}" "${U[owner]}" "$C1" "$RUN/clean-osv.json" "$DBD" "$VER" \
  --scanner osv-scanner --url "$CLONE_URL" --replicates "$ORIG" >>"$RUN/hook.log" 2>&1
refused_replication() {
  local n
  for n in verifier auditor observer; do saw "$n" "declining attest_propose from .*below 3 for replication" && return 0; done
  return 1
}
wait_for "$WAIT" refused_replication || fail "phase 7" "nobody refused the shill's replication at tier 3"
ctl attest "${ROOT[shill]}" "${U[owner]}" "$C1" "$RUN/clean-osv.json" "$DBD" "$VER" \
  --scanner osv-scanner --url "$CLONE_URL" >>"$RUN/hook.log" 2>&1
ctl attest "${ROOT[owner]}" "${U[owner]}" "$C1" "$RUN/clean-osv.json" "$DBD" "$VER" \
  --scanner osv-scanner --url "$CLONE_URL" >>"$RUN/hook.log" 2>&1
sleep $(( CHECKPOINT_SEC * 2 + 10 ))
python3 - "${ROOT[observer]}/etc/at/attested" "${U[owner]}" <<'P' || fail "phase 7" "an attestation by the owner about itself committed"
import glob, json, sys
for path in glob.glob(sys.argv[1] + '/*.json'):
    e = json.load(open(path))['entry']
    if e.get('p1_id') == sys.argv[2]:
        sys.exit(1)
P
standing_is observer c1s commit="$C1" state=failing agree=osv-scanner:probe:2 \
  || { cat "$RUN/standing-c1s.json"; fail "phase 7" "the shill moved the observer's standing"; }
if standing_is observer c1s2 counted=osv-scanner:probe:"${U[shill]}":yes; then
  fail "phase 7" "the observer counted the shill"
fi
show_standing c1s
ok "phase 7: the shill's replication refused below tier 3, its clean probe not counted, the owner's own never committed; still failing"

# --------------------------------------------------------------------------- #
# Phase 8 — ATTACK 3: the owner withdraws; the auditor's finding still lands
# --------------------------------------------------------------------------- #
log "Phase 8: the owner stops its node; the auditor attests a further finding"
node_stop owner
node_stop shill
echo '[{"RuleID": "generic-api-key", "File": "config.go", "StartLine": 3}]' >"$RUN/gitleaks.json"
before="$(committed_on observer)"
ctl attest "${ROOT[auditor]}" "${U[owner]}" "$C1" "$RUN/gitleaks.json" "$DBD" 8.21.2 \
  --scanner gitleaks --url "$CLONE_URL" >>"$RUN/hook.log" 2>&1 \
  || fail "phase 8" "the auditor's attest verb failed"
one_more() { [ "$(committed_on observer)" -gt "$before" ]; }
wait_for "$WAIT" one_more || fail "phase 8" "the auditor's finding did not commit without the owner"
wait_for "$WAIT" standing_is observer c1g commit="$C1" has=gitleaks:probe:vuln \
  || { cat "$RUN/standing-c1g.json"; fail "phase 8" "the observer never showed the auditor's finding"; }
ok "phase 8: the auditor's finding committed on the others' quorum with the owner gone"

# --------------------------------------------------------------------------- #
# Phase 9 — the fix: single-source, then verified-safe
# --------------------------------------------------------------------------- #
log "Phase 9: the owner returns, drops x/net and releases; two verifiers scan the fix"
node_start owner
wait_for "$WAIT" joined observer owner || true
printf 'package main\n\nfunc main() {}\n' >"$REPO/main.go"
printf 'module example.com/demo\n\ngo 1.21\n' >"$REPO/go.mod"
rm -rf "$REPO/.stele"
git -C "$REPO" -c user.name=owner -c user.email=owner@stele add -A
git -C "$REPO" -c user.name=owner -c user.email=owner@stele commit --quiet -m "drop golang.org/x/net"
C2="$(git -C "$REPO" rev-parse HEAD)"
[ "${FORGE:-0}" = "1" ] && { git -C "$REPO" push --quiet --force "$PUSH_URL" main || fail "phase 9" "push failed"; }
advertise "$C2" 2 || fail "phase 9" "the members never held the owner's ad for ${C2:0:12}"
scan_and_attest verifier "$C2" >>"$RUN/hook.log" 2>&1 || fail "phase 9" "the verifier's scan of the fix failed"
wait_for "$WAIT" standing_is observer c2a commit="$C2" state=single-source has=osv-scanner:probe:clean \
  || { cat "$RUN/standing-c2a.json"; fail "phase 9" "one verifier's clean scan is not single-source"; }
show_standing c2a
wait_for "$WAIT" saw auditor "stele attestation .* (clean, 0) from verifier" \
  || fail "phase 9" "the auditor never held the verifier's clean attestation"
replicator_at_tier auditor "phase 9"
REPL="$(replicate auditor)"
python3 -c "import json,sys; d=json.loads(sys.argv[1]); sys.exit(0 if 'clean' in d.values() else 1)" "$REPL" \
  || fail "phase 9" "the auditor's replication pass did not reproduce the clean scan: $REPL"
wait_for "$WAIT" standing_is observer c2b commit="$C2" state=verified-safe agree=osv-scanner:probe:2 \
  || { cat "$RUN/standing-c2b.json"; fail "phase 9" "two agreeing verifiers did not make it verified-safe"; }
show_standing c2b
ok "phase 9: single-source on one verifier, verified-safe on two"

log "PASS: stele red team — a patched build refused, a forged and a tampered badge disbelieved, the finding unstrippable, the shill uncounted, the auditor unfireable; green only on two verifiers' agreement"
exit 0
