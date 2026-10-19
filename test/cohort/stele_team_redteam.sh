#!/bin/bash
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
# stele_team_redteam.sh — Stele Phase 3's exit: a team cannot raise its badge,
# hide a finding, or expel its auditor (CODE_SHARING_PLAN §6, §8 Phase 3).
#
# Real steled nodes on one virtual L2 segment (bridge + netns):
#
#   officer  — the TEAM's release officer: advertises the team's releases,
#              signed under its office, and attacks from outside the binary
#   mate     — a teammate, and the guardian of the team's build machine
#   ci       — the team's build machine (a member the guardian answers for)
#   verifier — scans the team's release and attests (`probe`)
#   auditor  — a second verifier: replicates the verifier's check
#   observer — the viewer: co-signs as admissible, folds the standings
#
# The team is an Ethne polity (tools/stele_team.py founds it in an Ethne
# archive when an Ethne build with design D41 is importable, and writes the
# same file formats itself otherwise). Its root key signs the team roster, and
# every member's AT node consents to being listed with its own key.
#
# What it proves, in order:
#   1. Discovery: six nodes, one group, all on the allowlisted build.
#   2. The team roster, sent by the officer, is held by every node, and AT's
#      conflict set on the observer names exactly the team's three nodes.
#   3. The verifier and the auditor reach tier 3 in each co-signer's view.
#   4. The team's release with a known CVE: the observer attributes it to the
#      team, the verifier finds it, the auditor replicates it, and it commits
#      with the team's own nodes declining to witness. The repository and the
#      team are failing.
#   5. The finding lands on the guardian of the build machine (0.45), once two
#      verifiers confirm it, and is the team's concern.
#   6. HIDE A FINDING / RAISE THE BADGE: a newer roster that drops the officer
#      and the machine changes nothing the observer holds: the release stays
#      the team's, and the team stays failing.
#   7. EXPEL THE AUDITOR: a roster that claims the auditor as a teammate,
#      with a consent the officer forged, is refused by the officer's own node
#      (the honest build checks consents before it sends anything), no node
#      holds it, the auditor stays outside the conflict set, and its
#      replication keeps counting. (Refusal on receipt is pinned by the
#      conformance case stele-team-roster-without-consent-refused.)
#   8. The fix: single-source on one verifier, verified-safe on two, and the
#      team green only then.
#
# Needs root, a built steled (./build.sh) and network access for osv-scanner
# and its database. Usage:
#
#   sudo -E env "PATH=$PATH" ./test/cohort/stele_team_redteam.sh
#   FORGE=1 KEEP=1 sudo -E env "PATH=$PATH" ./test/cohort/stele_team_redteam.sh
#
# Environment: WAIT (default 180), WARM_WAIT (900), CHECKPOINT_SEC (20),
#   RESCORE_SEC (5), TIER_REP (0.80), SUBNET (10.9.14), BUILD_DIR, LOG_LEVEL,
#   KEEP=1, FORGE=1, STELE_TEAM_BUILTIN=1 (skip Ethne).
#   MIN_TENURE (AT_REP_MIN_TENURE_SEC, default 300: a member holds at most
#   tier 2 until a node has held it that long; steled's own default is 3600).

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STELE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$STELE_DIR/native/build}"
STELED="$BUILD_DIR/steled"
SHIM="$BUILD_DIR/libstele_shim.so"
ATCORE="$BUILD_DIR/at_core"
CTL="$STELE_DIR/tools/stele_ctl.py"
TEAMTOOL="$STELE_DIR/tools/stele_team.py"
HOOK="$STELE_DIR/verifier/stele_hook.py"

WAIT="${WAIT:-180}"
WARM_WAIT="${WARM_WAIT:-900}"
CHECKPOINT_SEC="${CHECKPOINT_SEC:-20}"
RESCORE_SEC="${RESCORE_SEC:-5}"
TIER_REP="${TIER_REP:-0.80}"
LOG_LEVEL="${LOG_LEVEL:-2}"
SUBNET="${SUBNET:-10.9.14}"
PREFIX=24

NODES=(officer mate ci verifier auditor observer)
OUTSIDE=(verifier auditor observer)
declare -A IP NS V VB ROOT PID LIBDIR U
i=41
for n in "${NODES[@]}"; do
  IP[$n]="$SUBNET.$i"; NS[$n]="agtm$n"; V[$n]="agtm${n:0:4}"; VB[$n]="agtm${n:0:4}b"
  i=$(( i + 1 ))
done
BR=agbr14

RUN="${STELE_COHORT_RUN:-$STELE_DIR/.coh/tm-$$}"
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

cleanup() {
  local rc="${1:-0}" n
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
committed_on() { count "$1" "attested score committed"; }
team() { # tool args...
  local builtin=()
  [ "${STELE_TEAM_BUILTIN:-0}" = "1" ] && builtin=(--builtin)
  python3 "$TEAMTOOL" "$@" "${builtin[@]}" 2>>"$RUN/team.log"
}
# The team standing the observer folds, checked against specs: state=S
# concern=CHANNEL (a concern on that channel) repos=N.
team_is() { # label spec...
  local label="$1"; shift
  ctl team-standing "${ROOT[observer]}" "$ISSUER" >"$RUN/team-$label.json" 2>/dev/null
  python3 - "$RUN/team-$label.json" "$@" <<'P'
import json, sys
try:
    ts = json.load(open(sys.argv[1]))
except (OSError, ValueError):
    sys.exit(1)
for spec in sys.argv[2:]:
    k, _, v = spec.partition('=')
    if k == 'state' and ts.get('state') != v:
        sys.exit(1)
    if k == 'concern' and not any(c.get('channel') == v for c in ts.get('concerns') or []):
        sys.exit(1)
    if k == 'repos' and len(ts.get('repos') or []) != int(v):
        sys.exit(1)
P
}
show_team() { # label
  python3 - "$RUN/team-$1.json" <<'P'
import json, sys
ts = json.load(open(sys.argv[1]))
t = ts['team']
print(f"    team {t['polity'][:24]}… (seq {t['seq']}, {len(t['members'])} members): {ts['state']}")
for c in ts.get('concerns') or []:
    print(f"      [{c.get('channel')}] {c.get('repo')}: {c.get('reason')}")
P
}
conflicts_on() { # node -> the conflict set's teams, as uuid lists joined by ','
  python3 - "${ROOT[$1]}/etc/at/attest_conflicts.cfg.json" <<'P' 2>/dev/null
import json, sys
print(';'.join(','.join(sorted(t)) for t in json.load(open(sys.argv[1]))['teams']))
P
}

net_up || exit 1

# --------------------------------------------------------------------------- #
# Phase 1 — discovery, under an allowlist of the honest build
# --------------------------------------------------------------------------- #
log "Phase 1: the officer founds the group; everyone joins on the allowlisted build"
node_start officer
wait_for "$WAIT" saw officer "Identity: package hash c:" \
  || fail "phase 1" "the officer never reported its package hash"
HONEST="$(grep -o 'Identity: package hash c:[0-9a-f]*' "${ROOT[officer]}/node.log" | head -1 | awk '{print $4}')"
wait_for "$WAIT" saw officer "self-bootstrapping a fresh group" || fail "phase 1" "no group"
for n in "${NODES[@]}"; do
  printf '{"accepted": ["%s"]}\n' "$HONEST" >"${ROOT[$n]}/etc/at/package_hashes.cfg.json"
done
start_and_join mate officer
start_and_join ci officer mate
start_and_join verifier officer mate ci
start_and_join auditor officer mate ci verifier
start_and_join observer officer mate ci verifier auditor
for n in "${NODES[@]}"; do
  for m in "${NODES[@]}"; do
    [ "$m" = "$n" ] && continue
    wait_for "$WAIT" joined "$n" "$m" || fail "phase 1" "$n never added $m"
  done
done
for n in "${NODES[@]}"; do
  U[$n]="$(ctl uuid "${ROOT[$n]}")" || fail "phase 1" "no identity for $n"
done
ok "phase 1: six nodes, one group"

# --------------------------------------------------------------------------- #
# Phase 2 — the team's roster
# --------------------------------------------------------------------------- #
SPEC="$RUN/team.json"
write_spec() { # seq officers(json list) [consent-forging extra member]
  python3 - "$SPEC" "$RUN/root.key" "$1" "$2" "${3:-}" \
    "${ROOT[officer]}" "${ROOT[mate]}" "${ROOT[ci]}" "${ROOT[auditor]}" <<'P'
import json, sys
spec_path, key, seq, officers, extra, officer, mate, ci, auditor = sys.argv[1:]
members = {'officer': officer, 'mate': mate, 'ci': ci}
spec = {'root': key, 'members': members, 'officers': json.loads(officers),
        'guardians': {'ci': 'mate'}, 'seq': int(seq)}
if extra == 'auditor':
    members['auditor'] = auditor
    spec['consent_by'] = {'auditor': 'officer'}
json.dump(spec, open(spec_path, 'w'))
P
}
publish_roster() { # sender label
  team roster "$SPEC" "$RUN/roster-$2.json" || fail "roster" "stele_team.py could not write the roster"
  ctl team "${ROOT[$1]}" "$RUN/roster-$2.json" >/dev/null
}
log "Phase 2: the team's root key signs its roster; the officer sends it"
write_spec 1 '["officer"]'
ISSUER="$(team issuer "$SPEC")"
publish_roster officer s1
holds_roster() { # seq
  local n
  for n in "${NODES[@]}"; do saw "$n" "stele team ${ISSUER:0:12} roster seq $1" || return 1; done
}
wait_for "$WAIT" holds_roster 1 || fail "phase 2" "not every node held the team roster"
want="$(printf '%s\n' "${U[officer]}" "${U[mate]}" "${U[ci]}" | sort | paste -sd,)"
[ "$(conflicts_on observer)" = "$want" ] \
  || fail "phase 2" "the observer's conflict set is '$(conflicts_on observer)', not the team's three nodes"
log "  team $ISSUER ($(tail -n1 "$RUN/team.log"))"
ok "phase 2: every node holds the roster; AT's conflict set names the team's three nodes"

# --------------------------------------------------------------------------- #
# Phase 3 — two outside verifiers at tier 3
# --------------------------------------------------------------------------- #
log "Phase 3: waiting for the verifier and the auditor to reach $TIER_REP (tier 3) (up to ${WARM_WAIT}s)"
for pair in "observer verifier" "observer auditor" "verifier auditor" "auditor verifier"; do
  set -- $pair
  wait_for "$WARM_WAIT" above "$1" "${U[$2]}" "$TIER_REP" \
    || fail "phase 3" "$1 holds $2 at '$(rep_of "$1" "${U[$2]}")', below $TIER_REP"
done
for v in verifier auditor; do
  wait_for "$WARM_WAIT" tier_at_least observer "${U[$v]}" 3 \
    || fail "phase 3" "the observer's roster does not record $v at tier 3"
done
ok "phase 3: both verifiers at tier 3 in the observer's roster"

# --------------------------------------------------------------------------- #
# Phase 4 — the team's release, its finding, and its replication
# --------------------------------------------------------------------------- #
REPO="$RUN/repo"
cp -r "$STELE_DIR/forge/seed" "$REPO"
git -C "$REPO" init --quiet -b main
git -C "$REPO" -c user.name=officer -c user.email=officer@stele add .
git -C "$REPO" -c user.name=officer -c user.email=officer@stele commit --quiet -m "seed"
C1="$(git -C "$REPO" rev-parse HEAD)"
if [ "${FORGE:-0}" = "1" ]; then
  [ -f "$STELE_DIR/forge/.forge.env" ] || fail "phase 4" "FORGE=1 but forge/.forge.env is missing"
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
release() { # commit seq — the officer authorizes and advertises a team release
  local c="$1" seq="$2"
  team release "$SPEC" demo "$CLONE_URL" "$c" "$RUN/release-${c:0:12}.json" --built-by ci \
    || fail "release" "stele_team.py could not write the release authorization"
  attributed() { local n; for n in "${OUTSIDE[@]}"; do saw "$n" "stele team release demo@${c:0:12}" || return 1; done; }
  for _ in 1 2 3 4 5; do
    ctl advertise "${ROOT[officer]}" demo "$CLONE_URL" main "$c" "$seq" \
      --polity "$ISSUER" --release "$RUN/release-${c:0:12}.json" >/dev/null
    wait_for 15 attributed && return 0
  done
  return 1
}
scan_and_attest() { # verifier-node commit
  STELE_SHIM="$SHIM" LD_LIBRARY_PATH="$ATCORE:${LD_LIBRARY_PATH:-}" python3 - \
    "$HOOK" "${ROOT[$1]}" "${U[officer]}" "$2" "$CLONE_URL" "$RUN/hook.json" <<'P'
import importlib.util, json, sys
hook_path, root, owner, commit, url, cfg_path = sys.argv[1:]
spec = importlib.util.spec_from_file_location('stele_hook', hook_path)
hook = importlib.util.module_from_spec(spec); spec.loader.exec_module(hook)
cfg = json.load(open(cfg_path))
report = hook.scan_commit(url, commit, cfg['osv_scanner'], cfg['osv_db'])
sys.exit(hook.attest(root, owner, commit, report, cfg, 'osv-scanner', url))
P
}
replicator_at_tier() { # replicator-node phase
  local n
  for n in verifier observer; do
    [ "$n" = "$1" ] && continue
    wait_for "$WARM_WAIT" above "$n" "${U[$1]}" "$TIER_REP" \
      || fail "$2" "$n holds $1 at '$(rep_of "$n" "${U[$1]}")', below $TIER_REP, before its replication"
  done
}
replicate() { # replicator-node -> its pass's JSON (and its guardian pass)
  STELE_SHIM="$SHIM" LD_LIBRARY_PATH="$ATCORE:${LD_LIBRARY_PATH:-}" \
    python3 "$HOOK" replicate --root "${ROOT[$1]}" --config "$RUN/hook.json" 2>>"$RUN/hook.log" \
    | tail -1
}

log "Phase 4: the officer releases demo @ ${C1:0:12} for the team; the verifier scans, the auditor replicates"
release "$C1" 1 || fail "phase 4" "the outside nodes never attributed the release to the team"
before="$(committed_on observer)"
scan_and_attest verifier "$C1" >>"$RUN/hook.log" 2>&1 || fail "phase 4" "the verifier's scan failed"
wait_for "$WAIT" saw auditor "stele attestation .* from verifier" \
  || fail "phase 4" "the auditor never held the verifier's attestation"
replicator_at_tier auditor "phase 4"
REPL="$(replicate auditor)"
python3 -c "import json,sys; d=json.loads(sys.argv[1]); sys.exit(0 if 'vuln' in d.values() else 1)" "$REPL" \
  || fail "phase 4" "the auditor's replication did not reproduce the finding: $REPL"
two_more() { [ "$(committed_on observer)" -ge $(( before + 2 )) ]; }
wait_for "$WAIT" two_more || fail "phase 4" "the observer did not commit the probe and its replication"
for n in mate ci; do
  saw "$n" "not co-signing an attestation about a teammate" \
    || fail "phase 4" "$n co-signed an attestation about its own team"
done
wait_for "$WAIT" standing_is observer c1 commit="$C1" state=failing agree=osv-scanner:probe:2 \
  || { cat "$RUN/standing-c1.json"; fail "phase 4" "the repository is not a confirmed finding"; }
show_standing c1
python3 -c "import json,sys; st=json.load(open(sys.argv[1])); sys.exit(0 if (st.get('team') or {}).get('polity') == sys.argv[2] else 1)" \
  "$RUN/standing-c1.json" "$ISSUER" || fail "phase 4" "the standing does not name the team"
wait_for "$WAIT" team_is p4 state=failing repos=1 || { cat "$RUN/team-p4.json"; fail "phase 4" "the team is not failing"; }
show_team p4
ok "phase 4: the team's release is failing, confirmed by two outside verifiers; its own nodes witnessed nothing"

# --------------------------------------------------------------------------- #
# Phase 5 — the finding lands on the build machine's guardian
# --------------------------------------------------------------------------- #
log "Phase 5: the confirmed finding is landed on the guardian of the machine that built it"
before="$(committed_on observer)"
replicate verifier >/dev/null
guardian_committed() { saw observer "attested score committed: .* subject=${U[mate]:0:8} score=0.45"; }
wait_for "$WAIT" guardian_committed || fail "phase 5" "the guardian attestation about mate never committed"
wait_for "$WAIT" team_is p5 state=failing concern=guardian \
  || { cat "$RUN/team-p5.json"; fail "phase 5" "the guardian's finding is not the team's concern"; }
show_team p5
ok "phase 5: mate, ci's guardian, answers at 0.45; the concern is the verifier's, signed by it"

# --------------------------------------------------------------------------- #
# Phase 6 — HIDE A FINDING / RAISE THE BADGE: republish the roster without it
# --------------------------------------------------------------------------- #
log "Phase 6: the team republishes its roster with no release officer and no build machine"
python3 - "$SPEC" "${ROOT[officer]}" "${ROOT[mate]}" <<'P'
import json, sys
spec = json.load(open(sys.argv[1]))
spec.update(seq=2, officers=[], guardians={}, members={'officer': sys.argv[2], 'mate': sys.argv[3]})
json.dump(spec, open(sys.argv[1], 'w'))
P
publish_roster mate s2
wait_for "$WAIT" holds_roster 2 || fail "phase 6" "not every node held roster seq 2"
standing_is observer c1b commit="$C1" state=failing \
  || { cat "$RUN/standing-c1b.json"; fail "phase 6" "the repository's finding moved"; }
python3 -c "import json,sys; st=json.load(open(sys.argv[1])); sys.exit(0 if (st.get('team') or {}).get('polity') == sys.argv[2] else 1)" \
  "$RUN/standing-c1b.json" "$ISSUER" || fail "phase 6" "the release stopped being the team's"
team_is p6 state=failing repos=1 || { cat "$RUN/team-p6.json"; fail "phase 6" "the team stopped failing"; }
show_team p6
ok "phase 6: a shorter roster narrowed the team from now on; the release it shipped is still its, still failing"

# --------------------------------------------------------------------------- #
# Phase 7 — EXPEL THE AUDITOR: claim it as a teammate
# --------------------------------------------------------------------------- #
log "Phase 7: the team's root lists the auditor as a teammate, with a consent the officer forged"
write_spec 3 '["officer"]' auditor
publish_roster officer s3
refused() { saw officer "lists ${U[auditor]:0:8} without that node's consent"; }
wait_for "$WAIT" refused || fail "phase 7" "the officer's node did not refuse the forged roster"
sleep 10
for n in "${NODES[@]}"; do
  saw "$n" "stele team ${ISSUER:0:12} roster seq 3" && fail "phase 7" "$n held the forged roster"
done
case "$(conflicts_on observer)" in
  *"${U[auditor]}"*) fail "phase 7" "the auditor is in the observer's conflict set" ;;
esac
standing_is observer c1c commit="$C1" state=failing agree=osv-scanner:probe:2 \
  counted=osv-scanner:probe:"${U[auditor]}":yes \
  || { cat "$RUN/standing-c1c.json"; fail "phase 7" "the auditor's replication stopped counting"; }
ok "phase 7: the forged roster never left the officer's node; the auditor is still an outsider and still counts"

# --------------------------------------------------------------------------- #
# Phase 8 — the fix: single-source, then verified-safe, and the team with it
# --------------------------------------------------------------------------- #
log "Phase 8: the team restores its officer, drops x/net and releases; two verifiers scan the fix"
write_spec 4 '["officer"]'
publish_roster officer s4
wait_for "$WAIT" holds_roster 4 || fail "phase 8" "not every node held roster seq 4"
printf 'package main\n\nfunc main() {}\n' >"$REPO/main.go"
printf 'module example.com/demo\n\ngo 1.21\n' >"$REPO/go.mod"
git -C "$REPO" -c user.name=officer -c user.email=officer@stele add -A
git -C "$REPO" -c user.name=officer -c user.email=officer@stele commit --quiet -m "drop golang.org/x/net"
C2="$(git -C "$REPO" rev-parse HEAD)"
[ "${FORGE:-0}" = "1" ] && { git -C "$REPO" push --quiet --force "$PUSH_URL" main || fail "phase 8" "push failed"; }
release "$C2" 2 || fail "phase 8" "the outside nodes never attributed the fix to the team"
scan_and_attest verifier "$C2" >>"$RUN/hook.log" 2>&1 || fail "phase 8" "the verifier's scan of the fix failed"
wait_for "$WAIT" standing_is observer c2a commit="$C2" state=single-source has=osv-scanner:probe:clean \
  || { cat "$RUN/standing-c2a.json"; fail "phase 8" "one clean scan is not single-source"; }
team_is p8a state=single-source || { cat "$RUN/team-p8a.json"; fail "phase 8" "the team went green on one verifier"; }
wait_for "$WAIT" saw auditor "stele attestation .* (clean, 0) from verifier" \
  || fail "phase 8" "the auditor never held the clean attestation"
replicator_at_tier auditor "phase 8"
REPL="$(replicate auditor)"
python3 -c "import json,sys; d=json.loads(sys.argv[1]); sys.exit(0 if 'clean' in d.values() else 1)" "$REPL" \
  || fail "phase 8" "the auditor's replication did not reproduce the clean scan: $REPL"
wait_for "$WAIT" standing_is observer c2b commit="$C2" state=verified-safe agree=osv-scanner:probe:2 \
  || { cat "$RUN/standing-c2b.json"; fail "phase 8" "two agreeing verifiers did not make it verified-safe"; }
show_standing c2b
wait_for "$WAIT" team_is p8b state=verified-safe || { cat "$RUN/team-p8b.json"; fail "phase 8" "the team is not green after the fix"; }
show_team p8b
ok "phase 8: single-source on one verifier, verified-safe on two, and the team with it"

log "PASS: stele team red team — the badge unraised, the finding unhidden, the auditor unexpelled; the team green only on two outside verifiers' agreement"
