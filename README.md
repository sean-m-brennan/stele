# Stele

Decentralized code sharing in which a repository's safety standing is authored
by others and cannot be faked or suppressed by its owner. The design is
[`CODE_SHARING_PLAN.md`](CODE_SHARING_PLAN.md). This tree holds **Phase 0**: a
CVE finding lowers a repository owner's AutonomousTrust reputation, verifiably,
off the owner's hand.

## How Phase 0 works

1. The **owner's** node signs a *repo ad* (name, url, ref, commit) and
   multicasts it to its group. An ad is accepted only from its owner, against
   the owner's own key, and is never relayed.
2. The **verifier** scans that commit with osv-scanner, from its own clone and
   its own offline database snapshot. A Forgejo push can trigger it through a
   webhook, but the scan never relies on anything the forge says.
3. The verifier's node signs an *attestation* (scanner, versions, digests,
   verdict, count, severity) and submits a **verifier-attested score** about the
   ad's owner to AutonomousTrust: 0.3 for a finding, 0.8 for a clean scan, on
   the `probe` channel, with the attestation's id as its evidence digest. The
   subject comes from the ad, never from the request.
4. AT commits the score on the verifier's half plus a quorum of the other
   members, who vouch that it is admissible: an eligible verifier, a
   well-formed entry, within the rate cap. They do not vouch that it is true.
   The owner's signature is neither needed nor counted. See AT
   `doc/architecture/reputation.md`, "Verifier-attested scores".
5. Any **observer** checks the result from its own persisted evidence and the
   members' public keys. The hash links hold, the checkpoint is
   quorum-signed, and the attested entry is inside it, carrying a certificate
   the owner never signed (`tools/stele_ctl.py verify`).

## Layout

| Path | What |
|---|---|
| `at-stele/c/stele/` | the C extension (`libat_stele`): codec, identity handlers, app verbs, client API (`at_stele.h`) |
| `at-stele/python/autonomous_trust/stele/` | the Python twin, which the conformance corpus runs against the C one |
| `at-stele/conformance/` | the `stele` conformance protocol: plug-in, C and Python adapters, scenarios |
| `at-stele/test-conformance.sh` | AT's conformance run with stele plugged in |
| `native/` | `steled` (the daemon) and `libstele_shim` (what `stele_ctl.py` drives) |
| `tools/stele_ctl.py` | uuid, pubkey, advertise, attest (from an osv-scanner report), reputation, verify |
| `verifier/stele_hook.py` | webhook → clone → osv-scanner → attest, on the verifier's host |
| `forge/` | Forgejo + runner (docker compose), a seeded vulnerable repo, the owner's own (unscored) CI scan, `up.sh` |
| `test/cohort/stele_cohort.sh` | the live three-node check |

## Build

```
./build.sh                          # native/build/{steled,libstele_shim.so}
BUILD_DIR=/tmp/stele-build ./build.sh
```

It builds with the system toolchain (a conda environment is stripped), and the
AT C core comes from `../../lib/autonomous_trust` (`git submodule update --init
--recursive`).

## Tests

```
at-stele/test-conformance.sh        # AT + stele, C and Python, 0 asymmetric
python -m pytest at-stele/python/tests tools/tests verifier/tests
```

The real-scan test in `verifier/tests` runs when `STELE_OSV_SCANNER` and
`STELE_OSV_DB` are set. `STELE_OSV_DB` is a cache directory holding
`osv-scalibr/Go/all.zip`, which is what osv-scanner 2.6 reads offline.

## The live check (host only)

```
./build.sh
sudo -E env "PATH=$PATH" ./test/cohort/stele_cohort.sh
```

It runs three `steled` nodes (owner, verifier, observer) in network
namespaces. It fetches osv-scanner and the Go database into the run directory
unless `OSV_SCANNER` / `OSV_DB` name them. The phases:

1. discovery;
2. the verifier rises above the attestation floor in the observer's view;
3. the owner advertises;
4. the verifier scans and attests, and the round commits without the owner;
5. the observer verifies;
6. the owner restarts with its chain wiped, and catch-up brings the certified
   entry back.

With the forge:

```
./forge/up.sh                                   # Forgejo, repo, webhook, runner
FORGE=1 sudo -E env "PATH=$PATH" ./test/cohort/stele_cohort.sh
```

The push then reaches `verifier/stele_hook.py` through the webhook. Knobs:
`WAIT`, `WARM_WAIT`, `CHECKPOINT_SEC`, `ATTEST_MIN_REP` (lowering it weakens
phase 2 and is reported), `SUBNET` (10.9.12), `KEEP=1`. Tear the forge down
with `docker compose -f forge/docker-compose.yml down -v`.
