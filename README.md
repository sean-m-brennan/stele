# Stele

Decentralized code sharing in which a repository's safety standing is authored
by others and cannot be faked or suppressed by its owner. The design is
[`CODE_SHARING_PLAN.md`](CODE_SHARING_PLAN.md). This tree holds **Phase 0**, in
which a CVE finding lowers a repository owner's AutonomousTrust reputation,
verifiably, off the owner's hand, and **Phase 1**, in which the repository's
own page shows a standing that the viewer's node verified, that fades without
fresh scans, and that the owner cannot turn green.

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

## How Phase 1 works

1. The owner's ad grows a version 2: a description and topics for discovery,
   the path and sha256 of an SBOM the owner commits, and the owner's own claim
   about the release (`clean`, `vuln` or `none`).
2. The verifier runs a **battery** over its own clone (`verifier/scanners.py`):
   osv-scanner, gitleaks, a license check over its own syft SBOM, and Semgrep
   when it has offline rules. Each makes one attestation on the `probe`
   channel. The owner's SBOM is checked against its digest and against the
   verifier's own syft output, on `certificate`. A clean claim that any of the
   verifier's scans contradicts is attested on `self_consistency` at 0.1.
3. Each attestation carries a **scope**, blake2b(owner | name | commit |
   scanner), and AT admits one attestation per verifier, subject, channel and
   scope. A fixed commit is a new scope, so its clean re-scan is admitted
   while a repeat of the same finding is not.
4. The owner may answer an attestation about its repository with a signed
   **rebuttal**. It is shown beside the finding and never scored.
5. Every node writes a **durable record** of each attested entry once a
   quorum-signed checkpoint covers it (`etc/at/attested/`), with the inclusion
   proof and the signers' public keys, so the record verifies alone, long
   after the entry has left the 200-entry window.
6. `viewer/stele_view.py`, beside the **viewer's** own node, folds those
   records and the node's Stele store into a per-repository standing:
   *verified-safe*, *aging*, *unknown* or *failing*, each with its committed
   reasons. A clean standing fades toward unknown on a 30-day half-life after
   a day; a failing one stays failing until a clean scan of a newer commit
   answers it.
7. The **trust panel** (`extension/`) reads the clone URL from the Forgejo
   page and asks that service, never the forge. Its popup searches what the
   node has heard, best standing first.

## How Phase 2 works

No single verifier is authoritative, and nothing the owner holds can turn the
panel green.

1. **Replication.** A second verifier re-runs another's probe: the same
   commit, scanner, scanner version and database snapshot
   (`verifier/stele_hook.py replicate`, or `--replicate-every SEC` beside the
   webhook). It attests what it got on AT's `replication` channel, as a
   version 3 attestation naming the one it re-ran. AT admits a replication
   only from a verifier at **tier 3** (0.80) in each co-signer's view, and
   every other attestation from tier 1. The tier is the effective one, after
   any standing ceiling, and is 0 once the verifier is excluded.
2. **Agreement.** The viewer counts a verifier only at tier 3 in its own
   node's roster. A check is *confirmed* when two counted verifiers report the
   same findings digest (`stele_view --replicas`, `--tier`). Findings are
   asymmetric:
   - a confirmed finding is *failing*;
   - counted verifiers who disagree make it *disputed*;
   - a finding nobody has confirmed is *failing-unconfirmed*;
   - a clean bill short of the replicas is *single-source*;
   - only all-clean, all-confirmed checks are *verified-safe*.
   A sybil below the tier is shown but not counted.
3. **The anchor.** AT writes the node's roster beside its archive
   (`etc/at/roster.cfg.json`): every member's key, its tier, and the
   checkpoints the node stored. A record verifies only against that roster,
   never against the keys it carries, which a forger writes too. A node with
   no roster verifies nothing.
4. **Bundles.** An owner may publish `stele_ctl.py bundle` output as
   `.stele/standing.json` in its repository. The extension fetches it from the
   forge and hands it to `stele_view`'s `POST /verify`, which believes only the
   records that verify against the viewer's roster. A bundle of the owner's
   own making does not.
5. **The package-hash gate.** Every node sends a hash of the build it runs.
   With `etc/at/package_hashes.cfg.json` (`{"accepted": ["c:<hex>", ...]}`), a
   node admits only listed hashes. A node logs its own hash at start
   (`Identity: package hash c:…`). The hash is self-reported, so the gate
   turns away a modified build that says what it is. Against one modified to
   lie, the verifier-attested rule holds instead: nothing it signs raises its
   own standing or erases a finding.

## Layout

| Path | What |
|---|---|
| `at-stele/c/stele/` | the C extension (`libat_stele`): codec, identity handlers, app verbs, client API (`at_stele.h`) |
| `at-stele/python/autonomous_trust/stele/` | the Python twin, which the conformance corpus runs against the C one |
| `at-stele/conformance/` | the `stele` conformance protocol: plug-in, C and Python adapters, scenarios |
| `at-stele/test-conformance.sh` | AT's conformance run with stele plugged in |
| `native/` | `steled` (the daemon) and `libstele_shim` (what `stele_ctl.py` drives) |
| `tools/stele_ctl.py` | uuid, pubkey, advertise, attest (from a scanner report; `--replicates`), rebut, reputation, verify, standing, search (`--bundle`), bundle |
| `verifier/stele_hook.py` | webhook → clone → the battery → attest, and replication of other verifiers' probes, on the verifier's host |
| `verifier/scanners.py` | the battery: each scanner's runner and summary, the SBOM, license and claim checks |
| `viewer/stele_view.py` | the per-repository standing from the viewer's node, over HTTP on 127.0.0.1 |
| `extension/` | the trust panel, a WebExtension for Chromium and Firefox |
| `forge/` | Forgejo + runner (docker compose), a seeded vulnerable repo, the owner's own (unscored) CI scan, `up.sh` |
| `test/cohort/stele_cohort.sh` | the live three-node check |
| `test/cohort/stele_redteam.sh` | Phase 2's live check: the four owner attacks on a hostile instance (`lib.sh`, `forge_bundle.py`) |

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
python -m pytest at-stele/python/tests tools/tests verifier/tests viewer/tests
node --test extension/tests/panel.test.mjs extension/tests/background.test.mjs
```

Run the pytest directories one at a time, since each holds its own `tests`
package.

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
   entry back;
7. the owner commits its syft SBOM and advertises the commit as clean, and the
   battery finds it failing, certifies the SBOM, and attests the contradicted
   claim;
8. the owner's rebuttal is shown beside the finding;
9. the owner drops the vulnerable dependency, the new commit is re-scanned
   under its own scope, and the standing is clean. With one verifier that is
   *single-source*, and phases 7 and 8 read *failing-unconfirmed*. Since
   Phase 2, green takes two verifiers, which the red team below has;
10. the observer's archived records verify alone, before and after its chain
    is wiped;
11. `stele_view` answers `/standing` and `/search` over HTTP with no CORS
    header.

Phases 7 to 11 also fetch syft and gitleaks unless `SYFT` / `GITLEAKS` name
them or they are on `PATH`. Semgrep joins the battery when `SEMGREP` and
`SEMGREP_RULES` (offline rules) are set.

With the forge:

```
./forge/up.sh                                   # Forgejo, repo, webhook, runner
FORGE=1 sudo -E env "PATH=$PATH" ./test/cohort/stele_cohort.sh
```

The push then reaches `verifier/stele_hook.py` through the webhook. Knobs:
`WAIT`, `WARM_WAIT`, `CHECKPOINT_SEC`, `ATTEST_MIN_REP` (lowering it weakens
phase 2 and is reported), `SUBNET` (10.9.12), `VIEW_PORT` (18099), `KEEP=1`.
Tear the forge down with `docker compose -f forge/docker-compose.yml down -v`.

### The red team (Phase 2)

```
sudo -E env "PATH=$PATH" ./test/cohort/stele_redteam.sh
FORGE=1 sudo -E env "PATH=$PATH" ./test/cohort/stele_redteam.sh   # bundle served by Forgejo
```

The cohort runs a hostile owner, a verifier, an auditor (a second verifier),
an observer (the viewer), the owner's shill (started late) and a rogue. The
rogue runs on a modified `libautonomous_trust`. Every node holds an allowlist
of the honest build's hash, which the founder reports. The phases:

1. discovery;
2. the verifier and auditor reach tier 3 (`WARM_WAIT`, default 900 s);
3. **Attack 4:** the rogue is refused as a counterfeit and never enters the
   observer's roster;
4. the verifier's finding, replicated by the auditor: *failing*, agreed by 2;
5. **Attack 1½:** neither entry carries the owner's signature;
6. **Attack 1:** a forged bundle (the owner's own key, a group of one) and a
   tampered one are refused by the observer's `POST /verify`, the real
   bundle verifies, and the standing stays failing. With `FORGE=1` the
   forged bundle is served from Forgejo as `.stele/standing.json`;
7. **Attack 2:** the owner rewrites its own history and restarts. The shill's
   replication is refused below tier 3, its clean probe is not counted, and
   the owner's attestation about itself never commits;
8. **Attack 3:** the owner withdraws, and the auditor's next finding commits
   without it;
9. the fix: *single-source* on one verifier's scan, *verified-safe* once the
   auditor replicates it.

Knobs: `WAIT`, `WARM_WAIT`, `CHECKPOINT_SEC`, `TIER_REP` (0.80), `SUBNET`
(10.9.13), `VIEW_PORT` (18199), `KEEP=1`, `FORGE=1`.

## The verifier's battery

`verifier/stele_hook.py --root VERIFIER_ROOT --config hook.json` takes a JSON
config:

| Key | What |
|---|---|
| `scanners` | the probes to run, from `osv-scanner`, `gitleaks`, `semgrep`, `license` (default `["osv-scanner"]`) |
| `osv_scanner`, `osv_db` | the binary and its offline database directory |
| `gitleaks`, `syft` | the binaries; `syft` also serves the SBOM and license checks |
| `semgrep`, `semgrep_rules` | the binary and an offline rules file or directory |
| `license_deny` | SPDX ids the license check refuses (default: AGPL-3.0, GPL-3.0 and SSPL-1.0) |
| `secret`, `repos` | the webhook secret, and `{clone url: owner uuid}` for repositories no ad names yet |

The SBOM check runs when the ad names an SBOM, and the claim check runs when
the ad claims `clean`. A scanner that fails is logged and skipped, and the
rest still attest.

## The trust panel

On the viewer's machine, beside its own `steled`:

```
python3 viewer/stele_view.py --root VIEWER_ROOT        # http://127.0.0.1:8099
```

Opening that address in a browser gives a page that searches what the node
has heard and looks up the standing of a clone URL. The extension uses
`/standing` and `/search` directly, and `POST /verify` when the repository
publishes a bundle. `--replicas N` (2) and `--tier T` (3) set how many counted
verifiers must agree, and the tier at which a verifier counts.

Then load `extension/` unpacked. One manifest serves both browsers. In
Chromium, open `chrome://extensions`, turn on developer mode and choose "Load
unpacked". In Firefox (140 or later), open `about:debugging`, choose "This
Firefox", then "Load Temporary Add-on", and pick `extension/manifest.json`.
Firefox does not grant an extension's site access at install, so open the
toolbar popup once and press "Grant access". Until then the panel cannot
appear on any page. The popup's settings take another port.

On a Forgejo or Gitea repository's home page the panel reads the clone URL,
from the `go-import` meta or, on Forgejo (which serves that meta only for
`?go-get=1`), from the HTTPS clone button. It then shows the standing the node
folded. The page
supplies only which repository it is. The toolbar badge, which no page can
draw over, is the authoritative indicator: `OK` for verified-safe, `OLD` for
aging, `1` for single-source, `?` for unknown or unverified, `!?` for
disputed, and `!` for failing, confirmed or not. Without an answer from the
node, the panel says *unverified*, never green. If the repository publishes
`.stele/standing.json` (on `main` or `master`), the panel hands it to the node
to verify. The forge's copy is never evidence on its own.
