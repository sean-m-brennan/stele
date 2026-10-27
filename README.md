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
   any standing ceiling, and is 0 once the verifier is excluded. A verifier
   also needs tenure: until a node has held it as a member for
   `AT_REP_MIN_TENURE_SEC`, which `steled` sets to an hour unless the
   environment says otherwise, that node holds it at tier 2 at most. A sybil
   that answers AT's probes honestly reaches tier 4 in seconds (red team
   `rt-3717776`), so tier alone was never a cost.
2. **Agreement.** The viewer counts a verifier only at tier 3 in its own
   node's roster. A check is *confirmed* when two counted verifiers report the
   same findings digest (`stele_view --replicas`, `--tier`). Findings are
   asymmetric:
   - a confirmed finding is *failing*;
   - counted verifiers who disagree make it *disputed*;
   - a finding nobody has confirmed is *failing-unconfirmed*;
   - a clean bill short of the replicas is *single-source*;
   - only all-clean, all-confirmed checks are *verified-safe*.
   A sybil below the tier, or short of its tenure, is shown but not counted.
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

## How Phase 3 works

A team is an Ethne polity (`../../lib/ethne`, design D41). It cannot raise its
badge, hide a finding, or expel its auditor.

1. **The roster.** The team's root key signs a roster (`stele-team-v1`) that
   lists each member's AT node, the release officers and the guardian edges.
   Each node consents to being listed with its own AT key, so the root cannot
   claim an outside node, such as an auditor, as a teammate. A listed member
   sends the roster (`stele_ctl.py team`, verb `stele team`). A node holds the
   newest one per team once the root signature and every consent verify.
2. **Releases.** The roll confers `ReleaseOfficer`, and the officer signs each
   release authorization (`stele-release-v1`) under its own key. The officer's
   node advertises a version-3 ad that carries the authorization
   (`stele_ctl.py advertise --polity --release`). The ad is the team's when the
   authorization verifies under an officer the held roster lists. Attribution is
   fixed once and never undone, so a shorter roster narrows the team from then
   on and never unlists what it shipped.
3. **Teammates do not witness.** Every node a team has ever listed goes into
   AT's conflict set (`etc/at/attest_conflicts.cfg.json`, AT ISSUES §2.54;
   the history is `etc/stele/conflicts.json`). A shorter roster never removes
   anyone from the set. A
   teammate does not co-sign an attestation about its team, is not counted
   toward its quorum, and cannot be the verifier. The viewer re-checks every
   record against its own copy of the roster.
4. **Who answers.** A finding scores the officer's node, which owns the ad.
   Once two verifiers confirm it, `stele_hook` lands it on the guardian of the
   machine that built the release (a version-4 attestation, 0.45).
5. **The team's standing** is the worst of its repositories' standings and its
   members' own repositories' standings (`stele_view` `/team?polity=`,
   `/teams?q=`; `stele_ctl.py team-standing`). The trust panel shows a team
   line on a team repository and a team panel on the forge organization's page.

`tools/stele_team.py` writes a team's roster and release files from a small
spec. It founds the polity in an Ethne archive when an Ethne build with D41 is
importable, and otherwise writes the same formats itself.

## How Phase 4 works: profiles

The chain records facts with reasons. "Safe enough" is a reading of those
facts, and readers differ, so the viewer reads every standing under a
**profile** (`viewer/stele_profile.py`) and names it in every answer.

1. **What a profile sets.** How many counted verifiers must agree
   (`replicas`) and the tier at which a verifier counts (`tier`); the
   `scanner:channel` checks that must be present and confirmed clean
   (`require`) and those set aside (`ignore`); the severity below which a
   finding is a concern rather than a failure (`severity_floor`: low, medium
   or high); how a clean reading fades (`onset_days`, `half_life_days`);
   whether a repository stands no better than its team (`team`: show or
   worst); and whether it stands no better than its worst dependency
   (`deps`: show or worst, below).
2. **Floors.** A profile tightens freely and relaxes only inside floors, and
   one outside them is refused, never clamped: at least one counted verifier at
   a real tier; a confirmed critical finding always fails, whatever the
   severity floor or `ignore` says, and an unrated finding always counts; a
   failure never fades; a required check that was never run is never green;
   a standing with nothing counted is unknown. A set-aside check is still
   shown, with the profile that set it aside.
3. **Where profiles come from.** Built in: `stele-default` (Stele's own
   reading, everything above) and `stele-strict` (three verifiers, the
   osv-scanner, gitleaks and license checks required, a 14-day half-life, a
   repository no better than its team or its worst dependency). Local: the viewer's
   `etc/stele/profiles/NAME.json`, naming only what it changes. Followed: a
   polity's signed profile (Ethne **D42**, border artifact #11), decided by
   its roll under D37's rule (a majority to tighten, more than a majority to
   loosen). `stele_ctl.py profile-follow` pins its issuer's key, and afterwards
   only a higher `seq` from that key replaces it.
4. **Which applies.** `--profile NAME|followed` (or `?profile=` on the HTTP
   endpoints, or the trust panel's setting); else the viewer node's
   `etc/stele/profile.json` (`stele_ctl.py profile-use`); else
   `stele-default`. A choice that cannot be applied is an error (HTTP 400,
   exit 2), never a silent fallback to another reading. A bundle may carry a
   newer profile from the followed polity, taken for that answer only.

`tools/stele_team.py profile SPEC OUT` writes a polity's signed profile from
the spec's `profile` and `profile_seq`.

## How Phase 4 works: the supply chain

A repository is also what it is built from. Its standing lists its
dependencies and, under a profile that says so, answers for the worst of them
(`viewer/stele_deps.py`, `stele_view.py`).

1. **The list is the owner's SBOM.** The ad pins the SBOM the owner committed
   by sha256, and verifiers already check it on `certificate` against their own
   syft SBOM of the commit: a dependency left out fails the repository itself.
   The SBOM is content-addressed, so it may come from anywhere and is kept only
   if its bytes hash to the digest: the verifier that checked it keeps it, the
   owner's node keeps its own (`advertise --sbom`), a bundle carries it, and
   `stele_ctl.py sbom-add FILE` or `sbom-fetch CLONE_URL` (Forgejo's raw path at
   the ad's commit) gives it to a viewer.
2. **A package resolves to the repositories that publish it.** A v4 ad says
   which package its repository publishes as (`advertise --provides
   pkg:golang/example.com/lib`, a purl without a version). Verifiers check the
   claim against the repository's own manifest (go.mod, package.json,
   Cargo.toml, pyproject.toml) on `certificate`, scanner `provides`, and a
   claim counts once counted verifiers confirm it clean. The release read is
   the ad whose ref names the version the dependent pins (`v1.2.0` or
   `1.2.0`; a Go pseudo-version by its commit), with its own dependencies,
   eight deep and never round a cycle.
3. **Several claimants: the worst stands.** Anyone can write a go.mod, so a
   squatter can publish the same package. Folding the worst of the claimants
   means a squatter can lower a dependency and never raise it. The viewer's
   answer to one is a **pin** (`stele_ctl.py deps-pin PURL CLONE_URL`, kept in
   `etc/stele/deps-map.json`), which replaces every claimant of that package.
4. **What Stele cannot read is shown, never folded.** A package no repository
   on Stele publishes, a version no held ad names, a claim no counted verifier
   confirmed, and an SBOM the viewer does not hold. The repository's own OSV
   probe already covers the known vulnerabilities in those.
5. **Show or worst.** Under `deps: show` (`stele-default`) the dependencies
   are read beside the repository and change nothing. Under `deps: worst`
   (`stele-strict`, or any profile that sets it) a repository stands no better
   than its worst resolved dependency, and the answer says `capped_by_deps`.
   Ethne's `SteleProfile` carries the field and writes it only when it is
   `worst`, so a D42 profile signed before it keeps its bytes.

## How Phase 4 works: discovery relays

Discovery used to reach only what the reader's own AutonomousTrust group
multicast. A **discovery relay** indexes claims from every group: an AT relay
that also serves Stele's `stl_` op family (`at-stele/c/stele/stele_relay.h`,
`AT_STELE_RELAY=1`). It indexes **verifiable claims, never authority**.

1. **Anyone publishes.** Every node files what it holds (ads, attestations,
   rebuttals, attested records, team rosters, group anchors, SBOMs) at the
   relays it registers with, each time it registers and every
   `AT_STELE_RELAY_REFILE_SEC` (120) after; `stele_ctl.py relay-publish` does it
   now. The relay files each claim by its content and keeps anchors and rosters
   by issuer, a higher seq replacing. So an owner cannot keep a finding out of
   the index: the verifier and the auditor that hold it publish it too.
2. **A record from another group verifies only under a followed anchor.** A
   reader holds the keys of its own group and no other's. A polity's **group
   anchor** (Ethne **D43**, border artifact #12) supplies them: the AT group its
   work is verified in, each node's key, which the node consented to under that
   key, its tier, and the checkpoints the group signed, all signed by the
   polity's root. The polity's root mints it from one node's roster, at a rising
   seq (`tools/stele_team.py anchor`; a node's consent is `stele_ctl.py
   anchor-consent`; a node files it with `anchor-publish`). The reader follows a
   polity with `stele_ctl.py anchor-follow`, pinning its root key. A verifier
   then counts at the tier the anchor states, under the reader's own profile,
   and the answer names the polity (`anchored_by`).
3. **The relay's word is shown and never believed.** A search answer carries
   the relay's own count of findings, clean scans and verifiers it holds,
   unverified, beside what the reader verified. A repository from a group whose
   polity the reader does not follow is listed and unverified.
4. **Gaps are counted, not judged.** Under an anchor the answer says how many of
   the checkpoints the group signed since the first record shown came with a
   record about the repository. Most checkpoints hold no record about any one
   repository, so a gap is shown and proves nothing.

`stele_ctl.py relay-search` and `relay-fetch` ask every relay the node is
connected to (the answers land in `etc/stele/relay/`); `relay-results` and
`relay-standing` print what the viewer makes of them, as `stele_view`'s
`/relay/search` and `/relay/standing` do. The trust panel asks the relays when
the node has not heard of the repository on the page.

## Layout

| Path | What |
|---|---|
| `at-stele/c/stele/` | the C extension (`libat_stele`): codec, identity handlers, app verbs, client API (`at_stele.h`) |
| `at-stele/python/autonomous_trust/stele/` | the Python twin, which the conformance corpus runs against the C one |
| `at-stele/conformance/` | the `stele` conformance protocol: plug-in, C and Python adapters, scenarios |
| `at-stele/test-conformance.sh` | AT's conformance run with stele plugged in |
| `native/` | `steled` (the daemon) and `libstele_shim` (what `stele_ctl.py` drives) |
| `tools/stele_ctl.py` | uuid, pubkey, advertise (`--polity --release` for a team release, `--provides` for a package), attest (from a scanner report; `--replicates`), rebut, reputation, verify, standing, search (`--bundle`, `--profile`), bundle, for teams consent, team, guardian, team-standing, for profiles profile-show, profile-follow, profile-unfollow, profile-use, and for the supply chain sbom-add, sbom-fetch, deps-pin, deps-unpin |
| `verifier/stele_hook.py` | webhook → clone → the battery → attest, and replication of other verifiers' probes, on the verifier's host |
| `verifier/scanners.py` | the battery: each scanner's runner and summary, the SBOM, license, claim and provides checks |
| `viewer/stele_view.py` | the per-repository standing from the viewer's node, over HTTP on 127.0.0.1 |
| `viewer/stele_profile.py` | profiles: the built-ins, parsing inside the floors, severities, signed profiles and following |
| `viewer/stele_deps.py` | the supply chain: purls, the content-addressed SBOM store, the viewer's pins |
| `extension/` | the trust panel, a WebExtension for Chromium and Firefox |
| `forge/` | Forgejo + runner (docker compose), a seeded vulnerable repo, the owner's own (unscored) CI scan, `up.sh` |
| `test/cohort/stele_cohort.sh` | the live three-node check |
| `test/cohort/stele_redteam.sh` | Phase 2's live check: the four owner attacks on a hostile instance (`lib.sh`, `forge_bundle.py`) |
| `test/cohort/stele_team_redteam.sh` | Phase 3's live check: a team's attacks on its badge, its findings and its auditor |
| `test/cohort/stele_relay_redteam.sh` | Phase 4's live check of discovery relays: two groups, a relay, omission, the relay's word, forgeries |
| `viewer/stele_anchors.py` | other groups: the polities' group anchors this reader follows |
| `at-stele/c/stele/stele_relay*.{h,c}` | the discovery relay: its store (`stl_` ops) and its network glue; Python twin `_python/relay.py` |
| `tools/stele_team.py` | a team's roster, release authorizations and Stele profile, through Ethne when it is importable |

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
./test.sh                           # all of the below, with a PASS/FAIL summary
```

or one at a time:

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
   replication is refused below tier 3, and still refused once its probes
   have earned tier 4, because it is short of its tenure. Its clean probe is
   not counted, and the owner's attestation about itself never commits. The
   shill, a member that joined late, also takes the history a smaller group
   certified, and no honest chain is refused after it joins (AT §2.48);
8. **Attack 3:** the owner withdraws, and the auditor's next finding commits
   without it;
9. the fix: *single-source* on one verifier's scan, *verified-safe* once the
   auditor replicates it;
10. profiles (Phase 4): the same fixed commit is *unknown* under
   `stele-strict` (its required gitleaks and license checks never ran),
   *single-source* under the observer's own three-verifier profile, and
   *verified-safe* under a polity's signed profile the observer follows. A
   second polity's profile is refused without `--replace`;
11. the supply chain (Phase 4): the owner publishes `lib`, whose v4 ad
   provides `example.com/lib`; both verifiers confirm the claim against its
   go.mod and a finding against it. demo is released again with an SBOM naming
   `lib@v1.0.0`. Nothing is listed until the observer holds the SBOM
   (`sbom-add`, or `sbom-fetch` from Forgejo with `FORGE=1`); then lib is a
   *failing* dependency beside a *verified-safe* demo, and a `deps: worst`
   profile holds demo at *failing*. A squatter ad claiming the same package
   from a repository whose go.mod names another module is refuted by both
   verifiers, listed as unconfirmed and never folded, and the observer's pin
   replaces every claimant.

Knobs: `WAIT`, `WARM_WAIT`, `CHECKPOINT_SEC`, `TIER_REP` (0.80), `SUBNET`
(10.9.13), `VIEW_PORT` (18199), `KEEP=1`, `FORGE=1`.

### The team red team (Phase 3)

```
sudo -E env "PATH=$PATH" ./test/cohort/stele_team_redteam.sh
FORGE=1 sudo -E env "PATH=$PATH" ./test/cohort/stele_team_redteam.sh
```

Six nodes take part: the team's officer, a teammate (`mate`), the team's build
machine (`ci`, guarded by `mate`), a verifier, an auditor and an observer. The
phases:

1. discovery;
2. the roster is held everywhere, and AT's conflict set names the team's three
   nodes;
3. the verifiers reach tier 3;
4. the team's vulnerable release is attributed to the team, found and
   replicated; it commits with the team's own nodes declining to witness. The
   repository and the team are *failing*;
5. the confirmed finding lands on the build machine's guardian (0.45) and is
   the team's concern;
6. **hide a finding / raise the badge:** a roster without the officer and the
   machine changes nothing. The release stays the team's and failing;
7. **expel the auditor:** a roster claiming the auditor with a forged consent is
   refused by the officer's own node. The auditor stays outside the conflict
   set and keeps counting;
8. the fix: *single-source* on one verifier, *verified-safe* on two, and the
   team with it.

Knobs: as for the red team, plus `SUBNET` (10.9.14) and `STELE_TEAM_BUILTIN=1`
(skip Ethne).

### The relay red team (Phase 4)

```
sudo -E env "PATH=$PATH" ./test/cohort/stele_relay_redteam.sh
```

Seven nodes on three segments joined by a router, so discovery stays in each
group and the relay is reached over TCP: group A (`owner`, `verifier`,
`auditor`, a team whose polity mints the anchor), group B (`viewer`, `b1`,
`b2`, the reader's own group) and the `relay`. The phases:

1. two groups and a relay; neither group holds the other's nodes;
2. group A's verifier and auditor reach tier 3;
3. a confirmed finding in group A, archived under a checkpoint;
4. the polity mints its group anchor from the owner's roster and the owner
   publishes it; the viewer follows the polity;
5. **omission:** the owner publishes with the finding left out; through the
   relay the repository reads *unknown*, never green;
6. **anyone publishes:** the auditor files what it holds; the viewer reads
   *failing*, agreed by 2, under the polity's anchor;
7. **the relay's word:** a node of group B files a clean scan it made up; the
   relay counts it, labelled as its word, and the viewer still reads failing;
8. **forgery:** an anchor edited after signing is not followed, and records
   edited after certification do not verify;
9. **unfollowed:** with the polity unfollowed, the repository is listed and
   nothing about it verifies.

Knobs: `WAIT`, `WARM_WAIT`, `CHECKPOINT_SEC`, `TIER_REP`, `NET` (10.9; segments
.15, .16 and .17), `KEEP=1`.

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
publishes a bundle. `--profile NAME|followed` sets the profile standings are
read under (see "How Phase 4 works"), and `--replicas N` and `--tier T`
override the profile's agreement and tier; an override is named in every
answer.

Then load `extension/` unpacked. One manifest serves both browsers. In
Chromium, open `chrome://extensions`, turn on developer mode and choose "Load
unpacked". In Firefox (140 or later), open `about:debugging`, choose "This
Firefox", then "Load Temporary Add-on", and pick `extension/manifest.json`.
Firefox does not grant an extension's site access at install, so open the
toolbar popup once and press "Grant access". Until then the panel cannot
appear on any page. The popup's settings take another port, and a profile to
read standings under (blank leaves it to the node). The panel names the
profile, shows each set-aside check with its reason, and re-checks the floors
itself.

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
