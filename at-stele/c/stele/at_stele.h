/********************
 *  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *******************/

/* at-stele: Stele's AutonomousTrust extension, app-facing API.
 *
 * Two app verbs, both handled by the identity process and both local-only:
 *
 *   AT_APP_STELE_ADVERTISE_REPO  publish this node's repository at a commit:
 *       {"name", "url", "ref", "commit", "seq"}. Identity signs a repo ad with
 *       this node's key and multicasts it to the group (`stele repo`).
 *
 *   AT_APP_STELE_ATTEST  record one scan of a repository this node holds an
 *       ad for: {"owner", "commit", "scanner", "scanner_version", "db_digest",
 *       "findings_digest", "verdict", "count", "max_severity"}. Identity
 *       refuses unless it holds a verified ad from @c owner at @c commit; it
 *       signs the attestation, multicasts it (`stele attest`), and submits a
 *       verifier-attested score about the ad's OWNER to AutonomousTrust (see
 *       AT doc/architecture/reputation.md, "Verifier-attested scores"): 0.3
 *       for a finding, 0.8 for a clean scan, on the `probe` channel, with the
 *       attestation's id as the evidence digest. The subject is taken from the
 *       ad, never from the request.
 *
 * Phase 1 adds version-2 artifacts (stele_codec.h): an ad that describes the
 * repo and carries the owner's claims (an SBOM's digest and path, its own CI
 * verdict), and an attestation that names its AT evidence channel and scope.
 * The attest verb scores by channel:
 *   - probe: 0.3 for a finding, 0.8 for a clean scan;
 *   - certificate (the owner's SBOM, checked): 0.3 if it does not hold, 0.8
 *     if it does; only for an ad that carries an SBOM;
 *   - self_consistency (the owner claimed clean, a scan says otherwise): 0.1;
 *     only for an ad whose claim_verdict is "clean", and only with a finding.
 * AT_APP_STELE_REBUT is the owner's signed reply to an attestation about its
 * repo, shown beside it and never scored.
 *
 * Phase 3 adds teams (stele_team.h). AT_APP_STELE_PUBLISH_TEAM hands this
 * node a team roster ({"roster": <file text>}); identity holds it when the
 * root signature and every member's consent verify and this node is listed,
 * then multicasts it (`stele team`). A held roster's members are written to
 * AT's conflict set (etc/at/attest_conflicts.cfg.json, AT ISSUES §2.54), so a
 * teammate neither witnesses for nor counts toward an attestation about its
 * team. The advertise verb takes "polity" (the team's root key, hex) and
 * "release_auth" (the officer's release authorization file) for a version-3
 * ad; the ad is the team's when the authorization verifies under an officer
 * of a held roster and this node is that officer's. A team ad found unsafe
 * lands on its officer's node (the ad owner) as before, and the attest verb
 * with {"attributes": <a held finding's id>} lands a weaker score on the
 * guardian of the machine that built the release (a version-4 attestation).
 *
 * Every ad, attestation and rebuttal a node holds is kept under
 * <root>/etc/stele/{ads,attestations,rebuttals}/<id>.json (the signed
 * envelope), and announced on the app channel as a STELE event (below).
 * Message types 2300-2309 are reserved for Stele (AT
 * doc/architecture/extensions.md); STELE_EVENT is 2300. */

#ifndef AT_STELE_H
#define AT_STELE_H

#include <stdint.h>

#include "app_events.h"

#define AT_APP_STELE_ADVERTISE_REPO "app_stele_advertise_repo"
#define AT_APP_STELE_ATTEST         "app_stele_attest"
#define AT_APP_STELE_REBUT          "app_stele_rebut"
#define AT_APP_STELE_PUBLISH_TEAM   "app_stele_publish_team"
/* Discovery relays (Phase 4, stele_relay.h). Each goes to this node's own
 * network process, which asks every relay it is connected to and writes the
 * merged answers to <root>/etc/stele/relay/<search|fetch>-<rid>.json, rid the
 * first 16 hex of sha256(kind "|" query). RELAY_PUBLISH files what this node
 * holds at its own relays now, as it does each time it registers. */
#define AT_APP_STELE_RELAY_SEARCH   "app_stele_relay_search"    /* {"q"} */
#define AT_APP_STELE_RELAY_FETCH    "app_stele_relay_fetch"     /* {"url"} */
#define AT_APP_STELE_RELAY_PUBLISH  "app_stele_relay_publish"   /* {} */

/* The Stele events: payload at_app_stele_t, read with at_stele_event. Kinds
 * 1110-1119 (AT doc/architecture/extensions.md). */
#define AT_APP_EVENT_STELE_AD_HELD          1110
#define AT_APP_EVENT_STELE_ATTESTATION_HELD 1111
#define AT_APP_EVENT_STELE_REBUTTAL_HELD    1112
/* A team roster held: @c id is the team's root key (hex), @c name its polity
 * DID, @c ts its seq. */
#define AT_APP_EVENT_STELE_TEAM_HELD        1113

/** One held artifact. @c id is its content id; @c owner the repo owner's uuid
 *  (for an attestation, the owner of the ad it is about); @c subject_id the
 *  attestation an attestation is about's ad, or a rebuttal's attestation. */
typedef struct {
    char    id[65];
    char    owner[37];
    char    verifier[37];       /* ATTESTATION_HELD only */
    char    name[65];
    char    commit[65];
    char    verdict[8];         /* ATTESTATION_HELD only */
    char    channel[32];        /* ATTESTATION_HELD only */
    char    subject_id[65];
    int64_t ts;
} at_app_stele_t;

AT_APP_STATIC_ASSERT(sizeof(at_app_stele_t) <= AT_APP_EVENT_PAYLOAD_MAX,
                     "at_app_stele_t fits the app event payload");

/** @brief The Stele payload of @p ev, or NULL unless @p ev is a STELE kind. */
const at_app_stele_t *at_stele_event(const at_app_event_t *ev);

/* The scores an attestation earns its subject (Phase 0, user decision
 * 2026-10-01): an anomaly-grade drop for a finding, never exclusion-grade, and
 * a good score for a clean scan. Decay never lifts a poor score on its own. */
#define STELE_SCORE_FINDING 0.3
#define STELE_SCORE_CLEAN   0.8
/* A clean claim the owner signed and a scan contradicts (Phase 1, user decision
 * 2026-10-05): lower than a plain finding, because the owner said otherwise. */
#define STELE_SCORE_CONTRADICTED 0.1
/* The guardian of the machine that built a team release with a finding
 * (Phase 3, user decision 2026-10-07): weaker than the finding itself, because
 * the guardian answers for the machine, not for the code. */
#define STELE_SCORE_GUARDIAN 0.45

/* Send AT_APP_STELE_ADVERTISE_REPO on @p q_out (the node's extern_to_at queue).
 * Returns 0, or -1 on a bad argument or a failed send. */
int at_stele_advertise_repo(const char *q_out, const char *name, const char *url,
                            const char *ref, const char *commit, int64_t seq);

/* Send AT_APP_STELE_ATTEST on @p q_out. @p owner is the ad owner's uuid string;
 * @p verdict is "clean" or "vuln". Returns 0, or -1. */
int at_stele_attest(const char *q_out, const char *owner, const char *commit,
                    const char *scanner, const char *scanner_version,
                    const char *db_digest, const char *findings_digest,
                    const char *verdict, int64_t count, const char *max_severity);

/* Version 2 of the advertise verb: also @p description, @p topics (comma-
 * separated), the owner's SBOM (@p sbom_digest, 64 hex, and @p sbom_path in
 * the repo; both "" for none) and its own CI verdict @p claim_verdict
 * ("clean", "vuln" or "none"). NULL reads as "". Returns 0, or -1. */
int at_stele_advertise_repo2(const char *q_out, const char *name, const char *url,
                             const char *ref, const char *commit, int64_t seq,
                             const char *description, const char *topics,
                             const char *sbom_digest, const char *sbom_path,
                             const char *claim_verdict);

/* Version 2 of the attest verb: also the AT evidence @p channel ("probe",
 * "certificate" or "self_consistency"; NULL reads as "probe") and the @p url
 * the verifier cloned (NULL to skip the check), which must be the ad's.
 * Returns 0, or -1. */
int at_stele_attest2(const char *q_out, const char *owner, const char *commit,
                     const char *scanner, const char *scanner_version,
                     const char *db_digest, const char *findings_digest,
                     const char *verdict, int64_t count, const char *max_severity,
                     const char *channel, const char *url);

/* Version 3 of the attest verb: as version 2, plus @p replicates, the id of
 * another verifier's held attestation this one re-ran (the same commit,
 * scanner, scanner version and database). Set it exactly when @p channel is
 * "replication"; NULL reads as "". Returns 0, or -1. */
int at_stele_attest3(const char *q_out, const char *owner, const char *commit,
                     const char *scanner, const char *scanner_version,
                     const char *db_digest, const char *findings_digest,
                     const char *verdict, int64_t count, const char *max_severity,
                     const char *channel, const char *url, const char *replicates);

/* Send AT_APP_STELE_REBUT: this node, as a repo's owner, replies @p text (at
 * most 280 bytes, no '|') to the attestation @p attestation_id about it.
 * Returns 0, or -1. */
int at_stele_rebut(const char *q_out, const char *attestation_id, const char *text);

/* Send AT_APP_STELE_PUBLISH_TEAM: @p roster is a team roster file's exact
 * text (stele_team.h). Returns 0, or -1. */
int at_stele_publish_team(const char *q_out, const char *roster);

/* Version 3 of the advertise verb: as version 2, plus the team's root key
 * @p polity (64 hex) and the officer's release authorization @p release_auth
 * (the file's exact text). Returns 0, or -1. */
int at_stele_advertise_repo3(const char *q_out, const char *name, const char *url,
                             const char *ref, const char *commit, int64_t seq,
                             const char *description, const char *topics,
                             const char *sbom_digest, const char *sbom_path,
                             const char *claim_verdict, const char *polity,
                             const char *release_auth);

/* Version 4 of the advertise verb: as version 3, plus @p provides, the
 * versionless purl the repo publishes as ("" for none). @p polity may be NULL
 * or "" for a solo release, and then @p release_auth is ignored. */
int at_stele_advertise_repo4(const char *q_out, const char *name, const char *url,
                             const char *ref, const char *commit, int64_t seq,
                             const char *description, const char *topics,
                             const char *sbom_digest, const char *sbom_path,
                             const char *claim_verdict, const char *polity,
                             const char *release_auth, const char *provides);

/* Discovery relays (Phase 4): ask this node's relays for @p q (search) or for
 * the claims about the repository at @p url (fetch), or file what this node
 * holds at its own relays now. The answers land as a file (see
 * AT_APP_STELE_RELAY_SEARCH). Returns 0, or -1. */
int at_stele_relay_search(const char *q_out, const char *q);
int at_stele_relay_fetch(const char *q_out, const char *url);
int at_stele_relay_publish(const char *q_out);

/* Land the held finding @p attributes on the guardian of the machine that
 * built its team release (a version-4 attestation, scored
 * STELE_SCORE_GUARDIAN). Returns 0, or -1. */
int at_stele_attest_guardian(const char *q_out, const char *attributes);

/* Keeps the extension in a static link (AT's registry-anchor rule). */
void at_stele_link(void);

#endif /* AT_STELE_H */
