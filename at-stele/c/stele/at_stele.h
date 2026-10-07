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

/* The Stele events: payload at_app_stele_t, read with at_stele_event. Kinds
 * 1110-1119 (AT doc/architecture/extensions.md). */
#define AT_APP_EVENT_STELE_AD_HELD          1110
#define AT_APP_EVENT_STELE_ATTESTATION_HELD 1111
#define AT_APP_EVENT_STELE_REBUTTAL_HELD    1112

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

/* Keeps the extension in a static link (AT's registry-anchor rule). */
void at_stele_link(void);

#endif /* AT_STELE_H */
