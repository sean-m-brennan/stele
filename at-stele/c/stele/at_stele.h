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
 * Message types 2300-2309 are reserved for Stele (AT
 * doc/architecture/extensions.md). Phase 0 emits no app events of its own:
 * the score's effect is read through the core's PEER_REPUTATION events and the
 * persisted evidence document. */

#ifndef AT_STELE_H
#define AT_STELE_H

#include <stdint.h>

#define AT_APP_STELE_ADVERTISE_REPO "app_stele_advertise_repo"
#define AT_APP_STELE_ATTEST         "app_stele_attest"

/* The scores an attestation earns its subject (Phase 0, user decision
 * 2026-10-01): an anomaly-grade drop for a finding, never exclusion-grade, and
 * a good score for a clean scan. Decay never lifts a poor score on its own. */
#define STELE_SCORE_FINDING 0.3
#define STELE_SCORE_CLEAN   0.8

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

/* Keeps the extension in a static link (AT's registry-anchor rule). */
void at_stele_link(void);

#endif /* AT_STELE_H */
