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

/* Stele's signed artifacts, canonical form and envelope. Mirrored byte for
 * byte by ../../python/autonomous_trust/stele/_python/codec.py.
 *
 * A REPO AD is an owner node's first-person statement that it publishes a
 * repository at a commit:
 *
 *   "STELE-REPO\0" owner "|" name "|" url "|" ref "|" commit "|" seq "|" ts
 *
 * An ATTESTATION is a verifier's signed account of one scan of that commit:
 *
 *   "STELE-ATTEST\0" verifier "|" repo_ad_id "|" commit "|" scanner "|"
 *   scanner_version "|" db_digest "|" findings_digest "|" verdict "|" count
 *   "|" max_severity "|" ts
 *
 * Version 2 (Phase 1) appends fields under its own tag, so a v1 artifact's
 * bytes, id and signature never change:
 *
 *   "STELE-REPO2\0" <the v1 fields> "|" description "|" topics "|"
 *   sbom_digest "|" sbom_path "|" claim_verdict
 *   "STELE-ATTEST2\0" <the v1 fields> "|" channel "|" scope
 *
 * Version 3 (Phase 2) adds the replicated attestation's id, for the
 * replication channel, again under its own tag:
 *   "STELE-ATTEST3\0" <the v2 fields> "|" replicates
 *
 * The envelope says which with "v": 2 or 3; an envelope without it is v1. A third
 * artifact, the REBUTTAL, is the owner's signed reply to an attestation (see
 * stele_rebuttal_t).
 *
 * uuids are canonical lowercase, integers decimal, ts whole epoch seconds.
 * A field may not contain '|' or a control character, so the form is
 * unambiguous. Each artifact's id is the lowercase-hex blake2b-256 of its
 * canonical bytes; the attestation's id is the EVIDENCE DIGEST the verifier's
 * attested score in AutonomousTrust carries. The signature is a detached
 * Ed25519 over the canonical bytes by the owner's (verifier's) node key. */

#ifndef AT_STELE_CODEC_H
#define AT_STELE_CODEC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <uuid/uuid.h>
#include <sodium.h>
#include <jansson.h>

#define STELE_NAME_MAX      64
#define STELE_URL_MAX       256
#define STELE_REF_MAX       64
#define STELE_COMMIT_MAX    64     /* 40 (sha1) or 64 (sha256) lowercase hex */
#define STELE_SCANNER_MAX   32
#define STELE_VERSION_MAX   32
#define STELE_SEVERITY_MAX  16
#define STELE_DIGEST_HEX    64     /* blake2b-256 / sha256, lowercase hex */
#define STELE_ID_HEX        64
#define STELE_SIG_HEX       (crypto_sign_BYTES * 2)
#define STELE_PK_HEX        (crypto_sign_PUBLICKEYBYTES * 2)
#define STELE_CANON_MAX     1024
#define STELE_UUID_STR      37     /* canonical uuid + NUL */

#define STELE_VERDICT_CLEAN "clean"
#define STELE_VERDICT_VULN  "vuln"

/* Version 2 (Phase 1). A v2 ad may describe the repo for discovery and carry
 * the OWNER'S claims a verifier then checks: the digest and forge path of an
 * SBOM it supplies, and its own CI verdict ("none" for no claim). A v2
 * attestation names the AT evidence channel its score is on and the scope AT
 * caps it by. v1 artifacts still parse, sign and hash exactly as before. */
#define STELE_DESC_MAX      256
#define STELE_TOPICS_MAX    128    /* comma-separated */
#define STELE_PATH_MAX      256
#define STELE_CLAIM_NONE    "none"
#define STELE_CHANNEL_MAX   31
#define STELE_REBUT_MAX     280

#define STELE_CHANNEL_PROBE            "probe"
#define STELE_CHANNEL_CERTIFICATE      "certificate"
#define STELE_CHANNEL_SELF_CONSISTENCY "self_consistency"
/* Version 3 (Phase 2): a REPLICATION re-runs another verifier's check, so it
 * names the attestation it replicates. Only v3 may be on this channel. */
#define STELE_CHANNEL_REPLICATION      "replication"

typedef struct {
    uuid_t  owner;
    char    name[STELE_NAME_MAX + 1];
    char    url[STELE_URL_MAX + 1];
    char    ref[STELE_REF_MAX + 1];
    char    commit[STELE_COMMIT_MAX + 1];
    int64_t seq;
    int64_t ts;
    /* v2 (version == 2); ignored for v1 */
    int     version;                     /* 1 or 2; 0 reads as 1 */
    char    description[STELE_DESC_MAX + 1];
    char    topics[STELE_TOPICS_MAX + 1];
    char    sbom_digest[STELE_DIGEST_HEX + 1];   /* "" for none */
    char    sbom_path[STELE_PATH_MAX + 1];       /* "" for none */
    char    claim_verdict[8];                    /* clean | vuln | none */
} stele_repo_ad_t;

typedef struct {
    uuid_t  verifier;
    char    repo_ad_id[STELE_ID_HEX + 1];
    char    commit[STELE_COMMIT_MAX + 1];
    char    scanner[STELE_SCANNER_MAX + 1];
    char    scanner_version[STELE_VERSION_MAX + 1];
    char    db_digest[STELE_DIGEST_HEX + 1];
    char    findings_digest[STELE_DIGEST_HEX + 1];
    char    verdict[8];
    int64_t count;
    char    max_severity[STELE_SEVERITY_MAX + 1];
    int64_t ts;
    /* v2 (version >= 2); ignored for v1, which is always on "probe" */
    int     version;                     /* 1, 2 or 3; 0 reads as 1 */
    char    channel[STELE_CHANNEL_MAX + 1];
    char    scope[STELE_DIGEST_HEX + 1];
    /* v3: the id of the attestation this one replicates; set exactly when the
     * channel is "replication", "" otherwise */
    char    replicates[STELE_ID_HEX + 1];
} stele_attestation_t;

/* The repo owner's signed reply to an attestation about one of its repos.
 * Shown beside the finding, never scored: a rebuttal is the owner's word, and
 * AT scores no first-person account into a verdict.
 * Canonical form: "STELE-REBUT\0" owner|attestation_id|text|ts */
typedef struct {
    uuid_t  owner;
    char    attestation_id[STELE_ID_HEX + 1];
    char    text[STELE_REBUT_MAX + 1];
    int64_t ts;
} stele_rebuttal_t;

/* Field checks: every field within its bound, no '|' or control character,
 * a commit and the digests lowercase hex of their length, a known verdict and
 * a count that agrees with it (clean == 0). */
bool stele_repo_ad_valid(const stele_repo_ad_t *ad);
bool stele_attestation_valid(const stele_attestation_t *at);
bool stele_rebuttal_valid(const stele_rebuttal_t *rb);

/* The scope an attestation about (@p owner, @p name, @p commit) by @p scanner
 * names: lowercase-hex blake2b-256 of "owner|name|commit|scanner". A new
 * commit is a new scope, so a fresh scan can answer an earlier finding while a
 * repeat about the same commit is capped (AT reputation.md). 0 on success. */
int stele_scope(const uuid_t owner, const char *name, const char *commit,
                const char *scanner, char out[STELE_DIGEST_HEX + 1]);

/* Canonical bytes into @p out; returns the length, or 0 when invalid. */
size_t stele_repo_ad_canonical(const stele_repo_ad_t *ad, uint8_t *out, size_t cap);
size_t stele_attestation_canonical(const stele_attestation_t *at, uint8_t *out,
                                   size_t cap);

/* Content id (lowercase-hex blake2b-256 of the canonical bytes). 0 on success. */
int stele_repo_ad_id(const stele_repo_ad_t *ad, char out[STELE_ID_HEX + 1]);
int stele_attestation_id(const stele_attestation_t *at, char out[STELE_ID_HEX + 1]);

/* Detached Ed25519 over the canonical bytes, lowercase hex. 0 on success. */
int stele_repo_ad_sign(const stele_repo_ad_t *ad,
                       const unsigned char sk[crypto_sign_SECRETKEYBYTES],
                       char sig_out[STELE_SIG_HEX + 1]);
bool stele_repo_ad_verify(const stele_repo_ad_t *ad,
                          const unsigned char pk[crypto_sign_PUBLICKEYBYTES],
                          const char *sig_hex);
int stele_attestation_sign(const stele_attestation_t *at,
                           const unsigned char sk[crypto_sign_SECRETKEYBYTES],
                           char sig_out[STELE_SIG_HEX + 1]);
bool stele_attestation_verify(const stele_attestation_t *at,
                              const unsigned char pk[crypto_sign_PUBLICKEYBYTES],
                              const char *sig_hex);

/* Envelopes: the artifact's fields plus "sig". Python's twin uses the same
 * keys. from_json returns 0 and fills @p sig_out, or -1 when malformed. */
json_t *stele_repo_ad_to_json(const stele_repo_ad_t *ad, const char *sig_hex);
int     stele_repo_ad_from_json(const json_t *obj, stele_repo_ad_t *ad,
                                char sig_out[STELE_SIG_HEX + 1]);
json_t *stele_attestation_to_json(const stele_attestation_t *at, const char *sig_hex);
int     stele_attestation_from_json(const json_t *obj, stele_attestation_t *at,
                                    char sig_out[STELE_SIG_HEX + 1]);

size_t  stele_rebuttal_canonical(const stele_rebuttal_t *rb, uint8_t *out, size_t cap);
int     stele_rebuttal_id(const stele_rebuttal_t *rb, char out[STELE_ID_HEX + 1]);
int     stele_rebuttal_sign(const stele_rebuttal_t *rb,
                            const unsigned char sk[crypto_sign_SECRETKEYBYTES],
                            char sig_out[STELE_SIG_HEX + 1]);
bool    stele_rebuttal_verify(const stele_rebuttal_t *rb,
                              const unsigned char pk[crypto_sign_PUBLICKEYBYTES],
                              const char *sig_hex);
json_t *stele_rebuttal_to_json(const stele_rebuttal_t *rb, const char *sig_hex);
int     stele_rebuttal_from_json(const json_t *obj, stele_rebuttal_t *rb,
                                 char sig_out[STELE_SIG_HEX + 1]);

#endif /* AT_STELE_CODEC_H */
