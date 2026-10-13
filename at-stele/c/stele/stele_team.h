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

/* Stele Phase 3: a team is an Ethne polity, and two files it emits say who the
 * team is and what it released (Ethne design D41, en-uplift module `stele`).
 * Stele checks both with ed25519 keys alone and never reads a charter.
 * Mirrored by ../../python/autonomous_trust/stele/_python/team.py.
 *
 * TEAM ROSTER: {"body": <exact JSON text>, "sig": <hex>}, where
 *
 *   sig  = ed25519(root, "stele-team-v1|" + body)
 *   body = {"v":1,"typename":"stele-team","polity":<did>,"issuer":<hex root>,
 *           "seq":N,"members":[{"did","key","at_uuid","consent"}, ...],
 *           "release_officers":[<did>, ...],
 *           "guardians":[{"machine":<did>,"guardian":<did>}, ...]}
 *
 * The issuer key verifies the roster and IS the team's identity here (the
 * polity DID embeds the same key). Each member's consent is its AT node
 * signing "stele-team-member-v1|" issuer "|" did "|" at_uuid with the node's
 * own key, checked against the key this node holds for that uuid, so the root
 * cannot list a node that did not agree: an outside auditor cannot be claimed
 * as a teammate, and a teammate does not count toward an attestation about its
 * team (AT ISSUES §2.54).
 *
 * RELEASE AUTHORIZATION: {"body", "sig"}, with sig = ed25519(officer_key,
 * "stele-release-v1|" + body) and body {"v":1,"typename":"stele-release",
 * "polity","issuer","officer","officer_key","repo","url","commit",
 * "built_by"?,"authorized_at"}. Believed while the officer is listed, with
 * that key, in a roster this node holds. */

#ifndef AT_STELE_TEAM_H
#define AT_STELE_TEAM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sodium.h>
#include <jansson.h>

#include "stele_codec.h"

#define STELE_DID_MAX        64     /* did:key:z6Mk... is 56 */
#define STELE_TEAM_MAX       64     /* members in one roster */
#define STELE_TEAM_FILE_MAX  32768  /* a roster file's text */
#define STELE_RELEASE_MAX    2048   /* a release authorization file's text */

#define STELE_TEAM_DOMAIN    "stele-team-v1|"
#define STELE_CONSENT_DOMAIN "stele-team-member-v1|"
#define STELE_RELEASE_DOMAIN "stele-release-v1|"

typedef struct {
    char did[STELE_DID_MAX + 1];
    char key[STELE_PK_HEX + 1];          /* the member's DID key, hex */
    char at_uuid[STELE_UUID_STR];
    char consent[STELE_SIG_HEX + 1];
} stele_team_member_t;

typedef struct {
    char machine[STELE_DID_MAX + 1];
    char guardian[STELE_DID_MAX + 1];
} stele_team_guardian_t;

typedef struct {
    char    issuer[STELE_PK_HEX + 1];    /* the polity root key, hex: the team's id */
    char    polity[STELE_DID_MAX + 1];
    int64_t seq;
    size_t  n_members;
    stele_team_member_t members[STELE_TEAM_MAX];
    size_t  n_officers;
    char    officers[STELE_TEAM_MAX][STELE_DID_MAX + 1];
    size_t  n_guardians;
    stele_team_guardian_t guardians[STELE_TEAM_MAX];
} stele_team_t;

typedef struct {
    char    issuer[STELE_PK_HEX + 1];
    char    polity[STELE_DID_MAX + 1];
    char    officer[STELE_DID_MAX + 1];
    char    officer_key[STELE_PK_HEX + 1];
    char    repo[STELE_NAME_MAX + 1];
    char    url[STELE_URL_MAX + 1];
    char    commit[STELE_COMMIT_MAX + 1];
    char    built_by[STELE_DID_MAX + 1];  /* "" for none */
    int64_t authorized_at;
} stele_release_t;

/* Parse a roster file and verify its root signature and shape: every officer
 * and both ends of every guardian edge are listed members, no member or node
 * twice. Consents are NOT checked here (stele_team_consents_ok). 0 on success. */
int stele_team_parse(const char *text, stele_team_t *out);

/* The AT signing key this node holds for @p at_uuid, or false. */
typedef bool (*stele_key_lookup_fn)(const char *at_uuid, void *ctx,
                                    unsigned char pk[crypto_sign_PUBLICKEYBYTES]);

/* Every member's consent verifies under the key @p lookup gives for its node.
 * On false, @p bad (when not NULL, STELE_UUID_STR bytes) names the first node
 * whose consent failed or whose key this node does not hold. */
bool stele_team_consents_ok(const stele_team_t *t, stele_key_lookup_fn lookup,
                            void *ctx, char *bad);

/* The listed member @p did, or NULL. */
const stele_team_member_t *stele_team_member(const stele_team_t *t, const char *did);
/* The listed member acting through node @p at_uuid, or NULL. */
const stele_team_member_t *stele_team_member_by_uuid(const stele_team_t *t,
                                                     const char *at_uuid);
bool stele_team_is_officer(const stele_team_t *t, const char *did);
/* The guardian @p machine answers to, or NULL. */
const char *stele_team_guardian_of(const stele_team_t *t, const char *machine);

/* Parse a release authorization file and verify the officer's signature over
 * it. 0 on success. */
int stele_release_parse(const char *text, stele_release_t *out);

/* {"body": <text>, "sig": <hex>}: the parsed body (owned by the caller) when
 * sig verifies over @p domain + body under the hex key the body names in
 * @p key_field, else NULL. Shared by the Stele signed files. */
json_t *stele_signed_body(const char *text, const char *domain, const char *key_field);

/* The bytes a member's AT node signs to consent; returns the length, or 0. */
size_t stele_consent_message(const char *issuer, const char *did, const char *at_uuid,
                             uint8_t *out, size_t cap);

#endif /* AT_STELE_TEAM_H */
