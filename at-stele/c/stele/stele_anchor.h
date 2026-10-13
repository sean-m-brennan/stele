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

/* Stele Phase 4: a polity's GROUP ANCHOR (Ethne design D43, border artifact
 * #12, en-uplift module `stele`). Mirrored by
 * ../../python/autonomous_trust/stele/_python/anchor.py.
 *
 *   {"body": <exact JSON text>, "sig": <hex>}
 *   sig  = ed25519(polity root, "stele-anchor-v1|" + body)
 *   body = {"v":1,"typename":"stele-group-anchor","polity":<did>,"issuer":<hex root>,
 *           "seq":N,"group_uuid":<uuid>,
 *           "members":[{"at_uuid","pubkey","tier","consent"}, ...],
 *           "checkpoints":[{"group_uuid","epoch","root","first_index","count"}, ...]}
 *
 * The polity's word about the AT group its work is verified in: each node's AT
 * key and tier, and the checkpoints the group signed. Each node's consent is
 * its own signature, under the key it is listed with, over
 * "stele-anchor-member-v1|" issuer "|" group_uuid "|" at_uuid "|" pubkey, so it
 * is checked here: an anchor whose root claims a node, or a key, that never
 * consented is not an anchor. A higher seq replaces the issuer's anchor. */

#ifndef AT_STELE_ANCHOR_H
#define AT_STELE_ANCHOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "stele_codec.h"
#include "stele_team.h"

#define STELE_ANCHOR_DOMAIN          "stele-anchor-v1|"
#define STELE_ANCHOR_CONSENT_DOMAIN  "stele-anchor-member-v1|"
#define STELE_ANCHOR_TYPENAME        "stele-group-anchor"
#define STELE_ANCHOR_MEMBERS_MAX     256
#define STELE_ANCHOR_CHECKPOINTS_MAX 512
#define STELE_ANCHOR_FILE_MAX        (256 * 1024)
#define STELE_ANCHOR_TIER_MAX        4

typedef struct {
    char at_uuid[STELE_UUID_STR];
    char pubkey[STELE_PK_HEX + 1];
    int  tier;
} stele_anchor_member_t;

typedef struct {
    char    group_uuid[STELE_UUID_STR];   /* "" for the primary chain */
    int64_t epoch;
    char    root[STELE_DIGEST_HEX + 1];
    int64_t first_index;
    int64_t count;
} stele_anchor_checkpoint_t;

/* Large (about 100 KB): allocate it, do not put it on the stack. */
typedef struct {
    char    issuer[STELE_PK_HEX + 1];
    char    polity[STELE_DID_MAX + 1];
    int64_t seq;
    char    group_uuid[STELE_UUID_STR];
    size_t  n_members;
    stele_anchor_member_t members[STELE_ANCHOR_MEMBERS_MAX];
    size_t  n_checkpoints;
    stele_anchor_checkpoint_t checkpoints[STELE_ANCHOR_CHECKPOINTS_MAX];
} stele_anchor_t;

/* Parse an anchor file and verify its root signature, its shape, and every
 * listed node's consent under the key it is listed with. 0 on success. */
int stele_anchor_parse(const char *text, stele_anchor_t *out);

/* The bytes a node signs to consent to an anchor; returns the length, or 0. */
size_t stele_anchor_consent_message(const char *issuer, const char *group_uuid,
                                    const char *at_uuid, const char *pubkey,
                                    uint8_t *out, size_t cap);

/* The listed node @p at_uuid, or NULL. */
const stele_anchor_member_t *stele_anchor_member(const stele_anchor_t *a,
                                                 const char *at_uuid);

#endif /* AT_STELE_ANCHOR_H */
