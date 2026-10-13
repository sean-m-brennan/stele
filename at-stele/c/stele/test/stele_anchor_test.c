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

/* The group anchor (Ethne D43), the C half: Ethne's pinned file (en-uplift
 * stele.rs, the_anchor_file_is_byte_pinned) parses, and an edited one does not.
 * python/tests/test_anchor.py holds the same file. */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include <sodium.h>
#include "stele/stele_anchor.h"

#include "anchor_vector.h"
#define PINNED ANCHOR_PINNED

static char *_edit(const char *from, const char *to)
{
    const char *at = strstr(PINNED, from);
    ck_assert(at != NULL);
    size_t n = strlen(PINNED) - strlen(from) + strlen(to) + 1;
    char *out = malloc(n);
    memcpy(out, PINNED, (size_t)(at - PINNED));
    strcpy(out + (at - PINNED), to);
    strcat(out, at + strlen(from));
    return out;
}

DEFINE_TEST(test_ethnes_pinned_anchor_parses)
{
    stele_anchor_t *a = calloc(1, sizeof(*a));
    ck_assert_ret_ok(stele_anchor_parse(PINNED, a));
    ck_assert_int_eq(a->seq, 4);
    ck_assert_str_eq(a->group_uuid, "3c4d5e6f-7081-4293-a4b5-c6d7e8f90a1b");
    ck_assert_int_eq((int)a->n_members, 3);
    ck_assert_int_eq((int)a->n_checkpoints, 2);
    const stele_anchor_member_t *m =
        stele_anchor_member(a, "1a2b3c4d-5e6f-4071-8293-a4b5c6d7e8f9");
    ck_assert(m != NULL);
    ck_assert_int_eq(m->tier, 1);
    ck_assert_int_eq((int)a->checkpoints[1].epoch, 2);
    free(a);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_edited_anchor_is_not_an_anchor)
{
    stele_anchor_t *a = calloc(1, sizeof(*a));
    /* A raised tier breaks the root signature. */
    char *raised = _edit("\\\"tier\\\":1", "\\\"tier\\\":3");
    ck_assert_int_eq(stele_anchor_parse(raised, a), -1);
    free(raised);
    /* So does a consent changed under it. */
    char *consent = _edit("\\\"consent\\\":\\\"7ae9", "\\\"consent\\\":\\\"8ae9");
    ck_assert_int_eq(stele_anchor_parse(consent, a), -1);
    free(consent);
    ck_assert_int_eq(stele_anchor_parse("{}", a), -1);
    ck_assert_int_eq(stele_anchor_parse(NULL, a), -1);
    free(a);
}
END_TEST_DEFINITION()

/* The root re-signs a body whose node-31 consent was signed by node 33: the
 * root signature verifies, so only the consent check can refuse it. */
DEFINE_TEST(test_the_root_cannot_list_a_node_that_did_not_consent)
{
    json_t *outer = json_loads(PINNED, 0, NULL);
    json_t *body = json_loads(json_string_value(json_object_get(outer, "body")), 0, NULL);
    json_t *m = json_array_get(json_object_get(body, "members"), 1);
    const char *issuer = json_string_value(json_object_get(body, "issuer"));
    const char *group = json_string_value(json_object_get(body, "group_uuid"));
    unsigned char seed[32], pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];
    memset(seed, 33, sizeof(seed));
    crypto_sign_seed_keypair(pk, sk, seed);
    uint8_t msg[512];
    size_t n = stele_anchor_consent_message(issuer, group,
                                            json_string_value(json_object_get(m, "at_uuid")),
                                            json_string_value(json_object_get(m, "pubkey")),
                                            msg, sizeof(msg));
    unsigned char sig[crypto_sign_BYTES];
    crypto_sign_detached(sig, NULL, msg, n, sk);
    char hex[STELE_SIG_HEX + 1];
    sodium_bin2hex(hex, sizeof(hex), sig, sizeof(sig));
    json_object_set_new(m, "consent", json_string(hex));

    char *text = json_dumps(body, JSON_COMPACT | JSON_PRESERVE_ORDER);
    memset(seed, 7, sizeof(seed));                      /* the polity root */
    crypto_sign_seed_keypair(pk, sk, seed);
    size_t dl = strlen(STELE_ANCHOR_DOMAIN), bl = strlen(text);
    uint8_t *signed_msg = malloc(dl + bl);
    memcpy(signed_msg, STELE_ANCHOR_DOMAIN, dl);
    memcpy(signed_msg + dl, text, bl);
    crypto_sign_detached(sig, NULL, signed_msg, dl + bl, sk);
    sodium_bin2hex(hex, sizeof(hex), sig, sizeof(sig));
    json_t *file = json_pack("{s:s, s:s}", "body", text, "sig", hex);
    char *forged = json_dumps(file, JSON_COMPACT);

    stele_anchor_t *a = calloc(1, sizeof(*a));
    ck_assert_int_eq(stele_anchor_parse(forged, a), -1);
    /* The same re-signing with the honest consent is an anchor: the refusal
     * above is the consent's, not the re-signing's. */
    json_object_set_new(m, "consent", json_string(
        json_string_value(json_object_get(json_array_get(json_object_get(
            json_loads(json_string_value(json_object_get(outer, "body")), 0, NULL),
            "members"), 1), "consent"))));
    free(text);
    text = json_dumps(body, JSON_COMPACT | JSON_PRESERVE_ORDER);
    bl = strlen(text);
    signed_msg = realloc(signed_msg, dl + bl);
    memcpy(signed_msg + dl, text, bl);
    crypto_sign_detached(sig, NULL, signed_msg, dl + bl, sk);
    sodium_bin2hex(hex, sizeof(hex), sig, sizeof(sig));
    json_decref(file);
    file = json_pack("{s:s, s:s}", "body", text, "sig", hex);
    free(forged);
    forged = json_dumps(file, JSON_COMPACT);
    ck_assert_ret_ok(stele_anchor_parse(forged, a));

    free(a);
    free(forged);
    free(text);
    free(signed_msg);
    json_decref(file);
    json_decref(body);
    json_decref(outer);
}
END_TEST_DEFINITION()

RUN_TESTS(SteleAnchor, test_the_root_cannot_list_a_node_that_did_not_consent, test_ethnes_pinned_anchor_parses, test_an_edited_anchor_is_not_an_anchor)
