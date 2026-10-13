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

/* Stele Phase 3: the team roster and the release authorization, verified
 * against the byte-pinned vectors Ethne emits (en-uplift stele.rs,
 * the_files_are_byte_pinned): root seed 7, officer seed 10, members seeds
 * 10/11/12 on nodes A/B/C whose AT keys are seeds 30/31/32. */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>
#include "stele/stele_team.h"

static const char TEAM[] = "{\"body\":\"{\\\"v\\\":1,\\\"typename\\\":\\\"stele-team\\\",\\\"polity\\\":\\\"did:key:z6MkvDqGT54cXesYGvABpF1UapVNwjCqRcafi4Px6Thv5T3Z\\\",\\\"issuer\\\":\\\"ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c\\\",\\\"seq\\\":3,\\\"members\\\":[{\\\"did\\\":\\\"did:key:z6MkfDSNRs2i9S6LZ5vd4RbpZ6754H7R3btDqRTeHhamqvuJ\\\",\\\"key\\\":\\\"0b513ad9b4924015ca0902ed079044d3ac5dbec2306f06948c10da8eb6e39f2d\\\",\\\"at_uuid\\\":\\\"2b3c4d5e-6f70-4182-93a4-b5c6d7e8f90a\\\",\\\"consent\\\":\\\"2aa71ad84c1bbe33f052af7053b75d920692743172936c9bf55ce38b181476689e6ab00381999f08ce4390d0c7500079fb10adf6a2e4e057a84ddf0a368f2f00\\\"},{\\\"did\\\":\\\"did:key:z6Mkj1MDZKcfx9AX5CeXHdysiGkRLzBbALyFuShD6wNeY1E3\\\",\\\"key\\\":\\\"43a72e714401762df66b68c26dfbdf2682aaec9f2474eca4613e424a0fbafd3c\\\",\\\"at_uuid\\\":\\\"0f1e2d3c-4b5a-4968-8776-655443322110\\\",\\\"consent\\\":\\\"9d50d0c830b505725bb63884dfa17d999d435dfdd7b8059bbad94bd9cf8ed45b3b5413172c6417b5a4bd8f0cd49598788664562ed9a7ac6530d45be974e6ac07\\\"},{\\\"did\\\":\\\"did:key:z6MkmNL6xksdEJENGk9Z1qqGsY5njKQdjU1UhnUEUvWyQUVX\\\",\\\"key\\\":\\\"66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a\\\",\\\"at_uuid\\\":\\\"1a2b3c4d-5e6f-4071-8293-a4b5c6d7e8f9\\\",\\\"consent\\\":\\\"b782515541bd3a0abb36bf41ff2d59ff3d17a85b63c312fe6fc2a35639a0ead8f490444496e4499c3675e8aae902ff2763434908542e138a9dacca6efed19f09\\\"}],\\\"release_officers\\\":[\\\"did:key:z6Mkj1MDZKcfx9AX5CeXHdysiGkRLzBbALyFuShD6wNeY1E3\\\"],\\\"guardians\\\":[{\\\"machine\\\":\\\"did:key:z6MkfDSNRs2i9S6LZ5vd4RbpZ6754H7R3btDqRTeHhamqvuJ\\\",\\\"guardian\\\":\\\"did:key:z6MkmNL6xksdEJENGk9Z1qqGsY5njKQdjU1UhnUEUvWyQUVX\\\"}]}\",\"sig\":\"1a3ffdfc52410608b4cfff8a3e242b2ae9086b07808ca210aec56fea53e6b6975276aa4dddc360d39cad16e6357b74bf0815e45fa938b3d84461eeb73c985404\"}";
static const char RELEASE[] = "{\"body\":\"{\\\"v\\\":1,\\\"typename\\\":\\\"stele-release\\\",\\\"polity\\\":\\\"did:key:z6MkvDqGT54cXesYGvABpF1UapVNwjCqRcafi4Px6Thv5T3Z\\\",\\\"issuer\\\":\\\"ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c\\\",\\\"officer\\\":\\\"did:key:z6Mkj1MDZKcfx9AX5CeXHdysiGkRLzBbALyFuShD6wNeY1E3\\\",\\\"officer_key\\\":\\\"43a72e714401762df66b68c26dfbdf2682aaec9f2474eca4613e424a0fbafd3c\\\",\\\"repo\\\":\\\"demo\\\",\\\"url\\\":\\\"http://localhost:3000/stele/demo.git\\\",\\\"commit\\\":\\\"c3cd66ac5a89e0d1f2a3b4c5d6e7f8091a2b3c4d\\\",\\\"built_by\\\":\\\"did:key:z6MkfDSNRs2i9S6LZ5vd4RbpZ6754H7R3btDqRTeHhamqvuJ\\\",\\\"authorized_at\\\":400}\",\"sig\":\"2d7e4af1f0f40f43f3251996825ecd749a90d3a0d879e7ecd23e64d8dcef98b9bcdc62f8b599aae6635804603f06801c48486bb7b1a90bb9bc2f8b352327d400\"}";

static const char UUID_A[] = "0f1e2d3c-4b5a-4968-8776-655443322110";
static const char UUID_B[] = "1a2b3c4d-5e6f-4071-8293-a4b5c6d7e8f9";
static const char UUID_C[] = "2b3c4d5e-6f70-4182-93a4-b5c6d7e8f90a";
static const char NODE30[] = "acdb0e29743f0ccb8686d0a104cb96e05abefec1538765e7595869f7dc8c49aa";
static const char NODE31[] = "43046bfe4092b3e94994eada15dcc20d8aaa07b658fd3954eb8e0efb8bdca5de";
static const char NODE32[] = "4ed32f63bf35f0eeefcb25f28a2e1fbdc873ae2835671b0c9460f5f12e4556a8";
static const char ISSUER[] =
    "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";

/* The AT keys this node "holds": A, B and C, unless ctx names one to forget. */
static bool _lookup(const char *at_uuid, void *ctx,
                    unsigned char pk[crypto_sign_PUBLICKEYBYTES])
{
    const char *forget = ctx;
    const char *hex = strcmp(at_uuid, UUID_A) == 0 ? NODE30
        : strcmp(at_uuid, UUID_B) == 0 ? NODE31
        : strcmp(at_uuid, UUID_C) == 0 ? NODE32 : NULL;
    if (hex == NULL || (forget != NULL && strcmp(forget, at_uuid) == 0))
        return false;
    size_t bin = 0;
    return sodium_hex2bin(pk, crypto_sign_PUBLICKEYBYTES, hex, 64, NULL, &bin, NULL) == 0
        && bin == crypto_sign_PUBLICKEYBYTES;
}

/* @p text with the first @p from replaced by @p to (same length). */
static char *_edit(const char *text, const char *from, const char *to)
{
    char *out = strdup(text);
    char *at = strstr(out, from);
    ck_assert_ptr_nonnull(at);
    memcpy(at, to, strlen(to));
    return out;
}

DEFINE_TEST(test_the_pinned_roster_verifies_with_consents)
{
    ck_assert(sodium_init() >= 0);
    stele_team_t t;
    ck_assert_ret_ok(stele_team_parse(TEAM, &t));
    ck_assert_str_eq(t.issuer, ISSUER);
    ck_assert_int_eq(t.seq, 3);
    ck_assert_int_eq((int)t.n_members, 3);
    ck_assert_int_eq((int)t.n_officers, 1);
    ck_assert_int_eq((int)t.n_guardians, 1);
    const stele_team_member_t *officer = stele_team_member(&t, t.officers[0]);
    ck_assert_ptr_nonnull(officer);
    ck_assert_str_eq(officer->at_uuid, UUID_A);
    const char *g = stele_team_guardian_of(&t, t.guardians[0].machine);
    ck_assert_str_eq(stele_team_member(&t, g)->at_uuid, UUID_B);
    ck_assert_str_eq(stele_team_member(&t, t.guardians[0].machine)->at_uuid, UUID_C);
    char bad[STELE_UUID_STR] = {0};
    ck_assert(stele_team_consents_ok(&t, _lookup, NULL, bad));
    /* A node this one holds no key for has not consented, as far as it knows. */
    ck_assert(!stele_team_consents_ok(&t, _lookup, (void *)UUID_B, bad));
    ck_assert_str_eq(bad, UUID_B);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_tampered_roster_or_a_borrowed_consent_fails)
{
    ck_assert(sodium_init() >= 0);
    stele_team_t t;
    /* The body is signed: one changed byte and the root signature fails. */
    char *seq = _edit(TEAM, "\\\"seq\\\":3", "\\\"seq\\\":4");
    ck_assert_int_eq(stele_team_parse(seq, &t), -1);
    free(seq);
    /* Under another domain the same bytes are not a roster. */
    ck_assert_int_eq(stele_team_parse(RELEASE, &t), -1);
    /* A consent moved to another node does not verify under that node's key:
     * this is the root claiming an outsider (an auditor) as a teammate. */
    ck_assert_ret_ok(stele_team_parse(TEAM, &t));
    stele_team_member_t tmp = t.members[0];
    snprintf(t.members[0].consent, sizeof(t.members[0].consent), "%s", t.members[1].consent);
    ck_assert(!stele_team_consents_ok(&t, _lookup, NULL, NULL));
    t.members[0] = tmp;
    ck_assert(stele_team_consents_ok(&t, _lookup, NULL, NULL));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_pinned_release_verifies_under_its_officer)
{
    ck_assert(sodium_init() >= 0);
    stele_release_t r;
    ck_assert_ret_ok(stele_release_parse(RELEASE, &r));
    ck_assert_str_eq(r.issuer, ISSUER);
    ck_assert_str_eq(r.repo, "demo");
    ck_assert_str_eq(r.url, "http://localhost:3000/stele/demo.git");
    ck_assert_str_eq(r.commit, "c3cd66ac5a89e0d1f2a3b4c5d6e7f8091a2b3c4d");
    ck_assert_int_eq(r.authorized_at, 400);
    stele_team_t t;
    ck_assert_ret_ok(stele_team_parse(TEAM, &t));
    ck_assert(stele_team_is_officer(&t, r.officer));
    ck_assert_str_eq(stele_team_member(&t, r.officer)->key, r.officer_key);
    ck_assert_str_eq(stele_team_member(&t, r.built_by)->at_uuid, UUID_C);
    /* A different commit under the same signature does not verify. */
    char *other = _edit(RELEASE, "c3cd66ac5a89", "c3cd66ac5a8a");
    ck_assert_int_eq(stele_release_parse(other, &r), -1);
    free(other);
    ck_assert_int_eq(stele_release_parse(TEAM, &r), -1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_consent_message_is_ethnes)
{
    uint8_t buf[256];
    size_t n = stele_consent_message(ISSUER, "did:key:z6Mkabc", UUID_A, buf, sizeof(buf));
    ck_assert(n > 0);
    char expect[256];
    snprintf(expect, sizeof(expect), "stele-team-member-v1|%s|did:key:z6Mkabc|%s",
             ISSUER, UUID_A);
    ck_assert_int_eq((int)n, (int)strlen(expect));
    ck_assert(memcmp(buf, expect, n) == 0);
}
END_TEST_DEFINITION()

RUN_TESTS(SteleTeam, test_the_pinned_roster_verifies_with_consents,
          test_a_tampered_roster_or_a_borrowed_consent_fails,
          test_the_pinned_release_verifies_under_its_officer,
          test_the_consent_message_is_ethnes)
