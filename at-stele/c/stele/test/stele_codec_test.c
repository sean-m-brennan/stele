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

/* Stele's codec: the field rules, sign/verify, and the envelope round trip.
 * The canonical bytes themselves are pinned across languages by the stele
 * conformance corpus; the twin of these checks is
 * python/tests/test_codec.py. */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>
#include "stele/stele_codec.h"

static const char COMMIT[] = "0123456789abcdef0123456789abcdef01234567";
static const char HEX64[] =
    "abababababababababababababababababababababababababababababababab";

static stele_repo_ad_t _ad(void)
{
    stele_repo_ad_t ad;
    memset(&ad, 0, sizeof(ad));
    uuid_generate(ad.owner);
    snprintf(ad.name, sizeof(ad.name), "demo");
    snprintf(ad.url, sizeof(ad.url), "http://forge.local/alice/demo.git");
    snprintf(ad.ref, sizeof(ad.ref), "main");
    snprintf(ad.commit, sizeof(ad.commit), "%s", COMMIT);
    ad.seq = 1;
    ad.ts = 1790000000;
    return ad;
}

DEFINE_TEST(test_stele_repo_ad_signs_verifies_and_round_trips)
{
    ck_assert(sodium_init() >= 0);
    unsigned char pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);
    stele_repo_ad_t ad = _ad();
    char sig[STELE_SIG_HEX + 1];
    ck_assert_ret_ok(stele_repo_ad_sign(&ad, sk, sig));
    ck_assert(stele_repo_ad_verify(&ad, pk, sig));

    json_t *env = stele_repo_ad_to_json(&ad, sig);
    stele_repo_ad_t back;
    char sig2[STELE_SIG_HEX + 1];
    ck_assert_ret_ok(stele_repo_ad_from_json(env, &back, sig2));
    json_decref(env);
    ck_assert(stele_repo_ad_verify(&back, pk, sig2));
    char a[STELE_ID_HEX + 1], b[STELE_ID_HEX + 1];
    ck_assert_ret_ok(stele_repo_ad_id(&ad, a));
    ck_assert_ret_ok(stele_repo_ad_id(&back, b));
    ck_assert_str_eq(a, b);

    /* Any changed field fails the signature. */
    back.seq = 2;
    ck_assert(!stele_repo_ad_verify(&back, pk, sig2));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_stele_field_rules)
{
    stele_repo_ad_t ad = _ad();
    ck_assert(stele_repo_ad_valid(&ad));
    snprintf(ad.name, sizeof(ad.name), "a|b");          /* the separator */
    ck_assert(!stele_repo_ad_valid(&ad));
    ad = _ad();
    snprintf(ad.commit, sizeof(ad.commit), "ABCDEF");   /* not lowercase hex */
    ck_assert(!stele_repo_ad_valid(&ad));

    stele_attestation_t at;
    memset(&at, 0, sizeof(at));
    uuid_generate(at.verifier);
    snprintf(at.repo_ad_id, sizeof(at.repo_ad_id), "%s", HEX64);
    snprintf(at.commit, sizeof(at.commit), "%s", COMMIT);
    snprintf(at.scanner, sizeof(at.scanner), "osv-scanner");
    snprintf(at.scanner_version, sizeof(at.scanner_version), "2.6.0");
    snprintf(at.db_digest, sizeof(at.db_digest), "%s", HEX64);
    snprintf(at.findings_digest, sizeof(at.findings_digest), "%s", HEX64);
    snprintf(at.verdict, sizeof(at.verdict), "vuln");
    at.count = 2;
    snprintf(at.max_severity, sizeof(at.max_severity), "HIGH");
    at.ts = 1790000000;
    ck_assert(stele_attestation_valid(&at));
    at.count = 0;                                        /* vuln with none */
    ck_assert(!stele_attestation_valid(&at));
    snprintf(at.verdict, sizeof(at.verdict), "clean");
    ck_assert(stele_attestation_valid(&at));
    snprintf(at.verdict, sizeof(at.verdict), "maybe");
    ck_assert(!stele_attestation_valid(&at));
}
END_TEST_DEFINITION()

/* The cross-language pin: a fixed owner and verifier, the ids the Python twin
 * computes for the same artifacts (python/tests/test_codec.py holds the same
 * two strings). A divergence in field order, the tag, or a number's spelling
 * changes them on one side only. */
DEFINE_TEST(test_stele_fixed_vectors)
{
    stele_repo_ad_t ad = _ad();
    uuid_parse("00000000-0000-4000-8000-000000000001", ad.owner);
    char id[STELE_ID_HEX + 1];
    ck_assert_ret_ok(stele_repo_ad_id(&ad, id));
    ck_assert_str_eq(id, "b7743ddb9be9a22fcde814ebc1ef49874f37d9bce617f0f6146b21011101b185");

    stele_attestation_t at;
    memset(&at, 0, sizeof(at));
    uuid_parse("00000000-0000-4000-8000-000000000002", at.verifier);
    snprintf(at.repo_ad_id, sizeof(at.repo_ad_id), "%s", id);
    snprintf(at.commit, sizeof(at.commit), "%s", COMMIT);
    snprintf(at.scanner, sizeof(at.scanner), "osv-scanner");
    snprintf(at.scanner_version, sizeof(at.scanner_version), "2.6.0");
    snprintf(at.db_digest, sizeof(at.db_digest),
             "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd");
    snprintf(at.findings_digest, sizeof(at.findings_digest),
             "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef");
    snprintf(at.verdict, sizeof(at.verdict), "vuln");
    at.count = 2;
    snprintf(at.max_severity, sizeof(at.max_severity), "HIGH");
    at.ts = 1790000100;
    ck_assert_ret_ok(stele_attestation_id(&at, id));
    ck_assert_str_eq(id, "bf31aacaa9a976e8ff224835433738bd82583a3029da8ff23319d2b85cd7aa4f");
}
END_TEST_DEFINITION()

/* Version 2 and the rebuttal (Phase 1): the ids the Python twin computes for
 * the same artifacts (python/tests/test_codec.py, test_v2_fixed_vectors). */
/* Version 3 (Phase 2): a replication names the attestation it re-ran
 * (python/tests/test_codec.py, test_v3_fixed_vectors). */
DEFINE_TEST(test_stele_v3_fixed_vectors)
{
    stele_repo_ad_t ad = _ad();
    uuid_parse("00000000-0000-4000-8000-000000000001", ad.owner);
    ad.version = 2;
    snprintf(ad.description, sizeof(ad.description), "a demo repo");
    snprintf(ad.topics, sizeof(ad.topics), "go,demo");
    snprintf(ad.sbom_digest, sizeof(ad.sbom_digest), "%s",
             "abababababababababababababababababababababababababababababababab");
    snprintf(ad.sbom_path, sizeof(ad.sbom_path), "sbom.cdx.json");
    snprintf(ad.claim_verdict, sizeof(ad.claim_verdict), "clean");
    char ad_id[STELE_ID_HEX + 1], sc[STELE_DIGEST_HEX + 1], orig[STELE_ID_HEX + 1];
    ck_assert_ret_ok(stele_repo_ad_id(&ad, ad_id));
    ck_assert_ret_ok(stele_scope(ad.owner, "demo", COMMIT, "osv-scanner", sc));

    stele_attestation_t at;
    memset(&at, 0, sizeof(at));
    uuid_parse("00000000-0000-4000-8000-000000000002", at.verifier);
    snprintf(at.repo_ad_id, sizeof(at.repo_ad_id), "%s", ad_id);
    snprintf(at.commit, sizeof(at.commit), "%s", COMMIT);
    snprintf(at.scanner, sizeof(at.scanner), "osv-scanner");
    snprintf(at.scanner_version, sizeof(at.scanner_version), "2.6.0");
    snprintf(at.db_digest, sizeof(at.db_digest),
             "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd");
    snprintf(at.findings_digest, sizeof(at.findings_digest),
             "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef");
    snprintf(at.verdict, sizeof(at.verdict), "vuln");
    at.count = 2;
    snprintf(at.max_severity, sizeof(at.max_severity), "HIGH");
    at.ts = 1790000100;
    at.version = 2;
    snprintf(at.channel, sizeof(at.channel), "self_consistency");
    snprintf(at.scope, sizeof(at.scope), "%s", sc);
    ck_assert_ret_ok(stele_attestation_id(&at, orig));

    /* v2 cannot carry a replication; v3 must name what it replicates. */
    snprintf(at.channel, sizeof(at.channel), "replication");
    ck_assert(!stele_attestation_valid(&at));
    at.version = 3;
    ck_assert(!stele_attestation_valid(&at));
    snprintf(at.replicates, sizeof(at.replicates), "%s", orig);
    ck_assert(stele_attestation_valid(&at));
    char id[STELE_ID_HEX + 1];
    ck_assert_ret_ok(stele_attestation_id(&at, id));
    ck_assert_str_eq(id, "d0af362981b137e5cc47219e63f164689e33ba54dba1c6c1858907418f0406b3");

    /* Round trip through the envelope keeps the version and the reference. */
    char sig[STELE_SIG_HEX + 1];
    memset(sig, '0', STELE_SIG_HEX);
    sig[STELE_SIG_HEX] = '\0';
    json_t *env = stele_attestation_to_json(&at, sig);
    ck_assert_ptr_nonnull(env);
    ck_assert_int_eq((int)json_integer_value(json_object_get(env, "v")), 3);
    stele_attestation_t back;
    char sig_back[STELE_SIG_HEX + 1];
    ck_assert_ret_ok(stele_attestation_from_json(env, &back, sig_back));
    ck_assert_str_eq(back.replicates, orig);
    json_object_del(env, "replicates");
    ck_assert(stele_attestation_from_json(env, &back, sig_back) != 0);
    json_decref(env);

    /* A non-replication v3 carries none. */
    snprintf(at.channel, sizeof(at.channel), "probe");
    ck_assert(!stele_attestation_valid(&at));
    at.replicates[0] = '\0';
    ck_assert(stele_attestation_valid(&at));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_stele_v2_fixed_vectors)
{
    stele_repo_ad_t ad = _ad();
    uuid_parse("00000000-0000-4000-8000-000000000001", ad.owner);
    ad.version = 2;
    snprintf(ad.description, sizeof(ad.description), "a demo repo");
    snprintf(ad.topics, sizeof(ad.topics), "go,demo");
    snprintf(ad.sbom_digest, sizeof(ad.sbom_digest), "%s",
             "abababababababababababababababababababababababababababababababab");
    snprintf(ad.sbom_path, sizeof(ad.sbom_path), "sbom.cdx.json");
    snprintf(ad.claim_verdict, sizeof(ad.claim_verdict), "clean");
    char id[STELE_ID_HEX + 1];
    ck_assert_ret_ok(stele_repo_ad_id(&ad, id));
    ck_assert_str_eq(id, "272c0cc3307694e5eca75b6415d11b1d71dc1e5f7690f0be0ee9b61c2d563b89");

    char sc[STELE_DIGEST_HEX + 1];
    ck_assert_ret_ok(stele_scope(ad.owner, "demo", COMMIT, "osv-scanner", sc));
    ck_assert_str_eq(sc, "7f198d461dddd03608116142875b6cfcabbd06e5d4336bd76444aee2d82372e4");

    stele_attestation_t at;
    memset(&at, 0, sizeof(at));
    uuid_parse("00000000-0000-4000-8000-000000000002", at.verifier);
    snprintf(at.repo_ad_id, sizeof(at.repo_ad_id), "%s", id);
    snprintf(at.commit, sizeof(at.commit), "%s", COMMIT);
    snprintf(at.scanner, sizeof(at.scanner), "osv-scanner");
    snprintf(at.scanner_version, sizeof(at.scanner_version), "2.6.0");
    snprintf(at.db_digest, sizeof(at.db_digest),
             "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd");
    snprintf(at.findings_digest, sizeof(at.findings_digest),
             "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef");
    snprintf(at.verdict, sizeof(at.verdict), "vuln");
    at.count = 2;
    snprintf(at.max_severity, sizeof(at.max_severity), "HIGH");
    at.ts = 1790000100;
    at.version = 2;
    snprintf(at.channel, sizeof(at.channel), "self_consistency");
    snprintf(at.scope, sizeof(at.scope), "%s", sc);
    ck_assert_ret_ok(stele_attestation_id(&at, id));
    ck_assert_str_eq(id, "ae530d953d26c613153103de30b8aca1aa17bc5a30833d03011aa3f105ada506");

    stele_rebuttal_t rb;
    memset(&rb, 0, sizeof(rb));
    uuid_copy(rb.owner, ad.owner);
    snprintf(rb.attestation_id, sizeof(rb.attestation_id), "%s", id);
    snprintf(rb.text, sizeof(rb.text), "fixed in the next release");
    rb.ts = 1790000200;
    ck_assert_ret_ok(stele_rebuttal_id(&rb, id));
    ck_assert_str_eq(id, "32472c5b8ecda607b2e84ec404bf3973f021990ec7beab33e6cedbfac1d6e8ce");
}
END_TEST_DEFINITION()

/* A v2 envelope round-trips as v2, a v1 envelope still reads as v1, and the
 * rebuttal signs, verifies and round-trips. */
DEFINE_TEST(test_stele_v2_envelopes_and_rebuttal)
{
    ck_assert(sodium_init() >= 0);
    unsigned char pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);
    stele_repo_ad_t ad = _ad();
    ad.version = 2;
    snprintf(ad.claim_verdict, sizeof(ad.claim_verdict), "none");
    char sig[STELE_SIG_HEX + 1], sig2[STELE_SIG_HEX + 1];
    ck_assert_ret_ok(stele_repo_ad_sign(&ad, sk, sig));
    json_t *env = stele_repo_ad_to_json(&ad, sig);
    stele_repo_ad_t back;
    ck_assert_ret_ok(stele_repo_ad_from_json(env, &back, sig2));
    ck_assert_int_eq(back.version, 2);
    ck_assert(stele_repo_ad_verify(&back, pk, sig2));
    json_object_del(env, "claim_verdict");               /* v2 without its field */
    ck_assert(stele_repo_ad_from_json(env, &back, sig2) != 0);
    json_decref(env);

    stele_repo_ad_t v1 = _ad();
    env = stele_repo_ad_to_json(&v1, sig);
    ck_assert_ret_ok(stele_repo_ad_from_json(env, &back, sig2));
    ck_assert_int_eq(back.version, 1);
    json_decref(env);

    ad = _ad();
    ad.version = 2;
    snprintf(ad.claim_verdict, sizeof(ad.claim_verdict), "clean");
    snprintf(ad.sbom_digest, sizeof(ad.sbom_digest), "%s", HEX64);
    ck_assert(!stele_repo_ad_valid(&ad));                /* digest without path */

    stele_rebuttal_t rb;
    memset(&rb, 0, sizeof(rb));
    uuid_generate(rb.owner);
    snprintf(rb.attestation_id, sizeof(rb.attestation_id), "%s", HEX64);
    snprintf(rb.text, sizeof(rb.text), "a false positive: the module is vendored");
    rb.ts = 1;
    ck_assert_ret_ok(stele_rebuttal_sign(&rb, sk, sig));
    env = stele_rebuttal_to_json(&rb, sig);
    stele_rebuttal_t rb2;
    ck_assert_ret_ok(stele_rebuttal_from_json(env, &rb2, sig2));
    json_decref(env);
    ck_assert(stele_rebuttal_verify(&rb2, pk, sig2));
    snprintf(rb2.text, sizeof(rb2.text), "changed");
    ck_assert(!stele_rebuttal_verify(&rb2, pk, sig2));
}
END_TEST_DEFINITION()

/* Version 4 (Phase 4): a solo ad names the package it provides
 * (python/tests/test_codec.py, test_v4_fixed_vector). */
static stele_repo_ad_t _ad4(void)
{
    stele_repo_ad_t ad = _ad();
    uuid_parse("00000000-0000-4000-8000-000000000001", ad.owner);
    ad.version = 4;
    snprintf(ad.description, sizeof(ad.description), "a demo repo");
    snprintf(ad.topics, sizeof(ad.topics), "go,demo");
    snprintf(ad.sbom_digest, sizeof(ad.sbom_digest), "%s",
             "abababababababababababababababababababababababababababababababab");
    snprintf(ad.sbom_path, sizeof(ad.sbom_path), "sbom.cdx.json");
    snprintf(ad.claim_verdict, sizeof(ad.claim_verdict), "clean");
    snprintf(ad.provides, sizeof(ad.provides), "pkg:golang/forge.local/alice/demo");
    return ad;
}

DEFINE_TEST(test_stele_v4_fixed_vector)
{
    stele_repo_ad_t ad = _ad4();
    char id[STELE_ID_HEX + 1];
    ck_assert_ret_ok(stele_repo_ad_id(&ad, id));
    ck_assert_str_eq(id, "a406d340c5f37d28ff8e1384f5d4bdb50892a0ab76c95d513ba317f9a3d8489c");
    ck_assert(!stele_repo_ad_is_team(&ad));

    /* The envelope carries provides and round-trips to the same id. */
    json_t *env = stele_repo_ad_to_json(&ad, "00");
    stele_repo_ad_t back;
    char sig[STELE_SIG_HEX + 1];
    ck_assert_ret_ok(stele_repo_ad_from_json(env, &back, sig));
    char id2[STELE_ID_HEX + 1];
    ck_assert_ret_ok(stele_repo_ad_id(&back, id2));
    ck_assert_str_eq(id, id2);
    json_object_del(env, "provides");
    ck_assert_int_eq(stele_repo_ad_from_json(env, &back, sig), -1);
    json_decref(env);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_stele_v4_field_rules)
{
    stele_repo_ad_t ad = _ad4();
    ck_assert(stele_repo_ad_valid(&ad));
    ad.provides[0] = '\0';
    ck_assert(stele_repo_ad_valid(&ad));
    const char *bad[] = {"pkg:golang/forge.local/alice/demo@v1.0.0",
                         "pkg:npm/left-pad?arch=x86", "pkg:npm/left-pad#lib",
                         "pkg:NPM/left-pad", "pkg:npm/", "pkg:npm", "npm/left-pad",
                         "pkg:npm/a//b", "pkg:npm/a/", "pkg:npm/left pad"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
    {
        snprintf(ad.provides, sizeof(ad.provides), "%s", bad[i]);
        if (stele_repo_ad_valid(&ad))
            fprintf(stderr, "accepted a bad provides: %s\n", bad[i]);
        ck_assert(!stele_repo_ad_valid(&ad));
    }
    snprintf(ad.provides, sizeof(ad.provides), "pkg:npm/left-pad");
    ck_assert(stele_repo_ad_valid(&ad));
    /* The team fields come together or not at all. */
    snprintf(ad.release_auth, sizeof(ad.release_auth), "x");
    ck_assert(!stele_repo_ad_valid(&ad));
    snprintf(ad.polity, sizeof(ad.polity), "%s",
             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    ck_assert(stele_repo_ad_valid(&ad));
    ck_assert(stele_repo_ad_is_team(&ad));
    ad.release_auth[0] = '\0';
    ck_assert(!stele_repo_ad_valid(&ad));

    /* Every field at its maximum still has a canonical form. */
    stele_repo_ad_t big = _ad4();
    memset(big.name, 'n', STELE_NAME_MAX);
    memset(big.url, 'u', STELE_URL_MAX);
    memset(big.ref, 'r', STELE_REF_MAX);
    memset(big.commit, 'a', 64);
    big.seq = INT64_MAX;
    big.ts = INT64_MAX;
    memset(big.description, 'd', STELE_DESC_MAX);
    memset(big.topics, 't', STELE_TOPICS_MAX);
    memset(big.sbom_path, 'p', STELE_PATH_MAX);
    memset(big.polity, 'a', STELE_PK_HEX);
    memset(big.release_auth, 'x', STELE_RELEASE_TEXT_MAX);
    snprintf(big.provides, sizeof(big.provides), "pkg:npm/%0120d", 0);
    uint8_t canon[STELE_CANON_MAX];
    ck_assert(stele_repo_ad_valid(&big));
    ck_assert(stele_repo_ad_canonical(&big, canon, sizeof(canon)) > 0);
}
END_TEST_DEFINITION()

RUN_TESTS(SteleCodec, test_stele_repo_ad_signs_verifies_and_round_trips,
          test_stele_field_rules, test_stele_fixed_vectors,
          test_stele_v2_fixed_vectors,
          test_stele_v3_fixed_vectors,
          test_stele_v2_envelopes_and_rebuttal,
          test_stele_v4_fixed_vector, test_stele_v4_field_rules)
