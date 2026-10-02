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

RUN_TESTS(SteleCodec, test_stele_repo_ad_signs_verifies_and_round_trips,
          test_stele_field_rules, test_stele_fixed_vectors)
