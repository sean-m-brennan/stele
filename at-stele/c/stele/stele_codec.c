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

#include "stele_codec.h"

#include <stdio.h>
#include <string.h>

/* A field is printable, '|'-free, and 1..@p max bytes (0..max when @p empty_ok). */
static bool _field_ok(const char *s, size_t max, bool empty_ok)
{
    if (s == NULL)
        return false;
    size_t n = strnlen(s, max + 1);
    if (n > max || (n == 0 && !empty_ok))
        return false;
    for (size_t i = 0; i < n; i++)
    {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 || c == 0x7f || c == '|')
            return false;
    }
    return true;
}

static bool _hex_ok(const char *s, size_t len)
{
    if (s == NULL || strnlen(s, len + 1) != len)
        return false;
    for (size_t i = 0; i < len; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return false;
    return true;
}

bool stele_repo_ad_valid(const stele_repo_ad_t *ad)
{
    return ad != NULL && !uuid_is_null(ad->owner)
        && _field_ok(ad->name, STELE_NAME_MAX, false)
        && _field_ok(ad->url, STELE_URL_MAX, false)
        && _field_ok(ad->ref, STELE_REF_MAX, false)
        && (_hex_ok(ad->commit, 40) || _hex_ok(ad->commit, 64))
        && ad->seq >= 0 && ad->ts >= 0;
}

bool stele_attestation_valid(const stele_attestation_t *at)
{
    if (at == NULL || uuid_is_null(at->verifier))
        return false;
    bool clean = strcmp(at->verdict, STELE_VERDICT_CLEAN) == 0;
    bool vuln = strcmp(at->verdict, STELE_VERDICT_VULN) == 0;
    return _hex_ok(at->repo_ad_id, STELE_ID_HEX)
        && (_hex_ok(at->commit, 40) || _hex_ok(at->commit, 64))
        && _field_ok(at->scanner, STELE_SCANNER_MAX, false)
        && _field_ok(at->scanner_version, STELE_VERSION_MAX, false)
        && _hex_ok(at->db_digest, STELE_DIGEST_HEX)
        && _hex_ok(at->findings_digest, STELE_DIGEST_HEX)
        && (clean || vuln)
        && (clean ? at->count == 0 : at->count > 0)
        && _field_ok(at->max_severity, STELE_SEVERITY_MAX, true)
        && at->ts >= 0;
}

static size_t _with_tag(const char *tag, const char *body, uint8_t *out, size_t cap)
{
    size_t tag_len = strlen(tag) + 1;   /* includes the NUL separator */
    size_t body_len = strlen(body);
    if (tag_len + body_len > cap)
        return 0;
    memcpy(out, tag, tag_len);
    memcpy(out + tag_len, body, body_len);
    return tag_len + body_len;
}

size_t stele_repo_ad_canonical(const stele_repo_ad_t *ad, uint8_t *out, size_t cap)
{
    if (!stele_repo_ad_valid(ad) || out == NULL)
        return 0;
    char owner[STELE_UUID_STR];
    uuid_unparse_lower(ad->owner, owner);
    char body[STELE_CANON_MAX];
    int n = snprintf(body, sizeof(body), "%s|%s|%s|%s|%s|%lld|%lld", owner,
                     ad->name, ad->url, ad->ref, ad->commit, (long long)ad->seq,
                     (long long)ad->ts);
    if (n < 0 || (size_t)n >= sizeof(body))
        return 0;
    return _with_tag("STELE-REPO", body, out, cap);
}

size_t stele_attestation_canonical(const stele_attestation_t *at, uint8_t *out,
                                   size_t cap)
{
    if (!stele_attestation_valid(at) || out == NULL)
        return 0;
    char verifier[STELE_UUID_STR];
    uuid_unparse_lower(at->verifier, verifier);
    char body[STELE_CANON_MAX];
    int n = snprintf(body, sizeof(body), "%s|%s|%s|%s|%s|%s|%s|%s|%lld|%s|%lld",
                     verifier, at->repo_ad_id, at->commit, at->scanner,
                     at->scanner_version, at->db_digest, at->findings_digest,
                     at->verdict, (long long)at->count, at->max_severity,
                     (long long)at->ts);
    if (n < 0 || (size_t)n >= sizeof(body))
        return 0;
    return _with_tag("STELE-ATTEST", body, out, cap);
}

static int _id_of(const uint8_t *canon, size_t len, char out[STELE_ID_HEX + 1])
{
    if (len == 0)
        return -1;
    unsigned char digest[32];
    crypto_generichash(digest, sizeof(digest), canon, len, NULL, 0);
    sodium_bin2hex(out, STELE_ID_HEX + 1, digest, sizeof(digest));
    return 0;
}

int stele_repo_ad_id(const stele_repo_ad_t *ad, char out[STELE_ID_HEX + 1])
{
    uint8_t canon[STELE_CANON_MAX];
    return _id_of(canon, stele_repo_ad_canonical(ad, canon, sizeof(canon)), out);
}

int stele_attestation_id(const stele_attestation_t *at, char out[STELE_ID_HEX + 1])
{
    uint8_t canon[STELE_CANON_MAX];
    return _id_of(canon, stele_attestation_canonical(at, canon, sizeof(canon)), out);
}

static int _sign(const uint8_t *canon, size_t len,
                 const unsigned char sk[crypto_sign_SECRETKEYBYTES],
                 char sig_out[STELE_SIG_HEX + 1])
{
    if (len == 0 || sk == NULL)
        return -1;
    unsigned char sig[crypto_sign_BYTES];
    if (crypto_sign_detached(sig, NULL, canon, len, sk) != 0)
        return -1;
    sodium_bin2hex(sig_out, STELE_SIG_HEX + 1, sig, sizeof(sig));
    return 0;
}

static bool _verify(const uint8_t *canon, size_t len,
                    const unsigned char pk[crypto_sign_PUBLICKEYBYTES],
                    const char *sig_hex)
{
    if (len == 0 || pk == NULL || sig_hex == NULL
        || strnlen(sig_hex, STELE_SIG_HEX + 1) != STELE_SIG_HEX)
        return false;
    unsigned char sig[crypto_sign_BYTES];
    size_t bin = 0;
    if (sodium_hex2bin(sig, sizeof(sig), sig_hex, STELE_SIG_HEX, NULL, &bin, NULL) != 0
        || bin != sizeof(sig))
        return false;
    return crypto_sign_verify_detached(sig, canon, len, pk) == 0;
}

int stele_repo_ad_sign(const stele_repo_ad_t *ad,
                       const unsigned char sk[crypto_sign_SECRETKEYBYTES],
                       char sig_out[STELE_SIG_HEX + 1])
{
    uint8_t canon[STELE_CANON_MAX];
    return _sign(canon, stele_repo_ad_canonical(ad, canon, sizeof(canon)), sk, sig_out);
}

bool stele_repo_ad_verify(const stele_repo_ad_t *ad,
                          const unsigned char pk[crypto_sign_PUBLICKEYBYTES],
                          const char *sig_hex)
{
    uint8_t canon[STELE_CANON_MAX];
    return _verify(canon, stele_repo_ad_canonical(ad, canon, sizeof(canon)), pk, sig_hex);
}

int stele_attestation_sign(const stele_attestation_t *at,
                           const unsigned char sk[crypto_sign_SECRETKEYBYTES],
                           char sig_out[STELE_SIG_HEX + 1])
{
    uint8_t canon[STELE_CANON_MAX];
    return _sign(canon, stele_attestation_canonical(at, canon, sizeof(canon)), sk,
                 sig_out);
}

bool stele_attestation_verify(const stele_attestation_t *at,
                              const unsigned char pk[crypto_sign_PUBLICKEYBYTES],
                              const char *sig_hex)
{
    uint8_t canon[STELE_CANON_MAX];
    return _verify(canon, stele_attestation_canonical(at, canon, sizeof(canon)), pk,
                   sig_hex);
}

json_t *stele_repo_ad_to_json(const stele_repo_ad_t *ad, const char *sig_hex)
{
    char owner[STELE_UUID_STR];
    uuid_unparse_lower(ad->owner, owner);
    return json_pack("{s:s, s:s, s:s, s:s, s:s, s:I, s:I, s:s}",
                     "owner", owner, "name", ad->name, "url", ad->url,
                     "ref", ad->ref, "commit", ad->commit,
                     "seq", (json_int_t)ad->seq, "ts", (json_int_t)ad->ts,
                     "sig", sig_hex != NULL ? sig_hex : "");
}

/* Copy a string field, refusing one that would be truncated. */
static bool _take(const json_t *obj, const char *key, char *dst, size_t cap)
{
    const char *v = json_string_value(json_object_get((json_t *)obj, key));
    if (v == NULL || strlen(v) >= cap)
        return false;
    memcpy(dst, v, strlen(v) + 1);
    return true;
}

static bool _take_int(const json_t *obj, const char *key, int64_t *dst)
{
    json_t *j = json_object_get((json_t *)obj, key);
    if (!json_is_integer(j))
        return false;
    *dst = (int64_t)json_integer_value(j);
    return true;
}

int stele_repo_ad_from_json(const json_t *obj, stele_repo_ad_t *ad,
                            char sig_out[STELE_SIG_HEX + 1])
{
    if (!json_is_object(obj) || ad == NULL)
        return -1;
    memset(ad, 0, sizeof(*ad));
    char owner[STELE_UUID_STR];
    if (!_take(obj, "owner", owner, sizeof(owner)) || uuid_parse(owner, ad->owner) != 0
        || !_take(obj, "name", ad->name, sizeof(ad->name))
        || !_take(obj, "url", ad->url, sizeof(ad->url))
        || !_take(obj, "ref", ad->ref, sizeof(ad->ref))
        || !_take(obj, "commit", ad->commit, sizeof(ad->commit))
        || !_take_int(obj, "seq", &ad->seq) || !_take_int(obj, "ts", &ad->ts)
        || !_take(obj, "sig", sig_out, STELE_SIG_HEX + 1))
        return -1;
    return stele_repo_ad_valid(ad) ? 0 : -1;
}

json_t *stele_attestation_to_json(const stele_attestation_t *at, const char *sig_hex)
{
    char verifier[STELE_UUID_STR];
    uuid_unparse_lower(at->verifier, verifier);
    json_t *o = json_pack("{s:s, s:s, s:s, s:s, s:s, s:s, s:s, s:s, s:I, s:s, s:I, s:s}",
                          "verifier", verifier, "repo_ad_id", at->repo_ad_id,
                          "commit", at->commit, "scanner", at->scanner,
                          "scanner_version", at->scanner_version,
                          "db_digest", at->db_digest,
                          "findings_digest", at->findings_digest,
                          "verdict", at->verdict, "count", (json_int_t)at->count,
                          "max_severity", at->max_severity, "ts", (json_int_t)at->ts,
                          "sig", sig_hex != NULL ? sig_hex : "");
    return o;
}

int stele_attestation_from_json(const json_t *obj, stele_attestation_t *at,
                                char sig_out[STELE_SIG_HEX + 1])
{
    if (!json_is_object(obj) || at == NULL)
        return -1;
    memset(at, 0, sizeof(*at));
    char verifier[STELE_UUID_STR];
    if (!_take(obj, "verifier", verifier, sizeof(verifier))
        || uuid_parse(verifier, at->verifier) != 0
        || !_take(obj, "repo_ad_id", at->repo_ad_id, sizeof(at->repo_ad_id))
        || !_take(obj, "commit", at->commit, sizeof(at->commit))
        || !_take(obj, "scanner", at->scanner, sizeof(at->scanner))
        || !_take(obj, "scanner_version", at->scanner_version, sizeof(at->scanner_version))
        || !_take(obj, "db_digest", at->db_digest, sizeof(at->db_digest))
        || !_take(obj, "findings_digest", at->findings_digest, sizeof(at->findings_digest))
        || !_take(obj, "verdict", at->verdict, sizeof(at->verdict))
        || !_take_int(obj, "count", &at->count)
        || !_take(obj, "max_severity", at->max_severity, sizeof(at->max_severity))
        || !_take_int(obj, "ts", &at->ts)
        || !_take(obj, "sig", sig_out, STELE_SIG_HEX + 1))
        return -1;
    return stele_attestation_valid(at) ? 0 : -1;
}
