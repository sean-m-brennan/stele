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

/* Versions 2, 3 and 4 of the ad all carry the v2 fields. */
static bool _v2(int version)
{
    return version >= 2 && version <= 4;
}

bool stele_repo_ad_is_team(const stele_repo_ad_t *ad)
{
    return ad != NULL && (ad->version == 3 || (ad->version == 4 && ad->polity[0] != '\0'));
}

bool stele_purl_base_ok(const char *s)
{
    if (!_field_ok(s, STELE_PROVIDES_MAX, false) || strncmp(s, "pkg:", 4) != 0)
        return false;
    const char *t = s + 4;
    size_t tn = 0;
    while (t[tn] != '\0' && t[tn] != '/')
    {
        char c = t[tn];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '+'
              || c == '-'))
            return false;
        tn++;
    }
    if (tn == 0 || t[tn] != '/' || t[tn + 1] == '\0')
        return false;
    for (const char *p = t + tn + 1; *p != '\0'; p++)
        if (*p == '@' || *p == '?' || *p == '#' || *p == ' '
            || (*p == '/' && (p[1] == '/' || p[1] == '\0')))
            return false;
    return true;
}

int stele_release_digest(const char *release_auth, char out[STELE_DIGEST_HEX + 1])
{
    if (release_auth == NULL || release_auth[0] == '\0'
        || strnlen(release_auth, STELE_RELEASE_TEXT_MAX + 1) > STELE_RELEASE_TEXT_MAX)
        return -1;
    unsigned char digest[32];
    crypto_generichash(digest, sizeof(digest), (const unsigned char *)release_auth,
                       strlen(release_auth), NULL, 0);
    sodium_bin2hex(out, STELE_DIGEST_HEX + 1, digest, sizeof(digest));
    return 0;
}

static bool _claim_ok(const char *c)
{
    return strcmp(c, STELE_VERDICT_CLEAN) == 0 || strcmp(c, STELE_VERDICT_VULN) == 0
        || strcmp(c, STELE_CLAIM_NONE) == 0;
}

static bool _channel_ok(const char *c)
{
    return strcmp(c, STELE_CHANNEL_PROBE) == 0
        || strcmp(c, STELE_CHANNEL_CERTIFICATE) == 0
        || strcmp(c, STELE_CHANNEL_SELF_CONSISTENCY) == 0;
}

bool stele_repo_ad_valid(const stele_repo_ad_t *ad)
{
    if (ad == NULL || (ad->version != 0 && ad->version != 1 && !_v2(ad->version)))
        return false;
    if (stele_repo_ad_is_team(ad))
    {
        char d[STELE_DIGEST_HEX + 1];
        if (!_hex_ok(ad->polity, STELE_PK_HEX) || stele_release_digest(ad->release_auth, d) != 0)
            return false;
    }
    else if (ad->version == 4 && ad->release_auth[0] != '\0')
        return false;   /* a release authorization needs its polity */
    if (ad->version == 4 && ad->provides[0] != '\0' && !stele_purl_base_ok(ad->provides))
        return false;
    bool v1 = !uuid_is_null(ad->owner)
        && _field_ok(ad->name, STELE_NAME_MAX, false)
        && _field_ok(ad->url, STELE_URL_MAX, false)
        && _field_ok(ad->ref, STELE_REF_MAX, false)
        && (_hex_ok(ad->commit, 40) || _hex_ok(ad->commit, 64))
        && ad->seq >= 0 && ad->ts >= 0;
    if (!v1 || !_v2(ad->version))
        return v1;
    /* An SBOM path and its digest come together or not at all. */
    bool has_sbom = ad->sbom_digest[0] != '\0';
    return _field_ok(ad->description, STELE_DESC_MAX, true)
        && _field_ok(ad->topics, STELE_TOPICS_MAX, true)
        && (has_sbom ? _hex_ok(ad->sbom_digest, STELE_DIGEST_HEX) : true)
        && _field_ok(ad->sbom_path, STELE_PATH_MAX, true)
        && (has_sbom == (ad->sbom_path[0] != '\0'))
        && _claim_ok(ad->claim_verdict);
}

/* A v3 attestation: any v2 channel with no `replicates`, or the replication
 * channel naming the attestation it re-ran. */
static bool _v3_ok(const stele_attestation_t *at)
{
    bool repl = strcmp(at->channel, STELE_CHANNEL_REPLICATION) == 0;
    return (repl || _channel_ok(at->channel))
        && _hex_ok(at->scope, STELE_DIGEST_HEX)
        && (repl ? _hex_ok(at->replicates, STELE_ID_HEX)
                 : at->replicates[0] == '\0');
}

/* A v4 attestation: a probe naming the finding it attributes and the builder
 * machine whose guardian it lands on. Only a finding is attributed. */
static bool _v4_ok(const stele_attestation_t *at)
{
    const char *g = at->guardian_of;
    size_t n = strnlen(g, STELE_DID_TEXT_MAX + 1);
    bool did = strncmp(g, "did:key:z", 9) == 0 && n <= STELE_DID_TEXT_MAX;
    for (size_t i = 0; did && i < n; i++)
        if ((unsigned char)g[i] < 0x21 || g[i] == '|' || (unsigned char)g[i] >= 0x7f)
            did = false;
    return strcmp(at->channel, STELE_CHANNEL_PROBE) == 0
        && strcmp(at->verdict, STELE_VERDICT_VULN) == 0
        && _hex_ok(at->scope, STELE_DIGEST_HEX)
        && _hex_ok(at->attributes, STELE_ID_HEX) && did
        && at->replicates[0] == '\0';
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
        && at->ts >= 0
        && (at->version == 0 || at->version == 1
            || (at->version == 2 && _channel_ok(at->channel)
                && _hex_ok(at->scope, STELE_DIGEST_HEX))
            || (at->version == 3 && _v3_ok(at))
            || (at->version == 4 && _v4_ok(at)));
}

bool stele_rebuttal_valid(const stele_rebuttal_t *rb)
{
    return rb != NULL && !uuid_is_null(rb->owner)
        && _hex_ok(rb->attestation_id, STELE_ID_HEX)
        && _field_ok(rb->text, STELE_REBUT_MAX, false)
        && rb->ts >= 0;
}

int stele_scope(const uuid_t owner, const char *name, const char *commit,
                const char *scanner, char out[STELE_DIGEST_HEX + 1])
{
    if (owner == NULL || name == NULL || commit == NULL || scanner == NULL)
        return -1;
    char o[STELE_UUID_STR];
    uuid_unparse_lower(owner, o);
    char buf[STELE_CANON_MAX];
    int n = snprintf(buf, sizeof(buf), "%s|%s|%s|%s", o, name, commit, scanner);
    if (n < 0 || (size_t)n >= sizeof(buf))
        return -1;
    unsigned char digest[32];
    crypto_generichash(digest, sizeof(digest), (const unsigned char *)buf,
                       (size_t)n, NULL, 0);
    sodium_bin2hex(out, STELE_DIGEST_HEX + 1, digest, sizeof(digest));
    return 0;
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
    if (!_v2(ad->version))
        return _with_tag("STELE-REPO", body, out, cap);
    int m = snprintf(body + n, sizeof(body) - (size_t)n, "|%s|%s|%s|%s|%s",
                     ad->description, ad->topics, ad->sbom_digest, ad->sbom_path,
                     ad->claim_verdict);
    if (m < 0 || (size_t)m >= sizeof(body) - (size_t)n)
        return 0;
    if (ad->version == 2)
        return _with_tag("STELE-REPO2", body, out, cap);
    n += m;
    char digest[STELE_DIGEST_HEX + 1] = "";
    if (stele_repo_ad_is_team(ad) && stele_release_digest(ad->release_auth, digest) != 0)
        return 0;
    m = snprintf(body + n, sizeof(body) - (size_t)n, "|%s|%s", ad->polity, digest);
    if (m < 0 || (size_t)m >= sizeof(body) - (size_t)n)
        return 0;
    if (ad->version == 3)
        return _with_tag("STELE-REPO3", body, out, cap);
    n += m;
    m = snprintf(body + n, sizeof(body) - (size_t)n, "|%s", ad->provides);
    if (m < 0 || (size_t)m >= sizeof(body) - (size_t)n)
        return 0;
    return _with_tag("STELE-REPO4", body, out, cap);
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
    if (at->version != 2 && at->version != 3 && at->version != 4)
        return _with_tag("STELE-ATTEST", body, out, cap);
    int m = snprintf(body + n, sizeof(body) - (size_t)n, "|%s|%s", at->channel,
                     at->scope);
    if (m < 0 || (size_t)m >= sizeof(body) - (size_t)n)
        return 0;
    if (at->version == 2)
        return _with_tag("STELE-ATTEST2", body, out, cap);
    n += m;
    if (at->version == 4)
    {
        m = snprintf(body + n, sizeof(body) - (size_t)n, "|%s|%s", at->attributes,
                     at->guardian_of);
        if (m < 0 || (size_t)m >= sizeof(body) - (size_t)n)
            return 0;
        return _with_tag("STELE-ATTEST4", body, out, cap);
    }
    m = snprintf(body + n, sizeof(body) - (size_t)n, "|%s", at->replicates);
    if (m < 0 || (size_t)m >= sizeof(body) - (size_t)n)
        return 0;
    return _with_tag("STELE-ATTEST3", body, out, cap);
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
    json_t *o = json_pack("{s:s, s:s, s:s, s:s, s:s, s:I, s:I, s:s}",
                          "owner", owner, "name", ad->name, "url", ad->url,
                          "ref", ad->ref, "commit", ad->commit,
                          "seq", (json_int_t)ad->seq, "ts", (json_int_t)ad->ts,
                          "sig", sig_hex != NULL ? sig_hex : "");
    if (o != NULL && _v2(ad->version))
    {
        json_object_set_new(o, "v", json_integer(ad->version));
        json_object_set_new(o, "description", json_string(ad->description));
        json_object_set_new(o, "topics", json_string(ad->topics));
        json_object_set_new(o, "sbom_digest", json_string(ad->sbom_digest));
        json_object_set_new(o, "sbom_path", json_string(ad->sbom_path));
        json_object_set_new(o, "claim_verdict", json_string(ad->claim_verdict));
        if (ad->version >= 3)
        {
            json_object_set_new(o, "polity", json_string(ad->polity));
            json_object_set_new(o, "release_auth", json_string(ad->release_auth));
        }
        if (ad->version == 4)
            json_object_set_new(o, "provides", json_string(ad->provides));
    }
    return o;
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
    ad->version = 1;
    json_t *v = json_object_get((json_t *)obj, "v");
    if (v != NULL)
    {
        json_int_t ver = json_is_integer(v) ? json_integer_value(v) : 0;
        if ((ver != 2 && ver != 3 && ver != 4)
            || (ver >= 3 && (!_take(obj, "polity", ad->polity, sizeof(ad->polity))
                             || !_take(obj, "release_auth", ad->release_auth,
                                       sizeof(ad->release_auth))))
            || (ver == 4 && !_take(obj, "provides", ad->provides, sizeof(ad->provides)))
            || !_take(obj, "description", ad->description, sizeof(ad->description))
            || !_take(obj, "topics", ad->topics, sizeof(ad->topics))
            || !_take(obj, "sbom_digest", ad->sbom_digest, sizeof(ad->sbom_digest))
            || !_take(obj, "sbom_path", ad->sbom_path, sizeof(ad->sbom_path))
            || !_take(obj, "claim_verdict", ad->claim_verdict,
                      sizeof(ad->claim_verdict)))
            return -1;
        ad->version = (int)ver;
    }
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
    if (o != NULL && at->version >= 2 && at->version <= 4)
    {
        json_object_set_new(o, "v", json_integer(at->version));
        json_object_set_new(o, "channel", json_string(at->channel));
        json_object_set_new(o, "scope", json_string(at->scope));
        if (at->version == 3)
            json_object_set_new(o, "replicates", json_string(at->replicates));
        if (at->version == 4)
        {
            json_object_set_new(o, "attributes", json_string(at->attributes));
            json_object_set_new(o, "guardian_of", json_string(at->guardian_of));
        }
    }
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
    at->version = 1;
    json_t *v = json_object_get((json_t *)obj, "v");
    if (v != NULL)
    {
        json_int_t ver = json_is_integer(v) ? json_integer_value(v) : 0;
        if (ver < 2 || ver > 4
            || !_take(obj, "channel", at->channel, sizeof(at->channel))
            || !_take(obj, "scope", at->scope, sizeof(at->scope))
            || (ver == 3 && !_take(obj, "replicates", at->replicates,
                                   sizeof(at->replicates)))
            || (ver == 4 && (!_take(obj, "attributes", at->attributes,
                                    sizeof(at->attributes))
                             || !_take(obj, "guardian_of", at->guardian_of,
                                       sizeof(at->guardian_of)))))
            return -1;
        at->version = (int)ver;
    }
    return stele_attestation_valid(at) ? 0 : -1;
}

size_t stele_rebuttal_canonical(const stele_rebuttal_t *rb, uint8_t *out, size_t cap)
{
    if (!stele_rebuttal_valid(rb) || out == NULL)
        return 0;
    char owner[STELE_UUID_STR];
    uuid_unparse_lower(rb->owner, owner);
    char body[STELE_CANON_MAX];
    int n = snprintf(body, sizeof(body), "%s|%s|%s|%lld", owner,
                     rb->attestation_id, rb->text, (long long)rb->ts);
    if (n < 0 || (size_t)n >= sizeof(body))
        return 0;
    return _with_tag("STELE-REBUT", body, out, cap);
}

int stele_rebuttal_id(const stele_rebuttal_t *rb, char out[STELE_ID_HEX + 1])
{
    uint8_t canon[STELE_CANON_MAX];
    return _id_of(canon, stele_rebuttal_canonical(rb, canon, sizeof(canon)), out);
}

int stele_rebuttal_sign(const stele_rebuttal_t *rb,
                        const unsigned char sk[crypto_sign_SECRETKEYBYTES],
                        char sig_out[STELE_SIG_HEX + 1])
{
    uint8_t canon[STELE_CANON_MAX];
    return _sign(canon, stele_rebuttal_canonical(rb, canon, sizeof(canon)), sk,
                 sig_out);
}

bool stele_rebuttal_verify(const stele_rebuttal_t *rb,
                           const unsigned char pk[crypto_sign_PUBLICKEYBYTES],
                           const char *sig_hex)
{
    uint8_t canon[STELE_CANON_MAX];
    return _verify(canon, stele_rebuttal_canonical(rb, canon, sizeof(canon)), pk,
                   sig_hex);
}

json_t *stele_rebuttal_to_json(const stele_rebuttal_t *rb, const char *sig_hex)
{
    char owner[STELE_UUID_STR];
    uuid_unparse_lower(rb->owner, owner);
    return json_pack("{s:s, s:s, s:s, s:I, s:s}", "owner", owner,
                     "attestation_id", rb->attestation_id, "text", rb->text,
                     "ts", (json_int_t)rb->ts, "sig", sig_hex != NULL ? sig_hex : "");
}

int stele_rebuttal_from_json(const json_t *obj, stele_rebuttal_t *rb,
                             char sig_out[STELE_SIG_HEX + 1])
{
    if (!json_is_object(obj) || rb == NULL)
        return -1;
    memset(rb, 0, sizeof(*rb));
    char owner[STELE_UUID_STR];
    if (!_take(obj, "owner", owner, sizeof(owner)) || uuid_parse(owner, rb->owner) != 0
        || !_take(obj, "attestation_id", rb->attestation_id, sizeof(rb->attestation_id))
        || !_take(obj, "text", rb->text, sizeof(rb->text))
        || !_take_int(obj, "ts", &rb->ts)
        || !_take(obj, "sig", sig_out, STELE_SIG_HEX + 1))
        return -1;
    return stele_rebuttal_valid(rb) ? 0 : -1;
}
