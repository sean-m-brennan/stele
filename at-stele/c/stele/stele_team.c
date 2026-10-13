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

#include "stele_team.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>

static bool _hex_ok(const char *s, size_t len)
{
    if (s == NULL || strnlen(s, len + 1) != len)
        return false;
    for (size_t i = 0; i < len; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return false;
    return true;
}

static bool _uuid_ok(const char *s)
{
    if (s == NULL || strnlen(s, 37) != 36)
        return false;
    for (size_t i = 0; i < 36; i++)
    {
        char c = s[i];
        bool dash = (i == 8 || i == 13 || i == 18 || i == 23);
        if (dash ? c != '-' : !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}

/* A did:key, printable and '|'-free (it is part of the consent message). */
static bool _did_ok(const char *s)
{
    if (s == NULL || strncmp(s, "did:key:z", 9) != 0)
        return false;
    size_t n = strnlen(s, STELE_DID_MAX + 1);
    if (n > STELE_DID_MAX)
        return false;
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)s[i] < 0x21 || s[i] == '|' || (unsigned char)s[i] >= 0x7f)
            return false;
    return true;
}

static bool _copy(const char *v, char *dst, size_t cap)
{
    if (v == NULL || strlen(v) >= cap)
        return false;
    memcpy(dst, v, strlen(v) + 1);
    return true;
}

static bool _str(json_t *o, const char *k, char *dst, size_t cap)
{
    return _copy(json_string_value(json_object_get(o, k)), dst, cap);
}

static bool _key_of(const char *hex, unsigned char pk[crypto_sign_PUBLICKEYBYTES])
{
    size_t bin = 0;
    return _hex_ok(hex, STELE_PK_HEX)
        && sodium_hex2bin(pk, crypto_sign_PUBLICKEYBYTES, hex, STELE_PK_HEX, NULL,
                          &bin, NULL) == 0
        && bin == crypto_sign_PUBLICKEYBYTES;
}

static bool _sig_ok(const unsigned char pk[crypto_sign_PUBLICKEYBYTES],
                    const uint8_t *msg, size_t len, const char *sig_hex)
{
    unsigned char sig[crypto_sign_BYTES];
    size_t bin = 0;
    if (!_hex_ok(sig_hex, STELE_SIG_HEX)
        || sodium_hex2bin(sig, sizeof(sig), sig_hex, STELE_SIG_HEX, NULL, &bin, NULL) != 0
        || bin != sizeof(sig))
        return false;
    return crypto_sign_verify_detached(sig, msg, len, pk) == 0;
}

/* Split {"body": <text>, "sig": <hex>}, verify sig over domain + body under the
 * hex key the body names in @p key_field, and return the parsed body (owned). */
json_t *stele_signed_body(const char *text, const char *domain, const char *key_field)
{
    if (text == NULL)
        return NULL;
    json_t *outer = json_loads(text, 0, NULL);
    const char *body = json_string_value(json_object_get(outer, "body"));
    const char *sig = json_string_value(json_object_get(outer, "sig"));
    json_t *parsed = body != NULL ? json_loads(body, 0, NULL) : NULL;
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    bool ok = json_is_object(parsed) && sig != NULL
        && _key_of(json_string_value(json_object_get(parsed, key_field)), pk);
    if (ok)
    {
        size_t dl = strlen(domain), bl = strlen(body);
        uint8_t *msg = malloc(dl + bl);
        ok = msg != NULL;
        if (ok)
        {
            memcpy(msg, domain, dl);
            memcpy(msg + dl, body, bl);
            ok = _sig_ok(pk, msg, dl + bl, sig);
            free(msg);
        }
    }
    json_decref(outer);
    if (!ok)
    {
        json_decref(parsed);
        return NULL;
    }
    return parsed;
}

const stele_team_member_t *stele_team_member(const stele_team_t *t, const char *did)
{
    for (size_t i = 0; t != NULL && did != NULL && i < t->n_members; i++)
        if (strcmp(t->members[i].did, did) == 0)
            return &t->members[i];
    return NULL;
}

const stele_team_member_t *stele_team_member_by_uuid(const stele_team_t *t,
                                                     const char *at_uuid)
{
    for (size_t i = 0; t != NULL && at_uuid != NULL && i < t->n_members; i++)
        if (strcmp(t->members[i].at_uuid, at_uuid) == 0)
            return &t->members[i];
    return NULL;
}

bool stele_team_is_officer(const stele_team_t *t, const char *did)
{
    for (size_t i = 0; t != NULL && did != NULL && i < t->n_officers; i++)
        if (strcmp(t->officers[i], did) == 0)
            return true;
    return false;
}

const char *stele_team_guardian_of(const stele_team_t *t, const char *machine)
{
    for (size_t i = 0; t != NULL && machine != NULL && i < t->n_guardians; i++)
        if (strcmp(t->guardians[i].machine, machine) == 0)
            return t->guardians[i].guardian;
    return NULL;
}

int stele_team_parse(const char *text, stele_team_t *out)
{
    if (out == NULL || text == NULL || strnlen(text, STELE_TEAM_FILE_MAX + 1)
        > STELE_TEAM_FILE_MAX)
        return -1;
    memset(out, 0, sizeof(*out));
    json_t *b = stele_signed_body(text, STELE_TEAM_DOMAIN, "issuer");
    if (b == NULL)
        return -1;
    json_t *v = json_object_get(b, "v"), *seq = json_object_get(b, "seq");
    json_t *members = json_object_get(b, "members");
    json_t *officers = json_object_get(b, "release_officers");
    json_t *guardians = json_object_get(b, "guardians");
    const char *typename = json_string_value(json_object_get(b, "typename"));
    bool ok = json_is_integer(v) && json_integer_value(v) == 1
        && typename != NULL && strcmp(typename, "stele-team") == 0
        && json_is_integer(seq) && json_integer_value(seq) >= 0
        && _str(b, "issuer", out->issuer, sizeof(out->issuer))
        && _str(b, "polity", out->polity, sizeof(out->polity)) && _did_ok(out->polity)
        && json_is_array(members) && json_array_size(members) <= STELE_TEAM_MAX
        && json_is_array(officers) && json_array_size(officers) <= STELE_TEAM_MAX
        && json_is_array(guardians) && json_array_size(guardians) <= STELE_TEAM_MAX;
    if (ok)
        out->seq = (int64_t)json_integer_value(seq);
    size_t i;
    json_t *e;
    json_array_foreach(ok ? members : NULL, i, e)
    {
        stele_team_member_t *m = &out->members[i];
        ok = json_is_object(e) && _str(e, "did", m->did, sizeof(m->did)) && _did_ok(m->did)
            && _str(e, "key", m->key, sizeof(m->key)) && _hex_ok(m->key, STELE_PK_HEX)
            && _str(e, "at_uuid", m->at_uuid, sizeof(m->at_uuid)) && _uuid_ok(m->at_uuid)
            && _str(e, "consent", m->consent, sizeof(m->consent))
            && _hex_ok(m->consent, STELE_SIG_HEX)
            && stele_team_member(out, m->did) == NULL
            && stele_team_member_by_uuid(out, m->at_uuid) == NULL;
        if (!ok)
            break;
        out->n_members = i + 1;
    }
    json_array_foreach(ok ? officers : NULL, i, e)
    {
        ok = _copy(json_string_value(e), out->officers[i], sizeof(out->officers[i]))
            && stele_team_member(out, out->officers[i]) != NULL;
        if (!ok)
            break;
        out->n_officers = i + 1;
    }
    json_array_foreach(ok ? guardians : NULL, i, e)
    {
        stele_team_guardian_t *g = &out->guardians[i];
        ok = json_is_object(e) && _str(e, "machine", g->machine, sizeof(g->machine))
            && _str(e, "guardian", g->guardian, sizeof(g->guardian))
            && stele_team_member(out, g->machine) != NULL
            && stele_team_member(out, g->guardian) != NULL
            && strcmp(g->machine, g->guardian) != 0;
        if (!ok)
            break;
        out->n_guardians = i + 1;
    }
    json_decref(b);
    return ok ? 0 : -1;
}

size_t stele_consent_message(const char *issuer, const char *did, const char *at_uuid,
                             uint8_t *out, size_t cap)
{
    if (issuer == NULL || did == NULL || at_uuid == NULL || out == NULL)
        return 0;
    int n = snprintf((char *)out, cap, "%s%s|%s|%s", STELE_CONSENT_DOMAIN, issuer,
                     did, at_uuid);
    return (n < 0 || (size_t)n >= cap) ? 0 : (size_t)n;
}

bool stele_team_consents_ok(const stele_team_t *t, stele_key_lookup_fn lookup,
                            void *ctx, char *bad)
{
    if (t == NULL || lookup == NULL)
        return false;
    for (size_t i = 0; i < t->n_members; i++)
    {
        const stele_team_member_t *m = &t->members[i];
        unsigned char pk[crypto_sign_PUBLICKEYBYTES];
        uint8_t msg[256];
        size_t len = stele_consent_message(t->issuer, m->did, m->at_uuid, msg,
                                           sizeof(msg));
        if (len == 0 || !lookup(m->at_uuid, ctx, pk) || !_sig_ok(pk, msg, len, m->consent))
        {
            if (bad != NULL)
                snprintf(bad, STELE_UUID_STR, "%s", m->at_uuid);
            return false;
        }
    }
    return true;
}

int stele_release_parse(const char *text, stele_release_t *out)
{
    if (out == NULL || text == NULL || strnlen(text, STELE_RELEASE_MAX + 1)
        > STELE_RELEASE_MAX)
        return -1;
    memset(out, 0, sizeof(*out));
    json_t *b = stele_signed_body(text, STELE_RELEASE_DOMAIN, "officer_key");
    if (b == NULL)
        return -1;
    json_t *v = json_object_get(b, "v"), *at = json_object_get(b, "authorized_at");
    const char *typename = json_string_value(json_object_get(b, "typename"));
    json_t *built = json_object_get(b, "built_by");
    bool ok = json_is_integer(v) && json_integer_value(v) == 1
        && typename != NULL && strcmp(typename, "stele-release") == 0
        && json_is_integer(at) && json_integer_value(at) >= 0
        && _str(b, "issuer", out->issuer, sizeof(out->issuer))
        && _hex_ok(out->issuer, STELE_PK_HEX)
        && _str(b, "polity", out->polity, sizeof(out->polity)) && _did_ok(out->polity)
        && _str(b, "officer", out->officer, sizeof(out->officer)) && _did_ok(out->officer)
        && _str(b, "officer_key", out->officer_key, sizeof(out->officer_key))
        && _str(b, "repo", out->repo, sizeof(out->repo))
        && _str(b, "url", out->url, sizeof(out->url))
        && _str(b, "commit", out->commit, sizeof(out->commit))
        && (_hex_ok(out->commit, 40) || _hex_ok(out->commit, 64))
        && (built == NULL || (_str(b, "built_by", out->built_by, sizeof(out->built_by))
                              && _did_ok(out->built_by)));
    if (ok)
        out->authorized_at = (int64_t)json_integer_value(at);
    json_decref(b);
    return ok ? 0 : -1;
}
