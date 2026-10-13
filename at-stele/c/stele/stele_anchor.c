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

#include "stele_anchor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include <sodium.h>

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

static bool _str(json_t *o, const char *k, char *dst, size_t cap)
{
    const char *v = json_string_value(json_object_get(o, k));
    if (v == NULL || strlen(v) >= cap)
        return false;
    memcpy(dst, v, strlen(v) + 1);
    return true;
}

/* A non-negative JSON integer (never a boolean, which jansson keeps apart). */
static bool _nat(json_t *o, const char *k, int64_t *dst)
{
    json_t *j = json_object_get(o, k);
    if (!json_is_integer(j) || json_integer_value(j) < 0)
        return false;
    *dst = (int64_t)json_integer_value(j);
    return true;
}

size_t stele_anchor_consent_message(const char *issuer, const char *group_uuid,
                                    const char *at_uuid, const char *pubkey,
                                    uint8_t *out, size_t cap)
{
    if (issuer == NULL || group_uuid == NULL || at_uuid == NULL || pubkey == NULL
        || out == NULL)
        return 0;
    int n = snprintf((char *)out, cap, "%s%s|%s|%s|%s", STELE_ANCHOR_CONSENT_DOMAIN,
                     issuer, group_uuid, at_uuid, pubkey);
    return (n < 0 || (size_t)n >= cap) ? 0 : (size_t)n;
}

const stele_anchor_member_t *stele_anchor_member(const stele_anchor_t *a,
                                                 const char *at_uuid)
{
    for (size_t i = 0; a != NULL && at_uuid != NULL && i < a->n_members; i++)
        if (strcmp(a->members[i].at_uuid, at_uuid) == 0)
            return &a->members[i];
    return NULL;
}

/* The consent of a listed node, under the key it is listed with. */
static bool _consent_ok(const stele_anchor_t *a, const stele_anchor_member_t *m,
                        const char *consent)
{
    unsigned char pk[crypto_sign_PUBLICKEYBYTES], sig[crypto_sign_BYTES];
    size_t bin = 0;
    if (sodium_hex2bin(pk, sizeof(pk), m->pubkey, STELE_PK_HEX, NULL, &bin, NULL) != 0
        || bin != sizeof(pk)
        || !_hex_ok(consent, STELE_SIG_HEX)
        || sodium_hex2bin(sig, sizeof(sig), consent, STELE_SIG_HEX, NULL, &bin, NULL) != 0
        || bin != sizeof(sig))
        return false;
    uint8_t msg[512];
    size_t n = stele_anchor_consent_message(a->issuer, a->group_uuid, m->at_uuid,
                                            m->pubkey, msg, sizeof(msg));
    return n > 0 && crypto_sign_verify_detached(sig, msg, n, pk) == 0;
}

int stele_anchor_parse(const char *text, stele_anchor_t *out)
{
    if (out == NULL || text == NULL
        || strnlen(text, STELE_ANCHOR_FILE_MAX + 1) > STELE_ANCHOR_FILE_MAX)
        return -1;
    memset(out, 0, sizeof(*out));
    json_t *b = stele_signed_body(text, STELE_ANCHOR_DOMAIN, "issuer");
    if (b == NULL)
        return -1;
    json_t *v = json_object_get(b, "v");
    json_t *members = json_object_get(b, "members");
    json_t *cks = json_object_get(b, "checkpoints");
    const char *typename = json_string_value(json_object_get(b, "typename"));
    bool ok = json_is_integer(v) && json_integer_value(v) == 1
        && typename != NULL && strcmp(typename, STELE_ANCHOR_TYPENAME) == 0
        && _nat(b, "seq", &out->seq)
        && _str(b, "issuer", out->issuer, sizeof(out->issuer))
        && _str(b, "polity", out->polity, sizeof(out->polity))
        && strncmp(out->polity, "did:key:z", 9) == 0
        && _str(b, "group_uuid", out->group_uuid, sizeof(out->group_uuid))
        && _uuid_ok(out->group_uuid)
        && json_is_array(members) && json_array_size(members) >= 1
        && json_array_size(members) <= STELE_ANCHOR_MEMBERS_MAX
        && json_is_array(cks) && json_array_size(cks) <= STELE_ANCHOR_CHECKPOINTS_MAX;
    size_t i;
    json_t *e;
    json_array_foreach(ok ? members : NULL, i, e)
    {
        stele_anchor_member_t *m = &out->members[i];
        int64_t tier = -1;
        char consent[STELE_SIG_HEX + 1];
        ok = json_is_object(e)
            && _str(e, "at_uuid", m->at_uuid, sizeof(m->at_uuid)) && _uuid_ok(m->at_uuid)
            && _str(e, "pubkey", m->pubkey, sizeof(m->pubkey))
            && _hex_ok(m->pubkey, STELE_PK_HEX)
            && _nat(e, "tier", &tier) && tier <= STELE_ANCHOR_TIER_MAX
            && _str(e, "consent", consent, sizeof(consent))
            && stele_anchor_member(out, m->at_uuid) == NULL;
        for (size_t j = 0; ok && j < out->n_members; j++)
            if (strcmp(out->members[j].pubkey, m->pubkey) == 0)
                ok = false;   /* one key, one node */
        if (ok)
        {
            m->tier = (int)tier;
            ok = _consent_ok(out, m, consent);
        }
        if (!ok)
            break;
        out->n_members = i + 1;
    }
    json_array_foreach(ok ? cks : NULL, i, e)
    {
        stele_anchor_checkpoint_t *c = &out->checkpoints[i];
        ok = json_is_object(e)
            && _str(e, "group_uuid", c->group_uuid, sizeof(c->group_uuid))
            && (c->group_uuid[0] == '\0' || _uuid_ok(c->group_uuid))
            && _nat(e, "epoch", &c->epoch)
            && _str(e, "root", c->root, sizeof(c->root)) && _hex_ok(c->root, STELE_DIGEST_HEX)
            && _nat(e, "first_index", &c->first_index) && _nat(e, "count", &c->count);
        if (!ok)
            break;
        out->n_checkpoints = i + 1;
    }
    json_decref(b);
    return ok ? 0 : -1;
}
