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

/* Conformance adapter for the stele extension: the identity adapter plus
 * Stele's fixtures, inbound builders, trigger and expected-state keys. Twin of
 * ../python/stele_adapter.py, whose docstring lists the steps and keys.
 *
 * Stele's state is process-global (id_stele.c), so every participant in one C
 * case shares it, as social's does; each scenario asserts on one participant. */

#include "identity_priv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <uuid/uuid.h>

#include "identity/identity.h"
#include "network/net_message.h"
#include "processes/processes.h"
#include "utilities/message.h"
#include "utilities/msg_types_priv.h"

#include "stele/at_stele.h"
#include "stele/stele_codec.h"
#include "stele/stele_team.h"
#include "stele/id_stele.h"
#include "stele/stele_relay.h"

void at_stele_run(const at_case_t *c, at_case_result_t *out);

static const char DEF_COMMIT[] = "0123456789abcdef0123456789abcdef01234567";

static ic_impl_t *_impl_of(sce_run_ctx_t *ctx, const char *pid)
{
    sce_participant_t *p = pid != NULL ? sce_find_participant(ctx, pid) : NULL;
    return p != NULL ? (ic_impl_t *)p->impl : NULL;
}

static const char *_s(json_t *o, const char *k, const char *dflt)
{
    const char *v = json_string_value(json_object_get(o, k));
    return v != NULL ? v : dflt;
}

static int64_t _i(json_t *o, const char *k, int64_t dflt)
{
    json_t *j = json_object_get(o, k);
    return json_is_integer(j) ? (int64_t)json_integer_value(j) : dflt;
}

/* Teams (Phase 3): the one team a scenario speaks of, from fixtures.stele_team.
 * Its root key is fixed (seed 0x07 * 32), a member's DID is "did:key:z<pid>",
 * and its key and node are the participant's own. Mirrors the Python adapter. */
static json_t *g_team = NULL;
#define TEAM_RELEASE_AT 1790000000

static void _team_root(unsigned char pk[crypto_sign_PUBLICKEYBYTES],
                       unsigned char sk[crypto_sign_SECRETKEYBYTES])
{
    unsigned char seed[crypto_sign_SEEDBYTES];
    memset(seed, 7, sizeof(seed));
    crypto_sign_seed_keypair(pk, sk, seed);
}

static void _hex(const unsigned char *b, size_t n, char *out)
{
    sodium_bin2hex(out, n * 2 + 1, b, n);
}

/* {"body": <compact JSON of @p body>, "sig": ed25519(sk, domain + body)}, owned. */
static char *_signed(const char *domain, json_t *body, const unsigned char *sk)
{
    char *text = json_dumps(body, JSON_COMPACT | JSON_PRESERVE_ORDER);
    if (text == NULL)
        return NULL;
    size_t dl = strlen(domain), bl = strlen(text);
    unsigned char *msg = malloc(dl + bl);
    unsigned char sig[crypto_sign_BYTES];
    char sig_hex[STELE_SIG_HEX + 1];
    memcpy(msg, domain, dl);
    memcpy(msg + dl, text, bl);
    crypto_sign_detached(sig, NULL, msg, dl + bl, sk);
    free(msg);
    _hex(sig, sizeof(sig), sig_hex);
    json_t *outer = json_pack("{s:s, s:s}", "body", text, "sig", sig_hex);
    free(text);
    char *out = json_dumps(outer, JSON_COMPACT | JSON_PRESERVE_ORDER);
    json_decref(outer);
    return out;
}

static void _did(const char *pid, char *out, size_t cap)
{
    snprintf(out, cap, "did:key:z%s", pid != NULL ? pid : "");
}

/* The scenario team's roster file, @p overrides applied; owned. */
static char *_team_text(sce_run_ctx_t *ctx, json_t *overrides)
{
    json_t *spec = json_deep_copy(g_team != NULL ? g_team : json_object());
    if (json_is_object(overrides))
        json_object_update(spec, overrides);
    unsigned char rpk[crypto_sign_PUBLICKEYBYTES], rsk[crypto_sign_SECRETKEYBYTES];
    _team_root(rpk, rsk);
    char issuer[STELE_PK_HEX + 1];
    _hex(rpk, sizeof(rpk), issuer);
    json_t *consent_by = json_object_get(spec, "consent_by");
    json_t *members = json_array();
    size_t i;
    json_t *v;
    json_array_foreach(json_object_get(spec, "members"), i, v)
    {
        const char *pid = json_string_value(v);
        ic_impl_t *me = _impl_of(ctx, pid);
        ic_impl_t *signer = _impl_of(ctx, _s(consent_by, pid, pid));
        if (me == NULL || signer == NULL || signer->full == NULL)
            continue;
        char did[STELE_DID_MAX + 1], uuid[STELE_UUID_STR], key[STELE_PK_HEX + 1];
        _did(pid, did, sizeof(did));
        uuid_unparse_lower(me->pub->uuid, uuid);
        _hex(me->pub->signature.public, crypto_sign_PUBLICKEYBYTES, key);
        uint8_t msg[256];
        size_t len = stele_consent_message(issuer, did, uuid, msg, sizeof(msg));
        unsigned char sig[crypto_sign_BYTES];
        char sig_hex[STELE_SIG_HEX + 1];
        crypto_sign_detached(sig, NULL, msg, len, signer->full->signature.private);
        _hex(sig, sizeof(sig), sig_hex);
        json_array_append_new(members, json_pack("{s:s, s:s, s:s, s:s}", "did", did,
            "key", key, "at_uuid", uuid, "consent", sig_hex));
    }
    json_t *officers = json_array();
    json_array_foreach(json_object_get(spec, "officers"), i, v)
    {
        char did[STELE_DID_MAX + 1];
        _did(json_string_value(v), did, sizeof(did));
        json_array_append_new(officers, json_string(did));
    }
    json_t *guardians = json_array();
    json_array_foreach(json_object_get(spec, "guardians"), i, v)
    {
        char m[STELE_DID_MAX + 1], g[STELE_DID_MAX + 1];
        _did(_s(v, "machine", ""), m, sizeof(m));
        _did(_s(v, "guardian", ""), g, sizeof(g));
        json_array_append_new(guardians, json_pack("{s:s, s:s}", "machine", m,
                                                   "guardian", g));
    }
    json_t *body = json_pack("{s:i, s:s, s:s, s:s, s:I, s:o, s:o, s:o}", "v", 1,
        "typename", "stele-team", "polity", "did:key:zteam", "issuer", issuer,
        "seq", (json_int_t)_i(spec, "seq", 1), "members", members,
        "release_officers", officers, "guardians", guardians);
    char *out = _signed(STELE_TEAM_DOMAIN, body, rsk);
    json_decref(body);
    json_decref(spec);
    return out;
}

/* @p ad made a v3 team ad when @p spec says `team: true`: the release signed by
 * `release_signer` (default the team's first officer). Mirrors _team_ad. */
static void _team_ad(sce_run_ctx_t *ctx, json_t *spec, stele_repo_ad_t *ad)
{
    if (!json_is_true(json_object_get(spec, "team")))
        return;
    const char *signer_pid = _s(spec, "release_signer",
        json_string_value(json_array_get(json_object_get(g_team, "officers"), 0)));
    ic_impl_t *who = _impl_of(ctx, signer_pid);
    if (who == NULL || who->full == NULL)
        return;
    unsigned char rpk[crypto_sign_PUBLICKEYBYTES], rsk[crypto_sign_SECRETKEYBYTES];
    _team_root(rpk, rsk);
    char issuer[STELE_PK_HEX + 1], key[STELE_PK_HEX + 1], officer[STELE_DID_MAX + 1];
    _hex(rpk, sizeof(rpk), issuer);
    _hex(who->pub->signature.public, crypto_sign_PUBLICKEYBYTES, key);
    _did(signer_pid, officer, sizeof(officer));
    json_t *body = json_pack("{s:i, s:s, s:s, s:s, s:s, s:s, s:s, s:s, s:s}", "v", 1,
        "typename", "stele-release", "polity", "did:key:zteam", "issuer", issuer,
        "officer", officer, "officer_key", key, "repo", ad->name, "url", ad->url,
        "commit", ad->commit);
    const char *built = _s(spec, "built_by", NULL);
    if (built != NULL)
    {
        char b[STELE_DID_MAX + 1];
        _did(built, b, sizeof(b));
        json_object_set_new(body, "built_by", json_string(b));
    }
    json_object_set_new(body, "authorized_at", json_integer(TEAM_RELEASE_AT));
    char *text = _signed(STELE_RELEASE_DOMAIN, body, who->full->signature.private);
    json_decref(body);
    if (ad->version < 2)
    {
        snprintf(ad->description, sizeof(ad->description), "%s", _s(spec, "description", ""));
        snprintf(ad->topics, sizeof(ad->topics), "%s", _s(spec, "topics", ""));
        snprintf(ad->sbom_digest, sizeof(ad->sbom_digest), "%s", _s(spec, "sbom_digest", ""));
        snprintf(ad->sbom_path, sizeof(ad->sbom_path), "%s", _s(spec, "sbom_path", ""));
        snprintf(ad->claim_verdict, sizeof(ad->claim_verdict), "%s",
                 _s(spec, "claim_verdict", "none"));
    }
    ad->version = 3;
    snprintf(ad->polity, sizeof(ad->polity), "%s", issuer);
    snprintf(ad->release_auth, sizeof(ad->release_auth), "%s", text != NULL ? text : "");
    free(text);
}

/* An ad from a step payload or fixture, owned by @p owner. */
static void _ad_from(json_t *spec, const uuid_t owner, stele_repo_ad_t *ad)
{
    memset(ad, 0, sizeof(*ad));
    uuid_copy(ad->owner, owner);
    snprintf(ad->name, sizeof(ad->name), "%s", _s(spec, "name", "demo"));
    snprintf(ad->url, sizeof(ad->url), "%s", _s(spec, "url", "http://forge.local/demo.git"));
    snprintf(ad->ref, sizeof(ad->ref), "%s", _s(spec, "ref", "main"));
    snprintf(ad->commit, sizeof(ad->commit), "%s", _s(spec, "commit", DEF_COMMIT));
    ad->seq = _i(spec, "seq", 1);
    ad->ts = _i(spec, "ts", 1790000000);
    int v = (int)_i(spec, "v", 1);
    if (v == 2 || v == 4)
    {
        ad->version = v;
        snprintf(ad->description, sizeof(ad->description), "%s",
                 _s(spec, "description", ""));
        snprintf(ad->topics, sizeof(ad->topics), "%s", _s(spec, "topics", ""));
        snprintf(ad->sbom_digest, sizeof(ad->sbom_digest), "%s",
                 _s(spec, "sbom_digest", ""));
        snprintf(ad->sbom_path, sizeof(ad->sbom_path), "%s", _s(spec, "sbom_path", ""));
        snprintf(ad->claim_verdict, sizeof(ad->claim_verdict), "%s",
                 _s(spec, "claim_verdict", "none"));
    }
    if (v == 4)   /* a solo release naming the package it publishes as */
        snprintf(ad->provides, sizeof(ad->provides), "%s", _s(spec, "provides", ""));
}

/* A (v1) attestation of @p ad by @p verifier, the rest from @p spec. Mirrors
 * the Python adapter's _attestation_from. */
static void _attestation_from(json_t *spec, const stele_repo_ad_t *ad,
                              const uuid_t verifier, stele_attestation_t *at)
{
    memset(at, 0, sizeof(*at));
    uuid_copy(at->verifier, verifier);
    stele_repo_ad_id(ad, at->repo_ad_id);
    snprintf(at->commit, sizeof(at->commit), "%s", ad->commit);
    snprintf(at->scanner, sizeof(at->scanner), "%s", _s(spec, "scanner", "osv-scanner"));
    snprintf(at->scanner_version, sizeof(at->scanner_version), "%s",
             _s(spec, "scanner_version", "2.6.0"));
    snprintf(at->db_digest, sizeof(at->db_digest), "%s", _s(spec, "db_digest",
             "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"));
    snprintf(at->findings_digest, sizeof(at->findings_digest), "%s",
             _s(spec, "findings_digest",
                "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef"));
    snprintf(at->verdict, sizeof(at->verdict), "%s", _s(spec, "verdict", "vuln"));
    at->count = _i(spec, "count", 1);
    snprintf(at->max_severity, sizeof(at->max_severity), "%s",
             _s(spec, "max_severity", "HIGH"));
    at->ts = _i(spec, "ts", 1790000100);
}

/* The attestation an `about` spec names (a stele_attestations entry), with its
 * ad. False when a participant it names is unknown. */
static bool _about(sce_run_ctx_t *ctx, json_t *about, stele_repo_ad_t *ad,
                   stele_attestation_t *at)
{
    ic_impl_t *owner = _impl_of(ctx, _s(about, "ad_owner", NULL));
    ic_impl_t *verifier = _impl_of(ctx, _s(about, "verifier", NULL));
    if (owner == NULL || owner->pub == NULL || verifier == NULL || verifier->pub == NULL)
        return false;
    _ad_from(about, owner->pub->uuid, ad);
    _team_ad(ctx, about, ad);
    _attestation_from(about, ad, verifier->pub->uuid, at);
    return true;
}

/* ---------------- the discovery relay's store (trigger_stele_relay) ----------------
 * One store per participant, made by its first trigger (`rate` sets its rate),
 * and every reply kept in order for `stele_relay_replies`. Mirrors the Python
 * adapter's _trigger_relay. */

#define RELAY_PIDS_MAX SCE_MAX_PARTICIPANTS
static const char RELAY_SIG[] =
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000";
static struct {
    char pid[SCE_ID_LEN];
    stele_relay_store_t *store;
    json_t *replies;
} g_relays[RELAY_PIDS_MAX];
static size_t g_n_relays;

static void _relays_reset(void)
{
    for (size_t i = 0; i < g_n_relays; i++)
    {
        stele_relay_store_free(g_relays[i].store);
        json_decref(g_relays[i].replies);
    }
    memset(g_relays, 0, sizeof(g_relays));
    g_n_relays = 0;
}

static size_t _relay_of(const char *pid, double rate)
{
    for (size_t i = 0; i < g_n_relays; i++)
        if (strcmp(g_relays[i].pid, pid) == 0)
            return i;
    size_t i = g_n_relays < RELAY_PIDS_MAX ? g_n_relays++ : 0;
    snprintf(g_relays[i].pid, sizeof(g_relays[i].pid), "%s", pid);
    g_relays[i].store = stele_relay_store_new(rate);
    g_relays[i].replies = json_array();
    return i;
}

/* A publish item from its scenario spec: an ad or attestation from an `about`
 * spec, anything else passed through as `item`. */
static json_t *_relay_item(sce_run_ctx_t *ctx, json_t *spec)
{
    const char *kind = _s(spec, "kind", "");
    json_t *about = json_object_get(spec, "about");
    if (json_is_object(about) && (strcmp(kind, "ad") == 0 || strcmp(kind, "attestation") == 0))
    {
        stele_repo_ad_t ad;
        stele_attestation_t at;
        json_t *item = NULL;
        if (strcmp(kind, "ad") == 0)
        {
            ic_impl_t *owner = _impl_of(ctx, _s(about, "ad_owner", NULL));
            if (owner != NULL && owner->pub != NULL)
            {
                _ad_from(about, owner->pub->uuid, &ad);
                item = stele_repo_ad_to_json(&ad, RELAY_SIG);
            }
        }
        else if (_about(ctx, about, &ad, &at))
            item = stele_attestation_to_json(&at, RELAY_SIG);
        return json_pack("{s:s, s:o}", "kind", kind, "item", item != NULL ? item : json_null());
    }
    return json_deep_copy(spec);
}

static void _relay_trigger(sce_run_ctx_t *ctx, const char *pid, json_t *jp)
{
    size_t r = _relay_of(pid, json_number_value(json_object_get(jp, "rate")));
    const char *op = _s(jp, "op", "");
    json_t *req = json_deep_copy(json_object_get(jp, "req"));
    if (!json_is_object(req))
    {
        json_decref(req);
        req = json_object();
    }
    json_t *items = json_object_get(req, "items");
    if (json_is_array(items))
    {
        json_t *built = json_array();
        size_t i;
        json_t *e;
        json_array_foreach(items, i, e)
            json_array_append_new(built, _relay_item(ctx, e));
        json_object_set_new(req, "items", built);
    }
    ic_impl_t *as = _impl_of(ctx, _s(jp, "as", pid));
    char uuid[STELE_UUID_STR] = "";
    if (as != NULL && as->pub != NULL)
        uuid_unparse_lower(as->pub->uuid, uuid);
    json_t *reply = stele_relay_serve(g_relays[r].store, uuid, op, req);
    json_array_append_new(g_relays[r].replies, reply != NULL ? reply : json_null());
    json_decref(req);
}

/* The value at a dotted @p path of @p root (a "#" segment is the size of what
 * it follows), as a new reference, or NULL. */
static json_t *_at_path(json_t *root, const char *path)
{
    json_t *cur = root;
    char buf[256];
    snprintf(buf, sizeof(buf), "%s", path);
    char *save = NULL;
    for (char *seg = strtok_r(buf, ".", &save); seg != NULL && cur != NULL;
         seg = strtok_r(NULL, ".", &save))
    {
        if (strcmp(seg, "#") == 0)
            return json_integer((json_int_t)(json_is_array(cur) ? json_array_size(cur)
                                             : json_object_size(cur)));
        char *end = NULL;
        long idx = strtol(seg, &end, 10);
        cur = (json_is_array(cur) && end != seg && *end == '\0')
            ? json_array_get(cur, (size_t)idx) : json_object_get(cur, seg);
    }
    return cur != NULL ? json_incref(cur) : NULL;
}

/* The key a step is signed with: its sender's, or `forged_by`'s. */
static const unsigned char *_signer_sk(sce_run_ctx_t *ctx, json_t *payload,
                                       ic_impl_t *sender_impl)
{
    ic_impl_t *f = _impl_of(ctx, _s(payload, "forged_by", NULL));
    ic_impl_t *who = f != NULL ? f : sender_impl;
    return who != NULL && who->full != NULL ? who->full->signature.private : NULL;
}

static void _stele_fixtures(sce_run_ctx_t *ctx, json_t *fixtures)
{
    json_decref(g_team);
    g_team = json_deep_copy(json_object_get(fixtures, "stele_team"));
    if (g_team != NULL)
    {
        /* A node checks each member's consent against the key it holds for
         * that node, so every participant holds every other's, as in a group
         * and as the Python harness stages by default. */
        for (size_t i = 0; i < ctx->participant_count; i++)
        {
            ic_impl_t *me = (ic_impl_t *)ctx->participants[i].impl;
            if (me == NULL || me->proc == NULL)
                continue;
            process_t *p = me->proc;
            for (size_t j = 0; j < ctx->participant_count; j++)
            {
                ic_impl_t *other = (ic_impl_t *)ctx->participants[j].impl;
                if (j == i || other == NULL || other->pub == NULL
                    || p->protocol.num_peers >= DEFAULT_MAX_PEERS)
                    continue;
                bool have = false;
                for (size_t k = 0; k < p->protocol.num_peers && !have; k++)
                    have = uuid_compare(p->protocol.peers[k].uuid, other->pub->uuid) == 0;
                if (!have)
                    memcpy(&p->protocol.peers[p->protocol.num_peers++], other->pub,
                           sizeof(public_identity_t));
            }
        }
    }
    if (json_array_size(json_object_get(fixtures, "stele_teams_held")) > 0)
    {
        /* One shared stele state in C: held by every participant at once. */
        char *text = _team_text(ctx, NULL);
        stele_hold_team_for_test(text);
        free(text);
    }
    json_t *ads = json_object_get(fixtures, "stele_ads");
    const char *pid;
    json_t *list;
    json_object_foreach(ads, pid, list)
    {
        size_t i;
        json_t *spec;
        json_array_foreach(list, i, spec)
        {
            ic_impl_t *owner = _impl_of(ctx, _s(spec, "owner", NULL));
            if (owner == NULL || owner->pub == NULL)
                continue;
            stele_repo_ad_t ad;
            _ad_from(spec, owner->pub->uuid, &ad);
            _team_ad(ctx, spec, &ad);
            stele_hold_ad_for_test(&ad);
        }
    }
    json_t *ats = json_object_get(fixtures, "stele_attestations");
    json_object_foreach(ats, pid, list)
    {
        size_t i;
        json_t *spec;
        json_array_foreach(list, i, spec)
        {
            stele_repo_ad_t ad;
            stele_attestation_t at;
            if (!_about(ctx, spec, &ad, &at))
                continue;
            stele_hold_ad_for_test(&ad);
            stele_hold_attestation_for_test(&at);
        }
    }
    stele_attribute_held_for_test();
}

static int _stele_inbound(sce_run_ctx_t *ctx, sce_participant_t *sender,
                          ic_impl_t *sender_impl, const char *from_id,
                          const char *to_id, const char *function,
                          json_t *payload, generic_msg_t *out)
{
    (void)sender; (void)from_id;
    if (strcmp(function, "trigger_stele_attest") == 0
        || strcmp(function, "trigger_stele_relay") == 0)
    {
        json_t *body = json_deep_copy(payload != NULL ? payload : json_object());
        net_msg_pack_json(&out->info.net_msg, body);
        json_decref(body);
        return 0;
    }
    if (strcmp(function, AT_APP_STELE_ATTEST) == 0)
    {
        /* A WIRE frame named like the app verb (the refusal case): the owner
         * pid resolved, the rest passed through. */
        json_t *body = json_deep_copy(payload != NULL ? payload : json_object());
        ic_impl_t *owner = _impl_of(ctx, _s(body, "owner", NULL));
        if (owner != NULL && owner->pub != NULL)
        {
            char o[STELE_UUID_STR];
            uuid_unparse_lower(owner->pub->uuid, o);
            json_object_set_new(body, "owner", json_string(o));
        }
        net_msg_pack_json(&out->info.net_msg, body);
        json_decref(body);
        return 0;
    }
    if (strcmp(function, "stele repo") == 0)
    {
        ic_impl_t *owner = _impl_of(ctx, _s(payload, "owner", NULL));
        if (owner == NULL)
            owner = sender_impl;
        stele_repo_ad_t ad;
        _ad_from(payload, owner->pub->uuid, &ad);
        _team_ad(ctx, payload, &ad);
        char sig[STELE_SIG_HEX + 1] = {0};
        if (stele_repo_ad_sign(&ad, _signer_sk(ctx, payload, sender_impl), sig) != 0)
        {
            snprintf(ctx->err, sizeof(ctx->err), "stele repo: cannot sign the ad");
            return -1;
        }
        json_t *env = stele_repo_ad_to_json(&ad, sig);
        net_msg_pack_json(&out->info.net_msg, env);
        json_decref(env);
        return 0;
    }
    if (strcmp(function, "stele team") == 0)
    {
        char *text = _team_text(ctx, payload);
        json_t *env = json_pack("{s:s}", "roster", text != NULL ? text : "");
        free(text);
        net_msg_pack_json(&out->info.net_msg, env);
        json_decref(env);
        return 0;
    }
    if (strcmp(function, "stele attest") == 0)
    {
        ic_impl_t *ad_owner = _impl_of(ctx, _s(payload, "ad_owner", to_id));
        ic_impl_t *verifier = _impl_of(ctx, _s(payload, "verifier", NULL));
        if (verifier == NULL)
            verifier = sender_impl;
        if (ad_owner == NULL || verifier == NULL)
        {
            snprintf(ctx->err, sizeof(ctx->err), "stele attest: unknown participant");
            return -1;
        }
        stele_repo_ad_t ad;
        _ad_from(payload, ad_owner->pub->uuid, &ad);
        stele_attestation_t at;
        _attestation_from(payload, &ad, verifier->pub->uuid, &at);
        char sig[STELE_SIG_HEX + 1] = {0};
        if (stele_attestation_sign(&at, _signer_sk(ctx, payload, sender_impl), sig) != 0)
        {
            snprintf(ctx->err, sizeof(ctx->err), "stele attest: cannot sign");
            return -1;
        }
        json_t *env = stele_attestation_to_json(&at, sig);
        net_msg_pack_json(&out->info.net_msg, env);
        json_decref(env);
        return 0;
    }
    if (strcmp(function, "stele rebut") == 0)
    {
        stele_repo_ad_t ad;
        stele_attestation_t at;
        if (!_about(ctx, json_object_get(payload, "about"), &ad, &at))
        {
            snprintf(ctx->err, sizeof(ctx->err), "stele rebut: unknown participant");
            return -1;
        }
        ic_impl_t *owner = _impl_of(ctx, _s(payload, "owner", NULL));
        if (owner == NULL)
            owner = sender_impl;
        stele_rebuttal_t rb;
        memset(&rb, 0, sizeof(rb));
        uuid_copy(rb.owner, owner->pub->uuid);
        stele_attestation_id(&at, rb.attestation_id);
        snprintf(rb.text, sizeof(rb.text), "%s", _s(payload, "text", "a false positive"));
        rb.ts = _i(payload, "ts", 1790000200);
        char sig[STELE_SIG_HEX + 1] = {0};
        if (stele_rebuttal_sign(&rb, _signer_sk(ctx, payload, sender_impl), sig) != 0)
        {
            snprintf(ctx->err, sizeof(ctx->err), "stele rebut: cannot sign");
            return -1;
        }
        json_t *env = stele_rebuttal_to_json(&rb, sig);
        net_msg_pack_json(&out->info.net_msg, env);
        json_decref(env);
        return 0;
    }
    return 1;
}

static int _stele_dispatch(sce_run_ctx_t *ctx, sce_participant_t *target,
                           generic_msg_t *inbound)
{
    ic_impl_t *impl = (ic_impl_t *)target->impl;
    if (inbound->type == NET_MESSAGE && inbound->info.net_msg.function != NULL
        && strcmp(inbound->info.net_msg.function, "trigger_stele_relay") == 0)
    {
        json_t *rp = NULL;
        if (net_msg_unpack_json(&inbound->info.net_msg, &rp) != 0 || rp == NULL)
            rp = json_object();
        _relay_trigger(ctx, target->id, rp);
        json_decref(rp);
        return 0;
    }
    if (inbound->type != NET_MESSAGE || inbound->info.net_msg.function == NULL
        || strcmp(inbound->info.net_msg.function, "trigger_stele_attest") != 0)
        return 1;
    /* The attest verb, with the owner named by participant id resolved. */
    json_t *jp = NULL;
    if (net_msg_unpack_json(&inbound->info.net_msg, &jp) != 0 || jp == NULL)
        jp = json_object();
    json_t *attributes = json_object_get(jp, "attributes");
    if (json_is_object(attributes))
    {
        /* The guardian attestation: the `about` spec resolved to its id. */
        stele_repo_ad_t gad;
        stele_attestation_t gat;
        char gid[STELE_ID_HEX + 1] = {0};
        if (_about(ctx, attributes, &gad, &gat))
            stele_attestation_id(&gat, gid);
        json_decref(jp);
        json_t *gb = json_pack("{s:s}", "attributes", gid);
        generic_msg_t gm = {0};
        gm.type = NET_MESSAGE;
        strncpy(gm.info.net_msg.process, "identity", PROC_NAME_LEN);
        gm.info.net_msg.function = (char *)AT_APP_STELE_ATTEST;
        net_msg_pack_json(&gm.info.net_msg, gb);
        json_decref(gb);
        run_message_handlers(impl->proc, NULL, NET_MESSAGE, &gm);
        if (gm.info.net_msg.obj != NULL)
            smrt_deref(gm.info.net_msg.obj);
        return 0;
    }
    ic_impl_t *owner = _impl_of(ctx, _s(jp, "owner", NULL));
    char owner_str[STELE_UUID_STR] = {0};
    if (owner != NULL && owner->pub != NULL)
        uuid_unparse_lower(owner->pub->uuid, owner_str);
    json_t *body = json_pack("{s:s, s:s, s:s, s:s, s:s, s:s, s:s, s:I, s:s}",
        "owner", owner_str, "commit", _s(jp, "commit", DEF_COMMIT),
        "scanner", _s(jp, "scanner", "osv-scanner"),
        "scanner_version", _s(jp, "scanner_version", "2.6.0"),
        "db_digest", _s(jp, "db_digest",
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"),
        "findings_digest", _s(jp, "findings_digest",
            "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef"),
        "verdict", _s(jp, "verdict", "vuln"), "count", (json_int_t)_i(jp, "count", 1),
        "max_severity", _s(jp, "max_severity", "HIGH"));
    json_object_set_new(body, "channel", json_string(_s(jp, "channel", "probe")));
    if (_s(jp, "url", NULL) != NULL)
        json_object_set_new(body, "url", json_string(_s(jp, "url", NULL)));
    /* `replicates`: an `about` spec naming the attestation this one re-ran,
     * resolved to its id. Mirrors the Python adapter's _trigger_attest. */
    json_t *about = json_object_get(jp, "replicates");
    stele_repo_ad_t rad;
    stele_attestation_t rat;
    char rid[STELE_ID_HEX + 1];
    if (json_is_object(about) && _about(ctx, about, &rad, &rat)
        && stele_attestation_id(&rat, rid) == 0)
        json_object_set_new(body, "replicates", json_string(rid));
    json_decref(jp);
    generic_msg_t m = {0};
    m.type = NET_MESSAGE;
    strncpy(m.info.net_msg.process, "identity", PROC_NAME_LEN);
    m.info.net_msg.function = (char *)AT_APP_STELE_ATTEST;
    net_msg_pack_json(&m.info.net_msg, body);
    json_decref(body);
    run_message_handlers(impl->proc, NULL, NET_MESSAGE, &m);
    if (m.info.net_msg.obj != NULL)
        smrt_deref(m.info.net_msg.obj);
    return 0;
}

static int _stele_check_key(sce_run_ctx_t *ctx, const char *pid, ic_impl_t *impl,
                            process_t *proc, const char *key, json_t *val)
{
    (void)impl; (void)proc;
    if (strcmp(key, "stele_ads_held") == 0)
    {
        json_t *ads = stele_held_ads_json();
        int n = (int)json_array_size(ads);
        json_decref(ads);
        if (n != (int)json_integer_value(val))
        {
            snprintf(ctx->err, sizeof(ctx->err), "%s: stele_ads_held=%d, expected %d",
                     pid, n, (int)json_integer_value(val));
            return -1;
        }
        return 0;
    }
    if (strcmp(key, "stele_attestations_held") == 0)
    {
        json_t *ats = stele_held_attestations_json();
        int n = (int)json_array_size(ats);
        json_decref(ats);
        if (n != (int)json_integer_value(val))
        {
            snprintf(ctx->err, sizeof(ctx->err), "%s: stele_attestations_held=%d, "
                     "expected %d", pid, n, (int)json_integer_value(val));
            return -1;
        }
        return 0;
    }
    if (strcmp(key, "stele_rebuttals_held") == 0)
    {
        json_t *rbs = stele_held_rebuttals_json();
        int n = (int)json_array_size(rbs);
        json_decref(rbs);
        if (n != (int)json_integer_value(val))
        {
            snprintf(ctx->err, sizeof(ctx->err), "%s: stele_rebuttals_held=%d, "
                     "expected %d", pid, n, (int)json_integer_value(val));
            return -1;
        }
        return 0;
    }
    if (strcmp(key, "stele_teams_held") == 0 || strcmp(key, "stele_team_ads") == 0)
    {
        bool teams = strcmp(key, "stele_teams_held") == 0;
        json_t *arr = teams ? stele_held_teams_json() : stele_held_ads_json();
        int n = 0;
        size_t i;
        json_t *e;
        json_array_foreach(arr, i, e)
            if (teams || json_object_get(e, "team") != NULL)
                n++;
        json_decref(arr);
        if (n != (int)json_integer_value(val))
        {
            snprintf(ctx->err, sizeof(ctx->err), "%s: %s=%d, expected %d", pid, key, n,
                     (int)json_integer_value(val));
            return -1;
        }
        return 0;
    }
    if (strcmp(key, "stele_relay_replies") == 0)
    {
        json_t *got = NULL;
        for (size_t i = 0; i < g_n_relays && got == NULL; i++)
            if (strcmp(g_relays[i].pid, pid) == 0)
                got = g_relays[i].replies;
        if (got == NULL || json_array_size(got) != json_array_size(val))
        {
            snprintf(ctx->err, sizeof(ctx->err), "%s: %zu relay repl(ies), expected %zu",
                     pid, got != NULL ? json_array_size(got) : 0, json_array_size(val));
            return -1;
        }
        size_t i;
        json_t *want;
        json_array_foreach(val, i, want)
        {
            const char *path;
            json_t *w;
            json_object_foreach(want, path, w)
            {
                json_t *v = _at_path(json_array_get(got, i), path);
                bool ok = v != NULL && json_equal(v, w);
                json_decref(v);
                if (!ok)
                {
                    snprintf(ctx->err, sizeof(ctx->err), "%s: relay reply %zu: %s is not "
                             "as expected", pid, i, path);
                    return -1;
                }
            }
        }
        return 0;
    }
    if (strcmp(key, "stele_scores") == 0)
    {
        stele_score_sent_t got[16];
        size_t n = stele_scores_sent(got, 16);
        bool ok = n == json_array_size(val);
        for (size_t i = 0; ok && i < n; i++)
        {
            json_t *w = json_array_get(val, i);
            ic_impl_t *subj = _impl_of(ctx, _s(w, "subject", NULL));
            double ws = json_number_value(json_object_get(w, "score"));
            ok = subj != NULL && uuid_compare(subj->pub->uuid, got[i].subject) == 0
                && got[i].score > ws - 1e-9 && got[i].score < ws + 1e-9;
        }
        if (!ok)
            snprintf(ctx->err, sizeof(ctx->err), "%s: stele_scores holds %zu "
                     "score(s), not the ones expected", pid, n);
        return ok ? 0 : -1;
    }
    return 1;
}

static const ic_ext_t STELE_EXT = {
    .name = "stele",
    .fixtures = _stele_fixtures,
    .inbound = _stele_inbound,
    .dispatch = _stele_dispatch,
    .check_key = _stele_check_key,
};

void at_stele_run(const at_case_t *c, at_case_result_t *out)
{
    at_stele_link();
    _relays_reset();   /* per case: the fixtures hook runs only when a case has fixtures */
    at_identity_run_ext(c, out, &STELE_EXT);
}
