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
#include "stele/id_stele.h"

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
            stele_hold_ad_for_test(&ad);
        }
    }
}

static int _stele_inbound(sce_run_ctx_t *ctx, sce_participant_t *sender,
                          ic_impl_t *sender_impl, const char *from_id,
                          const char *to_id, const char *function,
                          json_t *payload, generic_msg_t *out)
{
    (void)sender; (void)from_id;
    if (strcmp(function, "trigger_stele_attest") == 0)
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
        memset(&at, 0, sizeof(at));
        uuid_copy(at.verifier, verifier->pub->uuid);
        stele_repo_ad_id(&ad, at.repo_ad_id);
        snprintf(at.commit, sizeof(at.commit), "%s", ad.commit);
        snprintf(at.scanner, sizeof(at.scanner), "%s", _s(payload, "scanner", "osv-scanner"));
        snprintf(at.scanner_version, sizeof(at.scanner_version), "%s",
                 _s(payload, "scanner_version", "2.6.0"));
        snprintf(at.db_digest, sizeof(at.db_digest), "%s", _s(payload, "db_digest",
                 "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"));
        snprintf(at.findings_digest, sizeof(at.findings_digest), "%s",
                 _s(payload, "findings_digest",
                    "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef"));
        snprintf(at.verdict, sizeof(at.verdict), "%s", _s(payload, "verdict", "vuln"));
        at.count = _i(payload, "count", 1);
        snprintf(at.max_severity, sizeof(at.max_severity), "%s",
                 _s(payload, "max_severity", "HIGH"));
        at.ts = _i(payload, "ts", 1790000100);
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
    return 1;
}

static int _stele_dispatch(sce_run_ctx_t *ctx, sce_participant_t *target,
                           generic_msg_t *inbound)
{
    ic_impl_t *impl = (ic_impl_t *)target->impl;
    if (inbound->type != NET_MESSAGE || inbound->info.net_msg.function == NULL
        || strcmp(inbound->info.net_msg.function, "trigger_stele_attest") != 0)
        return 1;
    /* The attest verb, with the owner named by participant id resolved. */
    json_t *jp = NULL;
    if (net_msg_unpack_json(&inbound->info.net_msg, &jp) != 0 || jp == NULL)
        jp = json_object();
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
    at_identity_run_ext(c, out, &STELE_EXT);
}
