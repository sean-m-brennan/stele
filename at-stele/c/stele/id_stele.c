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

/* at-stele: the identity half of Stele (Phase 0). See at_stele.h for the verbs
 * and stele_codec.h for the artifacts. Twin of
 * ../../python/autonomous_trust/stele/_python/handlers.py.
 *
 * Wire functions, both group multicasts and both FIRST-PERSON: a repo ad is
 * accepted only from its owner, an attestation only from its verifier, each
 * signature checked against the sender's own key. Nothing is relayed. */

#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sodium.h>

#include "processes/processes.h"
#include "processes/extension.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"
#include "utilities/msg_registry.h"
#include "utilities/msg_types_priv.h"
#include "utilities/util.h"
#include "network/net_message.h"
#include "identity/identity_priv.h"
#include "identity/id_proc_priv.h"
#include "identity/id_ext.h"
#include "reputation/tx_channel.h"

#include "at_stele.h"
#include "stele_codec.h"
#include "id_stele.h"

static char ID_STELE_REPO[]   = "stele repo";
static char ID_STELE_ATTEST[] = "stele attest";
static char ID_APP_ADVERTISE[] = AT_APP_STELE_ADVERTISE_REPO;
static char ID_APP_ATTEST[]    = AT_APP_STELE_ATTEST;

AT_APP_VERB_REGISTER(stele_advertise_repo, AT_APP_STELE_ADVERTISE_REPO, "identity")
AT_APP_VERB_REGISTER(stele_attest,         AT_APP_STELE_ATTEST,         "identity")

#define STELE_ADS_CAP     64
#define STELE_ATTEST_CAP  64
#define STELE_SCORES_CAP  64

typedef struct {
    stele_repo_ad_t ad;
    char id[STELE_ID_HEX + 1];
} held_ad_t;

typedef struct {
    stele_attestation_t at;
    char id[STELE_ID_HEX + 1];
} held_attestation_t;

static struct {
    pthread_mutex_t    lock;
    bool               initialized;
    held_ad_t          ads[STELE_ADS_CAP];
    size_t             n_ads, next_ad;
    held_attestation_t attestations[STELE_ATTEST_CAP];
    size_t             n_at, next_at;
    stele_score_sent_t scores[STELE_SCORES_CAP];
    size_t             n_scores;
    int64_t            ad_seq;
} st = { .lock = PTHREAD_MUTEX_INITIALIZER };

static void _stele_reset(void)
{
    pthread_mutex_lock(&st.lock);
    st.n_ads = st.next_ad = 0;
    st.n_at = st.next_at = 0;
    st.n_scores = 0;
    st.ad_seq = 0;
    st.initialized = true;
    pthread_mutex_unlock(&st.lock);
}

static void _stele_init(void)
{
    _stele_reset();
}

/* Store an ad by id (a ring; a repeat is a no-op). True when it was new. */
static bool _hold_ad(const stele_repo_ad_t *ad, const char *id)
{
    pthread_mutex_lock(&st.lock);
    for (size_t i = 0; i < st.n_ads; i++)
        if (strcmp(st.ads[i].id, id) == 0)
        {
            pthread_mutex_unlock(&st.lock);
            return false;
        }
    held_ad_t *slot = &st.ads[st.next_ad];
    slot->ad = *ad;
    snprintf(slot->id, sizeof(slot->id), "%s", id);
    st.next_ad = (st.next_ad + 1) % STELE_ADS_CAP;
    if (st.n_ads < STELE_ADS_CAP)
        st.n_ads++;
    pthread_mutex_unlock(&st.lock);
    return true;
}

static bool _hold_attestation(const stele_attestation_t *at, const char *id)
{
    pthread_mutex_lock(&st.lock);
    for (size_t i = 0; i < st.n_at; i++)
        if (strcmp(st.attestations[i].id, id) == 0)
        {
            pthread_mutex_unlock(&st.lock);
            return false;
        }
    held_attestation_t *slot = &st.attestations[st.next_at];
    slot->at = *at;
    snprintf(slot->id, sizeof(slot->id), "%s", id);
    st.next_at = (st.next_at + 1) % STELE_ATTEST_CAP;
    if (st.n_at < STELE_ATTEST_CAP)
        st.n_at++;
    pthread_mutex_unlock(&st.lock);
    return true;
}

/* The newest held ad from @p owner at @p commit (highest seq), copied out. */
static bool _find_ad(const uuid_t owner, const char *commit, held_ad_t *out)
{
    bool found = false;
    pthread_mutex_lock(&st.lock);
    for (size_t i = 0; i < st.n_ads; i++)
    {
        const held_ad_t *h = &st.ads[i];
        if (uuid_compare(h->ad.owner, owner) == 0 && strcmp(h->ad.commit, commit) == 0
            && (!found || h->ad.seq > out->ad.seq))
        {
            *out = *h;
            found = true;
        }
    }
    pthread_mutex_unlock(&st.lock);
    return found;
}

static int _multicast(const process_t *proc, char *function, json_t *env,
                      const char *what)
{
    generic_msg_t out = {0};
    out.type = NET_MESSAGE;
    strncpy(out.info.net_msg.process, "identity", PROC_NAME_LEN);
    out.info.net_msg.function = function;
    out.info.net_msg.encrypt = false;
    out.info.net_msg.group_multicast = true;
    strncpy(out.info.net_msg.return_to, "identity", PROC_NAME_LEN);
    if (net_msg_pack_json(&out.info.net_msg, env) != 0)
        return -1;
    int rc = identity_send_to_network(proc, &out, what, "the group");
    net_msg_free_obj(&out.info.net_msg);
    return rc;
}

/* Submit the verifier-attested score to the reputation process, retried as
 * every identity one-shot is (identity_send_to). */
static void _submit_attested(const process_t *proc, const uuid_t subject,
                             double score, const char *digest)
{
    generic_msg_t msg = {0};
    msg.type = TRANSACTION_SCORE;
    msg.size = sizeof(tx_score_msg_t);
    uuid_copy(msg.info.tx_score.peer_uuid, subject);
    msg.info.tx_score.score = score;
    at_strlcpy(msg.info.tx_score.channel, TX_CHANNEL_PROBE,
               sizeof(msg.info.tx_score.channel));
    msg.info.tx_score.attested = true;
    at_strlcpy(msg.info.tx_score.evidence_digest, digest,
               sizeof(msg.info.tx_score.evidence_digest));
    /* Kept past a long burst and retried on the identity tick (AT ISSUES
     * §2.40); identity_send_to reports a loss itself. */
    (void)identity_send_to(proc, "reputation", &msg, "the attested score",
                           "reputation");
    /* The observable a scenario asserts, independent of the quorum round. */
    pthread_mutex_lock(&st.lock);
    if (st.n_scores < STELE_SCORES_CAP)
    {
        stele_score_sent_t *s = &st.scores[st.n_scores++];
        uuid_copy(s->subject, subject);
        s->score = score;
        snprintf(s->digest, sizeof(s->digest), "%s", digest);
    }
    pthread_mutex_unlock(&st.lock);
}

/* ---------------- wire: stele repo ---------------- */

static bool handle_stele_repo(const process_t *proc, directory_t *queues,
                              generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
        return true;
    stele_repo_ad_t ad;
    char sig[STELE_SIG_HEX + 1];
    int rc = stele_repo_ad_from_json(payload, &ad, sig);
    json_decref(payload);
    if (rc != 0)
    {
        log_warn(proc->logger, "Identity: stele repo ad from %s malformed, refusing\n",
                 nmsg->from_whom.nickname);
        return true;
    }
    /* First person only: the owner is the sender, and its key is the one the
     * signature must verify against. */
    if (uuid_compare(ad.owner, nmsg->from_whom.uuid) != 0)
    {
        log_warn(proc->logger, "Identity: stele repo ad from %s names another "
                 "owner; ads are never relayed, refusing\n", nmsg->from_whom.nickname);
        return true;
    }
    if (!stele_repo_ad_verify(&ad, nmsg->from_whom.signature.public, sig))
    {
        log_warn(proc->logger, "Identity: stele repo ad from %s: BAD SIGNATURE, "
                 "dropping\n", nmsg->from_whom.nickname);
        return true;
    }
    char id[STELE_ID_HEX + 1];
    if (stele_repo_ad_id(&ad, id) != 0)
        return true;
    if (_hold_ad(&ad, id))
        log_info(proc->logger, "Identity: stele repo %s@%.12s from %s (ad %.12s)\n",
                 ad.name, ad.commit, nmsg->from_whom.nickname, id);
    return true;
}

/* ---------------- wire: stele attest ---------------- */

static bool handle_stele_attest(const process_t *proc, directory_t *queues,
                                generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
        return true;
    stele_attestation_t at;
    char sig[STELE_SIG_HEX + 1];
    int rc = stele_attestation_from_json(payload, &at, sig);
    json_decref(payload);
    if (rc != 0)
    {
        log_warn(proc->logger, "Identity: stele attestation from %s malformed, "
                 "refusing\n", nmsg->from_whom.nickname);
        return true;
    }
    if (uuid_compare(at.verifier, nmsg->from_whom.uuid) != 0
        || !stele_attestation_verify(&at, nmsg->from_whom.signature.public, sig))
    {
        log_warn(proc->logger, "Identity: stele attestation from %s is not its "
                 "verifier's, refusing\n", nmsg->from_whom.nickname);
        return true;
    }
    char id[STELE_ID_HEX + 1];
    if (stele_attestation_id(&at, id) == 0 && _hold_attestation(&at, id))
        log_info(proc->logger, "Identity: stele attestation %.12s (%s, %lld) from %s\n",
                 id, at.verdict, (long long)at.count, nmsg->from_whom.nickname);
    return true;
}

/* ---------------- app verbs ---------------- */

static bool _str(json_t *o, const char *k, char *dst, size_t cap)
{
    const char *v = json_string_value(json_object_get(o, k));
    if (v == NULL || strlen(v) >= cap)
        return false;
    memcpy(dst, v, strlen(v) + 1);
    return true;
}

static bool handle_app_stele_advertise_repo(const process_t *proc,
                                            directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!identity_is_local_app_verb(proc, nmsg))
        return identity_refuse_remote_app_verb(proc, nmsg, AT_APP_STELE_ADVERTISE_REPO);
    const identity_t *self = identity_self_identity(proc);
    json_t *p = NULL;
    if (self == NULL || net_msg_unpack_json(nmsg, &p) != 0 || p == NULL)
        return true;
    stele_repo_ad_t ad;
    memset(&ad, 0, sizeof(ad));
    uuid_copy(ad.owner, self->uuid);
    bool ok = _str(p, "name", ad.name, sizeof(ad.name))
        && _str(p, "url", ad.url, sizeof(ad.url))
        && _str(p, "ref", ad.ref, sizeof(ad.ref))
        && _str(p, "commit", ad.commit, sizeof(ad.commit));
    json_t *js = json_object_get(p, "seq");
    pthread_mutex_lock(&st.lock);
    ad.seq = json_is_integer(js) ? (int64_t)json_integer_value(js) : ++st.ad_seq;
    pthread_mutex_unlock(&st.lock);
    json_decref(p);
    ad.ts = (int64_t)time(NULL);
    char sig[STELE_SIG_HEX + 1], id[STELE_ID_HEX + 1];
    if (!ok || stele_repo_ad_sign(&ad, self->signature.private, sig) != 0
        || stele_repo_ad_id(&ad, id) != 0)
    {
        log_warn(proc->logger, "Identity: stele advertise_repo malformed, refusing\n");
        return true;
    }
    _hold_ad(&ad, id);   /* our own, so a loopback copy is a no-op */
    json_t *env = stele_repo_ad_to_json(&ad, sig);
    if (env != NULL)
    {
        _multicast(proc, ID_STELE_REPO, env, "a stele repo ad");
        json_decref(env);
    }
    log_info(proc->logger, "Identity: advertised stele repo %s@%.12s (ad %.12s)\n",
             ad.name, ad.commit, id);
    return true;
}

static bool handle_app_stele_attest(const process_t *proc, directory_t *queues,
                                    generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!identity_is_local_app_verb(proc, nmsg))
        return identity_refuse_remote_app_verb(proc, nmsg, AT_APP_STELE_ATTEST);
    const identity_t *self = identity_self_identity(proc);
    json_t *p = NULL;
    if (self == NULL || net_msg_unpack_json(nmsg, &p) != 0 || p == NULL)
        return true;
    char owner_str[STELE_UUID_STR] = {0};
    stele_attestation_t at;
    memset(&at, 0, sizeof(at));
    bool ok = _str(p, "owner", owner_str, sizeof(owner_str))
        && _str(p, "commit", at.commit, sizeof(at.commit))
        && _str(p, "scanner", at.scanner, sizeof(at.scanner))
        && _str(p, "scanner_version", at.scanner_version, sizeof(at.scanner_version))
        && _str(p, "db_digest", at.db_digest, sizeof(at.db_digest))
        && _str(p, "findings_digest", at.findings_digest, sizeof(at.findings_digest))
        && _str(p, "verdict", at.verdict, sizeof(at.verdict));
    json_t *jc = json_object_get(p, "count");
    at.count = json_is_integer(jc) ? (int64_t)json_integer_value(jc) : -1;
    if (!_str(p, "max_severity", at.max_severity, sizeof(at.max_severity)))
        at.max_severity[0] = '\0';
    json_decref(p);
    uuid_t owner;
    if (!ok || uuid_parse(owner_str, owner) != 0)
    {
        log_warn(proc->logger, "Identity: stele attest malformed, refusing\n");
        return true;
    }
    /* The subject is the AD's owner: no ad, no attestation. */
    held_ad_t held;
    if (!_find_ad(owner, at.commit, &held))
    {
        log_warn(proc->logger, "Identity: stele attest: no verified ad from %.8s at "
                 "%.12s, refusing\n", owner_str, at.commit);
        return true;
    }
    uuid_copy(at.verifier, self->uuid);
    snprintf(at.repo_ad_id, sizeof(at.repo_ad_id), "%s", held.id);
    at.ts = (int64_t)time(NULL);
    char sig[STELE_SIG_HEX + 1], digest[STELE_ID_HEX + 1];
    if (stele_attestation_sign(&at, self->signature.private, sig) != 0
        || stele_attestation_id(&at, digest) != 0)
    {
        log_warn(proc->logger, "Identity: stele attest invalid, refusing\n");
        return true;
    }
    _hold_attestation(&at, digest);
    json_t *env = stele_attestation_to_json(&at, sig);
    if (env != NULL)
    {
        _multicast(proc, ID_STELE_ATTEST, env, "a stele attestation");
        json_decref(env);
    }
    bool finding = strcmp(at.verdict, STELE_VERDICT_VULN) == 0;
    _submit_attested(proc, held.ad.owner, finding ? STELE_SCORE_FINDING
                                                  : STELE_SCORE_CLEAN, digest);
    log_info(proc->logger, "Identity: attested %s@%.12s: %s (%lld), evidence %.12s\n",
             held.ad.name, at.commit, at.verdict, (long long)at.count, digest);
    return true;
}

/* ---------------- registration ---------------- */

static int _stele_register(process_t *proc, const char *proc_name)
{
    if (strcmp(proc_name, "identity") != 0)
        return 0;
    process_register_handler(proc, ID_STELE_REPO,   (handler_ptr_t)handle_stele_repo);
    process_register_handler(proc, ID_STELE_ATTEST, (handler_ptr_t)handle_stele_attest);
    process_register_handler(proc, ID_APP_ADVERTISE,
                             (handler_ptr_t)handle_app_stele_advertise_repo);
    process_register_handler(proc, ID_APP_ATTEST, (handler_ptr_t)handle_app_stele_attest);
    return 0;
}

static const identity_ext_t stele_identity_ext = {
    .name = "stele",
    .init = _stele_init,
    .reset = _stele_reset,
};
IDENTITY_EXT_REGISTER(stele, &stele_identity_ext)

static const at_extension_t stele_extension = {
    .name = "stele",
    .enabled = NULL,   /* present means on */
    .register_handlers = _stele_register,
    .reset = _stele_reset,
};
AT_EXTENSION_REGISTER(stele, &stele_extension)

void at_stele_link(void)
{
}

/* ---------------- observability (tests, conformance) ---------------- */

json_t *stele_held_ads_json(void)
{
    json_t *arr = json_array();
    pthread_mutex_lock(&st.lock);
    for (size_t i = 0; arr != NULL && i < st.n_ads; i++)
    {
        char owner[STELE_UUID_STR];
        uuid_unparse_lower(st.ads[i].ad.owner, owner);
        json_array_append_new(arr, json_pack("{s:s, s:s, s:s, s:s}",
            "owner", owner, "name", st.ads[i].ad.name,
            "commit", st.ads[i].ad.commit, "id", st.ads[i].id));
    }
    pthread_mutex_unlock(&st.lock);
    return arr;
}

json_t *stele_held_attestations_json(void)
{
    json_t *arr = json_array();
    pthread_mutex_lock(&st.lock);
    for (size_t i = 0; arr != NULL && i < st.n_at; i++)
    {
        char verifier[STELE_UUID_STR];
        uuid_unparse_lower(st.attestations[i].at.verifier, verifier);
        json_array_append_new(arr, json_pack("{s:s, s:s, s:s}",
            "verifier", verifier, "verdict", st.attestations[i].at.verdict,
            "id", st.attestations[i].id));
    }
    pthread_mutex_unlock(&st.lock);
    return arr;
}

size_t stele_scores_sent(stele_score_sent_t *out, size_t cap)
{
    pthread_mutex_lock(&st.lock);
    size_t n = st.n_scores < cap ? st.n_scores : cap;
    if (out != NULL)
        memcpy(out, st.scores, n * sizeof(*out));
    pthread_mutex_unlock(&st.lock);
    return n;
}

void stele_hold_ad_for_test(const stele_repo_ad_t *ad)
{
    char id[STELE_ID_HEX + 1];
    if (stele_repo_ad_id(ad, id) == 0)
        _hold_ad(ad, id);
}
