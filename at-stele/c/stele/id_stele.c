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

/* at-stele: the identity half of Stele. See at_stele.h for the verbs and
 * stele_codec.h for the artifacts. Twin of
 * ../../python/autonomous_trust/stele/_python/handlers.py.
 *
 * Wire functions, all group multicasts and all FIRST-PERSON: a repo ad is
 * accepted only from its owner, an attestation only from its verifier, a
 * rebuttal only from the owner of the repo the attestation it answers is
 * about, each signature checked against the sender's own key. Nothing is
 * relayed. Everything held is also kept on disk and announced to the app. */

#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
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
#include "config/configuration.h"
#include "app_events_registry.h"
#include "utilities/send_retry.h"

#include "at_stele.h"
#include "stele_codec.h"
#include "id_stele.h"

static char ID_STELE_REPO[]   = "stele repo";
static char ID_STELE_ATTEST[] = "stele attest";
static char ID_STELE_REBUT[]  = "stele rebut";
static char ID_APP_ADVERTISE[] = AT_APP_STELE_ADVERTISE_REPO;
static char ID_APP_ATTEST[]    = AT_APP_STELE_ATTEST;
static char ID_APP_REBUT[]     = AT_APP_STELE_REBUT;

AT_APP_VERB_REGISTER(stele_advertise_repo, AT_APP_STELE_ADVERTISE_REPO, "identity")
AT_APP_VERB_REGISTER(stele_attest,         AT_APP_STELE_ATTEST,         "identity")
AT_APP_VERB_REGISTER(stele_rebut,          AT_APP_STELE_REBUT,          "identity")

/* In memory, the newest of each. The store on disk (below) is the record. */
#define STELE_ADS_CAP     256
#define STELE_ATTEST_CAP  256
#define STELE_REBUT_CAP   256
#define STELE_SCORES_CAP  64

/* ---------------- the app event ---------------- */

/** Stele's one app-bound type (AT msg_registry.h reserves 2300-2309). */
#define STELE_EVENT ((message_type_t)(AT_MSG_TYPE_STELE_MIN + 0))

typedef struct {
    int32_t        kind;
    at_app_stele_t data;
} stele_event_msg_t;

AT_MSG_ASSERT_FITS(stele_event_msg_t);

static const at_msg_vtable_t stele_event_vt = {
    .name = "STELE_EVENT", .size = sizeof(stele_event_msg_t), .app_bound = true };
AT_MSG_TYPE_REGISTER(stele_event, STELE_EVENT, &stele_event_vt)

static bool _is_stele_kind(int32_t kind)
{
    return kind >= AT_APP_EVENT_STELE_AD_HELD
        && kind <= AT_APP_EVENT_STELE_REBUTTAL_HELD;
}

static int _decode_stele(const generic_msg_t *msg, at_app_event_t *ev)
{
    const stele_event_msg_t *m = AT_MSG_EXT_CONST(msg, stele_event_msg_t);
    if (!_is_stele_kind(m->kind))
        return -1;
    ev->kind = m->kind;
    memcpy(AT_APP_EVENT_EXT(ev, at_app_stele_t), &m->data, sizeof(m->data));
    return 0;
}
AT_APP_EVENT_DECODER_REGISTER(stele_event, STELE_EVENT, _decode_stele)

const at_app_stele_t *at_stele_event(const at_app_event_t *ev)
{
    if (ev == NULL || !_is_stele_kind(ev->kind))
        return NULL;
    return (const at_app_stele_t *)(const void *)ev->data.payload;
}

/* Announce a newly held artifact. One try, then kept for the tick (AT ISSUES
 * §2.14); NULL proc logs to the root logger. */
static void _emit(const process_t *proc, int32_t kind, const at_app_stele_t *d)
{
    generic_msg_t msg = {0};
    msg.type = STELE_EVENT;
    stele_event_msg_t *m = AT_MSG_EXT(&msg, stele_event_msg_t);
    m->kind = kind;
    m->data = *d;
    (void)at_send(proc, AT_MAIN_QUEUE, &msg, "a stele event", "the app",
                  AT_SEND_NOW, NULL, NULL, 0);
}

typedef struct {
    stele_repo_ad_t ad;
    char id[STELE_ID_HEX + 1];
} held_ad_t;

typedef struct {
    stele_attestation_t at;
    char id[STELE_ID_HEX + 1];
} held_attestation_t;

typedef struct {
    stele_rebuttal_t rb;
    char id[STELE_ID_HEX + 1];
} held_rebuttal_t;

static struct {
    pthread_mutex_t    lock;
    bool               initialized;
    held_ad_t          ads[STELE_ADS_CAP];
    size_t             n_ads, next_ad;
    held_attestation_t attestations[STELE_ATTEST_CAP];
    size_t             n_at, next_at;
    held_rebuttal_t    rebuttals[STELE_REBUT_CAP];
    size_t             n_rb, next_rb;
    stele_score_sent_t scores[STELE_SCORES_CAP];
    size_t             n_scores;
    int64_t            ad_seq;
} st = { .lock = PTHREAD_MUTEX_INITIALIZER };

static void _stele_reset(void)
{
    pthread_mutex_lock(&st.lock);
    st.n_ads = st.next_ad = 0;
    st.n_at = st.next_at = 0;
    st.n_rb = st.next_rb = 0;
    st.n_scores = 0;
    st.ad_seq = 0;
    st.initialized = true;
    pthread_mutex_unlock(&st.lock);
}

/* ---------------- the store: <root>/etc/stele/<kind>/<id>.json ---------------- */

static int _store_path(const char *kind, const char *id, char *out, size_t cap)
{
    const char *root = rootDir();
    int n = (id == NULL)
        ? snprintf(out, cap, "%s/etc/stele/%s", root, kind)
        : snprintf(out, cap, "%s/etc/stele/%s/%s.json", root, kind, id);
    return (n < 0 || (size_t)n >= cap) ? -1 : 0;
}

/* Keep @p env (a signed envelope) as <kind>/<id>.json, once. Atomic: a reader
 * (the viewer) never sees half a file. Failure costs only durability, so it is
 * logged at debug and swallowed. */
static void _store(const char *kind, const char *id, json_t *env)
{
    char dir[512], path[600], tmp[620];
    if (env == NULL || _store_path(kind, NULL, dir, sizeof(dir)) != 0
        || _store_path(kind, id, path, sizeof(path)) != 0)
        return;
    if (access(path, F_OK) == 0)
        return;
    char parent[512];
    snprintf(parent, sizeof(parent), "%s/etc", rootDir());
    (void)mkdir(parent, 0755);
    snprintf(parent, sizeof(parent), "%s/etc/stele", rootDir());
    (void)mkdir(parent, 0755);
    (void)mkdir(dir, 0755);
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    if (json_dump_file(env, tmp, JSON_INDENT(2) | JSON_SORT_KEYS) != 0
        || rename(tmp, path) != 0)
        log_debug(NULL, "Identity: stele: could not keep %s/%.12s\n", kind, id);
}

static bool _hold_ad(const stele_repo_ad_t *ad, const char *id);
static bool _hold_attestation(const stele_attestation_t *at, const char *id);
static bool _hold_rebuttal(const stele_rebuttal_t *rb, const char *id);

/* Reload what an earlier run kept, so a restarted node still holds the ads its
 * verbs need and the artifacts it announced. The files are this node's own
 * record of envelopes it verified on arrival, so they are not re-verified. */
static void _load_kind(const char *kind)
{
    char dir[512];
    if (_store_path(kind, NULL, dir, sizeof(dir)) != 0)
        return;
    DIR *d = opendir(dir);
    if (d == NULL)
        return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL)
    {
        size_t len = strlen(e->d_name);
        if (len != STELE_ID_HEX + 5 || strcmp(e->d_name + STELE_ID_HEX, ".json") != 0)
            continue;
        char path[600];
        snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
        json_error_t err;
        json_t *env = json_load_file(path, 0, &err);
        if (env == NULL)
            continue;
        char sig[STELE_SIG_HEX + 1], id[STELE_ID_HEX + 1];
        if (strcmp(kind, "ads") == 0)
        {
            stele_repo_ad_t ad;
            if (stele_repo_ad_from_json(env, &ad, sig) == 0
                && stele_repo_ad_id(&ad, id) == 0)
                (void)_hold_ad(&ad, id);
        }
        else if (strcmp(kind, "attestations") == 0)
        {
            stele_attestation_t at;
            if (stele_attestation_from_json(env, &at, sig) == 0
                && stele_attestation_id(&at, id) == 0)
                (void)_hold_attestation(&at, id);
        }
        else
        {
            stele_rebuttal_t rb;
            if (stele_rebuttal_from_json(env, &rb, sig) == 0
                && stele_rebuttal_id(&rb, id) == 0)
                (void)_hold_rebuttal(&rb, id);
        }
        json_decref(env);
    }
    closedir(d);
}

static void _stele_init(void)
{
    _stele_reset();
    _load_kind("ads");
    _load_kind("attestations");
    _load_kind("rebuttals");
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

static bool _hold_rebuttal(const stele_rebuttal_t *rb, const char *id)
{
    pthread_mutex_lock(&st.lock);
    for (size_t i = 0; i < st.n_rb; i++)
        if (strcmp(st.rebuttals[i].id, id) == 0)
        {
            pthread_mutex_unlock(&st.lock);
            return false;
        }
    held_rebuttal_t *slot = &st.rebuttals[st.next_rb];
    slot->rb = *rb;
    snprintf(slot->id, sizeof(slot->id), "%s", id);
    st.next_rb = (st.next_rb + 1) % STELE_REBUT_CAP;
    if (st.n_rb < STELE_REBUT_CAP)
        st.n_rb++;
    pthread_mutex_unlock(&st.lock);
    return true;
}

/* The held ad with content id @p id, copied out. */
static bool _find_ad_by_id(const char *id, held_ad_t *out)
{
    bool found = false;
    pthread_mutex_lock(&st.lock);
    for (size_t i = 0; i < st.n_ads && !found; i++)
        if (strcmp(st.ads[i].id, id) == 0)
        {
            *out = st.ads[i];
            found = true;
        }
    pthread_mutex_unlock(&st.lock);
    return found;
}

/* The held attestation with content id @p id, copied out. */
static bool _find_attestation(const char *id, held_attestation_t *out)
{
    bool found = false;
    pthread_mutex_lock(&st.lock);
    for (size_t i = 0; i < st.n_at && !found; i++)
        if (strcmp(st.attestations[i].id, id) == 0)
        {
            *out = st.attestations[i];
            found = true;
        }
    pthread_mutex_unlock(&st.lock);
    return found;
}

/* Keep, announce: the two things every newly held artifact gets. */
static void _ad_held(const process_t *proc, const stele_repo_ad_t *ad,
                     const char *id, const char *sig)
{
    json_t *env = stele_repo_ad_to_json(ad, sig);
    _store("ads", id, env);
    json_decref(env);
    at_app_stele_t d;
    memset(&d, 0, sizeof(d));
    snprintf(d.id, sizeof(d.id), "%s", id);
    uuid_unparse_lower(ad->owner, d.owner);
    snprintf(d.name, sizeof(d.name), "%s", ad->name);
    snprintf(d.commit, sizeof(d.commit), "%s", ad->commit);
    d.ts = ad->ts;
    _emit(proc, AT_APP_EVENT_STELE_AD_HELD, &d);
}

static void _attestation_held(const process_t *proc, const stele_attestation_t *at,
                              const char *id, const char *sig)
{
    json_t *env = stele_attestation_to_json(at, sig);
    _store("attestations", id, env);
    json_decref(env);
    at_app_stele_t d;
    memset(&d, 0, sizeof(d));
    snprintf(d.id, sizeof(d.id), "%s", id);
    uuid_unparse_lower(at->verifier, d.verifier);
    held_ad_t ad;
    if (_find_ad_by_id(at->repo_ad_id, &ad))
    {
        uuid_unparse_lower(ad.ad.owner, d.owner);
        snprintf(d.name, sizeof(d.name), "%s", ad.ad.name);
    }
    snprintf(d.commit, sizeof(d.commit), "%s", at->commit);
    snprintf(d.verdict, sizeof(d.verdict), "%s", at->verdict);
    snprintf(d.channel, sizeof(d.channel), "%s",
             at->version >= 2 ? at->channel : STELE_CHANNEL_PROBE);
    snprintf(d.subject_id, sizeof(d.subject_id), "%s", at->repo_ad_id);
    d.ts = at->ts;
    _emit(proc, AT_APP_EVENT_STELE_ATTESTATION_HELD, &d);
}

static void _rebuttal_held(const process_t *proc, const stele_rebuttal_t *rb,
                           const char *id, const char *sig)
{
    json_t *env = stele_rebuttal_to_json(rb, sig);
    _store("rebuttals", id, env);
    json_decref(env);
    at_app_stele_t d;
    memset(&d, 0, sizeof(d));
    snprintf(d.id, sizeof(d.id), "%s", id);
    uuid_unparse_lower(rb->owner, d.owner);
    snprintf(d.subject_id, sizeof(d.subject_id), "%s", rb->attestation_id);
    d.ts = rb->ts;
    _emit(proc, AT_APP_EVENT_STELE_REBUTTAL_HELD, &d);
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
                             double score, const char *digest, const char *channel,
                             const char *scope)
{
    generic_msg_t msg = {0};
    msg.type = TRANSACTION_SCORE;
    msg.size = sizeof(tx_score_msg_t);
    uuid_copy(msg.info.tx_score.peer_uuid, subject);
    msg.info.tx_score.score = score;
    at_strlcpy(msg.info.tx_score.channel, channel,
               sizeof(msg.info.tx_score.channel));
    msg.info.tx_score.attested = true;
    at_strlcpy(msg.info.tx_score.evidence_digest, digest,
               sizeof(msg.info.tx_score.evidence_digest));
    /* The scope keys AT's rate cap: a new commit is a new scope, so a fresh
     * scan answers an earlier finding (AT reputation.md). */
    if (scope != NULL)
        at_strlcpy(msg.info.tx_score.attest_scope, scope,
                   sizeof(msg.info.tx_score.attest_scope));
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
    {
        _ad_held(proc, &ad, id, sig);
        log_info(proc->logger, "Identity: stele repo %s@%.12s from %s (ad %.12s)\n",
                 ad.name, ad.commit, nmsg->from_whom.nickname, id);
    }
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
    {
        _attestation_held(proc, &at, id, sig);
        log_info(proc->logger, "Identity: stele attestation %.12s (%s, %lld) from %s\n",
                 id, at.verdict, (long long)at.count, nmsg->from_whom.nickname);
    }
    return true;
}

/* ---------------- wire: stele rebut ---------------- */

/* The owner of the repo the held attestation @p at_id is about, or false when
 * this node does not hold both the attestation and its ad. */
static bool _attested_owner(const char *at_id, uuid_t owner_out)
{
    held_attestation_t at;
    held_ad_t ad;
    if (!_find_attestation(at_id, &at) || !_find_ad_by_id(at.at.repo_ad_id, &ad))
        return false;
    uuid_copy(owner_out, ad.ad.owner);
    return true;
}

static bool handle_stele_rebut(const process_t *proc, directory_t *queues,
                               generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
        return true;
    stele_rebuttal_t rb;
    char sig[STELE_SIG_HEX + 1];
    int rc = stele_rebuttal_from_json(payload, &rb, sig);
    json_decref(payload);
    if (rc != 0)
    {
        log_warn(proc->logger, "Identity: stele rebuttal from %s malformed, refusing\n",
                 nmsg->from_whom.nickname);
        return true;
    }
    /* First person, and only the owner of the repo the finding is about. */
    uuid_t owner;
    if (uuid_compare(rb.owner, nmsg->from_whom.uuid) != 0
        || !stele_rebuttal_verify(&rb, nmsg->from_whom.signature.public, sig)
        || !_attested_owner(rb.attestation_id, owner)
        || uuid_compare(owner, rb.owner) != 0)
    {
        log_warn(proc->logger, "Identity: stele rebuttal from %s is not the owner's "
                 "reply to a held attestation, refusing\n", nmsg->from_whom.nickname);
        return true;
    }
    char id[STELE_ID_HEX + 1];
    if (stele_rebuttal_id(&rb, id) == 0 && _hold_rebuttal(&rb, id))
    {
        _rebuttal_held(proc, &rb, id, sig);
        log_info(proc->logger, "Identity: stele rebuttal %.12s to %.12s from %s\n",
                 id, rb.attestation_id, nmsg->from_whom.nickname);
    }
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
    /* Version 2: the optional description and the owner's claims. */
    ad.version = 2;
    if (!_str(p, "description", ad.description, sizeof(ad.description)))
        ad.description[0] = '\0';
    if (!_str(p, "topics", ad.topics, sizeof(ad.topics)))
        ad.topics[0] = '\0';
    if (!_str(p, "sbom_digest", ad.sbom_digest, sizeof(ad.sbom_digest)))
        ad.sbom_digest[0] = '\0';
    if (!_str(p, "sbom_path", ad.sbom_path, sizeof(ad.sbom_path)))
        ad.sbom_path[0] = '\0';
    if (!_str(p, "claim_verdict", ad.claim_verdict, sizeof(ad.claim_verdict)))
        snprintf(ad.claim_verdict, sizeof(ad.claim_verdict), "%s", STELE_CLAIM_NONE);
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
    if (_hold_ad(&ad, id))   /* our own, so a loopback copy is a no-op */
        _ad_held(proc, &ad, id, sig);
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
    at.version = 2;
    if (!_str(p, "channel", at.channel, sizeof(at.channel)))
        snprintf(at.channel, sizeof(at.channel), "%s", STELE_CHANNEL_PROBE);
    char cloned[STELE_URL_MAX + 1] = {0};
    bool url_given = _str(p, "url", cloned, sizeof(cloned));
    if (!_str(p, "replicates", at.replicates, sizeof(at.replicates)))
        at.replicates[0] = '\0';
    json_decref(p);
    uuid_t owner;
    if (!ok || uuid_parse(owner_str, owner) != 0)
    {
        log_warn(proc->logger, "Identity: stele attest malformed, refusing\n");
        return true;
    }
    /* A replication, and only a replication, names what it re-ran. */
    bool replication = strcmp(at.channel, STELE_CHANNEL_REPLICATION) == 0;
    if (replication != (at.replicates[0] != '\0'))
    {
        log_warn(proc->logger, "Identity: stele attest: a replication, and only a "
                 "replication, names the attestation it re-ran; refusing\n");
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
    /* A replication re-runs ANOTHER verifier's check: the same commit,
     * scanner, scanner version and database, about the same ad. Whether it
     * agrees is the viewer's fold; this only refuses what is not a re-run. */
    if (replication)
    {
        held_attestation_t orig;
        held_ad_t orig_ad;
        if (!_find_attestation(at.replicates, &orig)
            || !_find_ad_by_id(orig.at.repo_ad_id, &orig_ad)
            || uuid_compare(orig_ad.ad.owner, owner) != 0)
        {
            log_warn(proc->logger, "Identity: stele attest: replicates %.12s, which "
                     "is not a held attestation about this owner; refusing\n",
                     at.replicates);
            return true;
        }
        if (uuid_compare(orig.at.verifier, self->uuid) == 0)
        {
            log_warn(proc->logger, "Identity: stele attest: a verifier does not "
                     "replicate itself; refusing\n");
            return true;
        }
        if (strcmp(orig.at.commit, at.commit) != 0
            || strcmp(orig.at.scanner, at.scanner) != 0
            || strcmp(orig.at.scanner_version, at.scanner_version) != 0
            || strcmp(orig.at.db_digest, at.db_digest) != 0)
        {
            log_warn(proc->logger, "Identity: stele attest: a replication re-runs "
                     "the same check (commit, scanner, version, database); "
                     "refusing\n");
            return true;
        }
        held = orig_ad;
        at.version = 3;
    }
    /* The verifier says what it cloned; it must be what the owner advertised. */
    if (url_given && strcmp(cloned, held.ad.url) != 0)
    {
        log_warn(proc->logger, "Identity: stele attest: scanned %s, but the ad "
                 "advertises %s; refusing\n", cloned, held.ad.url);
        return true;
    }
    /* What each channel may attest, and what it scores (at_stele.h). */
    bool finding = strcmp(at.verdict, STELE_VERDICT_VULN) == 0;
    double score = finding ? STELE_SCORE_FINDING : STELE_SCORE_CLEAN;
    if (strcmp(at.channel, STELE_CHANNEL_CERTIFICATE) == 0)
    {
        if (held.ad.version != 2 || held.ad.sbom_digest[0] == '\0')
        {
            log_warn(proc->logger, "Identity: stele attest: a certificate needs an "
                     "ad that carries an SBOM; refusing\n");
            return true;
        }
    }
    else if (strcmp(at.channel, STELE_CHANNEL_SELF_CONSISTENCY) == 0)
    {
        if (held.ad.version != 2
            || strcmp(held.ad.claim_verdict, STELE_VERDICT_CLEAN) != 0 || !finding)
        {
            log_warn(proc->logger, "Identity: stele attest: self_consistency needs "
                     "the owner's clean claim and a finding; refusing\n");
            return true;
        }
        score = STELE_SCORE_CONTRADICTED;
    }
    else if (strcmp(at.channel, STELE_CHANNEL_PROBE) != 0 && !replication)
    {
        log_warn(proc->logger, "Identity: stele attest: channel '%s' is not one "
                 "Stele attests on; refusing\n", at.channel);
        return true;
    }
    if (stele_scope(held.ad.owner, held.ad.name, at.commit, at.scanner, at.scope) != 0)
        return true;
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
    if (_hold_attestation(&at, digest))
        _attestation_held(proc, &at, digest, sig);
    json_t *env = stele_attestation_to_json(&at, sig);
    if (env != NULL)
    {
        _multicast(proc, ID_STELE_ATTEST, env, "a stele attestation");
        json_decref(env);
    }
    _submit_attested(proc, held.ad.owner, score, digest, at.channel, at.scope);
    log_info(proc->logger, "Identity: attested %s@%.12s on %s: %s (%lld), evidence "
             "%.12s\n", held.ad.name, at.commit, at.channel, at.verdict,
             (long long)at.count, digest);
    return true;
}

static bool handle_app_stele_rebut(const process_t *proc, directory_t *queues,
                                   generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!identity_is_local_app_verb(proc, nmsg))
        return identity_refuse_remote_app_verb(proc, nmsg, AT_APP_STELE_REBUT);
    const identity_t *self = identity_self_identity(proc);
    json_t *p = NULL;
    if (self == NULL || net_msg_unpack_json(nmsg, &p) != 0 || p == NULL)
        return true;
    stele_rebuttal_t rb;
    memset(&rb, 0, sizeof(rb));
    bool ok = _str(p, "attestation_id", rb.attestation_id, sizeof(rb.attestation_id))
        && _str(p, "text", rb.text, sizeof(rb.text));
    json_decref(p);
    uuid_t owner;
    if (!ok || !_attested_owner(rb.attestation_id, owner)
        || uuid_compare(owner, self->uuid) != 0)
    {
        log_warn(proc->logger, "Identity: stele rebut: not a held attestation about "
                 "this node's repo; refusing\n");
        return true;
    }
    uuid_copy(rb.owner, self->uuid);
    rb.ts = (int64_t)time(NULL);
    char sig[STELE_SIG_HEX + 1], id[STELE_ID_HEX + 1];
    if (stele_rebuttal_sign(&rb, self->signature.private, sig) != 0
        || stele_rebuttal_id(&rb, id) != 0)
    {
        log_warn(proc->logger, "Identity: stele rebut malformed, refusing\n");
        return true;
    }
    if (_hold_rebuttal(&rb, id))
        _rebuttal_held(proc, &rb, id, sig);
    json_t *env = stele_rebuttal_to_json(&rb, sig);
    if (env != NULL)
    {
        _multicast(proc, ID_STELE_REBUT, env, "a stele rebuttal");
        json_decref(env);
    }
    log_info(proc->logger, "Identity: rebutted attestation %.12s (rebuttal %.12s)\n",
             rb.attestation_id, id);
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
    process_register_handler(proc, ID_STELE_REBUT, (handler_ptr_t)handle_stele_rebut);
    process_register_handler(proc, ID_APP_REBUT, (handler_ptr_t)handle_app_stele_rebut);
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

json_t *stele_held_rebuttals_json(void)
{
    json_t *arr = json_array();
    pthread_mutex_lock(&st.lock);
    for (size_t i = 0; arr != NULL && i < st.n_rb; i++)
    {
        char owner[STELE_UUID_STR];
        uuid_unparse_lower(st.rebuttals[i].rb.owner, owner);
        json_array_append_new(arr, json_pack("{s:s, s:s, s:s}",
            "owner", owner, "attestation_id", st.rebuttals[i].rb.attestation_id,
            "id", st.rebuttals[i].id));
    }
    pthread_mutex_unlock(&st.lock);
    return arr;
}

void stele_reload_for_test(void)
{
    _stele_init();
}

void stele_hold_attestation_for_test(const stele_attestation_t *at)
{
    char id[STELE_ID_HEX + 1];
    if (stele_attestation_id(at, id) == 0)
        _hold_attestation(at, id);
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
