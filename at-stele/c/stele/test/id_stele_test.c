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

/**
 * @file id_stele_test.c
 * @brief The identity half of Stele, Phase 1: the store under etc/stele, the
 *        app events, the channel rules and the scope of an attestation, and the
 *        owner's rebuttal. Driven through the real verbs, as an app sends them.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <dirent.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <jansson.h>
#include <uuid/uuid.h>

#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "identity/id_proc_priv.h"
#include "config/configuration.h"
#include "structures/data.h"
#include "structures/map.h"
#include "processes/processes.h"
#include "utilities/allocation.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"
#include "utilities/msg_types_priv.h"
#include "utilities/msg_registry.h"

#include "stele/at_stele.h"
#include "stele/stele_codec.h"
#include "stele/id_stele.h"

static const char COMMIT[] = "0123456789abcdef0123456789abcdef01234567";

/* The STELE_EVENT payload, as id_stele.c lays it out (stele_event_msg_t). */
typedef struct {
    int32_t        kind;
    at_app_stele_t data;
} stele_event_mirror_t;

/* What the node handed on: Stele events to the app, scores to reputation. */
static int    g_events[8];
static size_t g_n_events;
static char   g_last_channel[32];
static tx_score_msg_t g_last_score;
static size_t g_scores;

static int _hook(const char *key, const message_type_t type, generic_msg_t *msg,
                 bool blocking)
{
    (void)blocking;
    if (key != NULL && strcmp(key, AT_MAIN_QUEUE) == 0 && g_n_events < 8)
    {
        const stele_event_mirror_t *m = AT_MSG_EXT_CONST(msg, stele_event_mirror_t);
        g_events[g_n_events++] = m->kind;
        if (m->kind == AT_APP_EVENT_STELE_ATTESTATION_HELD)
            snprintf(g_last_channel, sizeof(g_last_channel), "%s", m->data.channel);
    }
    if (key != NULL && strcmp(key, "reputation") == 0 && type == TRANSACTION_SCORE)
    {
        g_last_score = msg->info.tx_score;
        g_scores++;
    }
    return 0;
}

static identity_t *_mk_identity(const char *name, const char *addr)
{
    uuid_t uuid;
    uuid_generate(uuid);
    identity_t *ident = NULL;
    ck_assert_ret_ok(identity_create(&uuid, addr, name, name, &ident));
    return ident;
}

static process_t *_mk_process(identity_t *self)
{
    process_t *proc = smrt_create(sizeof(process_t));
    ck_assert_ptr_nonnull(proc);
    pthread_rwlock_init(&proc->protocol.peers_rwlock, NULL);
    strncpy(proc->name, "identity", PROC_NAME_LEN);
    proc->protocol.phase = 3;
    config_t *id_cfg = calloc(1, sizeof(config_t));
    ck_assert_ptr_nonnull(id_cfg);
    id_cfg->name = "identity";
    id_cfg->data_struct = self;
    ck_assert_ret_ok(map_create(&proc->configs));
    map_set(proc->configs, (map_key_t)"identity",
            object_ptr_data((ptr_t)id_cfg, sizeof(config_t)));
    ck_assert_ret_ok(map_create(&proc->protocol.handlers));
    ck_assert_ret_ok(identity_register_handlers(proc));
    return proc;
}

/* An app verb, as the shim sends it: local, so no sender. */
static void _verb(process_t *proc, const char *verb, json_t *body)
{
    static char fn[64];
    snprintf(fn, sizeof(fn), "%s", verb);
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    msg.info.net_msg.function = fn;
    msg.info.net_msg.verified = true;
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, body));
    json_decref(body);
    run_message_handlers(proc, NULL, NET_MESSAGE, &msg);
    net_msg_free_obj(&msg.info.net_msg);
}

static int _count_files(const char *root, const char *kind)
{
    char dir[400];
    snprintf(dir, sizeof(dir), "%s/etc/stele/%s", root, kind);
    DIR *d = opendir(dir);
    if (d == NULL)
        return 0;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL)
        if (strstr(e->d_name, ".json") != NULL && strstr(e->d_name, ".tmp") == NULL)
            n++;
    closedir(d);
    return n;
}

static bool _has_event(int kind)
{
    for (size_t i = 0; i < g_n_events; i++)
        if (g_events[i] == kind)
            return true;
    return false;
}

static char g_root[64];
static identity_t *g_me, *g_other;
static process_t *g_proc;

static void _begin(void)
{
    snprintf(g_root, sizeof(g_root), "/tmp/stele-id-XXXXXX");
    ck_assert_ptr_nonnull(mkdtemp(g_root));
    setenv("AUTONOMOUS_TRUST_ROOT", g_root, 1);
    identity_reset_state();
    stele_reload_for_test();               /* empty store: nothing held */
    g_n_events = g_scores = 0;
    g_last_channel[0] = '\0';
    messaging_set_test_hook(_hook);
    g_me = _mk_identity("me", "10.0.7.1");
    g_other = _mk_identity("other", "10.0.7.2");
    g_proc = _mk_process(g_me);
}

static void _end(void)
{
    messaging_set_test_hook(NULL);
}

/* A held v2 ad from @p owner: its claims are what the channel rules read. */
static void _hold_ad_from(const identity_t *owner, const char *claim, bool sbom)
{
    stele_repo_ad_t ad;
    memset(&ad, 0, sizeof(ad));
    uuid_copy(ad.owner, owner->uuid);
    snprintf(ad.name, sizeof(ad.name), "demo");
    snprintf(ad.url, sizeof(ad.url), "http://forge.local/other/demo.git");
    snprintf(ad.ref, sizeof(ad.ref), "main");
    snprintf(ad.commit, sizeof(ad.commit), "%s", COMMIT);
    ad.seq = 1;
    ad.ts = 1790000000;
    ad.version = 2;
    snprintf(ad.claim_verdict, sizeof(ad.claim_verdict), "%s", claim);
    if (sbom)
    {
        snprintf(ad.sbom_digest, sizeof(ad.sbom_digest), "%s",
                 "abababababababababababababababababababababababababababababababab");
        snprintf(ad.sbom_path, sizeof(ad.sbom_path), "sbom.cdx.json");
    }
    stele_hold_ad_for_test(&ad);
}

static json_t *_attest_body(const identity_t *owner, const char *channel,
                            const char *url)
{
    char o[37];
    uuid_unparse_lower(owner->uuid, o);
    json_t *b = json_pack("{s:s, s:s, s:s, s:s, s:s, s:s, s:s, s:I, s:s, s:s}",
        "owner", o, "commit", COMMIT, "scanner", "osv-scanner",
        "scanner_version", "2.6.0",
        "db_digest", "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        "findings_digest", "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef",
        "verdict", "vuln", "count", (json_int_t)2, "max_severity", "7.5",
        "channel", channel);
    if (url != NULL)
        json_object_set_new(b, "url", json_string(url));
    return b;
}

/* An ad this node advertises is kept as a signed envelope and announced. */
DEFINE_TEST(test_an_advertised_ad_is_kept_and_announced)
{
    _begin();
    _verb(g_proc, AT_APP_STELE_ADVERTISE_REPO, json_pack(
        "{s:s, s:s, s:s, s:s, s:s, s:s}", "name", "mine",
        "url", "http://forge.local/me/mine.git", "ref", "v1.0.0", "commit", COMMIT,
        "description", "my repo", "claim_verdict", "clean"));
    ck_assert_int_eq(_count_files(g_root, "ads"), 1);
    ck_assert(_has_event(AT_APP_EVENT_STELE_AD_HELD));
    _end();
}
END_TEST_DEFINITION()

/* A contradicted clean claim is attested on self_consistency at 0.1, in the
 * scope of (owner, name, commit, scanner), and kept and announced. */
DEFINE_TEST(test_a_contradicted_claim_scores_in_its_scope)
{
    _begin();
    _hold_ad_from(g_other, "clean", false);
    _verb(g_proc, AT_APP_STELE_ATTEST, _attest_body(g_other, "self_consistency", NULL));
    ck_assert_uint_eq(g_scores, 1);
    ck_assert_str_eq(g_last_score.channel, "self_consistency");
    ck_assert(g_last_score.score > 0.0999 && g_last_score.score < 0.1001);
    char want[STELE_DIGEST_HEX + 1];
    ck_assert_ret_ok(stele_scope(g_other->uuid, "demo", COMMIT, "osv-scanner", want));
    ck_assert_str_eq(g_last_score.attest_scope, want);
    ck_assert_int_eq(_count_files(g_root, "attestations"), 1);
    ck_assert(_has_event(AT_APP_EVENT_STELE_ATTESTATION_HELD));
    ck_assert_str_eq(g_last_channel, "self_consistency");
    _end();
}
END_TEST_DEFINITION()

/* The channel rules: a certificate needs an SBOM, self_consistency a clean
 * claim, and the URL the verifier cloned must be the ad's. */
DEFINE_TEST(test_the_channel_rules_and_the_url_check_refuse)
{
    _begin();
    _hold_ad_from(g_other, "none", false);
    _verb(g_proc, AT_APP_STELE_ATTEST, _attest_body(g_other, "certificate", NULL));
    _verb(g_proc, AT_APP_STELE_ATTEST, _attest_body(g_other, "self_consistency", NULL));
    _verb(g_proc, AT_APP_STELE_ATTEST,
          _attest_body(g_other, "probe", "http://elsewhere.local/demo.git"));
    _verb(g_proc, AT_APP_STELE_ATTEST, _attest_body(g_other, "replication", NULL));
    ck_assert_uint_eq(g_scores, 0);
    _verb(g_proc, AT_APP_STELE_ATTEST,
          _attest_body(g_other, "probe", "http://forge.local/other/demo.git"));
    ck_assert_uint_eq(g_scores, 1);
    ck_assert(g_last_score.score > 0.2999 && g_last_score.score < 0.3001);
    _end();
}
END_TEST_DEFINITION()

/* The owner may rebut a finding about its repo; the rebuttal is kept and
 * announced, and a restart reloads everything from the store. */
DEFINE_TEST(test_the_owner_rebuts_and_a_restart_reloads)
{
    _begin();
    _verb(g_proc, AT_APP_STELE_ADVERTISE_REPO, json_pack(
        "{s:s, s:s, s:s, s:s}", "name", "mine",
        "url", "http://forge.local/me/mine.git", "ref", "main", "commit", COMMIT));
    json_t *ads = stele_held_ads_json();
    const char *ad_id = json_string_value(json_object_get(json_array_get(ads, 0), "id"));
    stele_attestation_t at;
    memset(&at, 0, sizeof(at));
    uuid_copy(at.verifier, g_other->uuid);
    snprintf(at.repo_ad_id, sizeof(at.repo_ad_id), "%s", ad_id);
    json_decref(ads);
    snprintf(at.commit, sizeof(at.commit), "%s", COMMIT);
    snprintf(at.scanner, sizeof(at.scanner), "osv-scanner");
    snprintf(at.scanner_version, sizeof(at.scanner_version), "2.6.0");
    snprintf(at.db_digest, sizeof(at.db_digest), "%s",
             "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd");
    snprintf(at.findings_digest, sizeof(at.findings_digest), "%s",
             "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef");
    snprintf(at.verdict, sizeof(at.verdict), "vuln");
    at.count = 1;
    at.ts = 1790000100;
    stele_hold_attestation_for_test(&at);
    char at_id[STELE_ID_HEX + 1];
    ck_assert_ret_ok(stele_attestation_id(&at, at_id));

    _verb(g_proc, AT_APP_STELE_REBUT, json_pack("{s:s, s:s}", "attestation_id", at_id,
                                                "text", "vendored, never built"));
    ck_assert_int_eq(_count_files(g_root, "rebuttals"), 1);
    ck_assert(_has_event(AT_APP_EVENT_STELE_REBUTTAL_HELD));

    /* Not ours to rebut: an attestation about somebody else's repo. */
    _hold_ad_from(g_other, "none", false);
    _verb(g_proc, AT_APP_STELE_ATTEST, _attest_body(g_other, "probe", NULL));
    json_t *ats = stele_held_attestations_json();
    size_t n_at = json_array_size(ats);
    json_decref(ats);
    ck_assert_uint_eq(n_at, 2);

    /* A restart: what was kept comes back. (The fixture attestation was held
     * for the test only, never kept, so it does not.) */
    stele_reload_for_test();
    ads = stele_held_ads_json();
    ck_assert_uint_eq(json_array_size(ads), 1);
    json_decref(ads);
    json_t *rbs = stele_held_rebuttals_json();
    ck_assert_uint_eq(json_array_size(rbs), 1);
    json_decref(rbs);
    ats = stele_held_attestations_json();
    ck_assert_uint_eq(json_array_size(ats), 1);
    json_decref(ats);
    _end();
}
END_TEST_DEFINITION()

/* A held attestation by @p verifier about the held ad, version 1, as a peer's
 * would arrive; its id in @p id_out. */
static void _hold_attestation_by(const identity_t *verifier, const char *db,
                                 char id_out[STELE_ID_HEX + 1])
{
    json_t *ads = stele_held_ads_json();
    const char *ad_id = json_string_value(json_object_get(json_array_get(ads, 0), "id"));
    stele_attestation_t at;
    memset(&at, 0, sizeof(at));
    uuid_copy(at.verifier, verifier->uuid);
    snprintf(at.repo_ad_id, sizeof(at.repo_ad_id), "%s", ad_id);
    json_decref(ads);
    snprintf(at.commit, sizeof(at.commit), "%s", COMMIT);
    snprintf(at.scanner, sizeof(at.scanner), "osv-scanner");
    snprintf(at.scanner_version, sizeof(at.scanner_version), "2.6.0");
    snprintf(at.db_digest, sizeof(at.db_digest), "%s", db);
    snprintf(at.findings_digest, sizeof(at.findings_digest), "%s",
             "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef");
    snprintf(at.verdict, sizeof(at.verdict), "vuln");
    at.count = 2;
    at.ts = 1790000100;
    stele_hold_attestation_for_test(&at);
    ck_assert_ret_ok(stele_attestation_id(&at, id_out));
}

/* A replication re-runs ANOTHER verifier's held check (same commit, scanner,
 * version and database) and is attested on `replication`, version 3, naming
 * it. Not a re-run, not someone else's, or not held: refused. */
DEFINE_TEST(test_a_replication_re_runs_another_verifiers_check)
{
    static const char DB[] =
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
    _begin();
    identity_t *third = _mk_identity("third", "10.0.7.3");
    _hold_ad_from(g_other, "none", false);
    char theirs[STELE_ID_HEX + 1], mine[STELE_ID_HEX + 1], other_db[STELE_ID_HEX + 1];
    _hold_attestation_by(third, DB, theirs);
    _hold_attestation_by(g_me, DB, mine);
    _hold_attestation_by(third,
        "1111111111111111111111111111111111111111111111111111111111111111", other_db);

    json_t *b = _attest_body(g_other, "replication", NULL);
    json_object_set_new(b, "replicates", json_string(mine));
    _verb(g_proc, AT_APP_STELE_ATTEST, b);                 /* itself */
    b = _attest_body(g_other, "replication", NULL);
    json_object_set_new(b, "replicates", json_string(other_db));
    _verb(g_proc, AT_APP_STELE_ATTEST, b);                 /* another database */
    b = _attest_body(g_other, "replication", NULL);
    json_object_set_new(b, "replicates", json_string(
        "2222222222222222222222222222222222222222222222222222222222222222"));
    _verb(g_proc, AT_APP_STELE_ATTEST, b);                 /* not held */
    b = _attest_body(g_other, "probe", NULL);
    json_object_set_new(b, "replicates", json_string(theirs));
    _verb(g_proc, AT_APP_STELE_ATTEST, b);                 /* not a replication */
    ck_assert_uint_eq(g_scores, 0);

    b = _attest_body(g_other, "replication", NULL);
    json_object_set_new(b, "replicates", json_string(theirs));
    _verb(g_proc, AT_APP_STELE_ATTEST, b);
    ck_assert_uint_eq(g_scores, 1);
    ck_assert_str_eq(g_last_score.channel, "replication");
    ck_assert(g_last_score.score > 0.2999 && g_last_score.score < 0.3001);
    ck_assert_str_eq(g_last_channel, "replication");
    ck_assert_int_eq(_count_files(g_root, "attestations"), 1);

    /* What was kept is version 3 and names the original. */
    char dir[400];
    snprintf(dir, sizeof(dir), "%s/etc/stele/attestations", g_root);
    DIR *d = opendir(dir);
    ck_assert_ptr_nonnull(d);
    bool found = false;
    struct dirent *de;
    while ((de = readdir(d)) != NULL)
    {
        if (strstr(de->d_name, ".json") == NULL || strstr(de->d_name, ".tmp") != NULL)
            continue;
        char path[700];
        snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
        json_t *env = json_load_file(path, 0, NULL);
        found = json_integer_value(json_object_get(env, "v")) == 3
            && strcmp(json_string_value(json_object_get(env, "replicates")), theirs) == 0;
        json_decref(env);
    }
    closedir(d);
    ck_assert(found);
    _end();
}
END_TEST_DEFINITION()

RUN_TESTS(IdStele,
          test_an_advertised_ad_is_kept_and_announced,
          test_a_contradicted_claim_scores_in_its_scope,
          test_the_channel_rules_and_the_url_check_refuse,
          test_a_replication_re_runs_another_verifiers_check,
          test_the_owner_rebuts_and_a_restart_reloads)
