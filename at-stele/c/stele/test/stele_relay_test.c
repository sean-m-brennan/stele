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

/* The discovery relay's store (stele_relay.h): what it files, what a search and
 * a fetch hand back, and what it refuses. The ad's owner is node A of Ethne's
 * pinned anchor, so a search names that anchor. */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include <uuid/uuid.h>
#include "stele/stele_codec.h"
#include "stele/stele_relay.h"
#include "stele/stele_relay_net.h"
#include "identity/identity_priv.h"
#include <pthread.h>
#include <unistd.h>
#include "anchor_vector.h"

#define OWNER "0f1e2d3c-4b5a-4968-8776-655443322110"
#define VERIFIER "1a2b3c4d-5e6f-4071-8293-a4b5c6d7e8f9"
#define COMMIT "0123456789abcdef0123456789abcdef01234567"
#define SIG "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

static int64_t clock_now = 1790000000;
static int64_t _clock(void) { return clock_now; }

static json_t *_ad(char id[STELE_ID_HEX + 1])
{
    stele_repo_ad_t ad;
    memset(&ad, 0, sizeof(ad));
    uuid_parse(OWNER, ad.owner);
    snprintf(ad.name, sizeof(ad.name), "demo");
    snprintf(ad.url, sizeof(ad.url), "http://forge.local/alice/demo.git");
    snprintf(ad.ref, sizeof(ad.ref), "main");
    snprintf(ad.commit, sizeof(ad.commit), COMMIT);
    ad.seq = 1;
    ad.ts = 1790000000;
    ad.version = 2;
    snprintf(ad.description, sizeof(ad.description), "a library for demos");
    snprintf(ad.topics, sizeof(ad.topics), "go,demo");
    snprintf(ad.claim_verdict, sizeof(ad.claim_verdict), "none");
    ck_assert_ret_ok(stele_repo_ad_id(&ad, id));
    return stele_repo_ad_to_json(&ad, SIG);
}

static json_t *_attestation(const char *ad_id, const char *verdict, char id[STELE_ID_HEX + 1])
{
    stele_attestation_t at;
    memset(&at, 0, sizeof(at));
    uuid_parse(VERIFIER, at.verifier);
    snprintf(at.repo_ad_id, sizeof(at.repo_ad_id), "%s", ad_id);
    snprintf(at.commit, sizeof(at.commit), COMMIT);
    snprintf(at.scanner, sizeof(at.scanner), "osv-scanner");
    snprintf(at.scanner_version, sizeof(at.scanner_version), "2.6.0");
    memset(at.db_digest, 'c', STELE_DIGEST_HEX);
    memset(at.findings_digest, 'e', STELE_DIGEST_HEX);
    snprintf(at.verdict, sizeof(at.verdict), "%s", verdict);
    at.count = strcmp(verdict, "vuln") == 0 ? 2 : 0;
    snprintf(at.max_severity, sizeof(at.max_severity), "%s",
             strcmp(verdict, "vuln") == 0 ? "HIGH" : "");
    at.ts = 1790000100;
    ck_assert_ret_ok(stele_attestation_id(&at, id));
    return stele_attestation_to_json(&at, SIG);
}

static json_t *_item(const char *kind, json_t *item)
{
    return json_pack("{s:s, s:o}", "kind", kind, "item", item);
}

static json_t *_publish(stele_relay_store_t *s, json_t *items)
{
    json_t *req = json_pack("{s:s, s:o}", "op", "stl_publish", "items", items);
    json_t *reply = stele_relay_serve(s, VERIFIER, "stl_publish", req);
    json_decref(req);
    return reply;
}

DEFINE_TEST(test_a_publish_files_each_kind_and_refuses_the_malformed)
{
    stele_relay_store_t *s = stele_relay_store_new(0);
    char ad_id[STELE_ID_HEX + 1], at_id[STELE_ID_HEX + 1];
    json_t *items = json_array();
    json_array_append_new(items, _item("ad", _ad(ad_id)));
    json_array_append_new(items, _item("attestation", _attestation(ad_id, "vuln", at_id)));
    json_array_append_new(items, _item("record", json_pack(
        "{s:s, s:{s:s}, s:{s:i, s:s}}", "schema", "1", "entry", "evidence_digest", at_id,
        "checkpoint", "epoch", 3,
        "root", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")));
    json_array_append_new(items, _item("anchor", json_string(ANCHOR_PINNED)));
    json_array_append_new(items, _item("sbom", json_pack("{s:s, s:s}", "digest",
        /* sha256("{}") */
        "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", "text", "{}")));
    json_array_append_new(items, _item("ad", json_pack("{s:s}", "owner", "nobody")));
    json_array_append_new(items, _item("sbom", json_pack("{s:s, s:s}", "digest",
        "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", "text", "[]")));
    json_array_append_new(items, _item("rumour", json_string("x")));
    json_t *r = _publish(s, items);
    ck_assert_str_eq(json_string_value(json_object_get(r, "op")), "stl_published");
    ck_assert_int_eq((int)json_integer_value(json_object_get(r, "accepted")), 5);
    json_t *refused = json_object_get(r, "refused");
    ck_assert_int_eq((int)json_array_size(refused), 3);
    ck_assert_str_eq(json_string_value(json_object_get(json_array_get(refused, 2),
                                                       "reason")), "unknown_kind");
    ck_assert_int_eq((int)stele_relay_store_size(s), 5);
    json_decref(r);

    /* The same claims again change nothing (content-addressed), and an anchor
     * at the same seq is no newer. */
    json_t *again = json_array();
    json_array_append_new(again, _item("ad", _ad(ad_id)));
    r = _publish(s, again);
    ck_assert_int_eq((int)json_integer_value(json_object_get(r, "accepted")), 1);
    ck_assert_int_eq((int)stele_relay_store_size(s), 5);
    json_decref(r);
    stele_relay_store_free(s);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_search_and_a_fetch_hand_back_the_claims_and_the_relays_word)
{
    stele_relay_store_t *s = stele_relay_store_new(0);
    char ad_id[STELE_ID_HEX + 1], at_id[STELE_ID_HEX + 1];
    json_t *items = json_array();
    json_array_append_new(items, _item("ad", _ad(ad_id)));
    json_array_append_new(items, _item("attestation", _attestation(ad_id, "vuln", at_id)));
    json_array_append_new(items, _item("anchor", json_string(ANCHOR_PINNED)));
    json_decref(_publish(s, items));

    json_t *req = json_pack("{s:s, s:s, s:s}", "op", "stl_search", "q", "demos", "rid", "r1");
    json_t *r = stele_relay_serve(s, OWNER, "stl_search", req);
    json_decref(req);
    ck_assert_str_eq(json_string_value(json_object_get(r, "rid")), "r1");
    json_t *res = json_object_get(r, "results");
    ck_assert_int_eq((int)json_array_size(res), 1);
    json_t *hit = json_array_get(res, 0);
    ck_assert_str_eq(json_string_value(json_object_get(json_object_get(hit, "repo"), "owner")),
                     OWNER);
    json_t *relay = json_object_get(hit, "relay");
    ck_assert_int_eq((int)json_integer_value(json_object_get(relay, "findings")), 1);
    ck_assert_str_eq(json_string_value(json_object_get(relay, "anchor_issuer")),
                     "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c");
    json_decref(r);
    req = json_pack("{s:s, s:s}", "op", "stl_search", "q", "nothing-like-it");
    r = stele_relay_serve(s, OWNER, "stl_search", req);
    ck_assert_int_eq((int)json_array_size(json_object_get(r, "results")), 0);
    json_decref(req);
    json_decref(r);

    req = json_pack("{s:s, s:s}", "op", "stl_fetch", "url", "http://forge.local/alice/demo.git");
    r = stele_relay_serve(s, OWNER, "stl_fetch", req);
    json_decref(req);
    json_t *b = json_object_get(r, "bundle");
    ck_assert_str_eq(json_string_value(json_object_get(b, "schema")), "stele-bundle-1");
    ck_assert_int_eq((int)json_array_size(json_object_get(b, "ads")), 1);
    ck_assert_int_eq((int)json_array_size(json_object_get(b, "attestations")), 1);
    ck_assert_int_eq((int)json_array_size(json_object_get(b, "anchors")), 1);
    json_decref(r);
    stele_relay_store_free(s);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_rate_and_the_unknown_are_refused)
{
    stele_relay_store_t *s = stele_relay_store_new(3);
    stele_relay_store_set_clock(s, _clock);
    json_t *req = json_pack("{s:s, s:s}", "op", "stl_search", "q", "");
    for (int i = 0; i < 3; i++)
    {
        json_t *r = stele_relay_serve(s, OWNER, "stl_search", req);
        ck_assert_str_eq(json_string_value(json_object_get(r, "op")), "stl_results");
        json_decref(r);
    }
    json_t *r = stele_relay_serve(s, OWNER, "stl_search", req);
    ck_assert_str_eq(json_string_value(json_object_get(r, "op")), "stl_limited");
    json_decref(r);
    r = stele_relay_serve(s, VERIFIER, "stl_search", req);      /* per registrant */
    ck_assert_str_eq(json_string_value(json_object_get(r, "op")), "stl_results");
    json_decref(r);
    clock_now += 60;                                            /* refilled */
    r = stele_relay_serve(s, OWNER, "stl_search", req);
    ck_assert_str_eq(json_string_value(json_object_get(r, "op")), "stl_results");
    json_decref(r);
    r = stele_relay_serve(s, OWNER, "stl_forget", req);
    ck_assert_str_eq(json_string_value(json_object_get(r, "reason")), "unknown_op");
    json_decref(r);
    json_decref(req);
    stele_relay_store_free(s);
    r = stele_relay_serve(NULL, OWNER, "stl_search", NULL);
    ck_assert_str_eq(json_string_value(json_object_get(r, "reason")), "not_stele_relay");
    json_decref(r);
}
END_TEST_DEFINITION()

/* -- over the relay's own link (as a node reaches it) ---------------------- */
static struct {
    pthread_mutex_t lock;
    int n;
    json_t *last;
} g_op = { .lock = PTHREAD_MUTEX_INITIALIZER };

static void _on_op(void *arg, const json_t *msg, const char *host, int port)
{
    (void)arg; (void)host; (void)port;
    pthread_mutex_lock(&g_op.lock);
    json_decref(g_op.last);
    g_op.last = json_deep_copy(msg);
    g_op.n++;
    pthread_mutex_unlock(&g_op.lock);
}

static bool _wait_op(int n)
{
    for (int i = 0; i < 500; i++)
    {
        pthread_mutex_lock(&g_op.lock);
        bool ok = g_op.n >= n;
        pthread_mutex_unlock(&g_op.lock);
        if (ok)
            return true;
        usleep(10 * 1000);
    }
    return false;
}

static void _nodeliver(void *arg, const char *from, const uint8_t *frame, size_t len,
                       const char *host, int port)
{
    (void)arg; (void)from; (void)frame; (void)len; (void)host; (void)port;
}

static identity_t *_mk(const char *name)
{
    uuid_t u;
    uuid_generate(u);
    identity_t *id = NULL;
    ck_assert_ret_ok(identity_create(&u, "127.0.0.1", name, name, &id));
    return id;
}

static const char *_op_of(const json_t *m)
{
    return json_string_value(json_object_get(m, "op"));
}

DEFINE_TEST(test_the_ops_run_over_the_relay_link)
{
    net_relay_server_t *srv = net_relay_server_start("127.0.0.1", 0, NULL);
    ck_assert(srv != NULL);
    stele_relay_serve_store(srv, stele_relay_store_new(0));
    identity_t *alice = _mk("alice"), *bob = _mk("bob");
    int port = net_relay_server_port(srv);
    net_relay_client_t *a = net_relay_client_new("127.0.0.1", port, alice, _nodeliver, NULL, NULL);
    net_relay_client_t *b = net_relay_client_new("127.0.0.1", port, bob, _nodeliver, NULL, NULL);
    net_relay_client_on_op(a, STELE_RELAY_PREFIX, _on_op, NULL);
    net_relay_client_on_op(b, STELE_RELAY_PREFIX, _on_op, NULL);
    g_op.n = 0;
    char ad_id[STELE_ID_HEX + 1], at_id[STELE_ID_HEX + 1];
    json_t *items = json_array();
    json_array_append_new(items, _item("ad", _ad(ad_id)));
    json_array_append_new(items, _item("anchor", json_string(ANCHOR_PINNED)));
    ck_assert_int_eq(net_relay_client_request(a, json_pack("{s:s, s:o}", "op", "stl_publish",
                                                           "items", items)), 0);
    ck_assert(_wait_op(1));
    ck_assert_str_eq(_op_of(g_op.last), "stl_published");
    ck_assert_int_eq((int)json_integer_value(json_object_get(g_op.last, "accepted")), 2);
    /* Another node files the finding the owner left out. */
    items = json_array();
    json_array_append_new(items, _item("attestation", _attestation(ad_id, "vuln", at_id)));
    ck_assert_int_eq(net_relay_client_request(b, json_pack("{s:s, s:o}", "op", "stl_publish",
                                                           "items", items)), 0);
    ck_assert(_wait_op(2));
    ck_assert_int_eq(net_relay_client_request(b, json_pack("{s:s, s:s, s:s}", "op",
        "stl_fetch", "rid", "f1", "url", "http://forge.local/alice/demo.git")), 0);
    ck_assert(_wait_op(3));
    ck_assert_str_eq(_op_of(g_op.last), "stl_bundle");
    ck_assert_str_eq(json_string_value(json_object_get(g_op.last, "rid")), "f1");
    json_t *bundle = json_object_get(g_op.last, "bundle");
    ck_assert_int_eq((int)json_array_size(json_object_get(bundle, "attestations")), 1);
    ck_assert_int_eq((int)json_array_size(json_object_get(bundle, "anchors")), 1);
    /* A plain relay (no store) refuses. */
    stele_relay_serve_store(srv, NULL);
    ck_assert_int_eq(net_relay_client_request(b, json_pack("{s:s, s:s}", "op", "stl_search",
                                                           "q", "demo")), 0);
    ck_assert(_wait_op(4));
    ck_assert_str_eq(_op_of(g_op.last), "stl_refused");
    net_relay_client_free(a);
    net_relay_client_free(b);
    net_relay_server_stop(srv);
    identity_free(alice);
    identity_free(bob);
    json_decref(g_op.last);
    g_op.last = NULL;
}
END_TEST_DEFINITION()

RUN_TESTS(SteleRelay, test_the_ops_run_over_the_relay_link, test_a_publish_files_each_kind_and_refuses_the_malformed,
          test_a_search_and_a_fetch_hand_back_the_claims_and_the_relays_word,
          test_the_rate_and_the_unknown_are_refused)
