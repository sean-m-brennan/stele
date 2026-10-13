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

/* The discovery relay on the wire (stele_relay.h), in the network process:
 *
 *  - a relay with $AT_STELE_RELAY=1 serves the "stl_" family from a store;
 *  - every node files what it holds at its own relays, each time it
 *    registers and every AT_STELE_RELAY_REFILE_SEC after (the relay keeps it
 *    in memory, and anyone may publish: a verifier files the finding an owner
 *    would leave out);
 *  - the app verbs AT_APP_STELE_RELAY_{SEARCH,FETCH,PUBLISH} come straight to
 *    this process; a search or fetch goes to every relay this node is
 *    connected to, and the answers, merged, land as a file the viewer reads
 *    (an app event cannot carry a bundle). */

#include <dirent.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <jansson.h>
#include <sodium.h>
#include <uuid/uuid.h>

#include "config/configuration.h"
#include "network/net_ext.h"
#include "network/net_message.h"
#include "network/net_proc_priv.h"
#include "processes/processes.h"
#include "network/network.h"
#include "utilities/msg_registry.h"
#include "utilities/msg_types_priv.h"
#include "utilities/util.h"
#include "rendezvous/net_relay.h"
#include "rendezvous/net_rendezvous.h"

#include "at_stele.h"
#include "stele_relay.h"
#include "stele_relay_net.h"

#define RELAY_QUERIES_MAX   16
#define RELAY_ASKED_MAX     8
#define RELAY_TIMEOUT_SEC   10.0
#define RELAY_REFILE_DEFAULT 120
#define RELAY_BATCH_BYTES   (2 * 1024 * 1024)
#define RELAY_QUERY_MAX     512

typedef struct {
    bool   used;
    char   rid[17];
    char   kind[8];                     /* "search" | "fetch" */
    char   query[RELAY_QUERY_MAX + 1];
    size_t n_asked;
    json_t *answers;                    /* [{relay, answer}] */
    double since;
} query_t;

static struct {
    pthread_mutex_t lock;
    logger_t *logger;
    stele_relay_store_t *store;         /* when this node is a Stele relay */
    query_t queries[RELAY_QUERIES_MAX];
    double last_refile;
} rn = { .lock = PTHREAD_MUTEX_INITIALIZER };

static double _mono(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static double _refile_sec(void)
{
    const char *e = getenv("AT_STELE_RELAY_REFILE_SEC");
    double v = e != NULL ? atof(e) : 0.0;
    return v > 0.0 ? v : RELAY_REFILE_DEFAULT;
}

/* ---------------- what this node holds, as publish items ---------------- */

static char *_slurp(const char *path, size_t max)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL)
        return NULL;
    char *buf = malloc(max + 1);
    size_t n = buf != NULL ? fread(buf, 1, max + 1, f) : 0;
    fclose(f);
    if (buf == NULL || n > max)
    {
        free(buf);
        return NULL;
    }
    buf[n] = '\0';
    return buf;
}

/* Append {kind, item} for each JSON file in <dir>, made by @p make from the file. */
static void _each_file(const char *dir, const char *kind, json_t *items,
                       json_t *(*make)(const char *name, const char *text))
{
    DIR *d = opendir(dir);
    if (d == NULL)
        return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL)
    {
        size_t n = strlen(e->d_name);
        if (n < 6 || strcmp(e->d_name + n - 5, ".json") != 0)
            continue;
        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
        char *text = _slurp(path, STELE_RELAY_SBOM_MAX);
        if (text == NULL)
            continue;
        char name[256];
        snprintf(name, sizeof(name), "%.*s", (int)(n - 5), e->d_name);
        json_t *item = make(name, text);
        free(text);
        if (item != NULL)
            json_array_append_new(items, json_pack("{s:s, s:o}", "kind", kind, "item", item));
    }
    closedir(d);
}

static json_t *_as_json(const char *name, const char *text)
{
    (void)name;
    json_t *j = json_loads(text, 0, NULL);
    if (!json_is_object(j))
    {
        json_decref(j);
        return NULL;
    }
    return j;
}

/* A kept roster ({"roster": text}) or anchor ({"text": text}): the file text. */
static json_t *_signed_text(const char *name, const char *text)
{
    (void)name;
    json_t *j = json_loads(text, 0, NULL);
    const char *t = json_string_value(json_object_get(j, "roster"));
    if (t == NULL)
        t = json_string_value(json_object_get(j, "text"));
    json_t *out = t != NULL ? json_string(t) : NULL;
    json_decref(j);
    return out;
}

static json_t *_sbom(const char *name, const char *text)
{
    return json_pack("{s:s, s:s}", "digest", name, "text", text);
}

static json_t *_held_items(void)
{
    const char *root = rootDir();
    json_t *items = json_array();
    char dir[768];
    static const struct { const char *sub, *kind; } plain[] = {
        { "etc/stele/ads", "ad" },
        { "etc/stele/attestations", "attestation" },
        { "etc/stele/rebuttals", "rebuttal" },
        { "etc/at/attested", "record" },
    };
    for (size_t i = 0; i < sizeof(plain) / sizeof(plain[0]); i++)
    {
        snprintf(dir, sizeof(dir), "%s/%s", root, plain[i].sub);
        _each_file(dir, plain[i].kind, items, _as_json);
    }
    snprintf(dir, sizeof(dir), "%s/etc/stele/teams", root);
    _each_file(dir, "team", items, _signed_text);
    /* Anchors: the one this node's polity asked it to publish, and every one
     * it follows (each is self-certifying, so passing it on costs nothing). */
    snprintf(dir, sizeof(dir), "%s/etc/stele/published-anchors", root);
    _each_file(dir, "anchor", items, _signed_text);
    snprintf(dir, sizeof(dir), "%s/etc/stele/anchors", root);
    _each_file(dir, "anchor", items, _signed_text);
    snprintf(dir, sizeof(dir), "%s/etc/stele/sboms", root);
    _each_file(dir, "sbom", items, _sbom);
    return items;
}

/* File @p items at relay @p c, in batches the relay takes. */
static void _publish_to(net_relay_client_t *c, json_t *items)
{
    json_t *batch = json_array();
    size_t bytes = 0, i;
    json_t *e;
    json_array_foreach(items, i, e)
    {
        char *one = json_dumps(e, JSON_COMPACT);
        size_t n = one != NULL ? strlen(one) : 0;
        free(one);
        if (json_array_size(batch) > 0 && (json_array_size(batch) >= STELE_RELAY_BATCH
                                           || bytes + n > RELAY_BATCH_BYTES))
        {
            (void)net_relay_client_request(c, json_pack("{s:s, s:o}", "op", "stl_publish",
                                                        "items", batch));
            batch = json_array();
            bytes = 0;
        }
        json_array_append(batch, e);
        bytes += n;
    }
    if (json_array_size(batch) > 0)
        (void)net_relay_client_request(c, json_pack("{s:s, s:o}", "op", "stl_publish",
                                                    "items", batch));
    else
        json_decref(batch);
}

static void _refile_all(void)
{
    net_relay_ep_t eps[RELAY_ASKED_MAX];
    net_relay_client_t *cs[RELAY_ASKED_MAX];
    size_t n = net_rendezvous_clients(true, eps, cs, RELAY_ASKED_MAX);
    if (n == 0)
        return;
    json_t *items = _held_items();
    for (size_t i = 0; i < n; i++)
        _publish_to(cs[i], items);
    json_decref(items);
}

/* ---------------- asking relays, and the answers ---------------- */

static void _rid_of(const char *kind, const char *query, char out[17])
{
    unsigned char d[crypto_hash_sha256_BYTES];
    size_t kl = strlen(kind), ql = strlen(query);
    unsigned char *buf = malloc(kl + 1 + ql);
    if (buf == NULL)
    {
        out[0] = '\0';
        return;
    }
    memcpy(buf, kind, kl);
    buf[kl] = '|';
    memcpy(buf + kl + 1, query, ql);
    crypto_hash_sha256(d, buf, kl + 1 + ql);
    free(buf);
    char hex[2 * sizeof(d) + 1];
    sodium_bin2hex(hex, sizeof(hex), d, sizeof(d));
    memcpy(out, hex, 16);
    out[16] = '\0';
}

static void _write_result(const query_t *q, bool complete)
{
    char dir[768], path[900], tmp[920];
    snprintf(dir, sizeof(dir), "%s/etc", rootDir());
    (void)mkdir(dir, 0755);
    snprintf(dir, sizeof(dir), "%s/etc/stele", rootDir());
    (void)mkdir(dir, 0755);
    snprintf(dir, sizeof(dir), "%s/etc/stele/relay", rootDir());
    (void)mkdir(dir, 0755);
    snprintf(path, sizeof(path), "%s/%s-%s.json", dir, q->kind, q->rid);
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    json_t *doc = json_pack("{s:s, s:s, s:s, s:O, s:b, s:I}", "kind", q->kind,
                            "rid", q->rid, "query", q->query, "relays", q->answers,
                            "complete", complete, "asked", (json_int_t)q->n_asked);
    if (doc == NULL || json_dump_file(doc, tmp, JSON_COMPACT) != 0 || rename(tmp, path) != 0)
        log_warn(rn.logger, "Stele relay: could not write %s\n", path);
    json_decref(doc);
}

static void _ask(const char *kind, const char *query)
{
    query_t q;
    memset(&q, 0, sizeof(q));
    q.used = true;
    snprintf(q.kind, sizeof(q.kind), "%s", kind);
    snprintf(q.query, sizeof(q.query), "%s", query);
    _rid_of(kind, query, q.rid);
    q.answers = json_array();
    q.since = _mono();
    net_relay_ep_t eps[RELAY_ASKED_MAX];
    net_relay_client_t *cs[RELAY_ASKED_MAX];
    size_t n = net_rendezvous_clients(false, eps, cs, RELAY_ASKED_MAX);
    for (size_t i = 0; i < n; i++)
    {
        json_t *req = strcmp(kind, "search") == 0
            ? json_pack("{s:s, s:s, s:s, s:i}", "op", "stl_search", "rid", q.rid, "q", query,
                        "limit", STELE_RELAY_RESULTS_MAX)
            : json_pack("{s:s, s:s, s:s}", "op", "stl_fetch", "rid", q.rid, "url", query);
        if (net_relay_client_request(cs[i], req) == 0)
            q.n_asked++;
    }
    if (q.n_asked == 0)
    {
        _write_result(&q, true);    /* nobody to ask: an empty, finished answer */
        json_decref(q.answers);
        return;
    }
    pthread_mutex_lock(&rn.lock);
    query_t *slot = NULL;
    for (size_t i = 0; i < RELAY_QUERIES_MAX && slot == NULL; i++)
        if (!rn.queries[i].used || strcmp(rn.queries[i].rid, q.rid) == 0)
            slot = &rn.queries[i];
    if (slot == NULL)
    {
        slot = &rn.queries[0];      /* full: replace the oldest */
        for (size_t i = 1; i < RELAY_QUERIES_MAX; i++)
            if (rn.queries[i].since < slot->since)
                slot = &rn.queries[i];
    }
    json_decref(slot->answers);
    *slot = q;
    pthread_mutex_unlock(&rn.lock);
}

/* An answer from relay @p host:@p port, on its reader thread. */
static void _on_answer(void *arg, const json_t *msg, const char *host, int port)
{
    (void)arg;
    const char *op = json_string_value(json_object_get(msg, "op"));
    const char *rid = json_string_value(json_object_get(msg, "rid"));
    if (op != NULL && strcmp(op, "stl_published") == 0)
    {
        size_t refused = json_array_size(json_object_get(msg, "refused"));
        if (refused > 0)
            log_debug(rn.logger, "Stele relay %s:%d refused %zu item(s)\n", host, port,
                      refused);
        return;
    }
    if (rid == NULL)
        return;
    char relay[300];
    snprintf(relay, sizeof(relay), "%s:%d", host, port);
    pthread_mutex_lock(&rn.lock);
    for (size_t i = 0; i < RELAY_QUERIES_MAX; i++)
        if (rn.queries[i].used && strcmp(rn.queries[i].rid, rid) == 0)
            json_array_append_new(rn.queries[i].answers,
                                  json_pack("{s:s, s:O}", "relay", relay, "answer", msg));
    pthread_mutex_unlock(&rn.lock);
}

/* Write every query all its relays answered, or that timed out. */
static void _drain(void)
{
    double now = _mono();
    pthread_mutex_lock(&rn.lock);
    for (size_t i = 0; i < RELAY_QUERIES_MAX; i++)
    {
        query_t *q = &rn.queries[i];
        if (!q->used)
            continue;
        bool all = json_array_size(q->answers) >= q->n_asked;
        if (all || now - q->since >= RELAY_TIMEOUT_SEC)
        {
            _write_result(q, all);
            json_decref(q->answers);
            memset(q, 0, sizeof(*q));
        }
    }
    pthread_mutex_unlock(&rn.lock);
}

/* ---------------- the relay service and the network extension ---------------- */

static json_t *_serve(void *arg, const char *uuid, const char *pub, const char *op,
                      const json_t *req)
{
    (void)arg;
    if (net_relay_is_distrusted(uuid, pub))
        return json_pack("{s:s, s:s}", "op", "stl_refused", "reason", "distrusted");
    pthread_mutex_lock(&rn.lock);
    stele_relay_store_t *s = rn.store;
    pthread_mutex_unlock(&rn.lock);
    return stele_relay_serve(s, uuid, op, req);
}

void stele_relay_serve_store(net_relay_server_t *srv, stele_relay_store_t *s)
{
    pthread_mutex_lock(&rn.lock);
    if (rn.store != s)
        stele_relay_store_free(rn.store);
    rn.store = s;
    pthread_mutex_unlock(&rn.lock);
    (void)net_relay_server_add_op(srv, STELE_RELAY_PREFIX, _serve, NULL);   /* once */
}

static void _server_started(net_relay_server_t *srv, net_thread_ctx_t *ctx)
{
    pthread_mutex_lock(&rn.lock);
    if (stele_relay_enabled() && rn.store == NULL)
    {
        rn.store = stele_relay_store_new(stele_relay_rate());
        if (rn.store != NULL && ctx != NULL)
            log_info(ctx->logger, "Stele relay: serving discovery (%.0f op/min each)\n",
                     stele_relay_rate());
    }
    pthread_mutex_unlock(&rn.lock);
    /* Always plugged in, so a relay that is not a Stele relay says so. */
    (void)net_relay_server_add_op(srv, STELE_RELAY_PREFIX, _serve, NULL);
}

static void _own_registered(const net_relay_ep_t *ep, net_relay_client_t *c)
{
    (void)ep;
    json_t *items = _held_items();
    _publish_to(c, items);
    json_decref(items);
}

static void _reset(void)
{
    pthread_mutex_lock(&rn.lock);
    for (size_t i = 0; i < RELAY_QUERIES_MAX; i++)
        json_decref(rn.queries[i].answers);
    memset(rn.queries, 0, sizeof(rn.queries));
    stele_relay_store_free(rn.store);
    rn.store = NULL;
    rn.last_refile = 0;
    pthread_mutex_unlock(&rn.lock);
}

static const net_rdv_service_t stele_relay_service = {
    .name = "stele_relay",
    .prefix = STELE_RELAY_PREFIX,
    .on_answer = _on_answer,
    .own_registered = _own_registered,
    .server_started = _server_started,
    .reset = _reset,
};
NET_RDV_SERVICE_REGISTER(stele_relay, &stele_relay_service)

static void _net_start(net_thread_ctx_t *ctx)
{
    pthread_mutex_lock(&rn.lock);
    rn.logger = ctx != NULL ? ctx->logger : NULL;
    rn.last_refile = _mono();
    pthread_mutex_unlock(&rn.lock);
}

static void _net_periodic(net_thread_ctx_t *ctx)
{
    (void)ctx;
    _drain();
    double now = _mono();
    pthread_mutex_lock(&rn.lock);
    bool due = now - rn.last_refile >= _refile_sec();
    if (due)
        rn.last_refile = now;
    pthread_mutex_unlock(&rn.lock);
    if (due)
        _refile_all();
}

static bool _local_verb(net_thread_ctx_t *ctx, net_msg_t *nmsg)
{
    const char *fn = nmsg->function;
    bool search = strcmp(fn, AT_APP_STELE_RELAY_SEARCH) == 0;
    bool fetch = strcmp(fn, AT_APP_STELE_RELAY_FETCH) == 0;
    bool publish = strcmp(fn, AT_APP_STELE_RELAY_PUBLISH) == 0;
    if (!search && !fetch && !publish)
        return false;
    if (!uuid_is_null(nmsg->from_whom.uuid))
    {
        log_warn(ctx != NULL ? ctx->logger : NULL,
                 "Stele relay: refusing %s from the wire\n", fn);
        return true;
    }
    if (publish)
    {
        _refile_all();
        return true;
    }
    json_t *body = NULL;
    const char *query = NULL;
    if (net_msg_unpack_json(nmsg, &body) == 0 && json_is_object(body))
        query = json_string_value(json_object_get(body, search ? "q" : "url"));
    if (query != NULL && strlen(query) <= RELAY_QUERY_MAX)
        _ask(search ? "search" : "fetch", query);
    json_decref(body);
    return true;
}

static const net_ext_t stele_net_ext = {
    .name = "stele",
    .start = _net_start,
    .periodic = _net_periodic,
    .local_verb = _local_verb,
};
NET_EXT_REGISTER(stele, &stele_net_ext)

AT_APP_VERB_REGISTER(stele_relay_search, AT_APP_STELE_RELAY_SEARCH, "network")
AT_APP_VERB_REGISTER(stele_relay_fetch, AT_APP_STELE_RELAY_FETCH, "network")
AT_APP_VERB_REGISTER(stele_relay_publish, AT_APP_STELE_RELAY_PUBLISH, "network")

void stele_relay_link(void)
{
}
