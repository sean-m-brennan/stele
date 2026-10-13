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

/* The discovery relay's store: what a relay holds and how it answers. The
 * network glue (stele_relay_net.c) plugs it into the relay. See stele_relay.h. */

#include "stele_relay.h"

#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sodium.h>
#include <uuid/uuid.h>

#include "stele_codec.h"
#include "stele_team.h"
#include "stele_anchor.h"

typedef enum { K_AD, K_ATTEST, K_REBUT, K_RECORD, K_SBOM } kind_t;

typedef struct {
    kind_t   kind;
    char     id[STELE_ID_HEX + 1];
    json_t  *item;          /* as published (sbom: its text, a json string) */
    uint64_t order;         /* insertion order, for eviction */
    /* what search and fetch read, by kind */
    stele_repo_ad_t     ad;
    stele_attestation_t at;
    char     ref_id[STELE_ID_HEX + 1];   /* rebuttal: its attestation; record: its digest */
} item_t;

typedef struct {
    char     issuer[STELE_PK_HEX + 1];
    int64_t  seq;
    char    *text;
    /* anchor: the nodes it lists; team: its polity root is the issuer */
    size_t   n_nodes;
    char   (*nodes)[STELE_UUID_STR];
} file_t;

typedef struct {
    char   uuid[STELE_UUID_STR];
    double tokens;
    int64_t last;
} bucket_t;

struct stele_relay_store_s {
    pthread_mutex_t lock;
    item_t   *items;
    size_t    n_items;
    uint64_t  next_order;
    file_t    teams[STELE_RELAY_FILES_MAX];
    size_t    n_teams;
    file_t    anchors[STELE_RELAY_FILES_MAX];
    size_t    n_anchors;
    bucket_t  buckets[STELE_RELAY_BUCKETS_MAX];
    size_t    n_buckets;
    double    rate;
    int64_t (*now)(void);
};

static int64_t _time(void)
{
    return (int64_t)time(NULL);
}

bool stele_relay_enabled(void)
{
    const char *e = getenv("AT_STELE_RELAY");
    return e != NULL && strcmp(e, "1") == 0;
}

double stele_relay_rate(void)
{
    const char *e = getenv("AT_STELE_RELAY_RATE");
    double r = e != NULL ? atof(e) : 0.0;
    return r > 0.0 ? r : STELE_RELAY_RATE_DEFAULT;
}

stele_relay_store_t *stele_relay_store_new(double rate)
{
    stele_relay_store_t *s = calloc(1, sizeof(*s));
    if (s == NULL)
        return NULL;
    s->items = calloc(STELE_RELAY_ITEMS_MAX, sizeof(item_t));
    if (s->items == NULL)
    {
        free(s);
        return NULL;
    }
    pthread_mutex_init(&s->lock, NULL);
    s->rate = rate > 0.0 ? rate : STELE_RELAY_RATE_DEFAULT;
    s->now = _time;
    return s;
}

static void _file_free(file_t *f)
{
    free(f->text);
    free(f->nodes);
    memset(f, 0, sizeof(*f));
}

void stele_relay_store_free(stele_relay_store_t *s)
{
    if (s == NULL)
        return;
    for (size_t i = 0; i < s->n_items; i++)
        json_decref(s->items[i].item);
    for (size_t i = 0; i < s->n_teams; i++)
        _file_free(&s->teams[i]);
    for (size_t i = 0; i < s->n_anchors; i++)
        _file_free(&s->anchors[i]);
    free(s->items);
    pthread_mutex_destroy(&s->lock);
    free(s);
}

void stele_relay_store_set_clock(stele_relay_store_t *s, int64_t (*now)(void))
{
    if (s != NULL)
        s->now = now != NULL ? now : _time;
}

size_t stele_relay_store_size(stele_relay_store_t *s)
{
    pthread_mutex_lock(&s->lock);
    size_t n = s->n_items + s->n_teams + s->n_anchors;
    pthread_mutex_unlock(&s->lock);
    return n;
}

/* ---------------- the rate (a token bucket per registrant) ---------------- */

static bool _spend_locked(stele_relay_store_t *s, const char *uuid)
{
    int64_t now = s->now();
    bucket_t *b = NULL;
    for (size_t i = 0; i < s->n_buckets && b == NULL; i++)
        if (strcmp(s->buckets[i].uuid, uuid) == 0)
            b = &s->buckets[i];
    if (b == NULL)
    {
        if (s->n_buckets < STELE_RELAY_BUCKETS_MAX)
            b = &s->buckets[s->n_buckets++];
        else
        {
            b = &s->buckets[0];   /* full: reuse the stalest */
            for (size_t i = 1; i < s->n_buckets; i++)
                if (s->buckets[i].last < b->last)
                    b = &s->buckets[i];
        }
        snprintf(b->uuid, sizeof(b->uuid), "%s", uuid);
        b->tokens = s->rate;
        b->last = now;
    }
    double refill = (double)(now - b->last) * s->rate / 60.0;
    b->tokens = b->tokens + refill > s->rate ? s->rate : b->tokens + refill;
    b->last = now;
    if (b->tokens < 1.0)
        return false;
    b->tokens -= 1.0;
    return true;
}

/* ---------------- filing ---------------- */

static bool _hex_ok(const char *s, size_t len)
{
    if (s == NULL || strnlen(s, len + 1) != len)
        return false;
    for (size_t i = 0; i < len; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return false;
    return true;
}

static void _blake(const char *text, char out[STELE_ID_HEX + 1])
{
    unsigned char d[32];
    crypto_generichash(d, sizeof(d), (const unsigned char *)text, strlen(text), NULL, 0);
    sodium_bin2hex(out, STELE_ID_HEX + 1, d, sizeof(d));
}

static item_t *_find_locked(stele_relay_store_t *s, kind_t kind, const char *id)
{
    for (size_t i = 0; i < s->n_items; i++)
        if (s->items[i].kind == kind && strcmp(s->items[i].id, id) == 0)
            return &s->items[i];
    return NULL;
}

/* A slot for a new item: the next free one, or the oldest's. */
static item_t *_slot_locked(stele_relay_store_t *s)
{
    if (s->n_items < STELE_RELAY_ITEMS_MAX)
        return &s->items[s->n_items++];
    item_t *old = &s->items[0];
    for (size_t i = 1; i < s->n_items; i++)
        if (s->items[i].order < old->order)
            old = &s->items[i];
    json_decref(old->item);
    memset(old, 0, sizeof(*old));
    return old;
}

/* A signed file kept by issuer, only a higher seq replacing it. */
static const char *_file_locked(file_t *files, size_t *n, const char *issuer, int64_t seq,
                                const char *text, char (*nodes)[STELE_UUID_STR],
                                size_t n_nodes)
{
    file_t *f = NULL;
    for (size_t i = 0; i < *n && f == NULL; i++)
        if (strcmp(files[i].issuer, issuer) == 0)
            f = &files[i];
    if (f != NULL && seq <= f->seq)
    {
        free(nodes);
        return strcmp(f->text, text) == 0 ? NULL : "stale";
    }
    if (f == NULL)
    {
        if (*n >= STELE_RELAY_FILES_MAX)
        {
            free(nodes);
            return "full";
        }
        f = &files[(*n)++];
    }
    _file_free(f);
    snprintf(f->issuer, sizeof(f->issuer), "%s", issuer);
    f->seq = seq;
    f->text = strdup(text);
    f->nodes = nodes;
    f->n_nodes = n_nodes;
    return f->text != NULL ? NULL : "full";
}

/* File one {kind, item}. NULL when taken (or already held), else why not. */
static const char *_publish_one_locked(stele_relay_store_t *s, const json_t *e)
{
    const char *kind = json_string_value(json_object_get(e, "kind"));
    json_t *item = json_object_get(e, "item");
    if (kind == NULL || item == NULL)
        return "malformed";
    char id[STELE_ID_HEX + 1] = "";
    char sig[STELE_SIG_HEX + 1];
    item_t tmp;
    memset(&tmp, 0, sizeof(tmp));
    if (strcmp(kind, "ad") == 0)
    {
        if (stele_repo_ad_from_json(item, &tmp.ad, sig) != 0 || !stele_repo_ad_valid(&tmp.ad)
            || stele_repo_ad_id(&tmp.ad, id) != 0)
            return "malformed";
        tmp.kind = K_AD;
    }
    else if (strcmp(kind, "attestation") == 0)
    {
        if (stele_attestation_from_json(item, &tmp.at, sig) != 0
            || !stele_attestation_valid(&tmp.at) || stele_attestation_id(&tmp.at, id) != 0)
            return "malformed";
        tmp.kind = K_ATTEST;
    }
    else if (strcmp(kind, "rebuttal") == 0)
    {
        stele_rebuttal_t rb;
        if (stele_rebuttal_from_json(item, &rb, sig) != 0 || !stele_rebuttal_valid(&rb)
            || stele_rebuttal_id(&rb, id) != 0)
            return "malformed";
        snprintf(tmp.ref_id, sizeof(tmp.ref_id), "%s", rb.attestation_id);
        tmp.kind = K_REBUT;
    }
    else if (strcmp(kind, "record") == 0)
    {
        json_t *entry = json_object_get(item, "entry");
        json_t *ck = json_object_get(item, "checkpoint");
        const char *schema = json_string_value(json_object_get(item, "schema"));
        const char *digest = json_string_value(json_object_get(entry, "evidence_digest"));
        const char *root = json_string_value(json_object_get(ck, "root"));
        json_t *epoch = json_object_get(ck, "epoch");
        if (schema == NULL || strcmp(schema, "1") != 0 || !_hex_ok(digest, STELE_ID_HEX)
            || !_hex_ok(root, STELE_DIGEST_HEX) || !json_is_integer(epoch)
            || json_integer_value(epoch) < 0)
            return "malformed";
        char key[STELE_ID_HEX + STELE_DIGEST_HEX + 32];
        snprintf(key, sizeof(key), "%s|%lld|%s", digest,
                 (long long)json_integer_value(epoch), root);
        _blake(key, id);
        snprintf(tmp.ref_id, sizeof(tmp.ref_id), "%s", digest);
        tmp.kind = K_RECORD;
    }
    else if (strcmp(kind, "sbom") == 0)
    {
        const char *digest = json_string_value(json_object_get(item, "digest"));
        const char *text = json_string_value(json_object_get(item, "text"));
        if (!_hex_ok(digest, STELE_DIGEST_HEX) || text == NULL
            || strlen(text) > STELE_RELAY_SBOM_MAX)
            return "malformed";
        unsigned char d[crypto_hash_sha256_BYTES];
        crypto_hash_sha256(d, (const unsigned char *)text, strlen(text));
        sodium_bin2hex(id, sizeof(id), d, sizeof(d));
        if (strcmp(id, digest) != 0)
            return "malformed";
        json_t *parsed = json_loads(text, 0, NULL);
        bool object = json_is_object(parsed);
        json_decref(parsed);
        if (!object)
            return "malformed";
        tmp.kind = K_SBOM;
        item = json_object_get(item, "text");
    }
    else if (strcmp(kind, "team") == 0)
    {
        const char *text = json_string_value(item);
        stele_team_t *t = calloc(1, sizeof(*t));
        const char *why = "malformed";
        if (t != NULL && text != NULL && stele_team_parse(text, t) == 0)
            why = _file_locked(s->teams, &s->n_teams, t->issuer, t->seq, text, NULL, 0);
        free(t);
        return why;
    }
    else if (strcmp(kind, "anchor") == 0)
    {
        const char *text = json_string_value(item);
        stele_anchor_t *a = calloc(1, sizeof(*a));
        const char *why = "malformed";
        if (a != NULL && text != NULL && stele_anchor_parse(text, a) == 0)
        {
            char (*nodes)[STELE_UUID_STR] = calloc(a->n_members ? a->n_members : 1,
                                                   STELE_UUID_STR);
            if (nodes != NULL)
            {
                for (size_t i = 0; i < a->n_members; i++)
                    memcpy(nodes[i], a->members[i].at_uuid, STELE_UUID_STR);
                why = _file_locked(s->anchors, &s->n_anchors, a->issuer, a->seq, text,
                                   nodes, a->n_members);
            }
        }
        free(a);
        return why;
    }
    else
        return "unknown_kind";
    if (_find_locked(s, tmp.kind, id) != NULL)
        return NULL;                            /* held already: content-addressed */
    item_t *slot = _slot_locked(s);
    *slot = tmp;
    snprintf(slot->id, sizeof(slot->id), "%s", id);
    slot->item = json_incref(item);
    slot->order = s->next_order++;
    return NULL;
}

static json_t *_publish_locked(stele_relay_store_t *s, const json_t *req)
{
    json_t *items = json_object_get(req, "items");
    if (!json_is_array(items) || json_array_size(items) > STELE_RELAY_BATCH)
        return json_pack("{s:s, s:s}", "op", "stl_refused", "reason", "malformed");
    json_t *refused = json_array();
    size_t accepted = 0, i;
    json_t *e;
    json_array_foreach(items, i, e)
    {
        const char *why = _publish_one_locked(s, e);
        if (why == NULL)
            accepted++;
        else
            json_array_append_new(refused, json_pack("{s:I, s:s}", "index", (json_int_t)i,
                                                     "reason", why));
    }
    return json_pack("{s:s, s:I, s:o}", "op", "stl_published", "accepted",
                     (json_int_t)accepted, "refused", refused);
}

/* ---------------- searching ---------------- */

static void _owner_of(const stele_repo_ad_t *ad, char out[STELE_UUID_STR])
{
    uuid_unparse_lower(ad->owner, out);
}

static bool _same_repo(const stele_repo_ad_t *a, const stele_repo_ad_t *b)
{
    return uuid_compare(a->owner, b->owner) == 0 && strcmp(a->name, b->name) == 0;
}

static bool _newer(const stele_repo_ad_t *a, const stele_repo_ad_t *b)
{
    return a->seq > b->seq || (a->seq == b->seq && a->ts > b->ts);
}

/* Case-insensitive substring. */
static bool _contains(const char *hay, const char *word)
{
    size_t n = strlen(word);
    for (const char *p = hay; *p != '\0'; p++)
    {
        size_t i = 0;
        while (i < n && p[i] != '\0'
               && tolower((unsigned char)p[i]) == tolower((unsigned char)word[i]))
            i++;
        if (i == n)
            return true;
    }
    return n == 0;
}

/* The issuer of the first anchor (by issuer) that lists @p owner, or NULL. */
static const char *_anchor_issuer_locked(stele_relay_store_t *s, const char *owner)
{
    const char *best = NULL;
    for (size_t i = 0; i < s->n_anchors; i++)
        for (size_t j = 0; j < s->anchors[i].n_nodes; j++)
            if (strcmp(s->anchors[i].nodes[j], owner) == 0
                && (best == NULL || strcmp(s->anchors[i].issuer, best) < 0))
                best = s->anchors[i].issuer;
    return best;
}

typedef struct {
    const item_t *ad;
    int match, findings, clean, verifiers;
} hit_t;

static int _hit_cmp(const void *pa, const void *pb)
{
    const hit_t *a = pa, *b = pb;
    if ((a->findings > 0) != (b->findings > 0))
        return (a->findings > 0) - (b->findings > 0);
    if (a->clean != b->clean)
        return b->clean - a->clean;
    if (a->match != b->match)
        return b->match - a->match;
    int c = strcmp(a->ad->ad.name, b->ad->ad.name);
    if (c != 0)
        return c;
    char oa[STELE_UUID_STR], ob[STELE_UUID_STR];
    _owner_of(&a->ad->ad, oa);
    _owner_of(&b->ad->ad, ob);
    return strcmp(oa, ob);
}

static json_t *_search_locked(stele_relay_store_t *s, const json_t *req)
{
    const char *q = json_string_value(json_object_get(req, "q"));
    json_int_t limit = json_integer_value(json_object_get(req, "limit"));
    if (limit <= 0 || limit > STELE_RELAY_RESULTS_MAX)
        limit = STELE_RELAY_RESULTS_MAX;
    char words[16][65];
    size_t n_words = 0;
    if (q != NULL)
    {
        const char *p = q;
        while (*p != '\0' && n_words < 16)
        {
            while (*p == ' ')
                p++;
            size_t n = strcspn(p, " ");
            if (n > 0)
            {
                snprintf(words[n_words++], sizeof(words[0]), "%.*s", (int)(n < 64 ? n : 64), p);
                p += n;
            }
        }
    }
    hit_t *hits = calloc(s->n_items ? s->n_items : 1, sizeof(hit_t));
    size_t n_hits = 0;
    for (size_t i = 0; hits != NULL && i < s->n_items; i++)
    {
        const item_t *it = &s->items[i];
        if (it->kind != K_AD)
            continue;
        bool newest = true;   /* only the newest ad of each repository */
        for (size_t j = 0; j < s->n_items && newest; j++)
            if (j != i && s->items[j].kind == K_AD && _same_repo(&s->items[j].ad, &it->ad)
                && (_newer(&s->items[j].ad, &it->ad)
                    || (!_newer(&it->ad, &s->items[j].ad) && j < i)))
                newest = false;
        if (!newest)
            continue;
        int match = 0;
        for (size_t w = 0; w < n_words; w++)
            match += (_contains(it->ad.name, words[w]) ? 4 : 0)
                + (_contains(it->ad.topics, words[w]) ? 3 : 0)
                + (_contains(it->ad.description, words[w]) ? 2 : 0)
                + (_contains(it->ad.url, words[w]) ? 1 : 0);
        if (n_words > 0 && match == 0)
            continue;
        hit_t h = { .ad = it, .match = match };
        /* The relay's word: what it holds about the shown commit, unverified. */
        char seen[64][STELE_UUID_STR];
        size_t n_seen = 0;
        for (size_t j = 0; j < s->n_items; j++)
        {
            const item_t *at = &s->items[j];
            if (at->kind != K_ATTEST)
                continue;
            const item_t *about = _find_locked(s, K_AD, at->at.repo_ad_id);
            if (about == NULL || !_same_repo(&about->ad, &it->ad)
                || strcmp(about->ad.commit, it->ad.commit) != 0)
                continue;
            if (strcmp(at->at.verdict, STELE_VERDICT_VULN) == 0)
                h.findings++;
            else
                h.clean++;
            char v[STELE_UUID_STR];
            uuid_unparse_lower(at->at.verifier, v);
            bool dup = false;
            for (size_t k = 0; k < n_seen && !dup; k++)
                dup = strcmp(seen[k], v) == 0;
            if (!dup && n_seen < 64)
                memcpy(seen[n_seen++], v, STELE_UUID_STR);
        }
        h.verifiers = (int)n_seen;
        hits[n_hits++] = h;
    }
    if (n_hits > 1)
        qsort(hits, n_hits, sizeof(hit_t), _hit_cmp);
    json_t *results = json_array();
    for (size_t i = 0; i < n_hits && (json_int_t)i < limit; i++)
    {
        const stele_repo_ad_t *ad = &hits[i].ad->ad;
        char owner[STELE_UUID_STR];
        _owner_of(ad, owner);
        const char *anchor = _anchor_issuer_locked(s, owner);
        json_t *repo = json_pack("{s:s, s:s, s:s, s:s, s:s, s:s, s:s, s:s}",
                                 "owner", owner, "name", ad->name, "url", ad->url,
                                 "ref", ad->ref, "commit", ad->commit,
                                 "description", ad->description, "topics", ad->topics,
                                 "polity", stele_repo_ad_is_team(ad) ? ad->polity : "");
        json_t *relay = json_pack("{s:i, s:i, s:i, s:o}", "findings", hits[i].findings,
                                  "clean", hits[i].clean, "verifiers", hits[i].verifiers,
                                  "anchor_issuer",
                                  anchor != NULL ? json_string(anchor) : json_null());
        json_array_append_new(results, json_pack("{s:o, s:o}", "repo", repo, "relay", relay));
    }
    free(hits);
    return json_pack("{s:s, s:s, s:o}", "op", "stl_results", "q", q != NULL ? q : "",
                     "results", results);
}

/* ---------------- fetching ---------------- */

static int _id_cmp(const void *pa, const void *pb)
{
    const item_t *const *a = pa, *const *b = pb;
    return strcmp((*a)->id, (*b)->id);
}

/* Append the items of @p kind that @p want admits, sorted by id, at most
 * STELE_RELAY_FETCH_MAX. */
static void _collect_locked(stele_relay_store_t *s, kind_t kind,
                            bool (*want)(const item_t *, void *), void *arg, json_t *out,
                            json_t *ids)
{
    const item_t **pick = calloc(s->n_items ? s->n_items : 1, sizeof(item_t *));
    size_t n = 0;
    for (size_t i = 0; pick != NULL && i < s->n_items; i++)
        if (s->items[i].kind == kind && want(&s->items[i], arg))
            pick[n++] = &s->items[i];
    if (n > 1)
        qsort(pick, n, sizeof(*pick), _id_cmp);
    for (size_t i = 0; i < n && i < STELE_RELAY_FETCH_MAX; i++)
    {
        json_array_append(out, pick[i]->item);
        if (ids != NULL)
            json_object_set_new(ids, pick[i]->id, json_true());
    }
    free(pick);
}

typedef struct {
    stele_relay_store_t *s;
    const char *url;
    json_t *ad_ids, *at_ids;
} fetch_ctx_t;

static bool _want_ad(const item_t *it, void *arg)
{
    fetch_ctx_t *c = arg;
    for (size_t i = 0; i < c->s->n_items; i++)
        if (c->s->items[i].kind == K_AD && strcmp(c->s->items[i].ad.url, c->url) == 0
            && _same_repo(&c->s->items[i].ad, &it->ad))
            return true;
    return false;
}

static bool _want_attest(const item_t *it, void *arg)
{
    return json_object_get(((fetch_ctx_t *)arg)->ad_ids, it->at.repo_ad_id) != NULL;
}

static bool _want_by_ref(const item_t *it, void *arg)
{
    return json_object_get(((fetch_ctx_t *)arg)->at_ids, it->ref_id) != NULL;
}

static json_t *_fetch_locked(stele_relay_store_t *s, const json_t *req)
{
    const char *url = json_string_value(json_object_get(req, "url"));
    fetch_ctx_t c = { .s = s, .url = url != NULL ? url : "",
                      .ad_ids = json_object(), .at_ids = json_object() };
    json_t *ads = json_array(), *ats = json_array(), *rbs = json_array();
    json_t *recs = json_array(), *teams = json_array(), *anchors = json_array();
    json_t *sboms = json_object();
    _collect_locked(s, K_AD, _want_ad, &c, ads, c.ad_ids);
    _collect_locked(s, K_ATTEST, _want_attest, &c, ats, c.at_ids);
    _collect_locked(s, K_REBUT, _want_by_ref, &c, rbs, NULL);
    _collect_locked(s, K_RECORD, _want_by_ref, &c, recs, NULL);
    /* The SBOMs, rosters and anchors the repository's ads name or list. */
    const char *id;
    json_t *v;
    json_object_foreach(c.ad_ids, id, v)
    {
        const item_t *ad = _find_locked(s, K_AD, id);
        if (ad == NULL)
            continue;
        if (ad->ad.sbom_digest[0] != '\0')
        {
            const item_t *sb = _find_locked(s, K_SBOM, ad->ad.sbom_digest);
            if (sb != NULL)
                json_object_set(sboms, sb->id, sb->item);
        }
        for (size_t i = 0; stele_repo_ad_is_team(&ad->ad) && i < s->n_teams; i++)
            if (strcmp(s->teams[i].issuer, ad->ad.polity) == 0)
            {
                bool dup = false;
                size_t k;
                json_t *t;
                json_array_foreach(teams, k, t)
                    dup = dup || strcmp(json_string_value(t), s->teams[i].text) == 0;
                if (!dup)
                    json_array_append_new(teams, json_string(s->teams[i].text));
            }
        char owner[STELE_UUID_STR];
        _owner_of(&ad->ad, owner);
        for (size_t i = 0; i < s->n_anchors; i++)
            for (size_t j = 0; j < s->anchors[i].n_nodes; j++)
                if (strcmp(s->anchors[i].nodes[j], owner) == 0)
                {
                    bool dup = false;
                    size_t k;
                    json_t *t;
                    json_array_foreach(anchors, k, t)
                        dup = dup || strcmp(json_string_value(t), s->anchors[i].text) == 0;
                    if (!dup)
                        json_array_append_new(anchors, json_string(s->anchors[i].text));
                }
    }
    json_decref(c.ad_ids);
    json_decref(c.at_ids);
    json_t *bundle = json_pack("{s:s, s:s, s:o, s:o, s:o, s:o, s:o, s:o, s:o}",
                               "schema", "stele-bundle-1", "url", c.url, "ads", ads,
                               "attestations", ats, "rebuttals", rbs, "records", recs,
                               "teams", teams, "anchors", anchors, "sboms", sboms);
    return json_pack("{s:s, s:s, s:o}", "op", "stl_bundle", "url", c.url, "bundle", bundle);
}

/* ---------------- the op family ---------------- */

json_t *stele_relay_serve(stele_relay_store_t *s, const char *uuid, const char *op,
                          const json_t *req)
{
    json_t *reply;
    if (s == NULL)
        reply = json_pack("{s:s, s:s}", "op", "stl_refused", "reason", "not_stele_relay");
    else
    {
        pthread_mutex_lock(&s->lock);
        if (op == NULL || (strcmp(op, "stl_publish") != 0 && strcmp(op, "stl_search") != 0
                           && strcmp(op, "stl_fetch") != 0))
            reply = json_pack("{s:s, s:s}", "op", "stl_refused", "reason", "unknown_op");
        else if (!_spend_locked(s, uuid != NULL ? uuid : ""))
            reply = json_pack("{s:s, s:s}", "op", "stl_limited", "reason", "rate");
        else if (strcmp(op, "stl_publish") == 0)
            reply = _publish_locked(s, req);
        else if (strcmp(op, "stl_search") == 0)
            reply = _search_locked(s, req);
        else
            reply = _fetch_locked(s, req);
        pthread_mutex_unlock(&s->lock);
    }
    json_t *rid = json_object_get(req, "rid");
    if (reply != NULL && json_is_string(rid))
        json_object_set(reply, "rid", rid);
    return reply;
}
