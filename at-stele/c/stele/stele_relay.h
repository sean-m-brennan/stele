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

/* Stele Phase 4: a DISCOVERY RELAY, Stele's op family ("stl_") on an
 * AutonomousTrust relay (AT doc/architecture/rendezvous.md, "services riding
 * the relays"). It indexes VERIFIABLE CLAIMS, never authority: repo ads,
 * attestations, attested records, rebuttals, team rosters, group anchors and
 * SBOMs that anyone publishes, filed by content, and handed back to whoever
 * asks. A reader verifies every one of them itself (a record only under a
 * group anchor it follows, Ethne D43); the relay's own ranking travels beside
 * them, labelled as the relay's word. Mirrored by
 * ../../python/autonomous_trust/stele/_python/relay.py.
 *
 * Ops (one JSON frame each way; the request's "rid" is echoed):
 *
 *   {op:"stl_publish", items:[{kind, item}, ...]}      at most STELE_RELAY_BATCH
 *     -> {op:"stl_published", accepted:N, refused:[{index, reason}, ...]}
 *   {op:"stl_search", q, limit?, rid}
 *     -> {op:"stl_results", rid, q, results:[{repo:{...}, relay:{...}}, ...]}
 *   {op:"stl_fetch", url, rid}
 *     -> {op:"stl_bundle", rid, url, bundle:{schema:"stele-bundle-1", ...}}
 *   anything else, or over the rate:
 *     -> {op:"stl_refused" | "stl_limited", rid?, reason}
 *
 * Kinds and how each is filed (a malformed item is refused, never stored):
 *   ad, attestation, rebuttal   an envelope; by its content id (codec)
 *   record                      an AT attested record; by blake2b-256 of
 *                               "evidence_digest|epoch|root"
 *   team, anchor                a signed file (text) whose root signature
 *                               verifies; by issuer, and only a higher seq
 *   sbom                        {digest, text}; by digest = sha256(text)
 *
 * An owner signature on an ad cannot be checked here (the relay holds no
 * keys), nor need it be: the reader checks it. The relay holds all of it in
 * memory, evicting the oldest past its caps, and its publishers file it again
 * each time they register. */

#ifndef AT_STELE_RELAY_H
#define AT_STELE_RELAY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <jansson.h>

#define STELE_RELAY_PREFIX        "stl_"
#define STELE_RELAY_ITEMS_MAX     16384   /* claims held, oldest evicted */
#define STELE_RELAY_FILES_MAX     256     /* team rosters, and anchors, by issuer */
#define STELE_RELAY_BATCH         256     /* items in one publish */
#define STELE_RELAY_RESULTS_MAX   32      /* results in one search */
#define STELE_RELAY_FETCH_MAX     512     /* of each kind in one bundle */
#define STELE_RELAY_SBOM_MAX      (1024 * 1024)
#define STELE_RELAY_RATE_DEFAULT  60.0    /* ops per minute per registrant */
#define STELE_RELAY_BUCKETS_MAX   1024

typedef struct stele_relay_store_s stele_relay_store_t;

/** A store answering at most @p rate ops a minute per registrant (<= 0: the
 *  default). NULL on allocation failure. */
stele_relay_store_t *stele_relay_store_new(double rate);
void stele_relay_store_free(stele_relay_store_t *s);
/** The clock the rate limit reads (unix seconds); NULL restores time(). */
void stele_relay_store_set_clock(stele_relay_store_t *s, int64_t (*now)(void));

/** Answer one "stl_" op from registrant @p uuid: the reply (new reference).
 *  Thread-safe. */
json_t *stele_relay_serve(stele_relay_store_t *s, const char *uuid, const char *op,
                          const json_t *req);

/** How many claims, and signed files, the store holds (tests). */
size_t stele_relay_store_size(stele_relay_store_t *s);

/** $AT_STELE_RELAY is "1": this node's relay serves the stl_ family. */
bool stele_relay_enabled(void);
/** $AT_STELE_RELAY_RATE, else the default. */
double stele_relay_rate(void);

/** Keep the relay glue (a network extension and a relay service, registered by
 *  constructor) in a static link. */
void stele_relay_link(void);

#endif /* AT_STELE_RELAY_H */
