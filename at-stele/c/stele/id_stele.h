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

/* at-stele internals the tests and the conformance adapter read. */

#ifndef AT_ID_STELE_H
#define AT_ID_STELE_H

#include <stddef.h>
#include <uuid/uuid.h>
#include <jansson.h>

#include "stele_codec.h"

/* One attested score this node submitted to its reputation process. */
typedef struct {
    uuid_t subject;
    double score;
    char   digest[STELE_ID_HEX + 1];
} stele_score_sent_t;

/* [{owner, name, commit, id}] / [{verifier, verdict, id}]; caller owns. */
json_t *stele_held_ads_json(void);
json_t *stele_held_attestations_json(void);

/* Copies up to @p cap submitted scores into @p out; returns how many. */
size_t stele_scores_sent(stele_score_sent_t *out, size_t cap);

/* Hold an ad as if it had arrived verified (fixtures only). */
void stele_hold_ad_for_test(const stele_repo_ad_t *ad);

/* [{owner, attestation_id, id}]; caller owns. */
json_t *stele_held_rebuttals_json(void);

/* Forget what is held and reload it from the store, as a restart does. */
void stele_reload_for_test(void);

/* Hold an attestation as if it had arrived verified (fixtures only). */
void stele_hold_attestation_for_test(const stele_attestation_t *at);

#endif /* AT_ID_STELE_H */
