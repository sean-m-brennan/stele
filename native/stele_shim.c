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

/* libstele_shim: the flat C surface stele_ctl.py drives through ctypes. Opens
 * the node's app-event channel and sends at-stele's two verbs; nothing else.
 * The effect of an attestation is read from the core's own persisted state
 * (the reputation evidence document), not from this channel. */

#include <stdint.h>
#include <stdlib.h>

#include "app_events.h"
#include "stele/at_stele.h"

void stele_set_root(const char *root)
{
    if (root != NULL && root[0] != '\0')
        setenv("AUTONOMOUS_TRUST_ROOT", root, 1);
}

void *stele_open(const char *recv_queue)
{
    at_stele_link();
    return (void *)at_app_events_open(recv_queue);
}

void stele_close(void *handle)
{
    at_app_events_close((at_app_events_t *)handle);
}

int stele_advertise_repo(const char *send_queue, const char *name, const char *url,
                         const char *ref, const char *commit, int64_t seq)
{
    return at_stele_advertise_repo(send_queue, name, url, ref, commit, seq);
}

int stele_attest(const char *send_queue, const char *owner, const char *commit,
                 const char *scanner, const char *scanner_version,
                 const char *db_digest, const char *findings_digest,
                 const char *verdict, int64_t count, const char *max_severity)
{
    return at_stele_attest(send_queue, owner, commit, scanner, scanner_version,
                           db_digest, findings_digest, verdict, count, max_severity);
}
