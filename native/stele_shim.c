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

/* libstele_shim: the flat C surface stele_ctl.py and the viewer drive through
 * ctypes. Opens the node's app-event channel, sends at-stele's verbs, and reads
 * the STELE events (at_stele.h) as flat records. The standing a viewer shows
 * is folded from the node's kept files (etc/at/attested, etc/stele); the
 * events say when to look again. */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

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

int stele_advertise_repo2(const char *send_queue, const char *name, const char *url,
                          const char *ref, const char *commit, int64_t seq,
                          const char *description, const char *topics,
                          const char *sbom_digest, const char *sbom_path,
                          const char *claim_verdict)
{
    return at_stele_advertise_repo2(send_queue, name, url, ref, commit, seq,
                                    description, topics, sbom_digest, sbom_path,
                                    claim_verdict);
}

int stele_attest2(const char *send_queue, const char *owner, const char *commit,
                  const char *scanner, const char *scanner_version,
                  const char *db_digest, const char *findings_digest,
                  const char *verdict, int64_t count, const char *max_severity,
                  const char *channel, const char *url)
{
    return at_stele_attest2(send_queue, owner, commit, scanner, scanner_version,
                            db_digest, findings_digest, verdict, count, max_severity,
                            channel, url);
}

int stele_attest3(const char *send_queue, const char *owner, const char *commit,
                  const char *scanner, const char *scanner_version,
                  const char *db_digest, const char *findings_digest,
                  const char *verdict, int64_t count, const char *max_severity,
                  const char *channel, const char *url, const char *replicates)
{
    return at_stele_attest3(send_queue, owner, commit, scanner, scanner_version,
                            db_digest, findings_digest, verdict, count, max_severity,
                            channel, url, replicates);
}

int stele_rebut(const char *send_queue, const char *attestation_id, const char *text)
{
    return at_stele_rebut(send_queue, attestation_id, text);
}

/* The size of one record stele_events_poll writes, for a ctypes caller to
 * check its own struct against before reading any. */
size_t stele_event_size(void)
{
    return sizeof(at_app_stele_t);
}

/* Read up to @p max pending events (non-blocking): the STELE ones go to
 * @p out with their kinds in @p kinds; everything else is skipped. Returns
 * how many were written, or -1 on a bad argument. */
int stele_events_poll(void *handle, int32_t *kinds, at_app_stele_t *out, int max)
{
    if (handle == NULL || kinds == NULL || out == NULL || max <= 0)
        return -1;
    at_app_event_t batch[16];
    int n_out = 0;
    while (n_out < max)
    {
        /* Never take more than there is room for: a polled event is gone. */
        size_t room = (size_t)(max - n_out);
        size_t cap = sizeof(batch) / sizeof(batch[0]);
        int n = at_app_events_poll((at_app_events_t *)handle, batch,
                                   room < cap ? room : cap);
        if (n <= 0)
            break;
        for (int i = 0; i < n && n_out < max; i++)
        {
            const at_app_stele_t *d = at_stele_event(&batch[i]);
            if (d == NULL)
                continue;
            kinds[n_out] = batch[i].kind;
            memcpy(&out[n_out], d, sizeof(*d));
            n_out++;
        }
    }
    return n_out;
}
