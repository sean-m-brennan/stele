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

/* The app side of at_stele.h's verbs: pack the JSON body and send it to the
 * node's identity process over the app queue, as at-social's at_agora.c does. */

#include <stdio.h>
#include <string.h>

#include "utilities/message.h"
#include "network/net_message.h"
#include "utilities/msg_types_priv.h"

#include "at_stele.h"

static int _send_verb(const char *q_out, const char *verb, json_t *env)
{
    if (q_out == NULL || env == NULL)
    {
        json_decref(env);
        return -1;
    }
    generic_msg_t req = {0};
    req.type = NET_MESSAGE;
    snprintf(req.info.net_msg.process, sizeof(req.info.net_msg.process), "identity");
    req.info.net_msg.function = (char *)verb;
    req.info.net_msg.encrypt = false;
    if (net_msg_pack_json(&req.info.net_msg, env) != 0)
    {
        json_decref(env);
        return -1;
    }
    json_decref(env);
    int rc = messaging_send(q_out, NET_MESSAGE, &req, false) == 0 ? 0 : -1;
    net_msg_free_obj(&req.info.net_msg);
    return rc;
}

int at_stele_advertise_repo(const char *q_out, const char *name, const char *url,
                            const char *ref, const char *commit, int64_t seq)
{
    if (name == NULL || url == NULL || ref == NULL || commit == NULL)
        return -1;
    return _send_verb(q_out, AT_APP_STELE_ADVERTISE_REPO,
                      json_pack("{s:s, s:s, s:s, s:s, s:I}", "name", name, "url", url,
                                "ref", ref, "commit", commit, "seq", (json_int_t)seq));
}

int at_stele_attest(const char *q_out, const char *owner, const char *commit,
                    const char *scanner, const char *scanner_version,
                    const char *db_digest, const char *findings_digest,
                    const char *verdict, int64_t count, const char *max_severity)
{
    if (owner == NULL || commit == NULL || scanner == NULL || scanner_version == NULL
        || db_digest == NULL || findings_digest == NULL || verdict == NULL)
        return -1;
    return _send_verb(q_out, AT_APP_STELE_ATTEST,
                      json_pack("{s:s, s:s, s:s, s:s, s:s, s:s, s:s, s:I, s:s}",
                                "owner", owner, "commit", commit, "scanner", scanner,
                                "scanner_version", scanner_version,
                                "db_digest", db_digest,
                                "findings_digest", findings_digest,
                                "verdict", verdict, "count", (json_int_t)count,
                                "max_severity", max_severity ? max_severity : ""));
}
