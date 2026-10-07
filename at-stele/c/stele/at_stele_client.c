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

static const char *_or_empty(const char *s)
{
    return s != NULL ? s : "";
}

int at_stele_advertise_repo2(const char *q_out, const char *name, const char *url,
                             const char *ref, const char *commit, int64_t seq,
                             const char *description, const char *topics,
                             const char *sbom_digest, const char *sbom_path,
                             const char *claim_verdict)
{
    if (name == NULL || url == NULL || ref == NULL || commit == NULL)
        return -1;
    return _send_verb(q_out, AT_APP_STELE_ADVERTISE_REPO,
                      json_pack("{s:s, s:s, s:s, s:s, s:I, s:s, s:s, s:s, s:s, s:s}",
                                "name", name, "url", url, "ref", ref, "commit", commit,
                                "seq", (json_int_t)seq,
                                "description", _or_empty(description),
                                "topics", _or_empty(topics),
                                "sbom_digest", _or_empty(sbom_digest),
                                "sbom_path", _or_empty(sbom_path),
                                "claim_verdict",
                                claim_verdict != NULL ? claim_verdict : "none"));
}

int at_stele_attest2(const char *q_out, const char *owner, const char *commit,
                     const char *scanner, const char *scanner_version,
                     const char *db_digest, const char *findings_digest,
                     const char *verdict, int64_t count, const char *max_severity,
                     const char *channel, const char *url)
{
    return at_stele_attest3(q_out, owner, commit, scanner, scanner_version,
                            db_digest, findings_digest, verdict, count,
                            max_severity, channel, url, NULL);
}

int at_stele_attest3(const char *q_out, const char *owner, const char *commit,
                     const char *scanner, const char *scanner_version,
                     const char *db_digest, const char *findings_digest,
                     const char *verdict, int64_t count, const char *max_severity,
                     const char *channel, const char *url, const char *replicates)
{
    if (owner == NULL || commit == NULL || scanner == NULL || scanner_version == NULL
        || db_digest == NULL || findings_digest == NULL || verdict == NULL)
        return -1;
    json_t *env = json_pack("{s:s, s:s, s:s, s:s, s:s, s:s, s:s, s:I, s:s, s:s}",
                            "owner", owner, "commit", commit, "scanner", scanner,
                            "scanner_version", scanner_version,
                            "db_digest", db_digest,
                            "findings_digest", findings_digest,
                            "verdict", verdict, "count", (json_int_t)count,
                            "max_severity", _or_empty(max_severity),
                            "channel", channel != NULL ? channel : "probe");
    if (env != NULL && url != NULL)
        json_object_set_new(env, "url", json_string(url));
    if (env != NULL && replicates != NULL && replicates[0] != '\0')
        json_object_set_new(env, "replicates", json_string(replicates));
    return _send_verb(q_out, AT_APP_STELE_ATTEST, env);
}

int at_stele_rebut(const char *q_out, const char *attestation_id, const char *text)
{
    if (attestation_id == NULL || text == NULL)
        return -1;
    return _send_verb(q_out, AT_APP_STELE_REBUT,
                      json_pack("{s:s, s:s}", "attestation_id", attestation_id,
                                "text", text));
}
