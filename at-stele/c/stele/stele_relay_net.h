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

/* The discovery relay's network glue (stele_relay_net.c), as far as a test
 * reaches it. */

#ifndef AT_STELE_RELAY_NET_H
#define AT_STELE_RELAY_NET_H

#include "rendezvous/net_relay.h"
#include "stele_relay.h"

/** Serve the "stl_" family on @p srv from @p s (which the glue then owns; NULL
 *  answers not_stele_relay). What $AT_STELE_RELAY does at server start. */
void stele_relay_serve_store(net_relay_server_t *srv, stele_relay_store_t *s);

#endif /* AT_STELE_RELAY_NET_H */
