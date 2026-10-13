# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ******************
"""Stele's verbs on the identity process. Twins of the strings in
at-stele/c/stele (id_stele.c, at_stele.h)."""
from autonomous_trust.core._python.protocol import Protocol


class SteleProtocol(Protocol):
    #: A repo ad, group multicast, first person only (never relayed).
    repo = 'stele repo'
    #: A signed attestation document, group multicast, first person only.
    attest = 'stele attest'
    #: The repo owner's signed reply to an attestation, group multicast.
    rebut = 'stele rebut'
    #: A team's roster, group multicast by a listed member (never relayed).
    team = 'stele team'
    #: App verbs (local only).
    app_advertise_repo = 'app_stele_advertise_repo'
    app_attest = 'app_stele_attest'
    app_rebut = 'app_stele_rebut'
    app_publish_team = 'app_stele_publish_team'
