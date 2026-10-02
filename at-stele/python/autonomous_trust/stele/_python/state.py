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
"""Stele's per-process state: the ads and attestations this node holds, and the
attested scores it submitted (the observable a scenario asserts). Twin of the
`st` struct in id_stele.c, with the same caps."""

ADS_CAP = 64
ATTEST_CAP = 64
SCORES_CAP = 64


class SteleState:
    def __init__(self):
        self.ads: dict = {}            # ad id -> ad (dict)
        self.attestations: dict = {}   # attestation id -> attestation (dict)
        self.scores_sent: list = []    # [{subject, score, digest}]
        self.ad_seq = 0

    def hold(self, table: dict, key: str, item: dict, cap: int) -> bool:
        if key in table:
            return False
        if len(table) >= cap:
            table.pop(next(iter(table)))
        table[key] = item
        return True
