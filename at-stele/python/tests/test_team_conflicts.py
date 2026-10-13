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
"""AT's conflict set as Stele writes it: every node a team ever listed (AT
ISSUES §2.54). Twin of id_stele.c _write_conflicts."""
import json
import logging
import threading
from types import SimpleNamespace

from autonomous_trust.core._python.config import Configuration
from autonomous_trust.stele._python import handlers

A, B, C = ('00000000-0000-4000-8000-00000000000%d' % i for i in (1, 2, 3))


def _team(seq, nodes):
    return {'issuer': 'ab' * 32, 'seq': seq, 'members': [{'at_uuid': u} for u in nodes]}


def test_a_shorter_roster_never_shrinks_the_conflict_set(tmp_path, monkeypatch):
    cfg = tmp_path / 'etc' / 'at'
    cfg.mkdir(parents=True)
    monkeypatch.setattr(Configuration, 'get_cfg_dir', staticmethod(lambda: str(cfg)))
    proc = SimpleNamespace(lock=threading.Lock(), logger=logging.getLogger('t'),
                           stele=SimpleNamespace(teams={'ab' * 32: _team(1, [A, B, C])}))
    handlers._write_conflicts(proc)
    proc.stele.teams['ab' * 32] = _team(2, [A, B])        # C dropped
    handlers._write_conflicts(proc)
    teams = json.loads((cfg / 'attest_conflicts.cfg.json').read_text())['teams']
    assert [sorted(t) for t in teams] == [[A, B, C]]
    hist = json.loads((tmp_path / 'etc' / 'stele' / 'conflicts.json').read_text())
    assert sorted(hist['ab' * 32]) == [A, B, C]
