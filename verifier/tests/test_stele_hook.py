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
"""stele_hook: the webhook gate, and a REAL scan of the seeded repository.

The scan test needs osv-scanner and an offline database: set STELE_OSV_SCANNER
and STELE_OSV_DB (a cache dir holding osv-scalibr/Go/all.zip); it skips
otherwise."""
import hashlib
import hmac
import os
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'tools'))
import stele_hook  # noqa: E402
import stele_ctl  # noqa: E402

SEED = os.path.join(os.path.dirname(__file__), '..', '..', 'forge', 'seed')


def test_the_webhook_signature_gate():
    body = b'{"after": "x"}'
    good = hmac.new(b's3cret', body, hashlib.sha256).hexdigest()
    assert stele_hook.signature_ok('s3cret', body, good)
    assert not stele_hook.signature_ok('s3cret', body + b' ', good)
    assert not stele_hook.signature_ok('', body, good)


def test_a_push_names_a_commit_and_a_deletion_does_not():
    c = '0123456789abcdef0123456789abcdef01234567'
    assert stele_hook.push_target(
        {'after': c, 'repository': {'clone_url': 'http://f/a/demo.git'}}) == \
        ('http://f/a/demo.git', c)
    assert stele_hook.push_target(
        {'after': '0' * 40, 'repository': {'clone_url': 'http://f/a/demo.git'}}) is None


@pytest.mark.skipif(not (os.environ.get('STELE_OSV_SCANNER')
                         and os.environ.get('STELE_OSV_DB')),
                    reason='needs STELE_OSV_SCANNER and STELE_OSV_DB')
def test_the_seeded_repository_scans_vulnerable(tmp_path):
    repo = tmp_path / 'demo'
    shutil.copytree(SEED, repo)
    git = ['git', '-C', str(repo), '-c', 'user.name=t', '-c', 'user.email=t@t']
    subprocess.run(['git', 'init', '--quiet', str(repo)], check=True)
    subprocess.run(git + ['add', '.'], check=True)
    subprocess.run(git + ['commit', '--quiet', '-m', 'seed'], check=True)
    commit = subprocess.run(git + ['rev-parse', 'HEAD'], check=True,
                            capture_output=True, text=True).stdout.strip()
    report = stele_hook.scan_commit(f'file://{repo}', commit,
                                    os.environ['STELE_OSV_SCANNER'],
                                    os.environ['STELE_OSV_DB'])
    verdict, count, sev, digest = stele_ctl.summarize_osv(report)
    assert verdict == 'vuln' and count > 0 and len(digest) == 64
    assert len(stele_hook.db_digest(os.environ['STELE_OSV_DB'])) == 64
