#!/usr/bin/env bash
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
#
# Bring up the Stele forge on the HOST and seed it: an admin user, the demo
# repository with the CI workflow, a push webhook to the verifier's
# stele_hook.py, and a registered runner. Idempotent enough to re-run.
#
#   ./forge/up.sh [HOOK_URL]        # default http://host.docker.internal:8098/
#
# Writes forge/.forge.env (FORGE_URL, FORGE_USER, FORGE_PASS, HOOK_SECRET,
# REPO_URL) for stele_cohort.sh and stele_hook.py's config.
set -euo pipefail
cd "$(dirname "$0")"
HOOK_URL="${1:-http://host.docker.internal:8098/}"
FORGE_URL=http://localhost:3000
FORGE_USER=stele
FORGE_PASS="${FORGE_PASS:-stele-phase0-pass}"
HOOK_SECRET="${HOOK_SECRET:-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')}"

docker compose up -d forgejo
echo "==> waiting for Forgejo"
for _ in $(seq 60); do curl -fs "$FORGE_URL/api/v1/version" >/dev/null && break; sleep 2; done
curl -fs "$FORGE_URL/api/v1/version"; echo

docker exec -u git stele-forgejo forgejo admin user create --admin \
  --username "$FORGE_USER" --password "$FORGE_PASS" --email stele@forge.local \
  --must-change-password=false 2>/dev/null || echo "(admin user exists)"
API=(curl -fs -u "$FORGE_USER:$FORGE_PASS" -H 'Content-Type: application/json')
"${API[@]}" -X POST "$FORGE_URL/api/v1/user/repos" \
  -d '{"name":"demo","private":false,"default_branch":"main"}' >/dev/null \
  || echo "(repo exists)"
"${API[@]}" -X POST "$FORGE_URL/api/v1/repos/$FORGE_USER/demo/hooks" -d "{
  \"type\":\"forgejo\",\"active\":true,\"events\":[\"push\"],
  \"config\":{\"url\":\"$HOOK_URL\",\"content_type\":\"json\",\"secret\":\"$HOOK_SECRET\"}}" \
  >/dev/null
echo "==> webhook -> $HOOK_URL"

TOKEN="$(docker exec -u git stele-forgejo forgejo actions generate-runner-token | tail -1)"
docker compose up -d runner
docker exec stele-runner sh -c "[ -f /data/.runner ] || forgejo-runner register \
  --no-interactive --instance http://forgejo:3000 --token $TOKEN \
  --name stele-runner --labels stele:host"
echo "==> runner registered (label stele:host)"

cat > .forge.env <<ENV
FORGE_URL=$FORGE_URL
FORGE_USER=$FORGE_USER
FORGE_PASS=$FORGE_PASS
HOOK_SECRET=$HOOK_SECRET
REPO_URL=$FORGE_URL/$FORGE_USER/demo.git
ENV
echo "==> wrote forge/.forge.env; push with test/cohort/stele_cohort.sh (FORGE=1)"
