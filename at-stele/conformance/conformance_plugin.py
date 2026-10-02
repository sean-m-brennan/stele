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
"""The stele protocol as an AutonomousTrust conformance plug-in.

AT's Python harness loads this file when its directory is named in
$AT_CONFORMANCE_PLUGINS: the corpus is scenarios/stele/, the adapter is
python/stele_adapter.py, and the stele distribution (../python) goes on sys.path
first. The C adapter is c/stele_adapter.c, registered by c/stele's
CMakeLists.txt. Run both through ../test-conformance.sh.
"""

#: Prepended to sys.path, relative to this directory, before adapters().
SYS_PATH = ['python', '../python']


def adapters():
    from stele_adapter import SteleAdapter
    return {'stele': SteleAdapter}
