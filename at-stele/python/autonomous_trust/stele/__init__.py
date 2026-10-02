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
"""Stele's AutonomousTrust extension (repo ads, attestations, and the
verifier-attested score they submit), as a distribution separate from the core.
Laid out as the core is, ``_python`` beside ``_native``, so
``autonomous_trust.stele.handlers`` resolves through the core's backend
redirector. The C twin is its own library (``libat_stele``, at-stele/c/stele).
"""
from autonomous_trust.core import register_backend_prefix

register_backend_prefix('autonomous_trust.stele.')
