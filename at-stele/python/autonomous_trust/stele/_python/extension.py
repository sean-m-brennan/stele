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
"""Stele as an identity extension. Twin of id_stele.c's extension tables."""
import functools

from autonomous_trust.core._python.extensions import Extension
from .protocol import SteleProtocol
from . import handlers
from .state import SteleState


def _enabled() -> bool:
    # Present means on: a node that has this package has Stele.
    return True


def _register(proc, proc_name: str) -> None:
    if proc_name != 'identity':
        return
    proc.stele = SteleState()
    for verb, fn in ((SteleProtocol.repo, handlers.handle_repo),
                     (SteleProtocol.attest, handlers.handle_attest),
                     (SteleProtocol.app_advertise_repo,
                      handlers.handle_app_advertise_repo),
                     (SteleProtocol.app_attest, handlers.handle_app_attest)):
        proc.protocol.register_handler(verb, functools.partial(fn, proc))


EXTENSION = Extension(
    name='stele',
    enabled=_enabled,
    register_handlers=_register,
    app_verbs=((SteleProtocol.app_advertise_repo, 'identity'),
               (SteleProtocol.app_attest, 'identity')),
)
