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

# libat_stele: Stele's AutonomousTrust extension (repo ads, attestations, and
# the verifier-attested score they submit). Built inside AT's CMake project,
# named in AT_EXTERNAL_EXTENSIONS (AT doc/architecture/extensions.md, "External
# extensions"). Present means on; the app-facing API is at_stele.h.

at_extension_library(stele
    SOURCES
        stele_codec.c
        id_stele.c
        at_stele_client.c
)

install(FILES at_stele.h DESTINATION include/autonomous_trust)

at_extension_tests(stele
    stele_codec_test
)

# The `stele` conformance protocol: corpus and C adapter (../../conformance).
at_conformance_adapter(
    PROTOCOL stele
    RUN at_stele_run
    SOURCES ../../conformance/c/stele_adapter.c
    LIBS at_stele_static
    CORPUS ../../conformance)
