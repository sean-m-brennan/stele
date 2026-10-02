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
# Native layer for Agora (Linux + macOS):
#   - builds the AutonomousTrust C core (libautonomous_trust, SHARED)
#   - libagora_shim : the flat FFI surface Dart binds
#   - agorad        : the standalone AT daemon the GUI spawns
#
# DTN (AT_NET_DTN) and ZTA (AT_ZTA) are left OFF (their defaults) — do not
# enable them here; the heavy third_party DTN stack is not needed for Agora.
# The five verification layers (AT_ORACLE_*) stay ON, their default, and are
# linked below as libat_<layer>.
# Social (libat_social) is Agora's own extension, ../at-social/c/social, built
# inside AT's project through AT_EXTERNAL_EXTENSIONS below.

# The AT C core is project(... C CXX); enable both here so the CXX toolchain is
# configured before the AT subdirectory is added.
cmake_minimum_required(VERSION 3.23)
project(stele_native C CXX)

# Stele's native layer: the AT C core with at-stele linked in (steled, the
# daemon) and libstele_shim (the flat surface stele_ctl.py drives). Modelled on
# apps/agora/native/CMakeLists.txt, which explains each step.

set(AT_C_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../lib/autonomous_trust/src/c"
    CACHE PATH "AutonomousTrust C core source directory")
if(NOT EXISTS "${AT_C_DIR}/CMakeLists.txt")
    message(FATAL_ERROR
        "AutonomousTrust C core not found at ${AT_C_DIR}. "
        "Run: git submodule update --init --recursive")
endif()
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)

set(STELE_EXT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../at-stele/c/stele")
set(AT_EXTERNAL_EXTENSIONS "${STELE_EXT_DIR}" CACHE STRING
    "Stele's AT extension (libat_stele)" FORCE)
add_subdirectory("${AT_C_DIR}" at_core)
set_property(TARGET autonomous_trust PROPERTY INTERFACE_SOURCES "")
if(NOT TARGET at_stele)
    message(FATAL_ERROR "Stele needs libat_stele; this AT tree does not support "
                        "external extensions")
endif()

set(AT_INCLUDE_DIRS
    "${AT_C_DIR}"
    "${AT_C_DIR}/autonomous_trust"
    "${AT_C_DIR}/extensions"
    "${STELE_EXT_DIR}/.."
    "${CMAKE_CURRENT_BINARY_DIR}/at_core"
    "${CMAKE_CURRENT_BINARY_DIR}/at_core/autonomous_trust"
    "${CMAKE_CURRENT_BINARY_DIR}/at_core/protobuf"
    "${CMAKE_CURRENT_BINARY_DIR}/at_core/protobuf/autonomous_trust/core/protobuf")

find_library(AT_SODIUM_LIB    sodium     REQUIRED)
find_library(AT_JANSSON_LIB   jansson    REQUIRED)
find_library(AT_UUID_LIB      uuid       REQUIRED)
find_library(AT_PROTOBUFC_LIB protobuf-c REQUIRED)
find_library(AT_PROTOBUF_LIB  protobuf   REQUIRED)

set(AT_EXT_LIBS)
set(AT_EXT_RPATH)
foreach(_layer physics calibration certificates prequential replication stele)
    if(TARGET at_${_layer})
        list(APPEND AT_EXT_LIBS at_${_layer})
        list(APPEND AT_EXT_RPATH "${CMAKE_CURRENT_BINARY_DIR}/at_core/extensions/${_layer}")
    endif()
endforeach()
if(AT_EXT_LIBS AND NOT APPLE)
    # --as-needed would drop a library referenced only through its constructors.
    set(AT_EXT_LIBS -Wl,--no-as-needed ${AT_EXT_LIBS})
endif()
set(AT_LINK_LIBS
    ${AT_EXT_LIBS}
    autonomous_trust
    ${AT_SODIUM_LIB} ${AT_JANSSON_LIB} ${AT_UUID_LIB}
    ${AT_PROTOBUFC_LIB} ${AT_PROTOBUF_LIB}
    pthread m stdc++)

add_compile_options(-fms-extensions)

add_library(stele_shim SHARED stele_shim.c)
target_include_directories(stele_shim PRIVATE ${AT_INCLUDE_DIRS})
target_link_libraries(stele_shim PRIVATE ${AT_LINK_LIBS})

add_executable(steled steled.c)
target_include_directories(steled PRIVATE ${AT_INCLUDE_DIRS})
target_link_libraries(steled PRIVATE ${AT_LINK_LIBS})

set_target_properties(stele_shim steled PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    BUILD_WITH_INSTALL_RPATH TRUE
    INSTALL_RPATH "$ORIGIN;${CMAKE_CURRENT_BINARY_DIR}/at_core;${AT_EXT_RPATH}")
