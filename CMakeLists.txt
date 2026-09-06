# =============================================================================
# Project: Prism - Deep Packet Inspection Engine
# Author:  Ashish Kumar Nanda
# =============================================================================

cmake_minimum_required(VERSION 3.16)
project(Prism VERSION 1.0.0 LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Global settings
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "" FORCE)
endif()

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(PRISM_BUILD_TESTS   "Build the Prism unit test suite"            ON)
option(PRISM_WERROR        "Treat compiler warnings as errors"          OFF)
set(PRISM_SANITIZE "" CACHE STRING
    "Comma-separated sanitizer list, e.g. address,undefined or thread")

# ---------------------------------------------------------------------------
# Warning / sanitizer interface targets (link to opt in)
# ---------------------------------------------------------------------------
add_library(prism_warnings INTERFACE)
target_compile_options(prism_warnings INTERFACE
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall -Wextra -Wpedantic -Wshadow>
    $<$<AND:$<BOOL:${PRISM_WERROR}>,$<CXX_COMPILER_ID:GNU,Clang,AppleClang>>:-Werror>
)

add_library(prism_sanitize INTERFACE)
if(PRISM_SANITIZE)
    message(STATUS "Prism: sanitizers enabled -> ${PRISM_SANITIZE}")
    target_compile_options(prism_sanitize INTERFACE
        -fsanitize=${PRISM_SANITIZE} -fno-omit-frame-pointer -g)
    target_link_options(prism_sanitize INTERFACE -fsanitize=${PRISM_SANITIZE})
endif()

find_package(Threads REQUIRED)

# ---------------------------------------------------------------------------
# prism_core  --  shared parsing / classification library
#   Everything that is not an engine main() lives here so it can be reused
#   by every engine flavour and exercised directly by the test suite.
# ---------------------------------------------------------------------------
add_library(prism_core STATIC
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/types.cpp
    # Flow + policy units (currently used by the "classic" engine; kept in the
    # core library so the test suite and future engines can link them).
    src/connection_tracker.cpp
    src/rule_manager.cpp
)
target_include_directories(prism_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(prism_core
    PUBLIC  Threads::Threads
    PRIVATE prism_warnings prism_sanitize)

# Convenience: fold the common link set into one name.
add_library(prism::core ALIAS prism_core)

function(prism_add_engine name)
    add_executable(${name} ${ARGN})
    target_link_libraries(${name} PRIVATE prism_core prism_warnings prism_sanitize)
    set_target_properties(${name} PROPERTIES RUNTIME_OUTPUT_DIRECTORY
        ${CMAKE_BINARY_DIR}/bin)
endfunction()

# ---------------------------------------------------------------------------
# Engine 1:  prism        -- multi-threaded pipeline (self-contained)
#   Reader -> Load Balancers -> Fast-Path workers -> Output writer.
# ---------------------------------------------------------------------------
prism_add_engine(prism src/dpi_mt.cpp)

# ---------------------------------------------------------------------------
# Engine 2:  prism-lite   -- single-threaded reference engine
#   Same classification + blocking, no threads. Easiest to read / debug.
# ---------------------------------------------------------------------------
prism_add_engine(prism-lite src/main_working.cpp)

# ---------------------------------------------------------------------------
# Engine 3:  prism-classic -- component-structured multi-threaded engine
#   DPIEngine + FPManager + LBManager + GlobalConnectionTable, wired by
#   dependency injection. The architecture the roadmap builds on.
# ---------------------------------------------------------------------------
prism_add_engine(prism-classic
    src/main_dpi.cpp
    src/dpi_engine.cpp
    src/fast_path.cpp
    src/load_balancer.cpp
)

# ---------------------------------------------------------------------------
# Tool:  prism-dump  -- per-packet protocol decoder (no DPI, no blocking)
# ---------------------------------------------------------------------------
prism_add_engine(prism-dump src/main.cpp)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(PRISM_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
message(STATUS "Prism ${PROJECT_VERSION}")
message(STATUS "  build type : ${CMAKE_BUILD_TYPE}")
message(STATUS "  tests      : ${PRISM_BUILD_TESTS}")
message(STATUS "  sanitizers : ${PRISM_SANITIZE}")
message(STATUS "  engines    : prism (mt), prism-lite (st), prism-classic (mt/components)")
