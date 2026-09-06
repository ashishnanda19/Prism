# =============================================================================
# Project: Prism - Deep Packet Inspection Engine
# Author:  Ashish Kumar Nanda
# =============================================================================
#
# libFuzzer harnesses for the wire-format parsers. Enabled with
#   cmake -B build-fuzz -DPRISM_BUILD_FUZZERS=ON \
#         -DPRISM_SANITIZE=address,undefined -DCMAKE_CXX_COMPILER=clang++
#
# When the toolchain ships a libFuzzer runtime (Linux + Clang) the harnesses
# are coverage-guided. Otherwise (e.g. Apple clang) they link a standalone
# replay driver -- they still build and run over the seed corpus under ASan.
#
# PRISM_HAVE_LIBFUZZER is detected in the top-level CMakeLists.

set(PRISM_FUZZERS packet_parser sni_extractor quic_sni http_host dns pcap_reader tls_fingerprint)

foreach(name IN LISTS PRISM_FUZZERS)
    set(tgt fuzz_${name})
    add_executable(${tgt} fuzz_${name}.cc)
    if(NOT PRISM_HAVE_LIBFUZZER)
        target_sources(${tgt} PRIVATE standalone_main.cc)
    endif()
    target_link_libraries(${tgt} PRIVATE prism_core prism_warnings prism_sanitize)
    if(PRISM_HAVE_LIBFUZZER)
        target_link_options(${tgt} PRIVATE -fsanitize=fuzzer)
    endif()
    set_target_properties(${tgt} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
endforeach()

add_custom_target(fuzzers)
foreach(name IN LISTS PRISM_FUZZERS)
    add_dependencies(fuzzers fuzz_${name})
endforeach()
