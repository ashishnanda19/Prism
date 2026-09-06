# =============================================================================
# Project: Prism - Deep Packet Inspection Engine
# Author:  Ashish Kumar Nanda
# =============================================================================
#
# Unit test suite. Exercises prism_core (parsers + classification + policy)
# directly, without going through an engine main().
#
#   ctest --test-dir build --output-on-failure
#
# Framework: vendored doctest (third_party/doctest). Swap for GoogleTest via
# FetchContent when CI lands (roadmap step 2) if richer fixtures are needed.

add_library(doctest INTERFACE)
target_include_directories(doctest INTERFACE ${CMAKE_SOURCE_DIR}/third_party)

add_executable(prism_tests
    test_main.cpp
    test_app_classification.cpp
    test_packet_parser.cpp
    test_sni_extractor.cpp
    test_pcap_reader.cpp
)
target_link_libraries(prism_tests PRIVATE prism_core doctest prism_sanitize)
target_compile_definitions(prism_tests PRIVATE
    PRISM_TEST_DATA_DIR="${CMAKE_SOURCE_DIR}")
set_target_properties(prism_tests PROPERTIES RUNTIME_OUTPUT_DIRECTORY
    ${CMAKE_BINARY_DIR}/bin)

add_test(NAME prism_tests COMMAND prism_tests)
