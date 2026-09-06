// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================
//
// QUICSNIExtractor scans for an embedded TLS ClientHello and calls
// SNIExtractor::extract() at a computed offset -- a spot that has already
// had an out-of-bounds pointer bug, so it gets its own harness.

#include <cstddef>
#include <cstdint>

#include "sni_extractor.h"

using namespace DPI;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    (void)QUICSNIExtractor::isQUICInitial(data, size);
    (void)QUICSNIExtractor::extract(data, size);
    return 0;
}
