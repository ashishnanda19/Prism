// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================
//
// Exercises the HTTP request "Host:" header extractor.

#include <cstddef>
#include <cstdint>

#include "sni_extractor.h"
#include "types.h"

using namespace DPI;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    (void)HTTPHostExtractor::isHTTPRequest(data, size);
    if (auto host = HTTPHostExtractor::extract(data, size)) {
        (void)sniToAppType(*host);
    }
    return 0;
}
