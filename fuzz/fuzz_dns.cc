// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================
//
// Exercises the DNS query-name extractor (label-length walk over the QNAME).

#include <cstddef>
#include <cstdint>

#include "sni_extractor.h"

using namespace DPI;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    (void)DNSExtractor::isDNSQuery(data, size);
    (void)DNSExtractor::extractQuery(data, size);
    return 0;
}
