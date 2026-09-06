// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================
//
// Exercises the TLS ClientHello -> SNI parser on arbitrary bytes.

#include <cstddef>
#include <cstdint>
#include <string>

#include "sni_extractor.h"
#include "types.h"

using namespace DPI;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    (void)SNIExtractor::isTLSClientHello(data, size);
    if (auto sni = SNIExtractor::extract(data, size)) {
        (void)sniToAppType(*sni);
    }
    return 0;
}
