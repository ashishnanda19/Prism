// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================
//
// Fuzz the fuller TLS ClientHello parser plus JA3/JA4 derivation.

#include <cstddef>
#include <cstdint>

#include "signature_set.h"
#include "tls_fingerprint.h"

using namespace DPI;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    TlsClientHello ch;
    if (parseClientHello(data, size, ch)) {
        const std::string j3s = ja3String(ch);
        const std::string j3 = ja3(ch);
        const std::string j4 = ja4(ch, size & 1);
        (void)classifyLabel(ch.sni, j3s, j3, j4);
    }
    return 0;
}
