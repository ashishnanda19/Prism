// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================
//
// Feeds arbitrary bytes to PacketParser::parse() as a single link-layer frame.

#include <cstdint>
#include <cstddef>

#include "packet_parser.h"

using namespace PacketAnalyzer;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    RawPacket raw;
    raw.header.ts_sec = 0;
    raw.header.ts_usec = 0;
    raw.header.incl_len = static_cast<uint32_t>(size);
    raw.header.orig_len = raw.header.incl_len;
    raw.data.assign(data, data + size);

    ParsedPacket parsed;
    if (PacketParser::parse(raw, parsed) && parsed.payload_data && parsed.payload_length) {
        // Touch the payload window the parser handed back so ASan validates it.
        volatile uint8_t sink = 0;
        for (size_t i = 0; i < parsed.payload_length; ++i) sink ^= parsed.payload_data[i];
        (void)sink;
    }
    return 0;
}
