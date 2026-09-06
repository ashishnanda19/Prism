// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================

#include "packet_source.h"

namespace PacketAnalyzer {

PcapGlobalHeader makePcapHeader(std::uint32_t link_type, std::uint32_t snaplen) {
    PcapGlobalHeader h{};
    h.magic_number = 0xa1b2c3d4;  // host byte order; readers detect the swap
    h.version_major = 2;
    h.version_minor = 4;
    h.thiszone = 0;
    h.sigfigs = 0;
    h.snaplen = snaplen ? snaplen : 262144;
    h.network = link_type;
    return h;
}

}  // namespace PacketAnalyzer
