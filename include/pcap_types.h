// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================

#ifndef PRISM_PCAP_TYPES_H
#define PRISM_PCAP_TYPES_H

#include <cstdint>
#include <vector>

namespace PacketAnalyzer {

// PCAP global header (24 bytes) -- one at the start of every .pcap file.
struct PcapGlobalHeader {
    uint32_t magic_number;   // 0xa1b2c3d4 (or byte-swapped)
    uint16_t version_major;  // 2
    uint16_t version_minor;  // 4
    int32_t  thiszone;       // GMT offset (usually 0)
    uint32_t sigfigs;        // timestamp accuracy (usually 0)
    uint32_t snaplen;        // max captured bytes per packet
    uint32_t network;        // link type (1 = Ethernet)
};

// PCAP per-record header (16 bytes).
struct PcapPacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;   // bytes present in the file/buffer
    uint32_t orig_len;   // length on the wire
};

// One captured frame.
struct RawPacket {
    PcapPacketHeader header;
    std::vector<uint8_t> data;
};

}  // namespace PacketAnalyzer

#endif  // PRISM_PCAP_TYPES_H
