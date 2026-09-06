// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================

#ifndef PRISM_PACKET_SOURCE_H
#define PRISM_PACKET_SOURCE_H

#include <cstdint>
#include <memory>
#include <string>

#include "pcap_types.h"  // RawPacket, PcapGlobalHeader

namespace PacketAnalyzer {

// PCAP link types (a.k.a. DLT_*) that Prism understands.
inline constexpr std::uint32_t LINKTYPE_NULL     = 0;    // BSD loopback: 4-byte AF header
inline constexpr std::uint32_t LINKTYPE_ETHERNET = 1;    // the only one the parser handles
inline constexpr std::uint32_t LINKTYPE_RAW      = 101;  // raw IPv4/IPv6, no L2 header

// ============================================================================
// PacketSource - a stream of link-layer frames
// ============================================================================
//
// One interface over "read frames from a .pcap file" and "read frames from a
// live network interface". Engines loop on next() until it returns End (file
// exhausted) or the process is asked to stop.
// ============================================================================
class PacketSource {
public:
    enum class Status {
        Packet  = 1,   // `out` holds a frame
        Timeout = 0,   // nothing right now (live source) -- poll again
        End     = -1,  // no more frames ever (file EOF)
        Failed  = -2,  // unrecoverable error; see errorMessage()
    };

    virtual ~PacketSource() = default;

    virtual Status next(RawPacket& out) = 0;

    virtual std::uint32_t linkType() const = 0;   // LINKTYPE_*
    virtual bool isLive() const = 0;

    // Frames the kernel dropped before Prism could read them (live only).
    virtual std::uint64_t kernelDrops() const { return 0; }

    virtual std::string errorMessage() const { return {}; }
    virtual void close() {}
};

// Synthesize a PCAP global header for writing capture output.
PcapGlobalHeader makePcapHeader(std::uint32_t link_type, std::uint32_t snaplen);

// Open a live capture on a network interface (AF_PACKET on Linux, BPF on
// macOS/BSD). Returns nullptr and fills `err` on failure -- unknown interface,
// insufficient privileges (root / CAP_NET_RAW), or an unsupported platform.
std::unique_ptr<PacketSource> openLiveInterface(const std::string& iface,
                                                int snaplen,
                                                bool promiscuous,
                                                int poll_timeout_ms,
                                                std::string& err);

}  // namespace PacketAnalyzer

#endif  // PRISM_PACKET_SOURCE_H
