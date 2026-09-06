// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================

#ifndef PCAP_READER_H
#define PCAP_READER_H

#include <cstdint>
#include <fstream>
#include <string>

#include "packet_source.h"
#include "pcap_types.h"

namespace PacketAnalyzer {

// Reads frames from a PCAP file. Also serves as the file-backed PacketSource.
class PcapReader : public PacketSource {
public:
    PcapReader() = default;
    ~PcapReader() override;

    // Open a pcap file for reading. Returns false if it cannot be parsed.
    bool open(const std::string& filename);

    void close() override;

    // Legacy convenience: read the next packet, false at EOF / error.
    bool readNextPacket(RawPacket& packet);

    const PcapGlobalHeader& getGlobalHeader() const { return global_header_; }
    bool isOpen() const { return file_.is_open(); }
    bool needsByteSwap() const { return needs_byte_swap_; }

    // Re-open from the top at EOF instead of ending (for demos / load tests).
    void setLoop(bool on) { loop_ = on; }

    // ---- PacketSource ----
    Status next(RawPacket& out) override {
        if (readNextPacket(out)) return Status::Packet;
        if (loop_ && !path_.empty()) {
            const std::string p = path_;
            close();
            if (open(p) && readNextPacket(out)) return Status::Packet;
        }
        return Status::End;
    }
    std::uint32_t linkType() const override { return global_header_.network; }
    bool isLive() const override { return false; }

private:
    std::ifstream file_;
    PcapGlobalHeader global_header_{};
    bool needs_byte_swap_ = false;
    bool loop_ = false;
    std::string path_;

    uint16_t maybeSwap16(uint16_t value);
    uint32_t maybeSwap32(uint32_t value);
};

}  // namespace PacketAnalyzer

#endif  // PCAP_READER_H
