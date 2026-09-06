// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================

#include "pcap_reader.h"

#include <cstring>
#include <ios>

#include "log.h"

namespace PacketAnalyzer {

// Magic numbers for PCAP files
constexpr uint32_t PCAP_MAGIC_NATIVE = 0xa1b2c3d4;  // Native byte order
constexpr uint32_t PCAP_MAGIC_SWAPPED = 0xd4c3b2a1; // Swapped byte order

PcapReader::~PcapReader() {
    close();
}

bool PcapReader::open(const std::string& filename) {
    // Close any previously opened file
    close();
    path_ = filename;  // remembered so setLoop() can re-open from the top

    // Open in binary mode - this is crucial for reading raw bytes
    file_.open(filename, std::ios::binary);
    if (!file_.is_open()) {
        PLOG_ERROR("pcap") << "cannot open " << filename;
        return false;
    }

    // Read the global header (first 24 bytes of the file)
    file_.read(reinterpret_cast<char*>(&global_header_), sizeof(PcapGlobalHeader));
    if (!file_.good()) {
        PLOG_ERROR("pcap") << filename << ": truncated global header";
        close();
        return false;
    }
    
    // Check the magic number to determine byte order
    if (global_header_.magic_number == PCAP_MAGIC_NATIVE) {
        needs_byte_swap_ = false;
    } else if (global_header_.magic_number == PCAP_MAGIC_SWAPPED) {
        needs_byte_swap_ = true;
        // Swap the header fields we've already read
        global_header_.version_major = maybeSwap16(global_header_.version_major);
        global_header_.version_minor = maybeSwap16(global_header_.version_minor);
        global_header_.snaplen = maybeSwap32(global_header_.snaplen);
        global_header_.network = maybeSwap32(global_header_.network);
    } else {
        PLOG_ERROR("pcap") << filename << ": bad magic 0x" << std::hex
                           << global_header_.magic_number;
        close();
        return false;
    }

    PLOG_DEBUG("pcap") << "opened " << filename << " v" << global_header_.version_major << "."
                       << global_header_.version_minor << " snaplen=" << global_header_.snaplen
                       << " linktype=" << global_header_.network;
    return true;
}

void PcapReader::close() {
    if (file_.is_open()) {
        file_.close();
    }
    needs_byte_swap_ = false;
}

bool PcapReader::readNextPacket(RawPacket& packet) {
    if (!file_.is_open()) {
        return false;
    }
    
    // Read the packet header (16 bytes)
    file_.read(reinterpret_cast<char*>(&packet.header), sizeof(PcapPacketHeader));
    if (!file_.good()) {
        // End of file or error
        return false;
    }
    
    // Swap bytes if needed
    if (needs_byte_swap_) {
        packet.header.ts_sec = maybeSwap32(packet.header.ts_sec);
        packet.header.ts_usec = maybeSwap32(packet.header.ts_usec);
        packet.header.incl_len = maybeSwap32(packet.header.incl_len);
        packet.header.orig_len = maybeSwap32(packet.header.orig_len);
    }
    
    // Sanity check on packet length
    if (packet.header.incl_len > global_header_.snaplen || 
        packet.header.incl_len > 65535) {
        PLOG_WARN("pcap") << "invalid packet length " << packet.header.incl_len;
        return false;
    }
    
    // Read the packet data
    packet.data.resize(packet.header.incl_len);
    file_.read(reinterpret_cast<char*>(packet.data.data()), packet.header.incl_len);
    if (!file_.good()) {
        PLOG_WARN("pcap") << "truncated packet data";
        return false;
    }
    
    return true;
}

uint16_t PcapReader::maybeSwap16(uint16_t value) {
    if (!needs_byte_swap_) return value;
    return ((value & 0xFF00) >> 8) | ((value & 0x00FF) << 8);
}

uint32_t PcapReader::maybeSwap32(uint32_t value) {
    if (!needs_byte_swap_) return value;
    return ((value & 0xFF000000) >> 24) |
           ((value & 0x00FF0000) >> 8)  |
           ((value & 0x0000FF00) << 8)  |
           ((value & 0x000000FF) << 24);
}

} // namespace PacketAnalyzer
