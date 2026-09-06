// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================
//
// Drives PcapReader over a whole file: global header parse + the
// readNextPacket() loop (length sanity checks, byte-swap paths).
// PcapReader is file-based, so the input is staged to a temp file.

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>

#include "pcap_reader.h"

using namespace PacketAnalyzer;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const auto path = std::filesystem::temp_directory_path() / "prism_fuzz_pcap.tmp";
    {
        std::ofstream f(path, std::ios::binary | std::ios::trunc);
        f.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
    }

    PcapReader reader;
    if (reader.open(path.string())) {
        RawPacket pkt;
        int guard = 0;
        while (reader.readNextPacket(pkt) && ++guard < 100000) {
            // consume
        }
    }

    std::error_code ec;
    std::filesystem::remove(path, ec);
    return 0;
}
