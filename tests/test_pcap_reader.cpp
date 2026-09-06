// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================
//
// Covers PcapReader against the checked-in capture fixture and a couple of
// bad-input cases. PRISM_TEST_DATA_DIR is injected by CMake.

#include "doctest/doctest.h"
#include "pcap_reader.h"
#include "packet_parser.h"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

using namespace PacketAnalyzer;

namespace {
const std::string kDataDir = PRISM_TEST_DATA_DIR;
const std::string kFixture = kDataDir + "/test_dpi.pcap";
}

TEST_CASE("PcapReader opens the fixture and yields parseable packets") {
    PcapReader reader;
    REQUIRE(reader.open(kFixture));

    const auto& hdr = reader.getGlobalHeader();
    CHECK(hdr.version_major == 2);
    CHECK(hdr.network == 1);           // LINKTYPE_ETHERNET

    RawPacket raw;
    size_t total = 0, ipv4 = 0;
    while (reader.readNextPacket(raw)) {
        ++total;
        CHECK(raw.data.size() == raw.header.incl_len);

        ParsedPacket p;
        if (PacketParser::parse(raw, p) && p.has_ip) {
            ++ipv4;
        }
    }
    CHECK(total > 0);
    CHECK(ipv4 > 0);
}

TEST_CASE("PcapReader fails cleanly on a missing file") {
    PcapReader reader;
    CHECK_FALSE(reader.open(kDataDir + "/does_not_exist_12345.pcap"));
}

TEST_CASE("PcapReader rejects a file with a bad magic number") {
    const auto path = std::filesystem::temp_directory_path() / "prism_bad_magic.pcap";
    {
        std::ofstream f(path, std::ios::binary);
        const char junk[24] = {'N', 'O', 'P', 'E'};
        f.write(junk, sizeof(junk));
    }
    PcapReader reader;
    CHECK_FALSE(reader.open(path.string()));
    std::error_code ec;
    std::filesystem::remove(path, ec);
}
