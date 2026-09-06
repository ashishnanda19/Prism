// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================
//
// Covers the shared capture CLI: argument parsing, source selection, the
// PacketSource abstraction over the pcap fixture, and graceful failure of
// live capture (unknown interface / no privileges).

#include "doctest/doctest.h"

#include "capture_cli.h"
#include "packet_source.h"
#include "pcap_reader.h"

#include <string>
#include <vector>

using namespace PacketAnalyzer;

namespace {
const std::string kFixture = std::string(PRISM_TEST_DATA_DIR) + "/test_dpi.pcap";

// parseRunOptions takes (argc, argv); build a throwaway argv from a vector.
struct Args {
    std::vector<std::string> store;
    std::vector<char*> ptrs;
    Args(std::initializer_list<const char*> a) {
        store.emplace_back("prog");
        for (auto* s : a) store.emplace_back(s);
        for (auto& s : store) ptrs.push_back(s.data());
    }
    int argc() const { return static_cast<int>(ptrs.size()); }
    char** argv() { return ptrs.data(); }
};
}  // namespace

TEST_CASE("parseRunOptions: a lone positional is the input pcap") {
    Args a{"capture.pcap"};
    RunOptions o;
    std::string err;
    REQUIRE(parseRunOptions(a.argc(), a.argv(), o, err));
    CHECK(o.pcap_in == "capture.pcap");
    CHECK(o.iface.empty());
    CHECK(o.pcap_out == "prism-out.pcap");   // default
    CHECK(o.max_frames == -1);
}

TEST_CASE("parseRunOptions: flags and their values") {
    Args a{"-i", "eth0", "-o", "filtered.pcap", "--count", "500", "--no-promisc", "--snaplen", "1600"};
    RunOptions o;
    std::string err;
    REQUIRE(parseRunOptions(a.argc(), a.argv(), o, err));
    CHECK(o.iface == "eth0");
    CHECK(o.pcap_out == "filtered.pcap");
    CHECK(o.max_frames == 500);
    CHECK(o.promiscuous == false);
    CHECK(o.snaplen == 1600);
}

TEST_CASE("parseRunOptions: unknown args are left in rest, in order") {
    Args a{"in.pcap", "--block-app", "YouTube", "--lbs", "4"};
    RunOptions o;
    std::string err;
    REQUIRE(parseRunOptions(a.argc(), a.argv(), o, err));
    CHECK(o.pcap_in == "in.pcap");
    REQUIRE(o.rest.size() == 4);
    CHECK(o.rest[0] == "--block-app");
    CHECK(o.rest[1] == "YouTube");
    CHECK(o.rest[2] == "--lbs");
    CHECK(o.rest[3] == "4");
}

TEST_CASE("parseRunOptions: errors") {
    RunOptions o;
    std::string err;

    SUBCASE("file and --iface together") {
        Args a{"in.pcap", "--iface", "eth0"};
        CHECK_FALSE(parseRunOptions(a.argc(), a.argv(), o, err));
        CHECK_FALSE(err.empty());
    }
    SUBCASE("missing value") {
        Args a{"--count"};
        CHECK_FALSE(parseRunOptions(a.argc(), a.argv(), o, err));
    }
    SUBCASE("non-numeric count") {
        Args a{"in.pcap", "--count", "lots"};
        CHECK_FALSE(parseRunOptions(a.argc(), a.argv(), o, err));
    }
    SUBCASE("--help wins") {
        Args a{"--help", "--count"};  // --count would otherwise error
        REQUIRE(parseRunOptions(a.argc(), a.argv(), o, err));
        CHECK(o.help);
    }
}

TEST_CASE("openSource: file mode returns a working PacketSource") {
    RunOptions o;
    o.pcap_in = kFixture;
    std::string err;
    auto src = openSource(o, err);
    REQUIRE(src != nullptr);
    CHECK(err.empty());
    CHECK_FALSE(src->isLive());
    CHECK(src->linkType() == LINKTYPE_ETHERNET);

    size_t n = 0;
    RawPacket pkt;
    while (src->next(pkt) == PacketSource::Status::Packet) ++n;
    CHECK(n > 0);
}

TEST_CASE("openSource: missing / bad input fails cleanly") {
    std::string err;

    RunOptions none;
    CHECK(openSource(none, err) == nullptr);

    RunOptions bad;
    bad.pcap_in = std::string(PRISM_TEST_DATA_DIR) + "/no_such_file_9x.pcap";
    err.clear();
    CHECK(openSource(bad, err) == nullptr);
    CHECK_FALSE(err.empty());
}

TEST_CASE("openLiveInterface: an unknown interface fails without crashing") {
    std::string err;
    auto src = openLiveInterface("prism_no_such_if0", 65536, false, 100, err);
    CHECK(src == nullptr);
    CHECK_FALSE(err.empty());   // either "unknown interface" or a privilege error
}

TEST_CASE("makePcapHeader is well-formed") {
    auto h = makePcapHeader(LINKTYPE_ETHERNET, 65536);
    CHECK(h.magic_number == 0xa1b2c3d4);
    CHECK(h.version_major == 2);
    CHECK(h.version_minor == 4);
    CHECK(h.network == LINKTYPE_ETHERNET);
    CHECK(h.snaplen == 65536);
    CHECK(makePcapHeader(LINKTYPE_ETHERNET, 0).snaplen == 262144);  // sane default
}
