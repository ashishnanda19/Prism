// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================
//
// Covers PacketParser: the Ethernet/IPv4/TCP/UDP decode path and the
// string formatting helpers. Frames are assembled by hand so the test
// doubles as documentation of the wire layout.

#include "doctest/doctest.h"
#include "packet_parser.h"

#include <cstdint>
#include <vector>

using namespace PacketAnalyzer;

namespace {

void put16(std::vector<uint8_t>& b, uint16_t v) {
    b.push_back(static_cast<uint8_t>(v >> 8));
    b.push_back(static_cast<uint8_t>(v & 0xFF));
}
void put32(std::vector<uint8_t>& b, uint32_t v) {
    b.push_back(static_cast<uint8_t>(v >> 24));
    b.push_back(static_cast<uint8_t>(v >> 16));
    b.push_back(static_cast<uint8_t>(v >> 8));
    b.push_back(static_cast<uint8_t>(v & 0xFF));
}

// Ethernet(14) + IPv4(20) + TCP(20) + `payload`.
std::vector<uint8_t> makeTcpFrame(uint16_t sport, uint16_t dport, uint8_t tcp_flags,
                                  const std::vector<uint8_t>& payload = {}) {
    std::vector<uint8_t> f;

    // --- Ethernet ---
    for (int i = 0; i < 6; ++i) f.push_back(0xAA);            // dst MAC
    for (int i = 0; i < 6; ++i) f.push_back(0xBB);            // src MAC
    put16(f, EtherType::IPv4);                                // 0x0800

    // --- IPv4 ---
    f.push_back(0x45);                                        // version 4, IHL 5
    f.push_back(0x00);                                        // DSCP/ECN
    put16(f, static_cast<uint16_t>(20 + 20 + payload.size()));// total length
    put16(f, 0x0000);                                         // identification
    put16(f, 0x4000);                                         // flags = DF
    f.push_back(64);                                          // TTL
    f.push_back(Protocol::TCP);                               // protocol = 6
    put16(f, 0x0000);                                         // checksum (unchecked)
    put32(f, 0xC0A80001);                                     // src 192.168.0.1
    put32(f, 0x08080808);                                     // dst 8.8.8.8

    // --- TCP ---
    put16(f, sport);
    put16(f, dport);
    put32(f, 0x00000001);                                     // seq
    put32(f, 0x00000000);                                     // ack
    f.push_back(0x50);                                        // data offset = 5 words
    f.push_back(tcp_flags);
    put16(f, 0xFFFF);                                         // window
    put16(f, 0x0000);                                         // checksum
    put16(f, 0x0000);                                         // urgent pointer

    f.insert(f.end(), payload.begin(), payload.end());
    return f;
}

RawPacket wrap(std::vector<uint8_t> bytes) {
    RawPacket p;
    p.header.ts_sec = 1;
    p.header.ts_usec = 0;
    p.header.incl_len = static_cast<uint32_t>(bytes.size());
    p.header.orig_len = p.header.incl_len;
    p.data = std::move(bytes);
    return p;
}

} // namespace

TEST_CASE("parses a well-formed TCP SYN frame") {
    RawPacket raw = wrap(makeTcpFrame(50000, 443, TCPFlags::SYN));
    ParsedPacket p;
    REQUIRE(PacketParser::parse(raw, p));

    CHECK(p.has_ip);
    CHECK(p.has_tcp);
    CHECK_FALSE(p.has_udp);
    CHECK(p.ip_version == 4);
    CHECK(p.protocol == Protocol::TCP);
    CHECK(p.ttl == 64);
    CHECK(p.src_port == 50000);
    CHECK(p.dest_port == 443);
    CHECK((p.tcp_flags & TCPFlags::SYN) != 0);
    CHECK((p.tcp_flags & TCPFlags::ACK) == 0);
    // NOTE: assumes a little-endian test host (all CI targets are).
    CHECK(p.src_ip == "192.168.0.1");
    CHECK(p.dest_ip == "8.8.8.8");
}

TEST_CASE("payload pointer and length are set past the TCP header") {
    const std::vector<uint8_t> body = {'h', 'e', 'l', 'l', 'o'};
    RawPacket raw = wrap(makeTcpFrame(1234, 80, TCPFlags::PSH | TCPFlags::ACK, body));
    ParsedPacket p;
    REQUIRE(PacketParser::parse(raw, p));
    REQUIRE(p.payload_data != nullptr);
    CHECK(p.payload_length == body.size());
    CHECK(p.payload_data[0] == 'h');
}

TEST_CASE("rejects frames that are too short to hold their headers") {
    ParsedPacket p;

    SUBCASE("shorter than Ethernet") {
        RawPacket raw = wrap({0x00, 0x01, 0x02});
        CHECK_FALSE(PacketParser::parse(raw, p));
    }
    SUBCASE("Ethernet ok but IPv4 truncated") {
        auto bytes = makeTcpFrame(1, 2, TCPFlags::SYN);
        bytes.resize(14 + 10);                    // half an IP header
        CHECK_FALSE(PacketParser::parse(wrap(bytes), p));
    }
    SUBCASE("IPv4 ok but TCP truncated") {
        auto bytes = makeTcpFrame(1, 2, TCPFlags::SYN);
        bytes.resize(14 + 20 + 8);                // partial TCP header
        // parse() still returns true (IP parsed) but must not claim TCP.
        PacketParser::parse(wrap(bytes), p);
        CHECK_FALSE(p.has_tcp);
    }
}

TEST_CASE("non-IPv4 ethertype is decoded but not treated as IP") {
    auto bytes = makeTcpFrame(1, 2, TCPFlags::SYN);
    bytes[12] = 0x86;  bytes[13] = 0xDD;          // IPv6 ethertype
    ParsedPacket p;
    REQUIRE(PacketParser::parse(wrap(bytes), p));
    CHECK(p.ether_type == EtherType::IPv6);
    CHECK_FALSE(p.has_ip);
}

TEST_CASE("formatting helpers") {
    CHECK(PacketParser::ipToString(0u) == "0.0.0.0");

    const uint8_t mac[6] = {0x01, 0x23, 0x45, 0xab, 0xcd, 0xef};
    CHECK(PacketParser::macToString(mac) == "01:23:45:ab:cd:ef");

    CHECK(PacketParser::protocolToString(Protocol::TCP) == "TCP");
    CHECK(PacketParser::protocolToString(Protocol::UDP) == "UDP");
    CHECK(PacketParser::protocolToString(200).rfind("Unknown", 0) == 0);

    CHECK(PacketParser::tcpFlagsToString(0) == "none");
    const std::string sa = PacketParser::tcpFlagsToString(TCPFlags::SYN | TCPFlags::ACK);
    CHECK(sa.find("SYN") != std::string::npos);
    CHECK(sa.find("ACK") != std::string::npos);
}
