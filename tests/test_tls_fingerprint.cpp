// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================

#include "doctest/doctest.h"

#include "hashes.h"
#include "tls_fingerprint.h"

#include <cstdint>
#include <string>
#include <vector>

using namespace DPI;

namespace {

void u16(std::vector<uint8_t>& b, uint16_t v) {
    b.push_back(uint8_t(v >> 8));
    b.push_back(uint8_t(v & 0xFF));
}
void u24(std::vector<uint8_t>& b, uint32_t v) {
    b.push_back(uint8_t(v >> 16));
    b.push_back(uint8_t(v >> 8));
    b.push_back(uint8_t(v & 0xFF));
}
void ext(std::vector<uint8_t>& e, uint16_t type, const std::vector<uint8_t>& body) {
    u16(e, type);
    u16(e, uint16_t(body.size()));
    e.insert(e.end(), body.begin(), body.end());
}

// A ClientHello with a controlled cipher/extension shape.
std::vector<uint8_t> makeHello() {
    std::vector<uint8_t> exts;

    // SNI: example.com
    {
        std::string host = "example.com";
        std::vector<uint8_t> b;
        u16(b, uint16_t(host.size() + 3));
        b.push_back(0x00);
        u16(b, uint16_t(host.size()));
        b.insert(b.end(), host.begin(), host.end());
        ext(exts, 0x0000, b);
    }
    // supported_groups: 0x001d, 0x0017  + a GREASE 0x0a0a (must be filtered)
    {
        std::vector<uint8_t> b;
        u16(b, 6);
        u16(b, 0x0a0a);
        u16(b, 0x001d);
        u16(b, 0x0017);
        ext(exts, 0x000a, b);
    }
    // ec_point_formats: [0x00]
    {
        std::vector<uint8_t> b{0x01, 0x00};
        ext(exts, 0x000b, b);
    }
    // supported_versions: list-len=4, then 0x0304, 0x0303
    {
        std::vector<uint8_t> b{0x04, 0x03, 0x04, 0x03, 0x03};
        ext(exts, 0x002b, b);
    }
    // ALPN: "h2"
    {
        std::vector<uint8_t> b;
        u16(b, 3);          // list length
        b.push_back(0x02);  // proto length
        b.push_back('h');
        b.push_back('2');
        ext(exts, 0x0010, b);
    }

    std::vector<uint8_t> body;
    u16(body, 0x0303);                 // legacy_version
    body.insert(body.end(), 32, 0x00);  // random
    body.push_back(0x00);             // session id len
    u16(body, 6);                     // cipher suites length: GREASE + 2 real
    u16(body, 0x0a0a);                // GREASE cipher (filtered)
    u16(body, 0x1301);
    u16(body, 0x1302);
    body.push_back(0x01);             // compression methods length
    body.push_back(0x00);
    u16(body, uint16_t(exts.size()));
    body.insert(body.end(), exts.begin(), exts.end());

    std::vector<uint8_t> hs;
    hs.push_back(0x01);
    u24(hs, uint32_t(body.size()));
    hs.insert(hs.end(), body.begin(), body.end());

    std::vector<uint8_t> rec;
    rec.push_back(0x16);
    u16(rec, 0x0301);
    u16(rec, uint16_t(hs.size()));
    rec.insert(rec.end(), hs.begin(), hs.end());
    return rec;
}

}  // namespace

TEST_CASE("parseClientHello extracts the fingerprint fields") {
    auto hello = makeHello();
    TlsClientHello ch;
    REQUIRE(parseClientHello(hello.data(), hello.size(), ch));

    CHECK(ch.valid);
    CHECK(ch.has_sni);
    CHECK(ch.sni == "example.com");
    CHECK(ch.legacy_version == 0x0303);
    CHECK(ch.negotiated_version == 0x0304);              // from supported_versions
    CHECK(ch.ciphers == std::vector<uint16_t>{0x0a0a, 0x1301, 0x1302});
    CHECK(ch.extensions ==
          std::vector<uint16_t>{0x0000, 0x000a, 0x000b, 0x002b, 0x0010});
    CHECK(ch.groups == std::vector<uint16_t>{0x0a0a, 0x001d, 0x0017});
    CHECK(ch.ec_formats == std::vector<uint16_t>{0x00});
    REQUIRE(ch.alpn.size() == 1);
    CHECK(ch.alpn[0] == "h2");
}

TEST_CASE("JA3 string and hash") {
    auto hello = makeHello();
    TlsClientHello ch;
    REQUIRE(parseClientHello(hello.data(), hello.size(), ch));

    // GREASE (0x0a0a) dropped from ciphers/extensions/groups.
    CHECK(ja3String(ch) == "771,4865-4866,0-10-11-43-16,29-23,0");
    CHECK(ja3(ch) == md5_hex(ja3String(ch)));
    CHECK(ja3(ch).size() == 32);
}

TEST_CASE("JA4 shape and prefix") {
    auto hello = makeHello();
    TlsClientHello ch;
    REQUIRE(parseClientHello(hello.data(), hello.size(), ch));

    const std::string j = ja4(ch);
    // t = TLS/TCP, 13 = TLS 1.3, d = SNI present, 02 ciphers, 05 extensions, h2 = ALPN
    CHECK(j.substr(0, 10) == "t13d0205h2");

    // a_b_c with 12-hex b and c
    auto u1 = j.find('_');
    auto u2 = j.rfind('_');
    REQUIRE(u1 != std::string::npos);
    REQUIRE(u2 != u1);
    CHECK(j.substr(u1 + 1, u2 - u1 - 1).size() == 12);
    CHECK(j.substr(u2 + 1).size() == 12);

    CHECK(ja4(ch, /*over_quic=*/true).substr(0, 1) == "q");
}

TEST_CASE("parseClientHello rejects junk / truncation without OOB") {
    TlsClientHello ch;
    CHECK_FALSE(parseClientHello(reinterpret_cast<const uint8_t*>(""), 0, ch));

    std::vector<uint8_t> junk(80, 0x16);
    CHECK_FALSE(parseClientHello(junk.data(), junk.size(), ch));

    auto hello = makeHello();
    for (size_t n = 0; n <= hello.size(); ++n) {
        TlsClientHello c;
        (void)parseClientHello(hello.data(), n, c);  // must not crash / assert
    }
    CHECK(true);
}
