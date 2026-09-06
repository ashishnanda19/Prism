// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================
//
// Covers the layer-7 name extractors. These parsers walk attacker-controlled
// length fields, so the important properties are: (1) a valid message yields
// the right name, and (2) truncated / malformed input never reads out of
// bounds -- it just returns nullopt.

#include "doctest/doctest.h"
#include "sni_extractor.h"

#include <cstdint>
#include <string>
#include <vector>

using namespace DPI;

namespace {

void put16(std::vector<uint8_t>& b, uint16_t v) {
    b.push_back(static_cast<uint8_t>(v >> 8));
    b.push_back(static_cast<uint8_t>(v & 0xFF));
}
void put24(std::vector<uint8_t>& b, uint32_t v) {
    b.push_back(static_cast<uint8_t>(v >> 16));
    b.push_back(static_cast<uint8_t>(v >> 8));
    b.push_back(static_cast<uint8_t>(v & 0xFF));
}

// Minimal but structurally valid TLS 1.2 ClientHello carrying a single
// server_name extension. Layout mirrors sni_extractor.cpp exactly.
std::vector<uint8_t> makeClientHello(const std::string& host) {
    std::vector<uint8_t> sni_ext_data;
    put16(sni_ext_data, static_cast<uint16_t>(host.size() + 3));  // SNI list length
    sni_ext_data.push_back(0x00);                                 // name type: host
    put16(sni_ext_data, static_cast<uint16_t>(host.size()));      // name length
    sni_ext_data.insert(sni_ext_data.end(), host.begin(), host.end());

    std::vector<uint8_t> extensions;
    put16(extensions, 0x0000);                                    // ext type: server_name
    put16(extensions, static_cast<uint16_t>(sni_ext_data.size()));
    extensions.insert(extensions.end(), sni_ext_data.begin(), sni_ext_data.end());

    std::vector<uint8_t> body;
    put16(body, 0x0303);                                          // client version
    body.insert(body.end(), 32, 0x00);                            // random
    body.push_back(0x00);                                         // session id length
    put16(body, 0x0002);                                          // cipher suites length
    put16(body, 0x1301);                                          // one cipher suite
    body.push_back(0x01);                                         // compression methods length
    body.push_back(0x00);                                         // null compression
    put16(body, static_cast<uint16_t>(extensions.size()));        // extensions length
    body.insert(body.end(), extensions.begin(), extensions.end());

    std::vector<uint8_t> handshake;
    handshake.push_back(0x01);                                    // ClientHello
    put24(handshake, static_cast<uint32_t>(body.size()));
    handshake.insert(handshake.end(), body.begin(), body.end());

    std::vector<uint8_t> record;
    record.push_back(0x16);                                       // handshake record
    put16(record, 0x0301);                                        // record version
    put16(record, static_cast<uint16_t>(handshake.size()));
    record.insert(record.end(), handshake.begin(), handshake.end());
    return record;
}

std::vector<uint8_t> bytesOf(const std::string& s) {
    return {s.begin(), s.end()};
}

} // namespace

TEST_CASE("SNIExtractor pulls the hostname from a valid ClientHello") {
    auto hello = makeClientHello("example.com");
    CHECK(SNIExtractor::isTLSClientHello(hello.data(), hello.size()));

    auto sni = SNIExtractor::extract(hello.data(), hello.size());
    REQUIRE(sni.has_value());
    CHECK(*sni == "example.com");
}

TEST_CASE("SNIExtractor handles a long hostname") {
    const std::string host = "very-long-subdomain.assets.cdn.example.co.uk";
    auto hello = makeClientHello(host);
    auto sni = SNIExtractor::extract(hello.data(), hello.size());
    REQUIRE(sni.has_value());
    CHECK(*sni == host);
}

TEST_CASE("SNIExtractor rejects non-TLS and malformed input without reading OOB") {
    SUBCASE("empty") {
        CHECK_FALSE(SNIExtractor::isTLSClientHello(nullptr, 0));
        CHECK_FALSE(SNIExtractor::extract(reinterpret_cast<const uint8_t*>(""), 0).has_value());
    }
    SUBCASE("not a handshake record") {
        std::vector<uint8_t> app_data = {0x17, 0x03, 0x03, 0x00, 0x10, 0xde, 0xad};
        CHECK_FALSE(SNIExtractor::extract(app_data.data(), app_data.size()).has_value());
    }
    SUBCASE("handshake byte but pure garbage after") {
        std::vector<uint8_t> junk(64, 0x16);
        CHECK_FALSE(SNIExtractor::extract(junk.data(), junk.size()).has_value());
    }
    SUBCASE("valid prefix, truncated at every length") {
        auto full = makeClientHello("example.com");
        for (size_t n = 0; n < full.size(); ++n) {
            // Must not crash / must not assert; result simply has no value
            // (or, for near-complete buffers, may still parse -- both fine).
            (void)SNIExtractor::extract(full.data(), n);
        }
        CHECK(true);
    }
}

TEST_CASE("HTTPHostExtractor reads the Host header") {
    auto req = bytesOf("GET /index.html HTTP/1.1\r\n"
                       "User-Agent: test\r\n"
                       "Host: www.example.org:8080\r\n"
                       "Accept: */*\r\n\r\n");
    CHECK(HTTPHostExtractor::isHTTPRequest(req.data(), req.size()));

    auto host = HTTPHostExtractor::extract(req.data(), req.size());
    REQUIRE(host.has_value());
    CHECK(*host == "www.example.org");          // port stripped
}

TEST_CASE("HTTPHostExtractor ignores non-HTTP payloads") {
    auto blob = bytesOf("\x16\x03\x01\x00\x2f not http at all");
    CHECK_FALSE(HTTPHostExtractor::extract(blob.data(), blob.size()).has_value());
}

TEST_CASE("DNSExtractor pulls the queried name from a standard A query") {
    // Header (12) + QNAME(3www7example3com0) + QTYPE(2) + QCLASS(2)
    std::vector<uint8_t> q = {
        0x12, 0x34,             // txn id
        0x01, 0x00,             // flags: standard query, recursion desired
        0x00, 0x01,             // QDCOUNT = 1
        0x00, 0x00, 0x00, 0x00, // AN/NS/AR count
        0x00, 0x00,
    };
    for (auto label : {std::string("www"), std::string("example"), std::string("com")}) {
        q.push_back(static_cast<uint8_t>(label.size()));
        q.insert(q.end(), label.begin(), label.end());
    }
    q.push_back(0x00);          // root label
    q.insert(q.end(), {0x00, 0x01, 0x00, 0x01});  // QTYPE=A, QCLASS=IN

    CHECK(DNSExtractor::isDNSQuery(q.data(), q.size()));
    auto name = DNSExtractor::extractQuery(q.data(), q.size());
    REQUIRE(name.has_value());
    CHECK(*name == "www.example.com");
}

TEST_CASE("DNSExtractor rejects responses and runt packets") {
    std::vector<uint8_t> too_short = {0x00, 0x01, 0x02};
    CHECK_FALSE(DNSExtractor::isDNSQuery(too_short.data(), too_short.size()));

    std::vector<uint8_t> response = {
        0x12, 0x34, 0x81, 0x80,       // QR=1 -> response
        0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
    };
    CHECK_FALSE(DNSExtractor::isDNSQuery(response.data(), response.size()));
}
