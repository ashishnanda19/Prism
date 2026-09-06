// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================
//
// Covers TcpReassembler: in-order / out-of-order / duplicate / overlapping /
// gapped segments, the SYN baseline, mid-flow join, sequence wrap, and the
// safety caps -- plus an end-to-end "split ClientHello still yields its SNI".
//
// Out-of-order tests establish the sequence baseline with a SYN first: without
// one, 32-bit sequence numbers have no reference point and the first data
// segment seen is necessarily treated as the start of the stream.

#include "doctest/doctest.h"

#include "sni_extractor.h"
#include "tcp_reassembler.h"

#include <cstdint>
#include <string>
#include <vector>

using namespace DPI;

namespace {

std::vector<uint8_t> bytes(const std::string& s) { return {s.begin(), s.end()}; }

// A reassembler with its baseline already pinned by a SYN at `isn - 1`,
// so stream offset 0 == sequence number `isn`.
struct Flow {
    TcpReassembler r;
    uint32_t isn;
    explicit Flow(uint32_t isn_) : isn(isn_) { r.addSegment(isn - 1, true, nullptr, 0); }
    void at(uint32_t offset, const std::vector<uint8_t>& b) {
        r.addSegment(isn + offset, false, b.data(), b.size());
    }
    std::string str() const { return std::string(r.data().begin(), r.data().end()); }
};

// --- a structurally valid TLS 1.2 ClientHello carrying server_name --------
void put16(std::vector<uint8_t>& b, uint16_t v) {
    b.push_back(uint8_t(v >> 8));
    b.push_back(uint8_t(v & 0xFF));
}
void put24(std::vector<uint8_t>& b, uint32_t v) {
    b.push_back(uint8_t(v >> 16));
    b.push_back(uint8_t(v >> 8));
    b.push_back(uint8_t(v & 0xFF));
}
std::vector<uint8_t> makeClientHello(const std::string& host, size_t pad = 0) {
    std::vector<uint8_t> sni;
    put16(sni, uint16_t(host.size() + 3));
    sni.push_back(0x00);
    put16(sni, uint16_t(host.size()));
    sni.insert(sni.end(), host.begin(), host.end());

    std::vector<uint8_t> exts;
    put16(exts, 0x0000);
    put16(exts, uint16_t(sni.size()));
    exts.insert(exts.end(), sni.begin(), sni.end());
    if (pad) {  // padding extension (type 21) to push the message past one segment
        put16(exts, 0x0015);
        put16(exts, uint16_t(pad));
        exts.insert(exts.end(), pad, 0x00);
    }

    std::vector<uint8_t> body;
    put16(body, 0x0303);
    body.insert(body.end(), 32, 0x00);
    body.push_back(0x00);
    put16(body, 0x0002);
    put16(body, 0x1301);
    body.push_back(0x01);
    body.push_back(0x00);
    put16(body, uint16_t(exts.size()));
    body.insert(body.end(), exts.begin(), exts.end());

    std::vector<uint8_t> hs;
    hs.push_back(0x01);
    put24(hs, uint32_t(body.size()));
    hs.insert(hs.end(), body.begin(), body.end());

    std::vector<uint8_t> rec;
    rec.push_back(0x16);
    put16(rec, 0x0301);
    put16(rec, uint16_t(hs.size()));
    rec.insert(rec.end(), hs.begin(), hs.end());
    return rec;
}

}  // namespace

TEST_CASE("in-order segments concatenate") {
    Flow f(1000);
    f.at(0, bytes("hello "));
    f.at(6, bytes("world"));
    CHECK(f.str() == "hello world");
    CHECK_FALSE(f.r.full());
}

TEST_CASE("SYN sets the baseline; data starts one sequence later") {
    TcpReassembler r;
    r.addSegment(5000, /*syn=*/true, nullptr, 0);
    r.addSegment(5001, false, reinterpret_cast<const uint8_t*>("abc"), 3);
    CHECK(std::string(r.data().begin(), r.data().end()) == "abc");
}

TEST_CASE("out-of-order segments are held until the gap fills") {
    Flow f(100);
    f.at(6, bytes("world"));       // arrives first
    CHECK(f.r.size() == 0);        // gap at [0,6)
    f.at(0, bytes("hello "));
    CHECK(f.str() == "hello world");
}

TEST_CASE("three out-of-order fragments of a message") {
    Flow f(10);
    f.at(8, bytes("CCCCCC"));
    f.at(0, bytes("AAAA"));
    f.at(4, bytes("BBBB"));
    CHECK(f.str() == "AAAABBBBCCCCCC");
}

TEST_CASE("duplicate and fully-old segments are ignored") {
    Flow f(0);
    f.at(0, bytes("abcdef"));
    f.at(0, bytes("abcdef"));   // exact retransmit
    f.at(2, bytes("cd"));       // subset of what we hold
    CHECK(f.str() == "abcdef");
}

TEST_CASE("overlapping segment contributes only its new tail") {
    Flow f(0);
    f.at(0, bytes("abcde"));
    f.at(3, bytes("defgh"));    // overlaps at d,e then adds fgh
    CHECK(f.str() == "abcdefgh");
}

TEST_CASE("a gap that never fills leaves the prefix short") {
    Flow f(0);
    f.at(0, bytes("abc"));
    f.at(10, bytes("xyz"));     // gap [3,10)
    CHECK(f.str() == "abc");
    CHECK(f.r.size() == 3);
}

TEST_CASE("mid-flow join without a SYN: first data segment becomes offset 0") {
    TcpReassembler r;
    r.addSegment(999999, false, reinterpret_cast<const uint8_t*>("partial"), 7);
    r.addSegment(999999 + 7, false, reinterpret_cast<const uint8_t*>(" data"), 5);
    CHECK(std::string(r.data().begin(), r.data().end()) == "partial data");
}

TEST_CASE("sequence-number wraparound is handled") {
    Flow f(0xFFFFFFF0);            // SYN at 0xFFFFFFEF, stream byte 0 at 0xFFFFFFF0
    f.at(0, bytes("0123456789"));
    f.at(10, bytes("ABCDEF"));     // seq 0xFFFFFFFA + 6 wraps through 0
    CHECK(f.str() == "0123456789ABCDEF");
}

TEST_CASE("byte cap: buffer stops growing and reports full()") {
    TcpReassembler r(TcpReassembler::Config{/*max_bytes=*/16, /*max_segments=*/64});
    r.addSegment(0, true, nullptr, 0);
    const std::vector<uint8_t> a(10, 'a'), b(20, 'b');
    r.addSegment(1, false, a.data(), a.size());
    r.addSegment(11, false, b.data(), b.size());   // would reach 30 > 16
    CHECK(r.size() == 16);
    CHECK(r.full());
    r.addSegment(17, false, a.data(), a.size());   // no-op once full
    CHECK(r.size() == 16);
}

TEST_CASE("segment cap trips full()") {
    TcpReassembler r(TcpReassembler::Config{/*max_bytes=*/65536, /*max_segments=*/4});
    r.addSegment(0, true, nullptr, 0);
    const std::vector<uint8_t> xy = bytes("xy");
    for (uint32_t i = 0; i < 10; ++i) r.addSegment(1 + i * 2, false, xy.data(), xy.size());
    CHECK(r.full());
}

TEST_CASE("clear() releases the buffer and freezes the reassembler") {
    Flow f(0);
    f.at(0, bytes("abcdef"));
    f.r.clear();
    CHECK(f.r.size() == 0);
    CHECK(f.r.full());
    f.at(6, bytes("ghi"));
    CHECK(f.r.size() == 0);
}

TEST_CASE("end to end: a ClientHello split across segments still yields its SNI") {
    // ~1500 bytes of padding forces the handshake well past a single 1460B MSS.
    const std::vector<uint8_t> hello = makeClientHello("split.example.com", 1500);
    REQUIRE(hello.size() > 1400);

    // A one-shot parse of just the first "segment" fails, as it does today.
    CHECK_FALSE(SNIExtractor::extract(hello.data(), 600).has_value());

    Flow f(7000);
    auto slice = [&](size_t a, size_t b) {
        return std::vector<uint8_t>(hello.begin() + a, hello.begin() + b);
    };
    f.at(500, slice(500, 1100));                // middle first
    f.at(0, slice(0, 600));
    f.at(0, slice(0, 600));                     // duplicate
    f.at(1100, slice(1100, hello.size()));

    REQUIRE(f.r.size() == hello.size());
    auto sni = SNIExtractor::extract(f.r.data().data(), f.r.data().size());
    REQUIRE(sni.has_value());
    CHECK(*sni == "split.example.com");
}
