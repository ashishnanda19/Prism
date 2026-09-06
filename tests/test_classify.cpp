// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================

#include "doctest/doctest.h"

#include "classify.h"
#include "signature_set.h"

using namespace DPI;

namespace {
SignatureSet builtin() {
    SignatureSet s;
    std::string err;
    s.loadString(builtinSignatureRules(), err);
    return s;
}
}  // namespace

TEST_CASE("classify: DNS") {
    FlowFacts f;
    f.protocol = 17;
    f.is_dns = true;
    f.dns_qname = "example.com";
    Verdict v = classify(f, builtin());
    CHECK(v.app == AppType::DNS);
    CHECK(v.decided);
    CHECK(v.reason.find("example.com") != std::string::npos);
}

TEST_CASE("classify: TLS SNI hits a signature") {
    FlowFacts f;
    f.protocol = 6;
    f.dst_port = 443;
    f.clienthello_seen = true;
    f.sni = "i.ytimg.com";
    f.ja3 = "deadbeef";
    Verdict v = classify(f, builtin());
    CHECK(v.app == AppType::YOUTUBE);
    CHECK(v.label == "YouTube");
    CHECK(v.decided);
    CHECK(v.reason.find("SNI 'i.ytimg.com' matched signature [contains ytimg]") !=
          std::string::npos);
}

TEST_CASE("classify: TLS SNI present but unattributed -> HTTPS") {
    FlowFacts f;
    f.protocol = 6;
    f.dst_port = 443;
    f.clienthello_seen = true;
    f.sni = "some-unknown-host.example";
    Verdict v = classify(f, builtin());
    CHECK(v.app == AppType::HTTPS);
    CHECK(v.decided);
    CHECK(v.reason.find("no signature") != std::string::npos);
}

TEST_CASE("classify: TLS, no SNI (ECH), no fingerprint match -> HTTPS + hint") {
    FlowFacts f;
    f.protocol = 6;
    f.dst_port = 443;
    f.clienthello_seen = true;  // parsed, but sni empty
    Verdict v = classify(f, builtin());
    CHECK(v.app == AppType::HTTPS);
    CHECK(v.decided);
    CHECK(v.reason.find("ECH") != std::string::npos);
}

TEST_CASE("classify: JA3-hash rule attributes an SNI-less flow") {
    SignatureSet s;
    std::string err;
    REQUIRE(s.loadString("ja3hash  abc123  Tor\n", err));

    FlowFacts f;
    f.protocol = 6;
    f.dst_port = 443;
    f.clienthello_seen = true;
    f.ja3 = "abc123";
    Verdict v = classify(f, s);
    CHECK(v.label == "Tor");
    CHECK(v.reason.find("JA3 abc123 matched signature [ja3hash abc123]") != std::string::npos);
}

TEST_CASE("classify: port fallback only becomes final when the first flight is full") {
    FlowFacts f;
    f.protocol = 6;
    f.dst_port = 443;
    f.clienthello_seen = false;

    Verdict a = classify(f, builtin());
    CHECK(a.app == AppType::HTTPS);
    CHECK_FALSE(a.decided);  // still waiting

    f.first_flight_full = true;
    Verdict b = classify(f, builtin());
    CHECK(b.app == AppType::HTTPS);
    CHECK(b.decided);
    CHECK(b.reason.find("port-based fallback") != std::string::npos);
}
