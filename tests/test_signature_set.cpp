// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================

#include "doctest/doctest.h"

#include "signature_set.h"
#include "types.h"

#include <string>

using namespace DPI;

TEST_CASE("SignatureSet parses the rule kinds and matches by host") {
    SignatureSet s;
    std::string err;
    REQUIRE(s.loadString(
        "# a comment\n"
        "suffix    youtu.be           YouTube\n"
        "contains  googlevideo        YouTube\n"
        "exact     t.co               Twitter/X\n"
        "\n"
        "contains  corp-vpn           Corp VPN\n",  // label with a space
        err));
    CHECK(err.empty());
    CHECK(s.size() == 4);

    CHECK(s.matchHost("youtu.be") == "YouTube");
    CHECK(s.matchHost("www.youtu.be") == "YouTube");
    CHECK(s.matchHost("notyoutu.be") == "");          // suffix needs a label boundary
    CHECK(s.matchHost("r5---sn-googlevideo.com") == "YouTube");
    CHECK(s.matchHost("t.co") == "Twitter/X");
    CHECK(s.matchHost("foo.t.co") == "");             // exact, not suffix
    CHECK(s.matchHost("gw.corp-vpn.internal") == "Corp VPN");
    CHECK(s.matchHost("EXAMPLE.COM") == "");
}

TEST_CASE("SignatureSet: first matching rule wins") {
    SignatureSet s;
    std::string err;
    REQUIRE(s.loadString("contains  cdn   GenericCDN\n"
                         "contains  cdn.example  Example\n",
                         err));
    CHECK(s.matchHost("cdn.example.com") == "GenericCDN");  // earlier rule
}

TEST_CASE("SignatureSet: JA3 / JA4 rules") {
    SignatureSet s;
    std::string err;
    REQUIRE(s.loadString(
        "ja3hash   a0e9f5d64349fb13191bc781f81f42e1   Tor\n"
        "ja3       771,4865-4866   Minimal\n"
        "ja4       t13d1516h2_8daaf6152771_b186095e22b6   Chrome\n"
        "ja4prefix t13d   ModernTLS13Client\n",
        err));
    CHECK(s.matchJa3("771,4865-4866", "") == "Minimal");
    CHECK(s.matchJa3("", "a0e9f5d64349fb13191bc781f81f42e1") == "Tor");
    CHECK(s.matchJa4("t13d1516h2_8daaf6152771_b186095e22b6") == "Chrome");
    CHECK(s.matchJa4("t13d99zzzz_aaaaaaaaaaaa_bbbbbbbbbbbb") == "ModernTLS13Client");  // prefix
    CHECK(s.matchJa4("q13d1234_x_y") == "");
}

TEST_CASE("SignatureSet: parse errors are reported with a line number") {
    SignatureSet s;
    std::string err;

    CHECK_FALSE(s.loadString("suffix example.com Example\nbogus foo bar\n", err));
    CHECK(err.find(":2:") != std::string::npos);

    err.clear();
    CHECK_FALSE(s.loadString("suffix example.com\n", err));  // no app label
    CHECK_FALSE(err.empty());
}

TEST_CASE("the built-in rules load and drive sniToAppType") {
    SignatureSet s;
    std::string err;
    REQUIRE(s.loadString(builtinSignatureRules(), err));
    CHECK(err.empty());
    CHECK(s.size() > 30);

    // sniToAppType goes through activeSignatures(), which is the built-in set.
    CHECK(sniToAppType("i.ytimg.com") == AppType::YOUTUBE);
    CHECK(sniToAppType("maps.google.com") == AppType::GOOGLE);
    CHECK(sniToAppType("raw.githubusercontent.com") == AppType::GITHUB);  // not Twitter
    CHECK(sniToAppType("unknown-host.example") == AppType::HTTPS);        // present, unattributed
    CHECK(sniToAppType("") == AppType::UNKNOWN);
}
