// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================
//
// Covers the SNI/host -> AppType mapping and the FiveTuple value type.

#include "doctest/doctest.h"
#include "types.h"

using namespace DPI;

TEST_CASE("sniToAppType maps well-known hostnames") {
    CHECK(sniToAppType("www.youtube.com")        == AppType::YOUTUBE);
    CHECK(sniToAppType("i.ytimg.com")            == AppType::YOUTUBE);
    CHECK(sniToAppType("maps.google.com")        == AppType::GOOGLE);
    CHECK(sniToAppType("static.xx.fbcdn.net")    == AppType::FACEBOOK);
    CHECK(sniToAppType("scontent.cdninstagram.com") == AppType::INSTAGRAM);
    CHECK(sniToAppType("api.telegram.org")       == AppType::TELEGRAM);
    CHECK(sniToAppType("gateway.discord.gg")     == AppType::DISCORD);
    CHECK(sniToAppType("raw.githubusercontent.com") == AppType::GITHUB);
}

TEST_CASE("sniToAppType is case-insensitive") {
    CHECK(sniToAppType("WWW.YouTube.CoM") == AppType::YOUTUBE);
}

TEST_CASE("sniToAppType fallbacks") {
    CHECK(sniToAppType("")                       == AppType::UNKNOWN);
    // Present but unrecognised -> still classified as generic HTTPS/TLS.
    CHECK(sniToAppType("some-unknown-host.example") == AppType::HTTPS);
}

TEST_CASE("appTypeToString round-trips through every enumerator") {
    for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); ++i) {
        const std::string s = appTypeToString(static_cast<AppType>(i));
        CHECK_FALSE(s.empty());
    }
}

TEST_CASE("FiveTuple equality and reverse") {
    FiveTuple a{0x0A000001, 0x0A000002, 12345, 443, 6};
    FiveTuple b = a;
    CHECK(a == b);

    FiveTuple r = a.reverse();
    CHECK(r.src_ip   == a.dst_ip);
    CHECK(r.dst_ip   == a.src_ip);
    CHECK(r.src_port == a.dst_port);
    CHECK(r.dst_port == a.src_port);
    CHECK(r.protocol == a.protocol);
    CHECK_FALSE(r == a);
    CHECK(r.reverse() == a);
}

TEST_CASE("FiveTupleHash is deterministic and equal for equal tuples") {
    FiveTupleHash h;
    FiveTuple a{0x0A000001, 0x0A000002, 12345, 443, 6};
    FiveTuple b{0x0A000001, 0x0A000002, 12345, 443, 6};
    FiveTuple c{0x0A000001, 0x0A000002, 12345, 80,  6};
    CHECK(h(a) == h(b));
    CHECK(h(a) != h(c));  // not guaranteed in theory, but true for this hash
}
