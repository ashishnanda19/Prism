// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================

#include "doctest/doctest.h"

#include "flow_explainer.h"
#include "pcap_reader.h"
#include "rule_manager.h"
#include "signature_set.h"

#include <algorithm>
#include <string>

using namespace DPI;

namespace {
const std::string kFixture = std::string(PRISM_TEST_DATA_DIR) + "/test_dpi.pcap";

SignatureSet builtin() {
    SignatureSet s;
    std::string err;
    s.loadString(builtinSignatureRules(), err);
    return s;
}

std::vector<FlowTrace> explain(const std::string& spec, const RuleManager* rules) {
    static SignatureSet sigs = builtin();
    std::string err;
    FlowFilter f = FlowFilter::parse(spec, err);
    REQUIRE(err.empty());
    PacketAnalyzer::PcapReader r;
    REQUIRE(r.open(kFixture));
    FlowExplainer ex(sigs, rules);
    ex.setFilter(std::move(f));
    return ex.run(r);
}

const FlowTrace* findBySni(const std::vector<FlowTrace>& v, const std::string& sni) {
    for (const auto& t : v)
        if (t.facts.sni == sni) return &t;
    return nullptr;
}
}  // namespace

TEST_CASE("FlowFilter::parse") {
    std::string err;

    auto all = FlowFilter::parse("", err);
    CHECK(err.empty());
    CHECK(all.endpoints.empty());

    auto pair = FlowFilter::parse("1.2.3.4:5-6.7.8.9:443", err);
    REQUIRE(err.empty());
    REQUIRE(pair.endpoints.size() == 2);
    CHECK(pair.endpoints[1].port == 443);

    auto port = FlowFilter::parse(":53", err);
    REQUIRE(err.empty());
    REQUIRE(port.endpoints.size() == 1);
    CHECK(port.endpoints[0].ip == 0);
    CHECK(port.endpoints[0].port == 53);

    FlowFilter::parse("nonsense:x:y", err);
    CHECK_FALSE(err.empty());
}

TEST_CASE("explain a TLS flow end to end") {
    auto traces = explain(":443", nullptr);
    REQUIRE(traces.size() > 3);

    const FlowTrace* yt = findBySni(traces, "www.youtube.com");
    REQUIRE(yt != nullptr);

    CHECK(yt->tuple.dst_port == 443);
    CHECK(yt->syn);
    CHECK(yt->facts.clienthello_seen);
    CHECK(yt->facts.ja3.size() == 32);
    CHECK(yt->facts.ja4.rfind("t13", 0) == 0);
    CHECK(yt->verdict.app == AppType::YOUTUBE);
    CHECK(yt->verdict.reason.find("matched signature") != std::string::npos);
    CHECK_FALSE(yt->blocked);
    CHECK(yt->block_reason.find("no block") != std::string::npos);
    CHECK_FALSE(yt->events.empty());

    // the human render mentions the key facts
    const std::string txt = yt->toText();
    CHECK(txt.find("www.youtube.com") != std::string::npos);
    CHECK(txt.find("verdict: FORWARD") != std::string::npos);
    CHECK(txt.find("timeline:") != std::string::npos);
}

TEST_CASE("explain shows a DROP with the matching rule") {
    RuleManager rules;
    rules.blockApp(AppType::YOUTUBE);

    auto traces = explain(":443", &rules);
    const FlowTrace* yt = findBySni(traces, "www.youtube.com");
    REQUIRE(yt != nullptr);
    CHECK(yt->blocked);
    CHECK(yt->block_reason.find("app") != std::string::npos);
    CHECK(yt->toJson().find("\"verdict\":\"DROP\"") != std::string::npos);

    // a different flow is untouched
    const FlowTrace* g = findBySni(traces, "www.google.com");
    REQUIRE(g != nullptr);
    CHECK_FALSE(g->blocked);
}

TEST_CASE("explain a DNS flow") {
    auto traces = explain(":53", nullptr);
    REQUIRE_FALSE(traces.empty());
    const FlowTrace& d = traces.front();
    CHECK(d.verdict.app == AppType::DNS);
    CHECK_FALSE(d.facts.dns_qname.empty());
    CHECK(d.toText().find("dns query:") != std::string::npos);
}

TEST_CASE("explain caps the number of flows") {
    std::string err;
    FlowFilter f = FlowFilter::parse("", err);
    f.max_flows = 3;
    PacketAnalyzer::PcapReader r;
    REQUIRE(r.open(kFixture));
    static SignatureSet sigs = builtin();
    FlowExplainer ex(sigs, nullptr);
    ex.setFilter(std::move(f));
    CHECK(ex.run(r).size() == 3);
}
