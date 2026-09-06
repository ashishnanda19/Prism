// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================
//
// "Explain this flow": a single-threaded analyzer that replays a capture and,
// for the flow(s) you name, records every fact it learned and every decision
// it made -- reassembly, SNI, JA3/JA4, which signature matched, the verdict
// and why. Shares the classification decision with the engines (classify.h).

#ifndef PRISM_FLOW_EXPLAINER_H
#define PRISM_FLOW_EXPLAINER_H

#include <cstdint>
#include <string>
#include <vector>

#include "classify.h"
#include "packet_source.h"
#include "rule_manager.h"
#include "signature_set.h"
#include "tcp_reassembler.h"
#include "types.h"

namespace DPI {

// Which flow(s) to explain. An endpoint pattern with ip==0 or port==0 is a
// wildcard on that field; every pattern must appear on some endpoint of the
// flow (in either direction).
struct FlowFilter {
    struct Endpoint {
        uint32_t ip = 0;
        uint16_t port = 0;
    };
    std::vector<Endpoint> endpoints;  // 0 = explain everything (up to max_flows)
    std::size_t max_flows = 12;

    // Spec: "ip:port-ip:port" | "ip:port" | "ip" | ":port"  (empty = all)
    static FlowFilter parse(const std::string& spec, std::string& err);
    bool matches(const FiveTuple& t) const;
};

struct FlowTrace {
    FiveTuple tuple{};                 // client -> server orientation
    std::uint64_t packets = 0, bytes = 0;
    std::uint64_t client_bytes = 0, server_bytes = 0;
    std::uint32_t ts_first = 0, ts_last = 0;

    bool syn = false, syn_ack = false, established = false, fin = false, rst = false;

    std::uint32_t reasm_segments = 0, reasm_bytes = 0;
    bool reasm_full = false;
    bool multi_segment_l7 = false;     // the L7 message needed >1 segment

    FlowFacts facts;
    std::uint16_t tls_version = 0;
    std::size_t tls_cipher_count = 0, tls_ext_count = 0;
    std::string alpn;                  // first ALPN value

    Verdict verdict;
    bool blocked = false;
    std::string block_reason;

    std::vector<std::string> events;

    std::string toText() const;
    std::string toJson() const;
};

class FlowExplainer {
public:
    // `rules` may be null (then nothing is ever blocked).
    FlowExplainer(const SignatureSet& sigs, const RuleManager* rules)
        : sigs_(sigs), rules_(rules) {}

    void setFilter(FlowFilter f) { filter_ = std::move(f); }

    std::vector<FlowTrace> run(PacketAnalyzer::PacketSource& src);

private:
    const SignatureSet& sigs_;
    const RuleManager* rules_;
    FlowFilter filter_;
};

}  // namespace DPI

#endif  // PRISM_FLOW_EXPLAINER_H
