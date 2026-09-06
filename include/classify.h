// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================
//
// The classification decision, factored out so the engines and the
// `prism explain` analyzer agree on how a flow becomes an app -- and, for
// explain mode, on *why*.

#ifndef PRISM_CLASSIFY_H
#define PRISM_CLASSIFY_H

#include <string>

#include "signature_set.h"
#include "types.h"

namespace DPI {

// Everything learned from a flow's client -> server first flight.
struct FlowFacts {
    uint8_t protocol = 0;
    uint16_t dst_port = 0;
    bool is_dns = false;              // UDP/TCP port 53 (either direction)
    std::string sni;                 // TLS SNI, if a ClientHello was parsed
    std::string http_host;           // HTTP Host header, if seen
    std::string dns_qname;           // DNS query name, if seen
    std::string ja3_string;          // JA3 pre-hash string, if TLS
    std::string ja3;                 // JA3 md5
    std::string ja4;                 // JA4
    bool clienthello_seen = false;   // a ClientHello parsed on this flow
    bool first_flight_full = false;  // reassembler hit a cap without an L7 hit
};

struct Verdict {
    AppType app = AppType::UNKNOWN;
    std::string label;   // richest label (may be a custom name)
    std::string reason;  // one-line human explanation
    bool decided = false;  // false => keep feeding more segments
};

// Pure: map the facts to an app + a reason using `sigs`.
Verdict classify(const FlowFacts& f, const SignatureSet& sigs);

}  // namespace DPI

#endif  // PRISM_CLASSIFY_H
