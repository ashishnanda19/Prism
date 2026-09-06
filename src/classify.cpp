// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================

#include "classify.h"

namespace DPI {

namespace {
std::string ruleDesc(const SignatureSet::Rule& r) {
    return std::string(SignatureSet::kindName(r.kind)) + " " + r.pattern;
}
}  // namespace

Verdict classify(const FlowFacts& f, const SignatureSet& sigs) {
    Verdict v;

    if (f.is_dns) {
        v.app = AppType::DNS;
        v.label = "DNS";
        v.reason = f.dns_qname.empty() ? "port 53" : ("DNS query '" + f.dns_qname + "'");
        v.decided = true;
        return v;
    }

    const bool is_tls = f.protocol == 6 && f.dst_port == 443;
    const bool is_http = f.protocol == 6 && f.dst_port == 80;

    if (is_tls && f.clienthello_seen) {
        // Host / SNI first, then JA3, then JA4. The first rule to match wins,
        // even if its label is a custom name outside the AppType enum.
        const SignatureSet::Rule* r = nullptr;
        std::string via;
        if (!f.sni.empty() && (r = sigs.matchHostRule(f.sni))) {
            via = "SNI '" + f.sni + "'";
        } else if ((r = sigs.matchJa3Rule(f.ja3_string, f.ja3))) {
            via = "JA3 " + f.ja3;
        } else if ((r = sigs.matchJa4Rule(f.ja4))) {
            via = "JA4 " + f.ja4;
        }

        v.decided = true;
        if (r) {
            v.label = r->app;
            AppType t = labelToAppType(v.label);
            v.app = (t != AppType::UNKNOWN) ? t : AppType::HTTPS;  // best enum approximation
            v.reason = via + " matched signature [" + ruleDesc(*r) + "]";
        } else {
            v.app = AppType::HTTPS;
            v.label = "HTTPS";
            v.reason = f.sni.empty()
                           ? "TLS ClientHello, no SNI (ECH?) and no fingerprint match"
                           : ("SNI '" + f.sni + "' present but matched no signature");
        }
        return v;
    }

    if (is_http && !f.http_host.empty()) {
        v.app = sniToAppType(f.http_host);
        if (const auto* r = sigs.matchHostRule(f.http_host)) {
            v.label = r->app;
            v.reason = "HTTP Host '" + f.http_host + "' matched signature [" + ruleDesc(*r) + "]";
        } else {
            v.label = "HTTP";
            v.reason = "HTTP Host '" + f.http_host + "' present but matched no signature";
        }
        v.decided = true;
        return v;
    }

    // Port-based fallback: only final once the first flight is exhausted.
    if (is_tls || is_http) {
        v.app = is_tls ? AppType::HTTPS : AppType::HTTP;
        v.label = is_tls ? "HTTPS" : "HTTP";
        v.reason = f.first_flight_full
                       ? "no L7 hint after the full first flight; port-based fallback"
                       : "port-based (still waiting for the first flight)";
        v.decided = f.first_flight_full;
        return v;
    }

    v.reason = "no classifier applies (not 53/80/443 TCP/UDP)";
    return v;
}

}  // namespace DPI
