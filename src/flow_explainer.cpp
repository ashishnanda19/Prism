// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================

#include "flow_explainer.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <tuple>
#include <unordered_map>

#include "packet_parser.h"
#include "sni_extractor.h"
#include "tls_fingerprint.h"

namespace DPI {

namespace {

using PacketAnalyzer::PacketParser;
using PacketAnalyzer::ParsedPacket;
using PacketAnalyzer::RawPacket;

uint32_t parseIpv4(const std::string& s) {
    uint32_t r = 0;
    int octet = 0, shift = 0;
    for (char c : s) {
        if (c == '.') {
            r |= (static_cast<uint32_t>(octet) << shift);
            shift += 8;
            octet = 0;
        } else if (c >= '0' && c <= '9') {
            octet = octet * 10 + (c - '0');
        }
    }
    return r | (static_cast<uint32_t>(octet) << shift);
}

std::string ipToStr(uint32_t ip) {
    char b[16];
    std::snprintf(b, sizeof(b), "%u.%u.%u.%u", ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF,
                  (ip >> 24) & 0xFF);
    return b;
}

std::string endpointStr(uint32_t ip, uint16_t port) {
    return ipToStr(ip) + ":" + std::to_string(port);
}

bool wellKnown(uint16_t port) { return port == 443 || port == 80 || port == 53; }

// Orient a tuple client -> server (well-known port as dst; otherwise stable).
FiveTuple canonical(const FiveTuple& t) {
    if (wellKnown(t.dst_port) && !wellKnown(t.src_port)) return t;
    if (wellKnown(t.src_port) && !wellKnown(t.dst_port)) return t.reverse();
    // no hint: smaller (ip,port) becomes the "client"
    if (std::tie(t.src_ip, t.src_port) <= std::tie(t.dst_ip, t.dst_port)) return t;
    return t.reverse();
}

const char* tlsVersionName(uint16_t v) {
    switch (v) {
        case 0x0304: return "TLS1.3";
        case 0x0303: return "TLS1.2";
        case 0x0302: return "TLS1.1";
        case 0x0301: return "TLS1.0";
        case 0x0300: return "SSL3.0";
        default: return "?";
    }
}

std::string jsonEsc(const std::string& s) {
    std::string o;
    for (char c : s) {
        if (c == '"' || c == '\\') {
            o += '\\';
            o += c;
        } else if (c == '\n') {
            o += "\\n";
        } else if (static_cast<unsigned char>(c) < 0x20) {
            char u[8];
            std::snprintf(u, sizeof(u), "\\u%04x", static_cast<unsigned char>(c));
            o += u;
        } else {
            o += c;
        }
    }
    return o;
}

struct Work {
    FlowTrace tr;
    TcpReassembler reasm;
    bool block_evaluated = false;
};

}  // namespace

// ---------------------------------------------------------------------------
// FlowFilter
// ---------------------------------------------------------------------------
FlowFilter FlowFilter::parse(const std::string& spec, std::string& err) {
    FlowFilter f;
    std::string s = spec;
    // trim
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.erase(s.begin());
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.pop_back();
    if (s.empty()) return f;  // match everything

    auto parseEndpoint = [&](const std::string& e, Endpoint& out) -> bool {
        auto colon = e.rfind(':');
        std::string ips = (colon == std::string::npos) ? e : e.substr(0, colon);
        std::string ports = (colon == std::string::npos) ? "" : e.substr(colon + 1);
        if (!ips.empty()) out.ip = parseIpv4(ips);
        if (!ports.empty()) {
            char* endp = nullptr;
            long p = std::strtol(ports.c_str(), &endp, 10);
            if (*endp != '\0' || p < 0 || p > 65535) return false;
            out.port = static_cast<uint16_t>(p);
        }
        return out.ip != 0 || out.port != 0;
    };

    auto dash = s.find('-');
    if (dash != std::string::npos) {
        Endpoint a, b;
        if (!parseEndpoint(s.substr(0, dash), a) || !parseEndpoint(s.substr(dash + 1), b)) {
            err = "bad flow spec '" + spec + "' (want ip:port-ip:port | ip:port | ip | :port)";
            return {};
        }
        f.endpoints = {a, b};
    } else {
        Endpoint a;
        if (!parseEndpoint(s, a)) {
            err = "bad flow spec '" + spec + "'";
            return {};
        }
        f.endpoints = {a};
    }
    return f;
}

bool FlowFilter::matches(const FiveTuple& t) const {
    if (endpoints.empty()) return true;
    auto hit = [](const Endpoint& e, uint32_t ip, uint16_t port) {
        return (e.ip == 0 || e.ip == ip) && (e.port == 0 || e.port == port);
    };
    for (const auto& e : endpoints) {
        if (!hit(e, t.src_ip, t.src_port) && !hit(e, t.dst_ip, t.dst_port)) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// FlowExplainer
// ---------------------------------------------------------------------------
std::vector<FlowTrace> FlowExplainer::run(PacketAnalyzer::PacketSource& src) {
    std::unordered_map<FiveTuple, Work, FiveTupleHash> flows;
    std::vector<FiveTuple> order;  // first-seen order

    RawPacket raw;
    ParsedPacket p;
    uint32_t pkt_no = 0;

    for (;;) {
        auto st = src.next(raw);
        if (st == PacketAnalyzer::PacketSource::Status::End ||
            st == PacketAnalyzer::PacketSource::Status::Failed) {
            break;
        }
        if (st == PacketAnalyzer::PacketSource::Status::Timeout) continue;
        ++pkt_no;
        if (!PacketParser::parse(raw, p) || !p.has_ip || (!p.has_tcp && !p.has_udp)) continue;

        FiveTuple seen{parseIpv4(p.src_ip), parseIpv4(p.dest_ip), p.src_port, p.dest_port,
                       p.protocol};
        if (!filter_.matches(seen)) continue;

        const FiveTuple key = canonical(seen);
        auto it = flows.find(key);
        if (it == flows.end()) {
            if (order.size() >= filter_.max_flows) continue;  // cap distinct flows
            it = flows.emplace(key, Work{}).first;
            it->second.tr.tuple = key;
            it->second.tr.ts_first = p.timestamp_sec;
            order.push_back(key);
        }
        Work& w = it->second;
        FlowTrace& tr = w.tr;

        const bool c2s = (seen == key);  // client -> server direction
        tr.packets++;
        tr.bytes += raw.data.size();
        (c2s ? tr.client_bytes : tr.server_bytes) += p.payload_length;
        tr.ts_last = p.timestamp_sec;

        // TCP state
        if (p.has_tcp) {
            const uint8_t fl = p.tcp_flags;
            if ((fl & 0x02) && !(fl & 0x10)) {
                tr.syn = true;
                tr.events.push_back("pkt " + std::to_string(pkt_no) + "  " +
                                    endpointStr(seen.src_ip, seen.src_port) + " -> " +
                                    endpointStr(seen.dst_ip, seen.dst_port) + "  SYN");
            } else if ((fl & 0x02) && (fl & 0x10)) {
                tr.syn_ack = true;
            }
            if (tr.syn && tr.syn_ack && (fl & 0x10) && !tr.established) {
                tr.established = true;
                tr.events.push_back("pkt " + std::to_string(pkt_no) + "  handshake established");
            }
            if (fl & 0x01) tr.fin = true;
            if (fl & 0x04) {
                tr.rst = true;
                tr.events.push_back("pkt " + std::to_string(pkt_no) + "  RST");
            }
        }

        // DNS is single-datagram; classify straight away.
        if ((seen.dst_port == 53 || seen.src_port == 53) && !tr.verdict.decided) {
            tr.facts.protocol = seen.protocol;
            tr.facts.dst_port = 53;
            tr.facts.is_dns = true;
            if (p.payload_length > 0) {
                if (auto q = DNSExtractor::extractQuery(p.payload_data, p.payload_length))
                    tr.facts.dns_qname = *q;
            }
            tr.verdict = classify(tr.facts, sigs_);
            tr.events.push_back("pkt " + std::to_string(pkt_no) + "  " + tr.verdict.reason);
        }

        // TLS / HTTP first flight (client -> server only).
        const bool l7 = p.has_tcp && (seen.dst_port == 443 || seen.dst_port == 80);
        if (l7 && c2s && !tr.verdict.decided) {
            const bool syn = p.has_tcp && (p.tcp_flags & 0x02) && !(p.tcp_flags & 0x10);
            const uint8_t* pl =
                (p.payload_length && p.payload_data) ? p.payload_data : nullptr;
            if (!w.reasm.full()) {
                w.reasm.addSegment(p.seq_number, syn, pl, pl ? p.payload_length : 0);
            }
            const auto& buf = w.reasm.data();
            tr.reasm_bytes = static_cast<uint32_t>(buf.size());
            if (pl) {
                tr.reasm_segments++;
                tr.events.push_back(
                    "pkt " + std::to_string(pkt_no) + "  client->server " +
                    std::to_string(p.payload_length) + " B -> reassembler: " +
                    std::to_string(tr.reasm_segments) + " seg, " + std::to_string(buf.size()) +
                    " B contiguous");
            }

            tr.facts.protocol = seen.protocol;
            tr.facts.dst_port = seen.dst_port;

            if (seen.dst_port == 443 && buf.size() > 9) {
                TlsClientHello ch;
                if (parseClientHello(buf.data(), buf.size(), ch)) {
                    tr.multi_segment_l7 = tr.reasm_segments > 1;
                    tr.facts.clienthello_seen = true;
                    tr.facts.sni = ch.sni;
                    tr.facts.ja3_string = ja3String(ch);
                    tr.facts.ja3 = ja3(ch);
                    tr.facts.ja4 = ja4(ch);
                    tr.tls_version = ch.negotiated_version;
                    tr.tls_cipher_count = ch.ciphers.size();
                    tr.tls_ext_count = ch.extensions.size();
                    if (!ch.alpn.empty()) tr.alpn = ch.alpn.front();

                    tr.events.push_back(
                        "pkt " + std::to_string(pkt_no) + "  parsed ClientHello: " +
                        tlsVersionName(tr.tls_version) + " ciphers=" +
                        std::to_string(tr.tls_cipher_count) + " exts=" +
                        std::to_string(tr.tls_ext_count) +
                        (tr.alpn.empty() ? "" : " alpn=" + tr.alpn) +
                        (ch.has_sni ? " sni=" + ch.sni : " sni=<none>"));
                    tr.events.push_back("        ja3=" + tr.facts.ja3 + "  ja4=" + tr.facts.ja4);
                }
            } else if (seen.dst_port == 80 && buf.size() > 10) {
                if (auto host = HTTPHostExtractor::extract(buf.data(), buf.size())) {
                    tr.multi_segment_l7 = tr.reasm_segments > 1;
                    tr.facts.http_host = *host;
                    tr.events.push_back("pkt " + std::to_string(pkt_no) + "  HTTP Host: " + *host);
                }
            }

            tr.reasm_full = w.reasm.full();
            tr.facts.first_flight_full = tr.reasm_full;

            Verdict v = classify(tr.facts, sigs_);
            if (v.decided || v.app != AppType::UNKNOWN) {
                tr.verdict = v;
                if (v.decided) {
                    tr.events.push_back("decision: " + v.reason + " -> " +
                                        (v.label.empty() ? appTypeToString(v.app) : v.label));
                }
            }
        }

        // Once decided, run the block check (needs an app + sni/host).
        if (tr.verdict.decided && !w.block_evaluated) {
            w.block_evaluated = true;
            if (rules_) {
                std::string dom = !tr.facts.sni.empty() ? tr.facts.sni
                                  : !tr.facts.http_host.empty() ? tr.facts.http_host
                                                               : tr.facts.dns_qname;
                auto br = rules_->shouldBlock(key.src_ip, key.dst_port, tr.verdict.app, dom);
                if (br) {
                    tr.blocked = true;
                    const char* k = br->type == RuleManager::BlockReason::Kind::Ip     ? "ip"
                                    : br->type == RuleManager::BlockReason::Kind::App   ? "app"
                                    : br->type == RuleManager::BlockReason::Kind::Domain ? "domain"
                                                                                        : "port";
                    tr.block_reason = std::string(k) + " rule '" + br->detail + "'";
                    tr.events.push_back("verdict: DROP -- matched block " + tr.block_reason);
                } else {
                    tr.block_reason = "no block rule matched";
                    tr.events.push_back("verdict: FORWARD (" + tr.block_reason + ")");
                }
            } else {
                tr.block_reason = "no block rules configured";
                tr.events.push_back("verdict: FORWARD (" + tr.block_reason + ")");
            }
        }
    }

    std::vector<FlowTrace> out;
    out.reserve(order.size());
    for (const auto& k : order) out.push_back(std::move(flows[k].tr));
    return out;
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------
std::string FlowTrace::toText() const {
    std::ostringstream o;
    o << "flow  " << endpointStr(tuple.src_ip, tuple.src_port) << "  ->  "
      << endpointStr(tuple.dst_ip, tuple.dst_port) << "  ("
      << (tuple.protocol == 6 ? "TCP" : tuple.protocol == 17 ? "UDP" : "?") << ")\n";
    o << "  packets " << packets << "  bytes " << bytes << "  (client " << client_bytes
      << " / server " << server_bytes << ")";
    if (ts_last >= ts_first) o << "  duration " << (ts_last - ts_first) << "s";
    o << "\n";
    if (tuple.protocol == 6) {
        o << "  tcp: " << (syn ? "SYN " : "") << (syn_ack ? "SYN-ACK " : "")
          << (established ? "established " : "") << (fin ? "FIN " : "") << (rst ? "RST " : "");
        if (!syn && !established) o << "(joined mid-stream)";
        o << "\n";
        o << "  first flight: " << reasm_segments << " segment(s), " << reasm_bytes
          << " B contiguous" << (reasm_full ? " (hit cap)" : "")
          << (multi_segment_l7 ? "  [L7 message spanned multiple segments]" : "") << "\n";
    }
    if (facts.clienthello_seen) {
        o << "  tls: " << tlsVersionName(tls_version) << "  ciphers " << tls_cipher_count
          << "  extensions " << tls_ext_count << (alpn.empty() ? "" : "  alpn " + alpn) << "\n";
        o << "       sni  " << (facts.sni.empty() ? "<none (ECH?)>" : facts.sni) << "\n";
        o << "       ja3  " << facts.ja3 << "\n";
        o << "       ja4  " << facts.ja4 << "\n";
    }
    if (!facts.http_host.empty()) o << "  http Host: " << facts.http_host << "\n";
    if (!facts.dns_qname.empty()) o << "  dns query: " << facts.dns_qname << "\n";
    o << "  classification: " << (verdict.label.empty() ? appTypeToString(verdict.app)
                                                        : verdict.label)
      << "\n";
    o << "        because:  " << (verdict.reason.empty() ? "n/a" : verdict.reason) << "\n";
    o << "  verdict: " << (blocked ? "DROP" : "FORWARD") << "  (" << block_reason << ")\n";
    if (!events.empty()) {
        o << "  timeline:\n";
        for (const auto& e : events) o << "    " << e << "\n";
    }
    return o.str();
}

std::string FlowTrace::toJson() const {
    std::ostringstream o;
    o << "{";
    o << "\"src\":\"" << endpointStr(tuple.src_ip, tuple.src_port) << "\",";
    o << "\"dst\":\"" << endpointStr(tuple.dst_ip, tuple.dst_port) << "\",";
    o << "\"proto\":" << int(tuple.protocol) << ",";
    o << "\"packets\":" << packets << ",\"bytes\":" << bytes << ",";
    o << "\"client_bytes\":" << client_bytes << ",\"server_bytes\":" << server_bytes << ",";
    o << "\"tcp\":{\"syn\":" << (syn ? "true" : "false") << ",\"established\":"
      << (established ? "true" : "false") << ",\"fin\":" << (fin ? "true" : "false")
      << ",\"rst\":" << (rst ? "true" : "false") << "},";
    o << "\"first_flight\":{\"segments\":" << reasm_segments << ",\"contiguous_bytes\":"
      << reasm_bytes << ",\"full\":" << (reasm_full ? "true" : "false")
      << ",\"multi_segment_l7\":" << (multi_segment_l7 ? "true" : "false") << "},";
    o << "\"sni\":\"" << jsonEsc(facts.sni) << "\",";
    o << "\"http_host\":\"" << jsonEsc(facts.http_host) << "\",";
    o << "\"dns_qname\":\"" << jsonEsc(facts.dns_qname) << "\",";
    o << "\"ja3\":\"" << facts.ja3 << "\",\"ja4\":\"" << facts.ja4 << "\",";
    o << "\"app\":\"" << jsonEsc(verdict.label.empty() ? appTypeToString(verdict.app)
                                                       : verdict.label)
      << "\",";
    o << "\"reason\":\"" << jsonEsc(verdict.reason) << "\",";
    o << "\"verdict\":\"" << (blocked ? "DROP" : "FORWARD") << "\",";
    o << "\"block_reason\":\"" << jsonEsc(block_reason) << "\",";
    o << "\"timeline\":[";
    for (std::size_t i = 0; i < events.size(); ++i) {
        if (i) o << ",";
        o << "\"" << jsonEsc(events[i]) << "\"";
    }
    o << "]}";
    return o.str();
}

}  // namespace DPI
