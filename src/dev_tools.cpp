// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================
//
// `prism <tool> ...` -- small commands that expose the prism_core primitives
// (signature matching, JA3/JA4, TCP reassembly, hashing) so every piece of the
// project is reachable from the CLI (and the dev dashboard) without a pcap.

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "hashes.h"
#include "signature_set.h"
#include "tcp_reassembler.h"
#include "tls_fingerprint.h"

int runDevTool(int argc, char* argv[]);  // forward decl for dpi_mt.cpp

namespace {

using namespace DPI;

std::string readAll(const std::string& path) {
    if (path == "-") {
        std::ostringstream ss;
        ss << std::cin.rdbuf();
        return ss.str();
    }
    std::ifstream f(path, std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

std::vector<uint8_t> fromHex(const std::string& in) {
    std::vector<uint8_t> out;
    int hi = -1;
    for (char c : in) {
        int v;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else continue;  // skip whitespace / 0x / colons
        if (hi < 0) {
            hi = v;
        } else {
            out.push_back(static_cast<uint8_t>((hi << 4) | v));
            hi = -1;
        }
    }
    return out;
}

std::string toHex(const std::vector<uint8_t>& b) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(b.size() * 2);
    for (uint8_t c : b) {
        s.push_back(d[c >> 4]);
        s.push_back(d[c & 0xF]);
    }
    return s;
}

std::string jesc(const std::string& s) {
    std::string o;
    for (char c : s) {
        if (c == '"' || c == '\\') { o += '\\'; o += c; }
        else if (c == '\n') o += "\\n";
        else if (static_cast<unsigned char>(c) < 0x20) { char u[8]; std::snprintf(u,sizeof u,"\\u%04x",(unsigned char)c); o += u; }
        else o += c;
    }
    return o;
}

std::string jarr(const std::vector<uint16_t>& v) {
    std::string s = "[";
    for (size_t i = 0; i < v.size(); ++i) { if (i) s += ","; s += std::to_string(v[i]); }
    return s + "]";
}

// ---- prism sig ----------------------------------------------------------------
int toolSig(int argc, char* argv[]) {
    std::string sigfile;
    bool json = false;
    std::vector<std::string> pos;
    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--json") json = true;
        else if (a == "--signatures" && i + 1 < argc) sigfile = argv[++i];
        else pos.push_back(a);
    }
    if (pos.size() < 2) {
        std::cerr << "usage: prism sig [--signatures f] [--json] "
                     "(host|ja3|ja3hash|ja4) <value>\n";
        return 2;
    }
    std::string err;
    if (!sigfile.empty() && !loadSignatureFile(sigfile, err)) {
        std::cerr << "prism sig: " << err << "\n";
        return 1;
    }
    const SignatureSet& s = activeSignatures();
    const std::string& kind = pos[0];
    const std::string& val = pos[1];

    const SignatureSet::Rule* r = nullptr;
    if (kind == "host") r = s.matchHostRule(val);
    else if (kind == "ja3") r = s.matchJa3Rule(val, "");
    else if (kind == "ja3hash") r = s.matchJa3Rule("", val);
    else if (kind == "ja4") r = s.matchJa4Rule(val);
    else { std::cerr << "prism sig: kind must be host|ja3|ja3hash|ja4\n"; return 2; }

    if (json) {
        std::cout << "{\"rules_loaded\":" << s.size() << ",\"query\":{\"kind\":\"" << kind
                  << "\",\"value\":\"" << jesc(val) << "\"},";
        if (r) {
            std::cout << "\"match\":{\"app\":\"" << jesc(r->app) << "\",\"rule\":\""
                      << SignatureSet::kindName(r->kind) << " " << jesc(r->pattern) << "\"}}\n";
        } else {
            std::cout << "\"match\":null}\n";
        }
    } else {
        std::cout << s.size() << " rules loaded\n";
        if (r)
            std::cout << kind << " '" << val << "'  ->  " << r->app << "   [rule: "
                      << SignatureSet::kindName(r->kind) << " " << r->pattern << "]\n";
        else
            std::cout << kind << " '" << val << "'  ->  (no match)\n";
    }
    return 0;
}

// ---- prism fp (fingerprint a ClientHello) ------------------------------------
int toolFp(int argc, char* argv[]) {
    bool json = false, quic = false;
    std::string path;
    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--json") json = true;
        else if (a == "--quic") quic = true;
        else path = a;
    }
    if (path.empty()) {
        std::cerr << "usage: prism fp [--json] [--quic] <hexfile|->\n"
                     "  input: hex of the TLS record starting at content-type 0x16\n";
        return 2;
    }
    std::vector<uint8_t> rec = fromHex(readAll(path));
    TlsClientHello ch;
    if (!parseClientHello(rec.data(), rec.size(), ch)) {
        if (json) std::cout << "{\"ok\":false,\"error\":\"not a parseable ClientHello\"}\n";
        else std::cerr << "prism fp: input is not a parseable TLS ClientHello (" << rec.size()
                       << " bytes)\n";
        return 1;
    }
    const std::string j3s = ja3String(ch);
    const std::string j3 = ja3(ch);
    const std::string j4 = ja4(ch, quic);

    if (json) {
        std::cout << "{\"ok\":true,\"bytes\":" << rec.size()
                  << ",\"legacy_version\":" << ch.legacy_version
                  << ",\"negotiated_version\":" << ch.negotiated_version
                  << ",\"sni\":\"" << jesc(ch.sni) << "\",\"has_sni\":" << (ch.has_sni ? "true" : "false")
                  << ",\"ciphers\":" << jarr(ch.ciphers)
                  << ",\"extensions\":" << jarr(ch.extensions)
                  << ",\"groups\":" << jarr(ch.groups)
                  << ",\"alpn\":[";
        for (size_t i = 0; i < ch.alpn.size(); ++i) { if (i) std::cout << ","; std::cout << "\"" << jesc(ch.alpn[i]) << "\""; }
        std::cout << "],\"ja3_string\":\"" << jesc(j3s) << "\",\"ja3\":\"" << j3
                  << "\",\"ja4\":\"" << j4 << "\"}\n";
    } else {
        std::cout << "parsed ClientHello (" << rec.size() << " bytes)\n";
        std::cout << "  version   legacy=0x" << std::hex << ch.legacy_version
                  << " negotiated=0x" << ch.negotiated_version << std::dec << "\n";
        std::cout << "  sni       " << (ch.has_sni ? ch.sni : "<none>") << "\n";
        std::cout << "  ciphers   " << ch.ciphers.size() << "   extensions " << ch.extensions.size()
                  << "   groups " << ch.groups.size() << "\n";
        if (!ch.alpn.empty()) {
            std::cout << "  alpn      ";
            for (auto& a : ch.alpn) std::cout << a << " ";
            std::cout << "\n";
        }
        std::cout << "\n  JA3 string  " << j3s << "\n";
        std::cout << "  JA3         " << j3 << "\n";
        std::cout << "  JA4         " << j4 << "\n";
    }
    return 0;
}

// ---- prism reasm (drive the TCP reassembler) --------------------------------
// script lines: "<seq> <syn 0|1> [hex payload]"   ('#' comments, blanks ignored)
int toolReasm(int argc, char* argv[]) {
    bool json = false;
    std::string path = "-";
    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--json") json = true;
        else path = a;
    }
    TcpReassembler r;
    std::istringstream in(readAll(path));
    std::string line;
    int applied = 0;
    while (std::getline(in, line)) {
        std::string t = line;
        auto h = t.find('#');
        if (h != std::string::npos) t = t.substr(0, h);
        std::istringstream ls(t);
        std::string seqs, syns, hex;
        if (!(ls >> seqs >> syns)) continue;
        ls >> hex;
        uint32_t seq = static_cast<uint32_t>(std::strtoul(seqs.c_str(), nullptr, 0));
        bool syn = (syns == "1" || syns == "true");
        std::vector<uint8_t> data = fromHex(hex);
        r.addSegment(seq, syn, data.empty() ? nullptr : data.data(), data.size());
        ++applied;
    }
    const auto& buf = r.data();
    std::string ascii;
    for (uint8_t c : buf) ascii += (c >= 0x20 && c < 0x7f) ? char(c) : '.';

    if (json) {
        std::cout << "{\"segments_applied\":" << applied << ",\"contiguous_bytes\":" << buf.size()
                  << ",\"full\":" << (r.full() ? "true" : "false") << ",\"started\":"
                  << (r.started() ? "true" : "false") << ",\"hex\":\"" << toHex(buf)
                  << "\",\"ascii\":\"" << jesc(ascii) << "\"}\n";
    } else {
        std::cout << applied << " segment(s) applied\n";
        std::cout << "contiguous: " << buf.size() << " bytes   full=" << (r.full() ? "yes" : "no")
                  << "\n";
        std::cout << "hex:   " << toHex(buf) << "\n";
        std::cout << "ascii: " << ascii << "\n";
    }
    return 0;
}

// ---- prism hash ------------------------------------------------------------------
int toolHash(int argc, char* argv[]) {
    bool json = false;
    std::vector<std::string> pos;
    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--json") json = true;
        else pos.push_back(a);
    }
    if (pos.empty() || (pos[0] != "md5" && pos[0] != "sha256")) {
        std::cerr << "usage: prism hash [--json] (md5|sha256) [text]   (text or stdin)\n";
        return 2;
    }
    std::string data = pos.size() > 1 ? pos[1] : readAll("-");
    std::string digest = pos[0] == "md5" ? md5_hex(data) : sha256_hex(data);
    if (json)
        std::cout << "{\"alg\":\"" << pos[0] << "\",\"len\":" << data.size() << ",\"digest\":\""
                  << digest << "\"}\n";
    else
        std::cout << digest << "\n";
    return 0;
}

}  // namespace

int runDevTool(int argc, char* argv[]) {
    const std::string cmd = argc >= 2 ? argv[1] : "";
    if (cmd == "sig") return toolSig(argc, argv);
    if (cmd == "fp") return toolFp(argc, argv);
    if (cmd == "reasm") return toolReasm(argc, argv);
    if (cmd == "hash") return toolHash(argc, argv);
    std::cerr << "prism: unknown tool '" << cmd << "'\n";
    return 2;
}
