// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================

#include "tls_fingerprint.h"

#include <algorithm>
#include <cstdio>

#include "hashes.h"

namespace DPI {

namespace {

constexpr uint8_t CONTENT_HANDSHAKE = 0x16;
constexpr uint8_t HS_CLIENT_HELLO = 0x01;

constexpr uint16_t EXT_SNI = 0x0000;
constexpr uint16_t EXT_SUPPORTED_GROUPS = 0x000a;
constexpr uint16_t EXT_EC_POINT_FORMATS = 0x000b;
constexpr uint16_t EXT_SIG_ALGS = 0x000d;
constexpr uint16_t EXT_ALPN = 0x0010;
constexpr uint16_t EXT_SUPPORTED_VERSIONS = 0x002b;

inline uint16_t be16(const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }
inline uint32_t be24(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 16) | (static_cast<uint32_t>(p[1]) << 8) | p[2];
}

// TLS GREASE (RFC 8701): 0x0a0a, 0x1a1a, ... 0xfafa.
inline bool isGrease(uint16_t v) {
    return (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0x00ff);
}

// A forward cursor with hard bounds; every read checks remaining length.
struct Cursor {
    const uint8_t* p;
    const uint8_t* end;
    bool ok = true;

    size_t left() const { return static_cast<size_t>(end - p); }
    bool need(size_t n) {
        if (left() < n) ok = false;
        return ok;
    }
    uint8_t u8() { return need(1) ? *p++ : (ok = false, 0); }
    uint16_t u16() {
        if (!need(2)) return 0;
        uint16_t v = be16(p);
        p += 2;
        return v;
    }
    void skip(size_t n) {
        if (need(n)) p += n;
    }
    // Read a length-prefixed vector of uint16 elements into `dst`.
    void u16vec(size_t len_bytes, std::vector<uint16_t>& dst) {
        size_t vlen = (len_bytes == 1) ? u8() : u16();
        if (!need(vlen)) return;
        const uint8_t* stop = p + vlen;
        while (p + 2 <= stop) {
            dst.push_back(be16(p));
            p += 2;
        }
        p = stop;
    }
};

// tls_version -> the two JA4 version characters.
const char* ja4Version(uint16_t v) {
    switch (v) {
        case 0x0304: return "13";
        case 0x0303: return "12";
        case 0x0302: return "11";
        case 0x0301: return "10";
        case 0x0300: return "s3";
        default: return "00";
    }
}

std::string join(const std::vector<uint16_t>& v, char sep, bool drop_grease) {
    std::string s;
    bool first = true;
    for (uint16_t x : v) {
        if (drop_grease && isGrease(x)) continue;
        if (!first) s.push_back(sep);
        first = false;
        s += std::to_string(x);
    }
    return s;
}

std::string hex4Join(std::vector<uint16_t> v, bool sorted) {
    v.erase(std::remove_if(v.begin(), v.end(), isGrease), v.end());
    if (sorted) std::sort(v.begin(), v.end());
    std::string s;
    char buf[8];
    for (size_t i = 0; i < v.size(); ++i) {
        std::snprintf(buf, sizeof(buf), "%04x", v[i]);
        if (i) s.push_back(',');
        s += buf;
    }
    return s;
}

}  // namespace

bool parseClientHello(const uint8_t* data, std::size_t len, TlsClientHello& out) {
    out = TlsClientHello{};
    if (len < 9 || data[0] != CONTENT_HANDSHAKE) return false;

    // Record header (5) then handshake header (4). The record length field is
    // advisory here -- a split ClientHello may exceed what we hold; parse what
    // we can within `len`.
    Cursor c{data + 5, data + len};
    if (c.u8() != HS_CLIENT_HELLO) return false;
    (void)be24(data + 6);  // handshake length -- not trusted

    c.p = data + 9;  // start of ClientHello body
    out.legacy_version = c.u16();
    c.skip(32);                          // random
    c.skip(c.u8());                      // session id
    c.u16vec(2, out.ciphers);            // cipher suites
    c.skip(c.u8());                      // compression methods
    if (!c.ok) return false;

    // Extensions
    size_t ext_total = c.u16();
    if (ext_total > c.left()) ext_total = c.left();  // truncated -- parse the prefix
    const uint8_t* ext_end = c.p + ext_total;

    while (c.p + 4 <= ext_end) {
        uint16_t etype = be16(c.p);
        uint16_t elen = be16(c.p + 2);
        c.p += 4;
        if (c.p + elen > ext_end) break;
        const uint8_t* ebody = c.p;
        out.extensions.push_back(etype);

        Cursor e{ebody, ebody + elen};
        switch (etype) {
            case EXT_SNI: {
                (void)e.u16();  // server_name_list length
                uint8_t nt = e.u8();
                uint16_t nlen = e.u16();
                if (e.ok && nt == 0 && e.need(nlen)) {
                    out.sni.assign(reinterpret_cast<const char*>(e.p), nlen);
                    out.has_sni = true;
                }
                break;
            }
            case EXT_SUPPORTED_GROUPS:
                e.u16vec(2, out.groups);
                break;
            case EXT_EC_POINT_FORMATS: {
                size_t n = e.u8();
                for (size_t i = 0; i < n && e.need(1); ++i) out.ec_formats.push_back(e.u8());
                break;
            }
            case EXT_SIG_ALGS:
                e.u16vec(2, out.sig_algs);
                break;
            case EXT_SUPPORTED_VERSIONS: {
                size_t n = e.u8();  // list length in bytes
                for (size_t i = 0; i + 2 <= n && e.need(2); i += 2) {
                    uint16_t v = e.u16();
                    if (!isGrease(v) && v > out.negotiated_version) out.negotiated_version = v;
                }
                break;
            }
            case EXT_ALPN: {
                (void)e.u16();  // ALPN list length
                while (e.left() > 0) {
                    uint8_t plen = e.u8();
                    if (!e.need(plen)) break;
                    out.alpn.emplace_back(reinterpret_cast<const char*>(e.p), plen);
                    e.p += plen;
                }
                break;
            }
            default:
                break;
        }
        c.p += elen;
    }

    if (out.negotiated_version == 0) out.negotiated_version = out.legacy_version;
    out.valid = !out.ciphers.empty() || !out.extensions.empty();
    return out.valid;
}

std::string ja3String(const TlsClientHello& ch) {
    std::string s = std::to_string(ch.legacy_version);
    s.push_back(',');
    s += join(ch.ciphers, '-', true);
    s.push_back(',');
    s += join(ch.extensions, '-', true);
    s.push_back(',');
    s += join(ch.groups, '-', true);
    s.push_back(',');
    s += join(ch.ec_formats, '-', false);
    return s;
}

std::string ja3(const TlsClientHello& ch) { return md5_hex(ja3String(ch)); }

std::string ja4(const TlsClientHello& ch, bool over_quic) {
    // ---- ja4_a ----
    size_t n_ciphers = 0;
    for (uint16_t x : ch.ciphers)
        if (!isGrease(x)) ++n_ciphers;
    size_t n_exts = 0;
    for (uint16_t x : ch.extensions)
        if (!isGrease(x)) ++n_exts;

    std::string alpn = "00";
    if (!ch.alpn.empty() && !ch.alpn[0].empty()) {
        const std::string& a = ch.alpn[0];
        alpn = std::string(1, a.front()) + std::string(1, a.back());
    }

    char a[16];
    std::snprintf(a, sizeof(a), "%c%s%c%02zu%02zu%s", over_quic ? 'q' : 't',
                  ja4Version(ch.negotiated_version), ch.has_sni ? 'd' : 'i',
                  std::min<size_t>(n_ciphers, 99), std::min<size_t>(n_exts, 99), alpn.c_str());

    // ---- ja4_b: sha256(sorted cipher hex list)[:12] ----
    std::string b = ch.ciphers.empty() ? std::string(12, '0')
                                       : sha256_hex(hex4Join(ch.ciphers, true)).substr(0, 12);

    // ---- ja4_c: sha256(sorted extensions (minus SNI/ALPN) + "_" + sig algs)[:12] ----
    std::vector<uint16_t> exts_c;
    for (uint16_t x : ch.extensions)
        if (x != EXT_SNI && x != EXT_ALPN) exts_c.push_back(x);
    std::string c_input = hex4Join(exts_c, true);
    c_input.push_back('_');
    c_input += hex4Join(ch.sig_algs, false);
    std::string c = ch.extensions.empty() ? std::string(12, '0')
                                          : sha256_hex(c_input).substr(0, 12);

    return std::string(a) + "_" + b + "_" + c;
}

}  // namespace DPI
