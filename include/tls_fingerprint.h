// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================
//
// Parse a TLS ClientHello into the fields JA3 and JA4 need, and compute both
// fingerprints. Input is the TCP payload starting at the TLS record header
// (same as SNIExtractor::extract). Bounds-checked; a malformed message yields
// `valid == false` rather than a read past the buffer.

#ifndef PRISM_TLS_FINGERPRINT_H
#define PRISM_TLS_FINGERPRINT_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace DPI {

struct TlsClientHello {
    bool valid = false;
    bool has_sni = false;
    std::string sni;

    uint16_t legacy_version = 0;         // ClientHello.legacy_version
    uint16_t negotiated_version = 0;     // max from supported_versions ext, else legacy

    std::vector<uint16_t> ciphers;       // wire order, GREASE included
    std::vector<uint16_t> extensions;    // wire order, GREASE included
    std::vector<uint16_t> groups;        // supported_groups (ext 0x000a)
    std::vector<uint16_t> ec_formats;    // ec_point_formats (ext 0x000b)
    std::vector<uint16_t> sig_algs;      // signature_algorithms (ext 0x000d)
    std::vector<std::string> alpn;       // ALPN protocol ids (ext 0x0010)
};

// Parse. `data`/`len` point at the TLS record header (content type 0x16).
bool parseClientHello(const uint8_t* data, std::size_t len, TlsClientHello& out);

// JA3: md5( "ver,ciphers,extensions,groups,ecformats" ), GREASE removed.
std::string ja3String(const TlsClientHello& ch);
std::string ja3(const TlsClientHello& ch);

// JA4 (foxio spec): "<a>_<b>_<c>". `over_quic` picks the 'q' vs 't' prefix.
std::string ja4(const TlsClientHello& ch, bool over_quic = false);

}  // namespace DPI

#endif  // PRISM_TLS_FINGERPRINT_H
