// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================
//
// Minimal one-shot MD5 and SHA-256 for TLS fingerprinting (JA3 uses MD5, JA4
// uses SHA-256). Self-contained so Prism keeps its "no external crypto lib"
// footprint. Not constant-time -- fingerprinting only, never for secrets.

#ifndef PRISM_HASHES_H
#define PRISM_HASHES_H

#include <cstddef>
#include <cstdint>
#include <string>

namespace DPI {

// Lowercase hex digest of the whole input.
std::string md5_hex(const void* data, std::size_t len);
std::string sha256_hex(const void* data, std::size_t len);

inline std::string md5_hex(const std::string& s) { return md5_hex(s.data(), s.size()); }
inline std::string sha256_hex(const std::string& s) { return sha256_hex(s.data(), s.size()); }

}  // namespace DPI

#endif  // PRISM_HASHES_H
