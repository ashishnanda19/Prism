// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================

#ifndef PRISM_TCP_REASSEMBLER_H
#define PRISM_TCP_REASSEMBLER_H

#include <cstddef>
#include <cstdint>
#include <map>
#include <vector>

namespace DPI {

// ============================================================================
// TcpReassembler - "first flight" reassembly for one direction of a TCP flow
// ============================================================================
//
// A TLS ClientHello (or an HTTP request) can be larger than a single TCP
// segment -- big cipher lists, many extensions, post-quantum key shares,
// Encrypted ClientHello. Inspecting only the first packet's payload misses
// those flows entirely.
//
// This class buffers the *contiguous* prefix of the client -> server byte
// stream, ordered by TCP sequence number, until an L7 parser has enough to
// work with or a safety cap is hit. It is deliberately small:
//
//   - only one direction (feed client -> server segments);
//   - only the first `max_bytes` of the stream (a ClientHello fits easily);
//   - out-of-order segments are stashed and merged when the gap fills;
//   - retransmits / overlaps keep the bytes already held (first writer wins);
//   - past `max_bytes` or `max_segments` it stops accepting data (full()).
//
// Not a general TCP stack: no windowing, no bidirectional state, no handling
// of an L7 message that itself spans more than `max_bytes`.
// ============================================================================

class TcpReassembler {
public:
    struct Config {
        // 16 KiB: one max-size TLS record; a ClientHello fits with room to spare.
        std::uint32_t max_bytes = 16 * 1024;
        // Cap distinct segments (contiguous + stashed) to bound work per flow.
        std::uint32_t max_segments = 64;
    };

    TcpReassembler() = default;
    explicit TcpReassembler(Config cfg) : cfg_(cfg) {}

    // Feed one client -> server TCP segment.
    //   seq  : raw 32-bit sequence number of the first payload byte
    //   syn  : true for the SYN segment (it consumes one sequence number)
    //   data : payload start (may be nullptr when len == 0)
    //   len  : payload length in bytes
    // Wrapping 32-bit arithmetic is used, so it is safe across the seq rollover.
    void addSegment(std::uint32_t seq, bool syn, const std::uint8_t* data, std::size_t len);

    // Contiguous bytes reassembled from the start of the stream.
    const std::vector<std::uint8_t>& data() const { return buf_; }
    std::size_t size() const { return buf_.size(); }

    // True once the sequence baseline is known (SYN or first data segment seen).
    bool started() const { return have_isn_; }

    // True once a cap was hit: stop feeding, the buffer will not grow.
    bool full() const { return full_; }

    // Release all buffers and stop accepting data (call once the flow is
    // classified or definitively cannot be). After this, full() is true and
    // data() is empty.
    void clear();

private:
    Config cfg_{};
    bool have_isn_ = false;
    bool full_ = false;
    std::uint32_t isn_ = 0;        // sequence number of the byte at stream offset 0
    std::uint32_t segments_ = 0;   // distinct segments accepted so far
    std::vector<std::uint8_t> buf_;                                // contiguous prefix
    std::map<std::uint32_t, std::vector<std::uint8_t>> pending_;   // offset -> gapped bytes

    void drainPending();
    void markFullIfCapReached();
};

}  // namespace DPI

#endif  // PRISM_TCP_REASSEMBLER_H
