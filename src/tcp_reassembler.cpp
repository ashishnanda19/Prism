// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================

#include "tcp_reassembler.h"

#include <algorithm>
#include <iterator>

namespace DPI {

void TcpReassembler::clear() {
    buf_.clear();
    buf_.shrink_to_fit();
    pending_.clear();
    // Keep have_isn_/isn_ so late segments still map to the right offset,
    // but never grow again.
    full_ = true;
}

void TcpReassembler::markFullIfCapReached() {
    if (buf_.size() >= cfg_.max_bytes || segments_ >= cfg_.max_segments) {
        full_ = true;
    }
}

void TcpReassembler::addSegment(std::uint32_t seq, bool syn,
                                const std::uint8_t* data, std::size_t len) {
    if (full_) return;

    if (!have_isn_) {
        // The SYN's sequence number labels the SYN itself; stream data starts
        // at seq + 1. Without a SYN, treat the first data segment's seq as the
        // baseline (we joined mid-flow and can only see from here on).
        isn_ = syn ? seq + 1u : seq;
        have_isn_ = true;
        if (syn) return;  // SYN carries no stream payload
    }

    if (len == 0 || data == nullptr) return;

    // Offset of this segment into the stream (wraps correctly at 2^32).
    const std::uint32_t off = seq - isn_;

    // At or beyond the byte cap -- also catches a wrapped "before the baseline"
    // sequence, which lands near 2^32.
    if (off >= cfg_.max_bytes) return;

    // Clamp to the cap.
    if (off + len > cfg_.max_bytes) {
        len = cfg_.max_bytes - off;
    }

    if (++segments_ > cfg_.max_segments) {
        full_ = true;
        return;
    }

    const std::uint32_t have = static_cast<std::uint32_t>(buf_.size());

    if (off + len <= have) {
        // Entirely bytes we already hold (a retransmit).
        return;
    }

    if (off <= have) {
        // Overlaps or extends the contiguous tail -- append only the new part.
        buf_.insert(buf_.end(), data + (have - off), data + len);
        drainPending();
        markFullIfCapReached();
        return;
    }

    // Gap ahead of the contiguous prefix -- stash it, unless an earlier stash
    // already covers this exact range or more.
    auto it = pending_.upper_bound(off);
    if (it != pending_.begin()) {
        const auto& prev = *std::prev(it);
        if (prev.first <= off && prev.first + prev.second.size() >= off + len) {
            return;
        }
    }
    pending_[off].assign(data, data + len);
    if (pending_.size() > cfg_.max_segments) {
        full_ = true;
    }
    markFullIfCapReached();
}

void TcpReassembler::drainPending() {
    while (!pending_.empty()) {
        auto it = pending_.begin();                       // lowest offset first
        const std::uint32_t off = it->first;
        const std::uint32_t have = static_cast<std::uint32_t>(buf_.size());

        if (off > have) return;                           // still a gap

        const auto& seg = it->second;
        if (off + seg.size() > have) {
            buf_.insert(buf_.end(), seg.data() + (have - off), seg.data() + seg.size());
        }
        pending_.erase(it);

        if (buf_.size() >= cfg_.max_bytes) {
            full_ = true;
            return;
        }
    }
}

}  // namespace DPI
