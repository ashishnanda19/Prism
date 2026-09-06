// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================
//
// Live packet capture. Linux uses an AF_PACKET raw socket; macOS/BSD use a
// /dev/bpf device. Both need elevated privileges (root or, on Linux,
// CAP_NET_RAW). A first cut: one frame per syscall on Linux, batched reads on
// BPF. PACKET_MMAP / zero-copy rings are a performance follow-up.

#include "packet_source.h"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>

#if defined(__linux__)
// Order matters: the glibc <net/*> headers must precede anything under
// <linux/*> or the two sets of IFF_* / struct ifreq definitions collide.
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <net/if.h>
#include <net/if_arp.h>          // ARPHRD_ETHER / ARPHRD_LOOPBACK / ARPHRD_NONE
#include <netpacket/packet.h>    // sockaddr_ll, packet_mreq, PACKET_* option ids
#include <arpa/inet.h>           // htons
#include <unistd.h>
#ifndef ETH_P_ALL
#define ETH_P_ALL 0x0003
#endif
#define PRISM_HAVE_AF_PACKET 1
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <deque>
#include <fcntl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#define PRISM_HAVE_BPF 1
#endif

namespace PacketAnalyzer {

namespace {

std::string privHint() {
#if defined(__linux__)
    return " (need root or: setcap cap_net_raw+ep <binary>)";
#else
    return " (need root, or read access to /dev/bpf*)";
#endif
}

#if defined(PRISM_HAVE_AF_PACKET)
// glibc's <netpacket/packet.h> gives us the PACKET_* option ids and
// sockaddr_ll but not struct tpacket_stats (that lives in <linux/if_packet.h>,
// which clashes with <net/if.h>). The layout is a stable two-u32 ABI.
#ifndef PACKET_STATISTICS
#define PACKET_STATISTICS 6
#endif
struct PrismTPacketStats {
    unsigned int tp_packets;
    unsigned int tp_drops;
};

// ---------------------------------------------------------------------------
// Linux: AF_PACKET raw socket
// ---------------------------------------------------------------------------
class AfPacketSource : public PacketSource {
public:
    AfPacketSource(int fd, int snaplen, std::uint32_t link_type)
        : fd_(fd), snaplen_(snaplen > 0 ? snaplen : 262144), link_type_(link_type) {
        buf_.resize(static_cast<std::size_t>(snaplen_));
    }
    ~AfPacketSource() override { close(); }

    Status next(RawPacket& out) override {
        ssize_t n = ::recv(fd_, buf_.data(), buf_.size(), MSG_TRUNC);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return Status::Timeout;
            err_ = std::string("recv: ") + std::strerror(errno);
            return Status::Failed;
        }
        if (n == 0) return Status::Timeout;

        const std::size_t wire = static_cast<std::size_t>(n);          // MSG_TRUNC => true length
        const std::size_t cap = std::min(wire, buf_.size());

        struct timeval tv {};
        ::gettimeofday(&tv, nullptr);
        out.header.ts_sec = static_cast<std::uint32_t>(tv.tv_sec);
        out.header.ts_usec = static_cast<std::uint32_t>(tv.tv_usec);
        out.header.incl_len = static_cast<std::uint32_t>(cap);
        out.header.orig_len = static_cast<std::uint32_t>(wire);
        out.data.assign(buf_.begin(), buf_.begin() + cap);
        return Status::Packet;
    }

    std::uint32_t linkType() const override { return link_type_; }
    bool isLive() const override { return true; }

    std::uint64_t kernelDrops() const override {
        struct PrismTPacketStats st {};
        socklen_t len = sizeof(st);
        if (::getsockopt(fd_, SOL_PACKET, PACKET_STATISTICS, &st, &len) == 0) drops_ += st.tp_drops;
        return drops_;
    }
    std::string errorMessage() const override { return err_; }
    void close() override {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }

private:
    int fd_ = -1;
    int snaplen_ = 262144;
    std::uint32_t link_type_ = LINKTYPE_ETHERNET;
    mutable std::uint64_t drops_ = 0;
    std::vector<std::uint8_t> buf_;
    std::string err_;
};

std::unique_ptr<PacketSource> openLinux(const std::string& iface, int snaplen, bool promiscuous,
                                        int poll_timeout_ms, std::string& err) {
    int fd = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        err = std::string("socket(AF_PACKET): ") + std::strerror(errno) + privHint();
        return nullptr;
    }

    struct ifreq ifr {};
    std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
    if (::ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        err = "unknown interface '" + iface + "': " + std::strerror(errno);
        ::close(fd);
        return nullptr;
    }
    const int ifindex = ifr.ifr_ifindex;

    std::uint32_t link_type = LINKTYPE_ETHERNET;
    if (::ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
        switch (ifr.ifr_hwaddr.sa_family) {
            case ARPHRD_ETHER:
            case ARPHRD_LOOPBACK:
                link_type = LINKTYPE_ETHERNET;
                break;
            case ARPHRD_NONE:
                link_type = LINKTYPE_RAW;
                break;
            default:
                link_type = LINKTYPE_ETHERNET;
                break;
        }
    }

    struct sockaddr_ll sll {};
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifindex;
    if (::bind(fd, reinterpret_cast<sockaddr*>(&sll), sizeof(sll)) < 0) {
        err = std::string("bind: ") + std::strerror(errno);
        ::close(fd);
        return nullptr;
    }

    if (promiscuous) {
        struct packet_mreq mr {};
        mr.mr_ifindex = ifindex;
        mr.mr_type = PACKET_MR_PROMISC;
        ::setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));  // best effort
    }

    struct timeval tv {};
    tv.tv_sec = poll_timeout_ms / 1000;
    tv.tv_usec = (poll_timeout_ms % 1000) * 1000;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct PrismTPacketStats st {};  // read once so kernelDrops() reports deltas
    socklen_t sl = sizeof(st);
    ::getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &st, &sl);

    return std::unique_ptr<PacketSource>(new AfPacketSource(fd, snaplen, link_type));
}

#elif defined(PRISM_HAVE_BPF)
// ---------------------------------------------------------------------------
// macOS / BSD: /dev/bpf
// ---------------------------------------------------------------------------
class BpfSource : public PacketSource {
public:
    BpfSource(int fd, std::size_t blen, std::uint32_t link_type)
        : fd_(fd), link_type_(link_type) {
        buf_.resize(blen);
    }
    ~BpfSource() override { close(); }

    Status next(RawPacket& out) override {
        if (!pending_.empty()) {
            out = std::move(pending_.front());
            pending_.pop_front();
            return Status::Packet;
        }

        ssize_t n = ::read(fd_, buf_.data(), buf_.size());
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return Status::Timeout;
            err_ = std::string("read: ") + std::strerror(errno);
            return Status::Failed;
        }
        if (n == 0) return Status::Timeout;

        const std::uint8_t* p = buf_.data();
        const std::uint8_t* end = p + n;
        while (p + sizeof(struct bpf_hdr) <= end) {
            auto* bh = reinterpret_cast<const struct bpf_hdr*>(p);
            const std::uint8_t* frame = p + bh->bh_hdrlen;
            if (frame + bh->bh_caplen > end) break;

            RawPacket rp;
            rp.header.ts_sec = static_cast<std::uint32_t>(bh->bh_tstamp.tv_sec);
            rp.header.ts_usec = static_cast<std::uint32_t>(bh->bh_tstamp.tv_usec);
            rp.header.incl_len = bh->bh_caplen;
            rp.header.orig_len = bh->bh_datalen;
            rp.data.assign(frame, frame + bh->bh_caplen);
            pending_.push_back(std::move(rp));

            p += BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);
        }

        if (pending_.empty()) return Status::Timeout;
        out = std::move(pending_.front());
        pending_.pop_front();
        return Status::Packet;
    }

    std::uint32_t linkType() const override { return link_type_; }
    bool isLive() const override { return true; }

    std::uint64_t kernelDrops() const override {
        struct bpf_stat bs {};
        if (::ioctl(fd_, BIOCGSTATS, &bs) == 0) return bs.bs_drop;
        return 0;
    }
    std::string errorMessage() const override { return err_; }
    void close() override {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }

private:
    int fd_ = -1;
    std::uint32_t link_type_ = LINKTYPE_ETHERNET;
    std::vector<std::uint8_t> buf_;
    std::deque<RawPacket> pending_;
    std::string err_;
};

std::unique_ptr<PacketSource> openBsd(const std::string& iface, int /*snaplen*/, bool promiscuous,
                                      int poll_timeout_ms, std::string& err) {
    int fd = -1;
    char dev[32];
    for (int i = 0; i < 256; ++i) {
        std::snprintf(dev, sizeof(dev), "/dev/bpf%d", i);
        fd = ::open(dev, O_RDONLY);
        if (fd >= 0) break;
        if (errno == EACCES) {
            err = std::string("cannot open ") + dev + ": permission denied" + privHint();
            return nullptr;
        }
        // ENOENT / EBUSY: try the next unit
    }
    if (fd < 0) {
        err = "no free /dev/bpf device";
        return nullptr;
    }

    unsigned int blen = 32 * 1024;
    ::ioctl(fd, BIOCSBLEN, &blen);  // must precede BIOCSETIF

    struct ifreq ifr {};
    std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
    if (::ioctl(fd, BIOCSETIF, &ifr) < 0) {
        err = "unknown interface '" + iface + "': " + std::strerror(errno);
        ::close(fd);
        return nullptr;
    }

    unsigned int one = 1;
    ::ioctl(fd, BIOCIMMEDIATE, &one);
    if (promiscuous) ::ioctl(fd, BIOCPROMISC, nullptr);

    unsigned int dlt = 0;
    ::ioctl(fd, BIOCGDLT, &dlt);
    std::uint32_t link_type = LINKTYPE_ETHERNET;
    if (dlt == DLT_EN10MB)
        link_type = LINKTYPE_ETHERNET;
    else if (dlt == DLT_NULL)
        link_type = LINKTYPE_NULL;
    else if (dlt == DLT_RAW)
        link_type = LINKTYPE_RAW;

    struct timeval tv {};
    tv.tv_sec = poll_timeout_ms / 1000;
    tv.tv_usec = (poll_timeout_ms % 1000) * 1000;
    ::ioctl(fd, BIOCSRTIMEOUT, &tv);

    unsigned int actual = blen;
    ::ioctl(fd, BIOCGBLEN, &actual);

    return std::unique_ptr<PacketSource>(new BpfSource(fd, actual, link_type));
}
#endif

}  // namespace

std::unique_ptr<PacketSource> openLiveInterface(const std::string& iface, int snaplen,
                                                bool promiscuous, int poll_timeout_ms,
                                                std::string& err) {
    if (iface.empty()) {
        err = "no interface name given";
        return nullptr;
    }
#if defined(PRISM_HAVE_AF_PACKET)
    return openLinux(iface, snaplen, promiscuous, poll_timeout_ms, err);
#elif defined(PRISM_HAVE_BPF)
    return openBsd(iface, snaplen, promiscuous, poll_timeout_ms, err);
#else
    (void)snaplen;
    (void)promiscuous;
    (void)poll_timeout_ms;
    err = "live capture is not supported on this platform";
    return nullptr;
#endif
}

}  // namespace PacketAnalyzer
