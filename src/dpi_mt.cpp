// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================

// Prism - Multi-threaded DPI Engine
// Architecture: Reader -> LB threads -> FP threads -> Output

#include <iostream>
#include <fstream>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <chrono>
#include <iomanip>
#include <algorithm>
#include <optional>

#include <csignal>

#include "capture_cli.h"
#include "http_server.h"
#include "log.h"
#include "metrics.h"
#include "pcap_reader.h"
#include "packet_parser.h"
#include "signature_set.h"
#include "sni_extractor.h"
#include "tcp_reassembler.h"
#include "tls_fingerprint.h"
#include "types.h"

using namespace PacketAnalyzer;
using namespace DPI;

// Set from a SIGINT handler so a live capture stops cleanly on Ctrl-C.
static std::atomic<bool> g_running{true};

// =============================================================================
// Thread-Safe Queue
// =============================================================================
template<typename T>
class TSQueue {
public:
    TSQueue(size_t max_size = 10000) : max_size_(max_size), shutdown_(false) {}
    
    void push(T item) {
        std::unique_lock<std::mutex> lock(mutex_);
        not_full_.wait(lock, [this] { return queue_.size() < max_size_ || shutdown_; });
        if (shutdown_) return;
        queue_.push(std::move(item));
        not_empty_.notify_one();
    }
    
    std::optional<T> pop(int timeout_ms = 100) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (!not_empty_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                                  [this] { return !queue_.empty() || shutdown_; })) {
            return std::nullopt;
        }
        if (queue_.empty()) return std::nullopt;
        T item = std::move(queue_.front());
        queue_.pop();
        not_full_.notify_one();
        return item;
    }
    
    void shutdown() {
        std::lock_guard<std::mutex> lock(mutex_);
        shutdown_ = true;
        not_empty_.notify_all();
        not_full_.notify_all();
    }
    
    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }
    
    bool is_shutdown() const { return shutdown_; }

private:
    std::queue<T> queue_;
    mutable std::mutex mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
    size_t max_size_;
    std::atomic<bool> shutdown_;
};

// =============================================================================
// Packet Job - Contains all packet data (self-contained, no pointers)
// =============================================================================
struct Packet {
    uint32_t id;
    uint32_t ts_sec;
    uint32_t ts_usec;
    FiveTuple tuple;
    std::vector<uint8_t> data;
    uint8_t tcp_flags;
    uint32_t tcp_seq = 0;   // raw TCP sequence number (first payload byte)
    size_t payload_offset;
    size_t payload_length;
};

// =============================================================================
// Flow Entry
// =============================================================================
struct FlowEntry {
    FiveTuple tuple;
    AppType app_type = AppType::UNKNOWN;
    std::string sni;
    uint64_t packets = 0;
    uint64_t bytes = 0;
    bool blocked = false;
    bool classified = false;
    std::string ja3;
    std::string ja4;
    std::string app_label;  // richest signature label (may be a custom name)
    std::unique_ptr<TcpReassembler> reasm;  // client first-flight, lazily created
};

// =============================================================================
// Blocking Rules
// =============================================================================
class Rules {
public:
    void blockIP(const std::string& ip) {
        std::lock_guard<std::mutex> lock(mutex_);
        blocked_ips_.insert(parseIP(ip));
        PLOG_INFO("rules") << "blocked IP " << ip;
    }
    
    void blockApp(const std::string& app) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
            if (appTypeToString(static_cast<AppType>(i)) == app) {
                blocked_apps_.insert(static_cast<AppType>(i));
                PLOG_INFO("rules") << "blocked app " << app;
                return;
            }
        }
        PLOG_WARN("rules") << "unknown app: " << app;
    }
    
    void blockDomain(const std::string& domain) {
        std::lock_guard<std::mutex> lock(mutex_);
        blocked_domains_.push_back(domain);
        PLOG_INFO("rules") << "blocked domain " << domain;
    }
    
    bool isBlocked(uint32_t src_ip, AppType app, const std::string& sni) const {
        std::lock_guard<std::mutex> lock(mutex_);
        if (blocked_ips_.count(src_ip)) return true;
        if (blocked_apps_.count(app)) return true;
        for (const auto& dom : blocked_domains_) {
            if (sni.find(dom) != std::string::npos) return true;
        }
        return false;
    }

private:
    static uint32_t parseIP(const std::string& ip) {
        uint32_t result = 0;
        int octet = 0, shift = 0;
        for (char c : ip) {
            if (c == '.') { result |= (octet << shift); shift += 8; octet = 0; }
            else if (c >= '0' && c <= '9') octet = octet * 10 + (c - '0');
        }
        return result | (octet << shift);
    }
    
    mutable std::mutex mutex_;
    std::unordered_set<uint32_t> blocked_ips_;
    std::unordered_set<AppType> blocked_apps_;
    std::vector<std::string> blocked_domains_;
};

// =============================================================================
// Statistics (thread-safe)
// =============================================================================
struct Stats {
    std::atomic<uint64_t> total_packets{0};
    std::atomic<uint64_t> total_bytes{0};
    std::atomic<uint64_t> forwarded{0};
    std::atomic<uint64_t> dropped{0};
    std::atomic<uint64_t> tcp_packets{0};
    std::atomic<uint64_t> udp_packets{0};
    
    // Per-app stats (protected by mutex)
    std::mutex app_mutex;
    std::unordered_map<AppType, uint64_t> app_counts;
    std::unordered_map<std::string, AppType> detected_snis;
    std::unordered_map<std::string, uint64_t> ja3_counts;   // ja3 md5 -> flows
    std::unordered_map<std::string, uint64_t> ja4_counts;

    void recordApp(AppType app, const std::string& sni) {
        std::lock_guard<std::mutex> lock(app_mutex);
        app_counts[app]++;
        if (!sni.empty()) {
            detected_snis[sni] = app;
        }
    }
    std::unordered_map<std::string, uint64_t> label_counts;  // signature label -> flows

    void recordFingerprint(const std::string& ja3, const std::string& ja4) {
        if (ja3.empty() && ja4.empty()) return;
        std::lock_guard<std::mutex> lock(app_mutex);
        if (!ja3.empty()) ja3_counts[ja3]++;
        if (!ja4.empty()) ja4_counts[ja4]++;
    }
    void recordLabel(const std::string& label) {
        if (label.empty()) return;
        std::lock_guard<std::mutex> lock(app_mutex);
        label_counts[label]++;
    }
};

// =============================================================================
// Fast Path Processor (one per FP thread)
// =============================================================================
class FastPath {
public:
    FastPath(int id, Rules* rules, Stats* stats, TSQueue<Packet>* output_queue)
        : id_(id), rules_(rules), stats_(stats), output_queue_(output_queue) {}
    
    void start() {
        running_ = true;
        thread_ = std::thread(&FastPath::run, this);
    }
    
    void stop() {
        running_ = false;
        input_queue_.shutdown();
        if (thread_.joinable()) thread_.join();
    }
    
    TSQueue<Packet>& queue() { return input_queue_; }
    
    uint64_t processed() const { return processed_; }

private:
    [[maybe_unused]] int id_;
    Rules* rules_;
    Stats* stats_;
    TSQueue<Packet>* output_queue_;
    TSQueue<Packet> input_queue_;
    std::unordered_map<FiveTuple, FlowEntry, FiveTupleHash> flows_;
    
    std::atomic<bool> running_{false};
    std::thread thread_;
    std::atomic<uint64_t> processed_{0};
    
    void run() {
        while (running_) {
            auto pkt_opt = input_queue_.pop(100);
            if (!pkt_opt) continue;
            
            processed_++;
            Packet& pkt = *pkt_opt;
            
            // Get or create flow
            FlowEntry& flow = flows_[pkt.tuple];
            if (flow.packets == 0) {
                flow.tuple = pkt.tuple;
            }
            flow.packets++;
            flow.bytes += pkt.data.size();
            
            // Try to classify if not done yet
            if (!flow.classified) {
                classifyFlow(pkt, flow);
            }
            
            // Check blocking
            if (!flow.blocked) {
                flow.blocked = rules_->isBlocked(pkt.tuple.src_ip, flow.app_type, flow.sni);
            }
            
            // Record stats
            stats_->recordApp(flow.app_type, flow.sni);
            
            // Forward or drop
            if (flow.blocked) {
                stats_->dropped++;
            } else {
                stats_->forwarded++;
                output_queue_->push(std::move(pkt));
            }
        }
    }
    
    void classifyFlow(Packet& pkt, FlowEntry& flow) {
        const bool is_tls  = pkt.tuple.protocol == 6 && pkt.tuple.dst_port == 443;
        const bool is_http = pkt.tuple.protocol == 6 && pkt.tuple.dst_port == 80;

        if (is_tls || is_http) {
            // Reassemble the client's first flight so a ClientHello / request
            // split across TCP segments still classifies.
            if (!flow.reasm) flow.reasm = std::make_unique<TcpReassembler>();
            if (!flow.reasm->full()) {
                const bool syn = (pkt.tcp_flags & 0x02) && !(pkt.tcp_flags & 0x10);
                const uint8_t* p = pkt.data.data() + pkt.payload_offset;
                flow.reasm->addSegment(pkt.tcp_seq, syn,
                                       pkt.payload_length ? p : nullptr,
                                       pkt.payload_length);
            }
            const auto& buf = flow.reasm->data();

            if (is_tls && buf.size() > 9) {
                TlsClientHello ch;
                if (parseClientHello(buf.data(), buf.size(), ch)) {
                    flow.ja3 = ja3(ch);
                    flow.ja4 = ja4(ch);
                    if (ch.has_sni) flow.sni = ch.sni;

                    // Richest label: host -> JA3 -> JA4 (custom names allowed).
                    flow.app_label = classifyLabel(flow.sni, ja3String(ch), flow.ja3, flow.ja4);
                    AppType t = labelToAppType(flow.app_label);
                    flow.app_type = (t != AppType::UNKNOWN) ? t : AppType::HTTPS;

                    stats_->recordFingerprint(flow.ja3, flow.ja4);
                    stats_->recordLabel(flow.app_label);
                    flow.classified = true;
                    flow.reasm.reset();
                    return;
                }
            }
            if (is_http && buf.size() > 10) {
                if (auto host = HTTPHostExtractor::extract(buf.data(), buf.size())) {
                    flow.sni = *host;
                    flow.app_type = sniToAppType(*host);
                    flow.classified = true;
                    flow.reasm.reset();
                    return;
                }
            }

            // Provisional port-based label; stop buffering once we've seen enough.
            flow.app_type = is_tls ? AppType::HTTPS : AppType::HTTP;
            if (flow.reasm->full()) {
                flow.classified = true;
                flow.reasm.reset();
            }
            return;
        }

        // DNS
        if (pkt.tuple.dst_port == 53 || pkt.tuple.src_port == 53) {
            flow.app_type = AppType::DNS;
            flow.classified = true;
            return;
        }
    }
};

// =============================================================================
// Load Balancer (one per LB thread)
// =============================================================================
class LoadBalancer {
public:
    LoadBalancer(int id, std::vector<FastPath*> fps)
        : id_(id), fps_(std::move(fps)), num_fps_(fps_.size()) {}
    
    void start() {
        running_ = true;
        thread_ = std::thread(&LoadBalancer::run, this);
    }
    
    void stop() {
        running_ = false;
        input_queue_.shutdown();
        if (thread_.joinable()) thread_.join();
    }
    
    TSQueue<Packet>& queue() { return input_queue_; }
    
    uint64_t dispatched() const { return dispatched_; }

private:
    [[maybe_unused]] int id_;
    std::vector<FastPath*> fps_;
    size_t num_fps_;
    TSQueue<Packet> input_queue_;
    
    std::atomic<bool> running_{false};
    std::thread thread_;
    std::atomic<uint64_t> dispatched_{0};
    
    void run() {
        while (running_) {
            auto pkt_opt = input_queue_.pop(100);
            if (!pkt_opt) continue;
            
            // Hash to select FP
            FiveTupleHash hasher;
            size_t fp_idx = hasher(pkt_opt->tuple) % num_fps_;
            
            fps_[fp_idx]->queue().push(std::move(*pkt_opt));
            dispatched_++;
        }
    }
};

// =============================================================================
// DPI Engine
// =============================================================================
class DPIEngine {
public:
    struct Config {
        int num_lbs = 2;
        int fps_per_lb = 2;
    };
    
    DPIEngine(const Config& cfg) : config_(cfg) {
        int total_fps = cfg.num_lbs * cfg.fps_per_lb;
        
        std::cout << "\n";
        std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
        std::cout << "║             PRISM v2.0  (Multi-threaded DPI)                  ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ Load Balancers: " << std::setw(2) << cfg.num_lbs 
                  << "    FPs per LB: " << std::setw(2) << cfg.fps_per_lb
                  << "    Total FPs: " << std::setw(2) << total_fps << "     ║\n";
        std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";
        
        // Create FP threads
        for (int i = 0; i < total_fps; i++) {
            fps_.push_back(std::make_unique<FastPath>(i, &rules_, &stats_, &output_queue_));
        }
        
        // Create LB threads, each managing a subset of FPs
        for (int lb = 0; lb < cfg.num_lbs; lb++) {
            std::vector<FastPath*> lb_fps;
            int start = lb * cfg.fps_per_lb;
            for (int i = 0; i < cfg.fps_per_lb; i++) {
                lb_fps.push_back(fps_[start + i].get());
            }
            lbs_.push_back(std::make_unique<LoadBalancer>(lb, std::move(lb_fps)));
        }
    }
    
    void blockIP(const std::string& ip) { rules_.blockIP(ip); }
    void blockApp(const std::string& app) { rules_.blockApp(app); }
    void blockDomain(const std::string& dom) { rules_.blockDomain(dom); }
    
    bool process(PacketSource& source, const std::string& output_file, long max_frames = -1) {
        // Open output
        std::ofstream output(output_file, std::ios::binary);
        if (!output.is_open()) {
            std::cerr << "Cannot open output file\n";
            return false;
        }

        // Write PCAP header (synthesized: preserves link type, standardises the rest)
        PcapGlobalHeader hdr = makePcapHeader(
            source.linkType() ? source.linkType() : LINKTYPE_ETHERNET, 262144);
        output.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));
        
        // Start all threads
        for (auto& fp : fps_) fp->start();
        for (auto& lb : lbs_) lb->start();
        
        // Start output writer thread
        std::atomic<bool> output_running{true};
        std::thread output_thread([&]() {
            while (output_running || output_queue_.size() > 0) {
                auto pkt_opt = output_queue_.pop(50);
                if (!pkt_opt) continue;
                
                PcapPacketHeader phdr;
                phdr.ts_sec = pkt_opt->ts_sec;
                phdr.ts_usec = pkt_opt->ts_usec;
                phdr.incl_len = pkt_opt->data.size();
                phdr.orig_len = pkt_opt->data.size();
                
                output.write(reinterpret_cast<const char*>(&phdr), sizeof(phdr));
                output.write(reinterpret_cast<const char*>(pkt_opt->data.data()), pkt_opt->data.size());
            }
        });
        
        // Read and dispatch packets
        if (source.isLive()) {
            PLOG_INFO("reader") << "capturing live (Ctrl-C to stop)";
        } else {
            PLOG_INFO("reader") << "processing packets";
        }
        RawPacket raw;
        ParsedPacket parsed;
        uint32_t pkt_id = 0;

        while (g_running) {
            if (max_frames >= 0 && pkt_id >= static_cast<uint32_t>(max_frames)) break;
            auto st = source.next(raw);
            if (st == PacketSource::Status::End) break;
            if (st == PacketSource::Status::Timeout) continue;
            if (st == PacketSource::Status::Failed) {
                PLOG_ERROR("reader") << source.errorMessage();
                break;
            }
            if (!PacketParser::parse(raw, parsed)) continue;
            if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp)) continue;
            
            // Create packet
            Packet pkt;
            pkt.id = pkt_id++;
            pkt.ts_sec = raw.header.ts_sec;
            pkt.ts_usec = raw.header.ts_usec;
            pkt.tcp_flags = parsed.tcp_flags;
            pkt.tcp_seq = parsed.seq_number;  // only meaningful for TCP
            pkt.data = std::move(raw.data);
            
            // Parse 5-tuple
            auto parseIP = [](const std::string& ip) -> uint32_t {
                uint32_t result = 0;
                int octet = 0, shift = 0;
                for (char c : ip) {
                    if (c == '.') { result |= (octet << shift); shift += 8; octet = 0; }
                    else if (c >= '0' && c <= '9') octet = octet * 10 + (c - '0');
                }
                return result | (octet << shift);
            };
            
            pkt.tuple.src_ip = parseIP(parsed.src_ip);
            pkt.tuple.dst_ip = parseIP(parsed.dest_ip);
            pkt.tuple.src_port = parsed.src_port;
            pkt.tuple.dst_port = parsed.dest_port;
            pkt.tuple.protocol = parsed.protocol;
            
            // Calculate payload offset
            pkt.payload_offset = 14;  // Ethernet
            if (pkt.data.size() > 14) {
                uint8_t ip_ihl = pkt.data[14] & 0x0F;
                pkt.payload_offset += ip_ihl * 4;
                
                if (parsed.has_tcp && pkt.payload_offset + 12 < pkt.data.size()) {
                    uint8_t tcp_off = (pkt.data[pkt.payload_offset + 12] >> 4) & 0x0F;
                    pkt.payload_offset += tcp_off * 4;
                } else if (parsed.has_udp) {
                    pkt.payload_offset += 8;
                }
                
                if (pkt.payload_offset < pkt.data.size()) {
                    pkt.payload_length = pkt.data.size() - pkt.payload_offset;
                } else {
                    pkt.payload_length = 0;
                }
            }
            
            // Update stats
            stats_.total_packets++;
            stats_.total_bytes += pkt.data.size();
            if (parsed.has_tcp) stats_.tcp_packets++;
            else if (parsed.has_udp) stats_.udp_packets++;
            
            // Dispatch to LB (hash-based)
            FiveTupleHash hasher;
            size_t lb_idx = hasher(pkt.tuple) % lbs_.size();
            lbs_[lb_idx]->queue().push(std::move(pkt));
        }
        
        PLOG_INFO("reader") << "done reading " << pkt_id << " packets";
        if (source.isLive() && source.kernelDrops() > 0) {
            PLOG_WARN("reader") << "kernel dropped " << source.kernelDrops() << " frames";
        }
        source.close();

        // Wait for queues to drain
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        // Stop all threads
        for (auto& lb : lbs_) lb->stop();
        for (auto& fp : fps_) fp->stop();
        
        output_running = false;
        output_queue_.shutdown();
        output_thread.join();
        
        output.close();
        
        // Print report
        printReport();
        
        return true;
    }

    // Prometheus text exposition, safe to call from the metrics thread.
    std::string metricsText() {
        using namespace prism::metrics;
        std::string o;
        o += counter("prism_packets_total", "Frames read from the source",
                     (int64_t)stats_.total_packets.load());
        o += counter("prism_bytes_total", "Bytes read from the source",
                     (int64_t)stats_.total_bytes.load());
        o += counter("prism_tcp_packets_total", "TCP frames", (int64_t)stats_.tcp_packets.load());
        o += counter("prism_udp_packets_total", "UDP frames", (int64_t)stats_.udp_packets.load());
        o += counter("prism_forwarded_total", "Frames forwarded",
                     (int64_t)stats_.forwarded.load());
        o += counter("prism_dropped_total", "Frames dropped by a rule",
                     (int64_t)stats_.dropped.load());

        int64_t qdepth = (int64_t)output_queue_.size();
        for (auto& lb : lbs_) qdepth += (int64_t)lb->queue().size();
        for (auto& fp : fps_) qdepth += (int64_t)fp->queue().size();
        o += gauge("prism_queue_depth", "Packets queued across all stages", qdepth);

        std::vector<std::pair<std::string, int64_t>> apps, labels, ja4s;
        {
            std::lock_guard<std::mutex> lk(stats_.app_mutex);
            for (auto& [a, n] : stats_.app_counts)
                apps.emplace_back(appTypeToString(a), (int64_t)n);
            for (auto& [l, n] : stats_.label_counts) labels.emplace_back(l, (int64_t)n);
            for (auto& [f, n] : stats_.ja4_counts) ja4s.emplace_back(f, (int64_t)n);
        }
        o += labeled("prism_app_packets_total", "Packets per detected app", "counter", "app", apps);
        o += labeled("prism_signature_label_flows", "Flows per signature label", "counter",
                     "label", labels);
        o += labeled("prism_ja4_flows", "Flows per JA4 fingerprint", "counter", "ja4", ja4s);
        return o;
    }

private:
    Config config_;
    Rules rules_;
    Stats stats_;
    TSQueue<Packet> output_queue_;
    std::vector<std::unique_ptr<FastPath>> fps_;
    std::vector<std::unique_ptr<LoadBalancer>> lbs_;

    void printReport() {
        std::cout << "\n";
        std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
        std::cout << "║                      PROCESSING REPORT                        ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ Total Packets:      " << std::setw(12) << stats_.total_packets.load() << "                           ║\n";
        std::cout << "║ Total Bytes:        " << std::setw(12) << stats_.total_bytes.load() << "                           ║\n";
        std::cout << "║ TCP Packets:        " << std::setw(12) << stats_.tcp_packets.load() << "                           ║\n";
        std::cout << "║ UDP Packets:        " << std::setw(12) << stats_.udp_packets.load() << "                           ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ Forwarded:          " << std::setw(12) << stats_.forwarded.load() << "                           ║\n";
        std::cout << "║ Dropped:            " << std::setw(12) << stats_.dropped.load() << "                           ║\n";
        
        // Thread stats
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ THREAD STATISTICS                                             ║\n";
        for (size_t i = 0; i < lbs_.size(); i++) {
            std::cout << "║   LB" << i << " dispatched:   " << std::setw(12) << lbs_[i]->dispatched() << "                           ║\n";
        }
        for (size_t i = 0; i < fps_.size(); i++) {
            std::cout << "║   FP" << i << " processed:    " << std::setw(12) << fps_[i]->processed() << "                           ║\n";
        }
        
        // App distribution
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║                   APPLICATION BREAKDOWN                       ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        
        std::lock_guard<std::mutex> lock(stats_.app_mutex);
        
        std::vector<std::pair<AppType, uint64_t>> sorted_apps(
            stats_.app_counts.begin(), stats_.app_counts.end());
        std::sort(sorted_apps.begin(), sorted_apps.end(),
                  [](const auto& a, const auto& b) { return a.second > b.second; });
        
        uint64_t total = stats_.total_packets.load();
        for (const auto& [app, count] : sorted_apps) {
            double pct = total > 0 ? (100.0 * count / total) : 0;
            int bar = static_cast<int>(pct / 5);
            std::string bar_str(bar, '#');
            
            std::cout << "║ " << std::setw(15) << std::left << appTypeToString(app)
                      << std::setw(8) << std::right << count
                      << " " << std::setw(5) << std::fixed << std::setprecision(1) << pct << "% "
                      << std::setw(20) << std::left << bar_str << "  ║\n";
        }
        
        std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
        
        // Detected SNIs
        if (!stats_.detected_snis.empty()) {
            std::cout << "\n[Detected Domains/SNIs]\n";
            for (const auto& [sni, app] : stats_.detected_snis) {
                std::cout << "  - " << sni << " -> " << appTypeToString(app) << "\n";
            }
        }

        if (!stats_.label_counts.empty()) {
            std::cout << "\n[Signature Labels]\n";
            for (const auto& [lbl, n] : stats_.label_counts)
                std::cout << "  " << lbl << "  x" << n << "\n";
        }

        if (!stats_.ja3_counts.empty()) {
            std::cout << "\n[TLS Fingerprints]\n";
            for (const auto& [fp, n] : stats_.ja3_counts)
                std::cout << "  JA3  " << fp << "  x" << n << "\n";
            for (const auto& [fp, n] : stats_.ja4_counts)
                std::cout << "  JA4  " << fp << "  x" << n << "\n";
        }
    }
};

// =============================================================================
// Main
// =============================================================================
void printUsage(const char* prog) {
    std::cout << "\nPrism v2.0 - Multi-threaded Deep Packet Inspection Engine\n"
              << "========================================================\n\n"
              << "Usage: " << prog << " (<input.pcap> | --iface <name>) [options]\n\n"
              << captureHelp()
              << "\nEngine:\n"
                 "  --block-ip <ip>        Block source IP\n"
                 "  --block-app <app>     Block application (YouTube, Facebook, ...)\n"
                 "  --block-domain <dom>  Block domain (substring match)\n"
                 "  --lbs <n>             Load balancer threads (default: 2)\n"
                 "  --fps <n>             FP threads per LB (default: 2)\n\n"
              << "Examples:\n"
              << "  " << prog << " capture.pcap -o filtered.pcap --block-app YouTube\n"
              << "  sudo " << prog << " --iface eth0 --block-domain tiktok\n";
}

int main(int argc, char* argv[]) {
    RunOptions opt;
    std::string err;
    if (!parseRunOptions(argc, argv, opt, err)) {
        std::cerr << "prism: " << err << "\n";
        return 2;
    }
    if (opt.help || (opt.pcap_in.empty() && opt.iface.empty())) {
        printUsage(argv[0]);
        return opt.help ? 0 : 1;
    }

    prism::LogLevel lvl;
    if (!prism::parseLogLevel(opt.log_level, lvl)) {
        std::cerr << "prism: unknown --log-level '" << opt.log_level << "'\n";
        return 2;
    }
    prism::setLogLevel(lvl);
    prism::setLogJson(opt.log_json);

    // Engine-specific flags left over by parseRunOptions.
    DPIEngine::Config cfg;
    std::vector<std::string> block_ips, block_apps, block_domains;
    for (size_t i = 0; i < opt.rest.size(); ++i) {
        const std::string& a = opt.rest[i];
        auto val = [&]() -> std::string {
            return (i + 1 < opt.rest.size()) ? opt.rest[++i] : std::string();
        };
        if (a == "--block-ip") block_ips.push_back(val());
        else if (a == "--block-app") block_apps.push_back(val());
        else if (a == "--block-domain") block_domains.push_back(val());
        else if (a == "--lbs") cfg.num_lbs = std::stoi(val());
        else if (a == "--fps") cfg.fps_per_lb = std::stoi(val());
        else { std::cerr << "prism: unknown option '" << a << "'\n"; return 2; }
    }

    if (!opt.signatures.empty() && !loadSignatureFile(opt.signatures, err)) {
        std::cerr << "prism: " << err << "\n";
        return 1;
    }

    auto source = openSource(opt, err);
    if (!source) {
        std::cerr << "prism: " << err << "\n";
        return 1;
    }

    std::signal(SIGINT, [](int) { g_running = false; });
    std::signal(SIGTERM, [](int) { g_running = false; });

    DPIEngine engine(cfg);
    for (const auto& ip : block_ips) engine.blockIP(ip);
    for (const auto& app : block_apps) engine.blockApp(app);
    for (const auto& dom : block_domains) engine.blockDomain(dom);

    std::unique_ptr<prism::MetricsServer> metrics;
    std::string mhost;
    uint16_t mport = 0;
    if (metricsEndpoint(opt, mhost, mport, err)) {
        metrics = std::make_unique<prism::MetricsServer>(
            mhost, mport, [&engine] { return engine.metricsText(); });
        if (!metrics->start(err)) {
            std::cerr << "prism: " << err << "\n";
            return 1;
        }
    } else if (!err.empty()) {
        std::cerr << "prism: " << err << "\n";
        return 2;
    }

    bool ok = engine.process(*source, opt.pcap_out, opt.max_frames);
    if (metrics) metrics->stop();
    if (!ok) return 1;

    std::cout << "\nOutput written to: " << opt.pcap_out << "\n";
    return 0;
}
