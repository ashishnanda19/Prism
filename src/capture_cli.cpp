// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================

#include "capture_cli.h"

#include <cstdlib>
#include <cstring>
#include <string>

#include "pcap_reader.h"

namespace PacketAnalyzer {

namespace {
bool wantsValue(const std::string& a) {
    return a == "-i" || a == "--iface" || a == "-o" || a == "--output" || a == "-w" ||
           a == "-c" || a == "--count" || a == "--snaplen" || a == "--signatures" ||
           a == "--metrics" || a == "--log-level";
}
}  // namespace

bool parseRunOptions(int argc, char** argv, RunOptions& out, std::string& err) {
    out = RunOptions{};
    out.pcap_out = "prism-out.pcap";

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        const char* val = (i + 1 < argc) ? argv[i + 1] : nullptr;

        if (a == "-h" || a == "--help") {
            out.help = true;
            return true;
        }
        if (wantsValue(a) && !val) {
            err = a + " needs a value";
            return false;
        }

        if (a == "-i" || a == "--iface") {
            out.iface = val;
            ++i;
        } else if (a == "-o" || a == "--output" || a == "-w") {
            out.pcap_out = val;
            ++i;
        } else if (a == "-c" || a == "--count") {
            char* endp = nullptr;
            out.max_frames = std::strtol(val, &endp, 10);
            if (endp == val || out.max_frames < 0) {
                err = "--count expects a non-negative integer";
                return false;
            }
            ++i;
        } else if (a == "--snaplen") {
            char* endp = nullptr;
            out.snaplen = static_cast<int>(std::strtol(val, &endp, 10));
            if (endp == val || out.snaplen <= 0) {
                err = "--snaplen expects a positive integer";
                return false;
            }
            ++i;
        } else if (a == "--signatures") {
            out.signatures = val;
            ++i;
        } else if (a == "--metrics") {
            out.metrics_bind = val;
            ++i;
        } else if (a == "--log-level") {
            out.log_level = val;
            ++i;
        } else if (a == "--log-json") {
            out.log_json = true;
        } else if (a == "--loop") {
            out.loop = true;
        } else if (a == "--promisc") {
            out.promiscuous = true;
        } else if (a == "--no-promisc") {
            out.promiscuous = false;
        } else if (!a.empty() && a[0] != '-' && out.pcap_in.empty() && out.iface.empty()) {
            out.pcap_in = a;  // the one positional: input pcap
        } else {
            out.rest.push_back(a);  // engine-specific; leave it
        }
    }

    if (!out.pcap_in.empty() && !out.iface.empty()) {
        err = "give either a .pcap file or --iface, not both";
        return false;
    }
    return true;
}

std::string captureHelp() {
    return
        "Input / capture:\n"
        "  <file.pcap>            read frames from a capture file\n"
        "  -i, --iface <name>    capture live from an interface (needs root / CAP_NET_RAW)\n"
        "  -o, --output <file>   write forwarded frames here (default: prism-out.pcap)\n"
        "  -c, --count <n>       stop after n frames\n"
        "      --snaplen <n>     bytes captured per frame, live (default: 262144)\n"
        "      --promisc / --no-promisc   promiscuous mode, live (default: on)\n"
        "      --signatures <f>  load app signatures from <f> (replaces the built-ins)\n"
        "      --metrics <a>    serve Prometheus /metrics on <a> (host:port | port)\n"
        "      --log-level <l>  trace|debug|info|warn|error|off (default: info)\n"
        "      --loop           file mode: replay from the top at EOF\n"
        "      --log-json       emit logs as JSON lines\n"
        "  -h, --help\n";
}

bool metricsEndpoint(const RunOptions& opt, std::string& host, uint16_t& port,
                     std::string& err) {
    if (opt.metrics_bind.empty()) return false;
    const std::string& spec = opt.metrics_bind;
    std::string h = "127.0.0.1";
    std::string p;
    auto colon = spec.rfind(':');
    if (colon == std::string::npos) {
        p = spec;  // bare port
    } else {
        if (colon > 0) h = spec.substr(0, colon);
        p = spec.substr(colon + 1);
    }
    char* endp = nullptr;
    long pn = std::strtol(p.c_str(), &endp, 10);
    if (endp == p.c_str() || *endp != '\0' || pn < 0 || pn > 65535) {
        err = "bad --metrics endpoint '" + opt.metrics_bind + "' (want host:port or port)";
        return false;
    }
    host = h;
    port = static_cast<uint16_t>(pn);
    return true;
}

std::unique_ptr<PacketSource> openSource(const RunOptions& opt, std::string& err) {
    if (!opt.iface.empty()) {
        auto src = openLiveInterface(opt.iface, opt.snaplen, opt.promiscuous,
                                     /*poll_timeout_ms=*/200, err);
        if (!src) return nullptr;
        if (src->linkType() != LINKTYPE_ETHERNET) {
            err = "interface '" + opt.iface + "' has link type " +
                  std::to_string(src->linkType()) +
                  "; Prism only decodes Ethernet (1). Try a physical interface.";
            return nullptr;
        }
        return src;
    }

    if (opt.pcap_in.empty()) {
        err = "no input: pass a .pcap file or --iface <name>";
        return nullptr;
    }
    auto reader = std::make_unique<PcapReader>();
    reader->setLoop(opt.loop);
    if (!reader->open(opt.pcap_in)) {
        err = "cannot open pcap file: " + opt.pcap_in;
        return nullptr;
    }
    return reader;
}

}  // namespace PacketAnalyzer
