// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================

#ifndef PRISM_CAPTURE_CLI_H
#define PRISM_CAPTURE_CLI_H

#include <memory>
#include <string>
#include <vector>

#include "packet_source.h"

namespace PacketAnalyzer {

// ============================================================================
// Shared command-line surface for the engines: choosing an input (a .pcap
// file or a live interface), the output file, and capture limits. Anything
// the parser does not recognise is left in `rest` for the engine to handle
// (--block-*, --lbs, --fps, ...).
// ============================================================================
struct RunOptions {
    std::string pcap_in;      // file mode: path to a .pcap  (mutually exclusive with iface)
    std::string iface;        // live mode: interface name   (needs root / CAP_NET_RAW)
    std::string pcap_out;     // where forwarded frames are written
    std::string signatures;   // optional: replace the built-in signature set
    std::string metrics_bind; // "" = off; "host:port" | "port" | ":port" for /metrics
    std::string log_level = "info";
    bool log_json = false;

    long max_frames = -1;      // stop after N frames read (-1 = unlimited)
    int  snaplen    = 262144;  // bytes captured per frame (live)
    bool promiscuous = true;   // put the interface in promiscuous mode (live)
    bool loop = false;        // file mode: restart at EOF (demos / load tests)
    bool help = false;

    std::vector<std::string> rest;  // unrecognised args, in order
};

// Parse argv (skipping argv[0]). Recognises:
//   <path.pcap>                 positional input file
//   -i, --iface <name>          live capture on <name>
//   -o, --output, -w <path>     output pcap (default: prism-out.pcap)
//   -c, --count <n>             stop after n frames
//   --snaplen <n>               live snap length
//   --promisc / --no-promisc    promiscuous mode (default on)
//   -h, --help
// Returns false and fills `err` on a malformed value or an input/iface clash.
bool parseRunOptions(int argc, char** argv, RunOptions& out, std::string& err);

// Help text for the shared options (engines append their own).
std::string captureHelp();

// Split RunOptions::metrics_bind into host + port. Returns false when metrics
// are disabled (empty) or the spec is malformed (fills `err`).
bool metricsEndpoint(const RunOptions& opt, std::string& host, uint16_t& port,
                     std::string& err);

// Build the PacketSource described by `opt`. Returns nullptr and fills `err`
// on failure (missing input, unknown interface, insufficient privileges,
// unsupported link type, ...).
std::unique_ptr<PacketSource> openSource(const RunOptions& opt, std::string& err);

}  // namespace PacketAnalyzer

#endif  // PRISM_CAPTURE_CLI_H
