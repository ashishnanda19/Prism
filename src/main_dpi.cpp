// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================

#include <csignal>
#include <iostream>
#include <string>
#include <sstream>
#include <vector>

#include "capture_cli.h"
#include "dpi_engine.h"

using namespace DPI;
using PacketAnalyzer::RunOptions;

void printUsage(const char* program) {
    std::cout << R"(
╔══════════════════════════════════════════════════════════════╗
║                         PRISM v1.0                           ║
║               Deep Packet Inspection Engine                   ║
╚══════════════════════════════════════════════════════════════╝

Usage: )" << program << R"( (<input.pcap> | --iface <name>) [options]

)" << PacketAnalyzer::captureHelp() << R"(
Engine:
  --block-ip <ip>       Block packets from source IP
  --block-app <app>     Block application (e.g. YouTube, Facebook)
  --block-domain <dom>  Block domain (supports wildcards: *.facebook.com)
  --rules <file>        Load blocking rules from file
  --lbs <n>             Load balancer threads (default: 2)
  --fps <n>             FP threads per LB (default: 2)
  --verbose             Enable verbose output

Examples:
  )" << program << R"( capture.pcap -o filtered.pcap --block-app YouTube
  sudo )" << program << R"( --iface eth0 --block-domain *.tiktok.com
  )" << program << R"( capture.pcap -o filtered.pcap --rules blocking_rules.txt

Supported Apps for Blocking:
  Google, YouTube, Facebook, Instagram, Twitter/X, Netflix, Amazon,
  Microsoft, Apple, WhatsApp, Telegram, TikTok, Spotify, Zoom, Discord, GitHub

Architecture:
  ┌─────────────┐
  │ PCAP Reader │  Reads packets from input file
  └──────┬──────┘
         │ hash(5-tuple) % num_lbs
         ▼
  ┌──────┴──────┐
  │ Load Balancer │  2 LB threads distribute to FPs
  │   LB0 │ LB1   │
  └──┬────┴────┬──┘
     │         │  hash(5-tuple) % fps_per_lb
     ▼         ▼
  ┌──┴──┐   ┌──┴──┐
  │FP0-1│   │FP2-3│  4 FP threads: DPI, classification, blocking
  └──┬──┘   └──┬──┘
     │         │
     ▼         ▼
  ┌──┴─────────┴──┐
  │ Output Writer │  Writes forwarded packets to output
  └───────────────┘

)";
}

int main(int argc, char* argv[]) {
    RunOptions opt;
    std::string err;
    if (!PacketAnalyzer::parseRunOptions(argc, argv, opt, err)) {
        std::cerr << "prism-classic: " << err << "\n";
        return 2;
    }
    if (opt.help || (opt.pcap_in.empty() && opt.iface.empty())) {
        printUsage(argv[0]);
        return opt.help ? 0 : 1;
    }

    DPIEngine::Config config;
    config.num_load_balancers = 2;
    config.fps_per_lb = 2;

    std::vector<std::string> block_ips, block_apps, block_domains;
    std::string rules_file;

    for (size_t i = 0; i < opt.rest.size(); ++i) {
        const std::string& a = opt.rest[i];
        auto val = [&]() -> std::string {
            return (i + 1 < opt.rest.size()) ? opt.rest[++i] : std::string();
        };
        if (a == "--block-ip") block_ips.push_back(val());
        else if (a == "--block-app") block_apps.push_back(val());
        else if (a == "--block-domain") block_domains.push_back(val());
        else if (a == "--rules") rules_file = val();
        else if (a == "--lbs") config.num_load_balancers = std::stoi(val());
        else if (a == "--fps") config.fps_per_lb = std::stoi(val());
        else if (a == "--verbose") config.verbose = true;
        else { std::cerr << "prism-classic: unknown option '" << a << "'\n"; return 2; }
    }

    auto source = PacketAnalyzer::openSource(opt, err);
    if (!source) {
        std::cerr << "prism-classic: " << err << "\n";
        return 1;
    }

    std::signal(SIGINT, [](int) { g_dpi_running = false; });
    std::signal(SIGTERM, [](int) { g_dpi_running = false; });

    DPIEngine engine(config);
    if (!engine.initialize()) {
        std::cerr << "Failed to initialize DPI engine\n";
        return 1;
    }
    if (!rules_file.empty()) engine.loadRules(rules_file);
    for (const auto& ip : block_ips) engine.blockIP(ip);
    for (const auto& app : block_apps) engine.blockApp(app);
    for (const auto& domain : block_domains) engine.blockDomain(domain);

    if (!engine.processFile(*source, opt.pcap_out, opt.max_frames)) {
        std::cerr << "Failed to process\n";
        return 1;
    }

    std::cout << "\nProcessing complete!\n";
    std::cout << "Output written to: " << opt.pcap_out << "\n";
    return 0;
}
