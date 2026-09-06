// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================

#include "log.h"

#include <atomic>
#include <cstdio>
#include <ctime>
#include <iostream>
#include <mutex>

namespace prism {

namespace {
std::atomic<int> g_level{static_cast<int>(LogLevel::Info)};
std::atomic<bool> g_json{false};
std::ostream* g_stream = &std::cerr;
std::mutex g_mutex;

std::string nowIso8601() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char b[32];
    std::strftime(b, sizeof(b), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return b;
}

std::string jsonEscape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char u[8];
                    std::snprintf(u, sizeof(u), "\\u%04x", static_cast<unsigned char>(c));
                    o += u;
                } else {
                    o += c;
                }
        }
    }
    return o;
}
}  // namespace

bool parseLogLevel(const std::string& s, LogLevel& out) {
    if (s == "trace") out = LogLevel::Trace;
    else if (s == "debug") out = LogLevel::Debug;
    else if (s == "info") out = LogLevel::Info;
    else if (s == "warn" || s == "warning") out = LogLevel::Warn;
    else if (s == "error") out = LogLevel::Error;
    else if (s == "off" || s == "none") out = LogLevel::Off;
    else return false;
    return true;
}

const char* logLevelName(LogLevel l) {
    switch (l) {
        case LogLevel::Trace: return "trace";
        case LogLevel::Debug: return "debug";
        case LogLevel::Info: return "info";
        case LogLevel::Warn: return "warn";
        case LogLevel::Error: return "error";
        case LogLevel::Off: return "off";
    }
    return "info";
}

void setLogLevel(LogLevel l) { g_level.store(static_cast<int>(l)); }
LogLevel logLevel() { return static_cast<LogLevel>(g_level.load()); }
void setLogJson(bool on) { g_json.store(on); }
void setLogStream(std::ostream* os) {
    std::lock_guard<std::mutex> lk(g_mutex);
    g_stream = os ? os : &std::cerr;
}

bool logEnabled(LogLevel l) { return static_cast<int>(l) >= g_level.load(); }

void logEmit(LogLevel l, const char* component, const std::string& msg) {
    if (!logEnabled(l)) return;
    const std::string ts = nowIso8601();
    std::lock_guard<std::mutex> lk(g_mutex);
    if (!g_stream) return;
    if (g_json.load()) {
        (*g_stream) << "{\"ts\":\"" << ts << "\",\"level\":\"" << logLevelName(l)
                    << "\",\"comp\":\"" << (component ? component : "") << "\",\"msg\":\""
                    << jsonEscape(msg) << "\"}\n";
    } else {
        const char* lname = logLevelName(l);
        (*g_stream) << ts << "  " << lname;
        for (size_t i = std::string(lname).size(); i < 5; ++i) (*g_stream) << ' ';
        (*g_stream) << ' ' << (component ? component : "-") << ": " << msg << '\n';
    }
    g_stream->flush();
}

}  // namespace prism
