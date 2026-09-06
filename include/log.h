// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================
//
// Small structured logger. One line per record, thread-safe, to stderr by
// default. Human-readable format normally; `--log-json` switches to JSON lines
// for ingestion. Report tables still go to stdout -- those are output, not logs.
//
//   PLOG_INFO("reader") << "captured " << n << " frames";
//   PLOG_WARN("rules")  << "unknown app: " << name;

#ifndef PRISM_LOG_H
#define PRISM_LOG_H

#include <ostream>
#include <sstream>
#include <string>

namespace prism {

enum class LogLevel { Trace, Debug, Info, Warn, Error, Off };

bool parseLogLevel(const std::string& s, LogLevel& out);
const char* logLevelName(LogLevel l);

void setLogLevel(LogLevel l);
LogLevel logLevel();
void setLogJson(bool on);
void setLogStream(std::ostream* os);  // nullptr => back to std::cerr

bool logEnabled(LogLevel l);
void logEmit(LogLevel l, const char* component, const std::string& msg);

// Stream builder: accumulates until destruction, then emits one record iff the
// level is enabled.
class LogLine {
public:
    LogLine(LogLevel level, const char* component)
        : level_(level), component_(component), on_(logEnabled(level)) {}
    ~LogLine() {
        if (on_) logEmit(level_, component_, buf_.str());
    }
    LogLine(const LogLine&) = delete;
    LogLine& operator=(const LogLine&) = delete;

    template <class T>
    LogLine& operator<<(const T& v) {
        if (on_) buf_ << v;
        return *this;
    }

private:
    LogLevel level_;
    const char* component_;
    bool on_;
    std::ostringstream buf_;
};

}  // namespace prism

#define PLOG(LEVEL, COMP) ::prism::LogLine(::prism::LogLevel::LEVEL, COMP)
#define PLOG_TRACE(COMP) PLOG(Trace, COMP)
#define PLOG_DEBUG(COMP) PLOG(Debug, COMP)
#define PLOG_INFO(COMP) PLOG(Info, COMP)
#define PLOG_WARN(COMP) PLOG(Warn, COMP)
#define PLOG_ERROR(COMP) PLOG(Error, COMP)

#endif  // PRISM_LOG_H
