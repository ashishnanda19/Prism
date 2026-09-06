// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================
//
// Helpers to emit the Prometheus text exposition format. No client library:
// an engine builds a std::string of metrics at scrape time and MetricsServer
// serves it on GET /metrics.

#ifndef PRISM_METRICS_H
#define PRISM_METRICS_H

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace prism::metrics {

// One `# HELP` + `# TYPE` + value line.
std::string scalar(const std::string& name, const std::string& help, const char* type,
                   int64_t value);

inline std::string counter(const std::string& name, const std::string& help, int64_t v) {
    return scalar(name, help, "counter", v);
}
inline std::string gauge(const std::string& name, const std::string& help, int64_t v) {
    return scalar(name, help, "gauge", v);
}

// A labelled family: name{label_key="<v>"} value, one line per pair.
std::string labeled(const std::string& name, const std::string& help, const char* type,
                    const std::string& label_key,
                    const std::vector<std::pair<std::string, int64_t>>& series);

}  // namespace prism::metrics

#endif  // PRISM_METRICS_H
