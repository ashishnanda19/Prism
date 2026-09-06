// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================

#include "metrics.h"

namespace prism::metrics {

namespace {
std::string escapeLabel(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 4);
    for (char c : s) {
        if (c == '\\') o += "\\\\";
        else if (c == '"') o += "\\\"";
        else if (c == '\n') o += "\\n";
        else o += c;
    }
    return o;
}
}  // namespace

std::string scalar(const std::string& name, const std::string& help, const char* type,
                   int64_t value) {
    std::string o;
    o += "# HELP " + name + " " + help + "\n";
    o += "# TYPE " + name + " " + type + "\n";
    o += name + " " + std::to_string(value) + "\n";
    return o;
}

std::string labeled(const std::string& name, const std::string& help, const char* type,
                    const std::string& label_key,
                    const std::vector<std::pair<std::string, int64_t>>& series) {
    std::string o;
    o += "# HELP " + name + " " + help + "\n";
    o += "# TYPE " + name + " " + type + "\n";
    for (const auto& [label, v] : series) {
        o += name + "{" + label_key + "=\"" + escapeLabel(label) + "\"} " + std::to_string(v) +
             "\n";
    }
    return o;
}

}  // namespace prism::metrics
