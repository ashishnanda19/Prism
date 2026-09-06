// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================
//
// Data-driven application signatures. Replaces the hard-coded sniToAppType()
// substring chain: rules live in a plain-text file (or the built-in default)
// and map an SNI / host, a JA3, or a JA4 to an application label.
//
// File format -- one rule per line, "#" starts a comment:
//
//     <kind>  <pattern>  <app label ...>
//
//   suffix     example.com     Example        # host == pattern or *.pattern
//   contains   googlevideo     YouTube        # substring of the host
//   exact      t.co            Twitter/X      # host == pattern
//   ja3        771,4865-...    SomeClient     # exact JA3 pre-hash string
//   ja3hash    a0e9f5d6...     SomeClient     # exact JA3 md5 hex
//   ja4        t13d1516h2_..._...  SomeClient # exact JA4
//   ja4prefix  t13d             GoClient      # JA4_a (client family) prefix
//
// First matching rule of the relevant kind wins (file order = priority).

#ifndef PRISM_SIGNATURE_SET_H
#define PRISM_SIGNATURE_SET_H

#include <string>
#include <vector>

namespace DPI {

class SignatureSet {
public:
    enum class Kind { Suffix, Contains, Exact, Ja3, Ja3Hash, Ja4, Ja4Prefix };
    struct Rule {
        Kind kind;
        std::string pattern;  // lowercased for host kinds
        std::string app;
    };

    // Replace all rules with those parsed from `text` / `path`.
    // Returns false and fills `err` (with "file:line: message") on a parse error.
    bool loadString(const std::string& text, std::string& err, const char* src = "<string>");
    bool loadFile(const std::string& path, std::string& err);

    void add(Kind kind, std::string pattern, std::string app);
    void clear();
    std::size_t size() const { return rules_.size(); }
    const std::vector<Rule>& rules() const { return rules_; }

    // Return the app label of the first matching rule, or "" if none.
    std::string matchHost(const std::string& host) const;
    std::string matchJa3(const std::string& ja3_string, const std::string& ja3_hash) const;
    std::string matchJa4(const std::string& ja4) const;

    // Same, but also hand back the rule that matched (nullptr on no match) so
    // callers can explain *why* a flow was attributed.
    const Rule* matchHostRule(const std::string& host) const;
    const Rule* matchJa3Rule(const std::string& ja3_string, const std::string& ja3_hash) const;
    const Rule* matchJa4Rule(const std::string& ja4) const;

    static const char* kindName(Kind k);

private:
    std::vector<Rule> rules_;
};

// The richest label for a flow from the active set: SNI/host match first,
// then JA3 (pre-hash string or md5), then JA4. Returns "" if nothing matches.
std::string classifyLabel(const std::string& host, const std::string& ja3_string,
                          const std::string& ja3_hash, const std::string& ja4);

// Process-wide active set. Starts as the built-in default; an engine may
// replace it once, at startup, from --signatures <file>.
SignatureSet& activeSignatures();
bool loadSignatureFile(const std::string& path, std::string& err);  // replaces activeSignatures()
const char* builtinSignatureRules();

}  // namespace DPI

#endif  // PRISM_SIGNATURE_SET_H
