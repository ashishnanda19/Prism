// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================

#include "signature_set.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>

namespace DPI {

namespace {

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

bool kindFromString(const std::string& k, SignatureSet::Kind& out) {
    if (k == "suffix") out = SignatureSet::Kind::Suffix;
    else if (k == "contains") out = SignatureSet::Kind::Contains;
    else if (k == "exact") out = SignatureSet::Kind::Exact;
    else if (k == "ja3") out = SignatureSet::Kind::Ja3;
    else if (k == "ja3hash") out = SignatureSet::Kind::Ja3Hash;
    else if (k == "ja4") out = SignatureSet::Kind::Ja4;
    else if (k == "ja4prefix") out = SignatureSet::Kind::Ja4Prefix;
    else return false;
    return true;
}

bool hostEndsWithLabel(const std::string& host, const std::string& dom) {
    if (host == dom) return true;
    if (host.size() <= dom.size()) return false;
    return host.compare(host.size() - dom.size() - 1, dom.size() + 1, "." + dom) == 0;
}

}  // namespace

void SignatureSet::clear() { rules_.clear(); }

void SignatureSet::add(Kind kind, std::string pattern, std::string app) {
    bool host_kind = kind == Kind::Suffix || kind == Kind::Contains || kind == Kind::Exact;
    rules_.push_back({kind, host_kind ? lower(std::move(pattern)) : std::move(pattern),
                      std::move(app)});
}

bool SignatureSet::loadString(const std::string& text, std::string& err, const char* src) {
    std::vector<Rule> parsed;
    std::istringstream in(text);
    std::string line;
    int lineno = 0;
    while (std::getline(in, line)) {
        ++lineno;
        std::string t = trim(line);
        if (t.empty() || t[0] == '#') continue;

        std::istringstream ls(t);
        std::string kind_s, pattern, app_rest;
        ls >> kind_s >> pattern;
        std::getline(ls, app_rest);
        std::string app = trim(app_rest);

        Kind kind;
        if (!kindFromString(kind_s, kind)) {
            err = std::string(src) + ":" + std::to_string(lineno) + ": unknown rule kind '" +
                  kind_s + "'";
            return false;
        }
        if (pattern.empty() || app.empty()) {
            err = std::string(src) + ":" + std::to_string(lineno) +
                  ": expected '<kind> <pattern> <app>'";
            return false;
        }
        bool host_kind = kind == Kind::Suffix || kind == Kind::Contains || kind == Kind::Exact;
        parsed.push_back({kind, host_kind ? lower(pattern) : pattern, app});
    }
    rules_ = std::move(parsed);
    return true;
}

bool SignatureSet::loadFile(const std::string& path, std::string& err) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        err = "cannot open signatures file: " + path;
        return false;
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    return loadString(ss.str(), err, path.c_str());
}

const char* SignatureSet::kindName(Kind k) {
    switch (k) {
        case Kind::Suffix: return "suffix";
        case Kind::Contains: return "contains";
        case Kind::Exact: return "exact";
        case Kind::Ja3: return "ja3";
        case Kind::Ja3Hash: return "ja3hash";
        case Kind::Ja4: return "ja4";
        case Kind::Ja4Prefix: return "ja4prefix";
    }
    return "?";
}

const SignatureSet::Rule* SignatureSet::matchHostRule(const std::string& host_in) const {
    const std::string host = lower(host_in);
    for (const auto& r : rules_) {
        switch (r.kind) {
            case Kind::Suffix:
                if (hostEndsWithLabel(host, r.pattern)) return &r;
                break;
            case Kind::Contains:
                if (host.find(r.pattern) != std::string::npos) return &r;
                break;
            case Kind::Exact:
                if (host == r.pattern) return &r;
                break;
            default:
                break;
        }
    }
    return nullptr;
}

const SignatureSet::Rule* SignatureSet::matchJa3Rule(const std::string& ja3_string,
                                                     const std::string& ja3_hash) const {
    for (const auto& r : rules_) {
        if (r.kind == Kind::Ja3 && r.pattern == ja3_string) return &r;
        if (r.kind == Kind::Ja3Hash && r.pattern == ja3_hash) return &r;
    }
    return nullptr;
}

const SignatureSet::Rule* SignatureSet::matchJa4Rule(const std::string& ja4_in) const {
    for (const auto& r : rules_) {
        if (r.kind == Kind::Ja4 && r.pattern == ja4_in) return &r;
        if (r.kind == Kind::Ja4Prefix && ja4_in.compare(0, r.pattern.size(), r.pattern) == 0)
            return &r;
    }
    return nullptr;
}

std::string SignatureSet::matchHost(const std::string& host) const {
    const Rule* r = matchHostRule(host);
    return r ? r->app : "";
}

std::string SignatureSet::matchJa3(const std::string& ja3_string,
                                   const std::string& ja3_hash) const {
    const Rule* r = matchJa3Rule(ja3_string, ja3_hash);
    return r ? r->app : "";
}

std::string SignatureSet::matchJa4(const std::string& ja4_in) const {
    const Rule* r = matchJa4Rule(ja4_in);
    return r ? r->app : "";
}

// ---------------------------------------------------------------------------
// Built-in default: mirrors the previous hard-coded sniToAppType() table.
// ---------------------------------------------------------------------------
const char* builtinSignatureRules() {
    return R"(# Prism built-in application signatures (host / SNI based).
# JA3 / JA4 rules can be added here or supplied via --signatures.

contains  google           Google
contains  gstatic          Google
contains  googleapis       Google
contains  ggpht            Google
contains  gvt1             Google

contains  youtube          YouTube
contains  ytimg            YouTube
suffix    youtu.be         YouTube

contains  facebook         Facebook
contains  fbcdn            Facebook
contains  fbsbx            Facebook
suffix    fb.com           Facebook
suffix    meta.com         Facebook

contains  instagram        Instagram
contains  cdninstagram     Instagram

contains  whatsapp         WhatsApp
suffix    wa.me            WhatsApp

contains  twitter          Twitter/X
contains  twimg            Twitter/X
suffix    x.com            Twitter/X
suffix    t.co             Twitter/X

contains  netflix          Netflix
contains  nflxvideo        Netflix
contains  nflximg          Netflix

contains  amazon           Amazon
contains  amazonaws        Amazon
contains  cloudfront       Amazon
contains  aws              Amazon

contains  microsoft        Microsoft
contains  msn.com          Microsoft
contains  office           Microsoft
contains  azure            Microsoft
contains  live.com         Microsoft
contains  outlook          Microsoft
contains  bing             Microsoft

contains  apple            Apple
contains  icloud           Apple
contains  mzstatic         Apple
contains  itunes           Apple

contains  telegram         Telegram
suffix    t.me             Telegram

contains  tiktok           TikTok
contains  tiktokcdn        TikTok
contains  musical.ly       TikTok
contains  bytedance        TikTok

contains  spotify          Spotify
contains  scdn.co          Spotify

contains  zoom             Zoom

contains  discord          Discord
contains  discordapp       Discord

contains  github           GitHub
contains  githubusercontent GitHub

contains  cloudflare       Cloudflare
contains  cf-              Cloudflare
)";
}

std::string classifyLabel(const std::string& host, const std::string& ja3_string,
                          const std::string& ja3_hash, const std::string& ja4) {
    const SignatureSet& s = activeSignatures();
    std::string lbl;
    if (!host.empty()) lbl = s.matchHost(host);
    if (lbl.empty() && (!ja3_string.empty() || !ja3_hash.empty()))
        lbl = s.matchJa3(ja3_string, ja3_hash);
    if (lbl.empty() && !ja4.empty()) lbl = s.matchJa4(ja4);
    return lbl;
}

SignatureSet& activeSignatures() {
    static SignatureSet* s = [] {
        auto* set = new SignatureSet();
        std::string err;
        set->loadString(builtinSignatureRules(), err, "<builtin>");
        return set;
    }();
    return *s;
}

bool loadSignatureFile(const std::string& path, std::string& err) {
    return activeSignatures().loadFile(path, err);
}

}  // namespace DPI
