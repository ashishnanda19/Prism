// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================
//
// Fallback driver used when the toolchain has no libFuzzer runtime
// (notably Apple clang). It just replays every file given on the command
// line -- or every *.bin under a directory -- through LLVMFuzzerTestOneInput,
// so the harnesses still build and run under ASan/UBSan locally and in CI.
//
// Real coverage-guided fuzzing happens in the Linux/clang CI job, which
// links the same .cc files against -fsanitize=fuzzer instead of this file.

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

namespace {

int runFile(const std::filesystem::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) {
        std::fprintf(stderr, "skip (unreadable): %s\n", p.string().c_str());
        return 0;
    }
    std::vector<uint8_t> buf((std::istreambuf_iterator<char>(f)),
                             std::istreambuf_iterator<char>());
    return LLVMFuzzerTestOneInput(buf.data(), buf.size());
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        // No inputs: exercise the empty buffer so the harness is never a no-op.
        const uint8_t empty = 0;
        return LLVMFuzzerTestOneInput(&empty, 0);
    }

    int rc = 0;
    size_t n = 0;
    for (int i = 1; i < argc; ++i) {
        if (argv[i][0] == '-') continue;  // ignore libFuzzer-style flags
        std::filesystem::path arg(argv[i]);
        std::error_code ec;
        if (std::filesystem::is_directory(arg, ec)) {
            for (const auto& entry : std::filesystem::recursive_directory_iterator(arg, ec)) {
                if (entry.is_regular_file()) {
                    rc |= runFile(entry.path());
                    ++n;
                }
            }
        } else {
            rc |= runFile(arg);
            ++n;
        }
    }
    std::fprintf(stderr, "[standalone] replayed %zu input(s)\n", n);
    return rc;
}
