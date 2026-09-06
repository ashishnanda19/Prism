# Prism fuzz harnesses

Coverage-guided fuzz targets for the wire-format parsers -- the code paths that
walk attacker-controlled length fields.

| Harness | Exercises |
|---------|-----------|
| `fuzz_packet_parser` | `PacketParser::parse` (Ethernet / IPv4 / TCP / UDP) |
| `fuzz_sni_extractor` | `SNIExtractor::extract` (TLS ClientHello → SNI) + `sniToAppType` |
| `fuzz_quic_sni`       | `QUICSNIExtractor::extract` (embedded ClientHello scan) |
| `fuzz_http_host`      | `HTTPHostExtractor::extract` (HTTP `Host:` header) |
| `fuzz_dns`            | `DNSExtractor::extractQuery` (QNAME label walk) |
| `fuzz_pcap_reader`    | `PcapReader` global header + `readNextPacket` loop |

## Build & run

Requires Clang. On Linux (has a libFuzzer runtime) the harnesses are
coverage-guided; elsewhere (e.g. Apple clang) they fall back to
`standalone_main.cc`, which just replays every file passed on the command line.

```bash
cmake -S . -B build-fuzz -DCMAKE_CXX_COMPILER=clang++ \
      -DPRISM_BUILD_FUZZERS=ON -DPRISM_BUILD_TESTS=OFF \
      -DPRISM_SANITIZE=address,undefined
cmake --build build-fuzz -j

python3 fuzz/seed_corpus.py                 # populate fuzz/corpus/<target>/

./build-fuzz/bin/fuzz_sni_extractor -max_total_time=60 fuzz/corpus/sni_extractor
# or, standalone build: replay the corpus once
./build-fuzz/bin/fuzz_sni_extractor fuzz/corpus/sni_extractor
```

## Corpus

`fuzz/corpus/<target>/` holds seed inputs and is tracked in git. `seed_corpus.py`
(re)generates it: synthetic well-formed messages for the L7 parsers, and every
frame of `test_dpi.pcap` for the packet/pcap parsers. New interesting inputs
found by CI are uploaded as build artifacts, not committed automatically.

A crash reproducer (`crash-<hash>`) is replayed with:

```bash
./build-fuzz/bin/fuzz_<target> crash-<hash>
```
