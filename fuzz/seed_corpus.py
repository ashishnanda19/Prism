#!/usr/bin/env python3
# Author: Ashish Kumar Nanda
"""
Populate fuzz/corpus/<target>/ with seed inputs.

- packet_parser / pcap_reader: every frame (and the whole file) from a PCAP.
- sni_extractor / quic_sni / http_host / dns: small synthetic, well-formed
  messages so the fuzzer starts from valid structure instead of noise.

Usage:  python3 fuzz/seed_corpus.py [path/to/capture.pcap]
        (defaults to test_dpi.pcap next to the repo root)
"""
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join(ROOT, "fuzz", "corpus")


def write(target, name, data: bytes):
    d = os.path.join(CORPUS, target)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "wb") as f:
        f.write(data)


def seed_from_pcap(pcap_path):
    with open(pcap_path, "rb") as f:
        blob = f.read()
    if len(blob) < 24:
        print(f"! {pcap_path}: too small, skipping pcap seeds")
        return
    write("pcap_reader", "capture_full", blob)                 # whole file
    write("pcap_reader", "header_only", blob[:24])              # just the global header

    magic = struct.unpack("<I", blob[:4])[0]
    le = magic == 0xA1B2C3D4
    endian = "<" if le else ">"
    off, idx = 24, 0
    while off + 16 <= len(blob) and idx < 200:
        ts_s, ts_us, incl, orig = struct.unpack(endian + "IIII", blob[off:off + 16])
        off += 16
        if incl > 262144 or off + incl > len(blob):
            break
        frame = blob[off:off + incl]
        off += incl
        write("packet_parser", f"frame_{idx:03d}", frame)      # raw link-layer frame
        idx += 1
    print(f"  pcap: {idx} frames -> corpus/packet_parser/")


def seed_synthetic():
    # --- TLS ClientHello with SNI=example.com (mirrors sni_extractor.cpp) ---
    host = b"example.com"
    sni = struct.pack(">H", len(host) + 3) + b"\x00" + struct.pack(">H", len(host)) + host
    ext = struct.pack(">H", 0) + struct.pack(">H", len(sni)) + sni
    body = (b"\x03\x03" + b"\x00" * 32 + b"\x00" +
            struct.pack(">H", 2) + b"\x13\x01" + b"\x01\x00" +
            struct.pack(">H", len(ext)) + ext)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    rec = b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs
    write("sni_extractor", "clienthello_example_com", rec)
    write("tls_fingerprint", "clienthello_example_com", rec)
    write("quic_sni", "clienthello_blob", b"\xc0\x00\x00\x00\x01" + b"\x00" * 8 + rec)

    # --- HTTP request with Host header ---
    write("http_host", "get_with_host",
          b"GET /a HTTP/1.1\r\nHost: www.example.org\r\nAccept: */*\r\n\r\n")

    # --- DNS standard query for www.example.com ---
    dns = bytes([0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0])
    for label in (b"www", b"example", b"com"):
        dns += bytes([len(label)]) + label
    dns += b"\x00\x00\x01\x00\x01"
    write("dns", "query_www_example_com", dns)
    print("  synthetic: sni_extractor, quic_sni, http_host, dns")


def main():
    pcap = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "test_dpi.pcap")
    print(f"seeding corpus under {CORPUS}")
    seed_synthetic()
    if os.path.exists(pcap):
        seed_from_pcap(pcap)
    else:
        print(f"! {pcap} not found -- skipping pcap-derived seeds")


if __name__ == "__main__":
    main()
