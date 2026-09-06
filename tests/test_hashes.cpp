// =============================================================================
// Project: Prism - Deep Packet Inspection Engine
// Author:  Ashish Kumar Nanda
// =============================================================================
//
// MD5 / SHA-256 against published test vectors (JA3 uses MD5, JA4 uses SHA-256).

#include "doctest/doctest.h"
#include "hashes.h"

#include <string>

using namespace DPI;

TEST_CASE("MD5 known-answer tests (RFC 1321)") {
    CHECK(md5_hex("") == "d41d8cd98f00b204e9800998ecf8427e");
    CHECK(md5_hex("a") == "0cc175b9c0f1b6a831c399e269772661");
    CHECK(md5_hex("abc") == "900150983cd24fb0d6963f7d28e17f72");
    CHECK(md5_hex("message digest") == "f96b697d7cb7938d525a2f31aaf161d0");
    CHECK(md5_hex("abcdefghijklmnopqrstuvwxyz") == "c3fcd3d76192e4007dfb496cca67e13b");
    CHECK(md5_hex("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
          == "d174ab98d277d9f5a5611c2c9f419d9f");  // 62 bytes -> two-block message
}

TEST_CASE("SHA-256 known-answer tests (FIPS 180-4)") {
    CHECK(sha256_hex("") ==
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(sha256_hex("abc") ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(sha256_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    // exactly one block of padding-forcing length (56 bytes)
    CHECK(sha256_hex(std::string(56, 'a')).size() == 64);
    CHECK(sha256_hex(std::string(1000, 'a')).size() == 64);
}
