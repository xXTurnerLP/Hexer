// Tests for core/hash: catalogue check values, RFC / NIST vectors, incremental == one-shot,
// HashJob over multi-block snapshots, cancel, name lookup and expected-value matching.
#include <doctest/doctest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <memory>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "core/document.h"
#include "core/hash.h"

using namespace hx;

namespace {

using Bytes = std::vector<uint8_t>;

std::string hs(const std::string& algo, const std::string& s) {
    return hash_hex(algo, reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

std::shared_ptr<const Snapshot> snap_of(const Bytes& b) {
    auto doc = Document::create_from_bytes("test", b.data(), b.size());
    REQUIRE(doc);
    return doc->snapshot();
}

Bytes random_bytes(size_t n, uint32_t seed) {
    std::mt19937 rng(seed);
    Bytes b(n);
    for (auto& v : b) v = uint8_t(rng());
    return b;
}

void wait_for(const HashJob& job, uint64_t gen) {
    auto t0 = std::chrono::steady_clock::now();
    while (job.generation() == gen) {
        REQUIRE(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(120));
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

}  // namespace

TEST_CASE("hash: catalogue check values of \"123456789\"") {
    const std::string c = "123456789";
    CHECK(hs("Sum-8", c) == "dd");
    CHECK(hs("XOR-8", c) == "31");
    CHECK(hs("CRC-8", c) == "f4");
    CHECK(hs("CRC-16/CCITT-FALSE", c) == "29b1");
    CHECK(hs("CRC-16/MODBUS", c) == "4b37");
    CHECK(hs("CRC-16/XMODEM", c) == "31c3");
    CHECK(hs("CRC-32", c) == "cbf43926");
    CHECK(hs("CRC-32C", c) == "e3069283");
    CHECK(hs("Adler-32", c) == "091e01de");
    CHECK(hs("Fletcher-16", c) == "1ede");
    CHECK(hs("FNV-1a/32", c) == "bb86b11c");
    CHECK(hs("FNV-1a/64", c) == "06d5573923c6cdfc");
    CHECK(hs("MD5", c) == "25f9e794323b453885f5181f1b624d0b");
    CHECK(hs("SHA-1", c) == "f7c3bc1d808e04732adf679965ccc34ca7ae3441");
    CHECK(hs("SHA-256", c) == "15e2b0d3c33891ebb0f1ef609ec419420c20e320ce94c65fbc8c3312448eb225");
}

TEST_CASE("hash: empty input") {
    CHECK(hs("CRC-32", "") == "00000000");
    CHECK(hs("CRC-16/CCITT-FALSE", "") == "ffff");
    CHECK(hs("Adler-32", "") == "00000001");
    CHECK(hs("FNV-1a/32", "") == "811c9dc5");
    CHECK(hs("FNV-1a/64", "") == "cbf29ce484222325");
    CHECK(hs("MD5", "") == "d41d8cd98f00b204e9800998ecf8427e");
    CHECK(hs("SHA-1", "") == "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    CHECK(hs("SHA-256", "") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(hs("SHA-512", "") ==
          "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
          "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    CHECK(hash_hex("SHA-256", nullptr, 0) == hs("SHA-256", ""));
}

TEST_CASE("hash: other published vectors (Adler-32, Fletcher-16, FNV-1a)") {
    CHECK(hs("Adler-32", "Wikipedia") == "11e60398");
    CHECK(hs("Fletcher-16", "abcde") == "c8f0");
    CHECK(hs("Fletcher-16", "abcdef") == "2057");
    CHECK(hs("Fletcher-16", "abcdefgh") == "0627");
    CHECK(hs("FNV-1a/32", "a") == "e40c292c");
    CHECK(hs("FNV-1a/32", "foobar") == "bf9cf968");
    CHECK(hs("FNV-1a/64", "a") == "af63dc4c8601ec8c");
    CHECK(hs("FNV-1a/64", "foobar") == "85944171f73967e8");
}

TEST_CASE("hash: MD5 RFC 1321 test suite") {
    CHECK(hs("MD5", "a") == "0cc175b9c0f1b6a831c399e269772661");
    CHECK(hs("MD5", "abc") == "900150983cd24fb0d6963f7d28e17f72");
    CHECK(hs("MD5", "message digest") == "f96b697d7cb7938d525a2f31aaf161d0");
    CHECK(hs("MD5", "abcdefghijklmnopqrstuvwxyz") == "c3fcd3d76192e4007dfb496cca67e13b");
    CHECK(hs("MD5", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") ==
          "d174ab98d277d9f5a5611c2c9f419d9f");
    CHECK(hs("MD5", "12345678901234567890123456789012345678901234567890123456789012345678901234567890") ==
          "57edf4a22be3c955ac49da2e2107b67a");
}

TEST_CASE("hash: SHA-1 / SHA-256 / SHA-512 FIPS 180 vectors") {
    const std::string m448 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    const std::string m896 =
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrst"
        "nopqrstu";
    CHECK(hs("SHA-1", "abc") == "a9993e364706816aba3e25717850c26c9cd0d89d");
    CHECK(hs("SHA-1", m448) == "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
    CHECK(hs("SHA-256", "abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(hs("SHA-256", m448) == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    CHECK(hs("SHA-512", "abc") ==
          "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
          "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    CHECK(hs("SHA-512", m896) ==
          "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
          "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
}

TEST_CASE("hash: one million 'a' (SHA-1, SHA-256, SHA-512, MD5)") {
    const std::string a(1000000, 'a');
    CHECK(hs("SHA-256", a) == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    CHECK(hs("SHA-1", a) == "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
    CHECK(hs("SHA-512", a) ==
          "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
          "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b");
    CHECK(hs("MD5", a) == "7707d6ae4e027c70eea2a935c2296f21");
}

TEST_CASE("hash: padding boundaries agree between block and byte feeding") {
    // Lengths around the 55/56/64 (MD5/SHA-1/SHA-256) and 111/112/128 (SHA-512) padding edges.
    const Bytes data = random_bytes(300, 7);
    for (const auto& algo : hash_algorithms()) {
        for (size_t len : {0, 1, 55, 56, 57, 63, 64, 65, 111, 112, 113, 127, 128, 129, 300}) {
            auto h = algo.create();
            for (size_t i = 0; i < len; ++i) h->update(&data[i], 1);
            INFO(algo.name << " len " << len);
            CHECK(to_hex(h->finish()) == hash_hex(algo.name, data.data(), len));
        }
    }
}

TEST_CASE("hash: incremental equals one-shot at random split points; init() resets") {
    const Bytes data = random_bytes(20000, 42);
    std::mt19937 rng(1);
    for (const auto& algo : hash_algorithms()) {
        const std::string ref = hash_hex(algo.name, data.data(), data.size());
        CHECK(ref.size() == algo.digest_size * 2);
        auto h = algo.create();
        for (int round = 0; round < 5; ++round) {
            h->init();
            size_t pos = 0;
            while (pos < data.size()) {
                size_t n = std::min<size_t>(data.size() - pos, rng() % 3000);
                h->update(data.data() + pos, n);
                pos += n;
            }
            INFO(algo.name << " round " << round);
            CHECK(to_hex(h->finish()) == ref);
        }
    }
}

TEST_CASE("hash: registry lookup and names") {
    CHECK(hash_algorithms().size() == 16);
    CHECK(find_hash_algorithm("crc32") == find_hash_algorithm("CRC-32"));
    CHECK(find_hash_algorithm("Crc_32")->name == std::string("CRC-32"));
    CHECK(find_hash_algorithm("sha256")->name == std::string("SHA-256"));
    CHECK(find_hash_algorithm("crc32c")->name == std::string("CRC-32C"));
    CHECK(find_hash_algorithm("castagnoli")->name == std::string("CRC-32C"));
    CHECK(find_hash_algorithm("crc16-modbus")->name == std::string("CRC-16/MODBUS"));
    CHECK(find_hash_algorithm("crc16ccitt")->name == std::string("CRC-16/CCITT-FALSE"));
    CHECK(find_hash_algorithm("fnv1a64")->name == std::string("FNV-1a/64"));
    CHECK(find_hash_algorithm("crc8smbus")->name == std::string("CRC-8"));
    CHECK(find_hash_algorithm("nope") == nullptr);
    CHECK(find_hash_algorithm("") == nullptr);
    CHECK(make_hasher("nope") == nullptr);
    CHECK(hs("nope", "abc").empty());
    int defaults = 0;
    for (const auto& a : hash_algorithms()) defaults += a.is_default ? 1 : 0;
    CHECK(defaults == 4);
    CHECK(to_hex({0xAB, 0x01}, true) == "AB01");
}

TEST_CASE("hash: expected-value normalisation") {
    CHECK(normalize_hex("0xCBF43926") == "cbf43926");
    CHECK(normalize_hex("  CB F4 39 26 ") == "cbf43926");
    CHECK(normalize_hex("cb:f4:39:26") == "cbf43926");
    CHECK(normalize_hex("xyz").empty());
    CHECK(normalize_hex("0x").empty());
    CHECK(hex_matches("0XCBF43926", "cbf43926"));
    CHECK(hex_matches("cbf43926", "cbf43926"));
    CHECK_FALSE(hex_matches("cbf4392", "cbf43926"));
    CHECK_FALSE(hex_matches("", "cbf43926"));
    CHECK_FALSE(hex_matches("zz", "cbf43926"));
}

TEST_CASE("hash: hash_range / hash_snapshot_hex over a multi-block snapshot") {
    const Bytes data = random_bytes((size_t(9) << 20) + 12345, 3);  // > 2 blocks of 4 MiB
    auto snap = snap_of(data);
    std::string out, err;
    REQUIRE(hash_snapshot_hex(*snap, "sha256", 0, UINT64_MAX, out, &err));
    CHECK(out == hash_hex("SHA-256", data.data(), data.size()));
    REQUIRE(hash_snapshot_hex(*snap, "crc32", 1000, 5000000, out, &err));
    CHECK(out == hash_hex("CRC-32", data.data() + 1000, 5000000));
    // Range past the end is clamped.
    REQUIRE(hash_snapshot_hex(*snap, "md5", data.size() - 10, 1000, out, &err));
    CHECK(out == hash_hex("MD5", data.data() + data.size() - 10, 10));
    REQUIRE(hash_snapshot_hex(*snap, "md5", data.size() + 10, 1000, out, &err));
    CHECK(out == hs("MD5", ""));
    CHECK_FALSE(hash_snapshot_hex(*snap, "bogus", 0, 10, out, &err));
    CHECK(err.find("bogus") != std::string::npos);

    std::atomic<bool> cancel{true};
    auto h = make_hasher("md5");
    CHECK_FALSE(hash_range(*snap, 0, UINT64_MAX, {h.get()}, &cancel));
}

TEST_CASE("hash: HashJob computes every algorithm in one pass") {
    const Bytes data = random_bytes((size_t(10) << 20) + 777, 9);
    auto snap = snap_of(data);
    std::vector<std::string> names;
    for (const auto& a : hash_algorithms()) names.push_back(a.name);
    names.push_back("unknown-algo");  // skipped

    HashJob job;
    uint64_t gen = job.generation();
    job.start(snap, 0, UINT64_MAX, names);
    wait_for(job, gen);
    CHECK_FALSE(job.running());
    CHECK(job.progress() == doctest::Approx(1.0));
    HashJob::Result r = job.result();
    CHECK_FALSE(r.cancelled);
    CHECK_FALSE(r.io_error);
    CHECK(r.offset == 0);
    CHECK(r.length == data.size());
    REQUIRE(r.values.size() == hash_algorithms().size());
    for (size_t i = 0; i < r.values.size(); ++i) {
        INFO(r.values[i].algo);
        CHECK(r.values[i].algo == hash_algorithms()[i].name);
        CHECK(r.values[i].hex == hash_hex(r.values[i].algo, data.data(), data.size()));
    }

    // Sub-range spanning a block boundary.
    gen = job.generation();
    const uint64_t off = (uint64_t(4) << 20) - 100, len = 3000000;
    job.start(snap, off, len, {"SHA-256", "CRC-32C"});
    wait_for(job, gen);
    r = job.result();
    REQUIRE(r.values.size() == 2);
    CHECK(r.offset == off);
    CHECK(r.length == len);
    CHECK(r.values[0].hex == hash_hex("SHA-256", data.data() + off, size_t(len)));
    CHECK(r.values[1].hex == hash_hex("CRC-32C", data.data() + off, size_t(len)));

    // Empty range.
    gen = job.generation();
    job.start(snap, 5, 0, {"MD5"});
    wait_for(job, gen);
    r = job.result();
    REQUIRE(r.values.size() == 1);
    CHECK(r.values[0].hex == hs("MD5", ""));
}

TEST_CASE("hash: HashJob cancel and supersede") {
    // 2 GiB of filled data (pieces only, no RAM): SHA-512 over it takes seconds.
    auto doc = Document::create_empty("big");
    REQUIRE(doc);
    const uint8_t pat[4] = {1, 2, 3, 4};
    REQUIRE(doc->fill(0, uint64_t(2) << 30, pat, sizeof pat));
    auto snap = doc->snapshot();

    HashJob job;
    uint64_t gen = job.generation();
    job.start(snap, 0, UINT64_MAX, {"SHA-512", "SHA-256"});
    CHECK(job.running());
    job.cancel();
    wait_for(job, gen);
    HashJob::Result r = job.result();
    CHECK(r.cancelled);
    CHECK(r.values.empty());
    CHECK_FALSE(job.running());

    // start() supersedes a running job: only the newest run publishes.
    gen = job.generation();
    job.start(snap, 0, UINT64_MAX, {"SHA-512"});
    job.start(snap, 0, 4, {"CRC-32"});
    wait_for(job, gen);
    CHECK(job.generation() == gen + 1);
    r = job.result();
    CHECK_FALSE(r.cancelled);
    REQUIRE(r.values.size() == 1);
    CHECK(r.values[0].algo == std::string("CRC-32"));
    CHECK(r.values[0].hex == hash_hex("CRC-32", pat, sizeof pat));
    // The destructor cancels and joins the superseded run.
}
