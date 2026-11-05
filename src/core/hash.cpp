#include "core/hash.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

namespace hx {

namespace {

// ---- helpers ------------------------------------------------------------------------------------

inline uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
inline uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
inline uint64_t rotr64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

inline uint32_t load32le(const uint8_t* p) {
    return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
}
inline uint32_t load32be(const uint8_t* p) {
    return uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 | uint32_t(p[3]);
}
inline uint64_t load64be(const uint8_t* p) { return uint64_t(load32be(p)) << 32 | load32be(p + 4); }

// Big-endian bytes of the low `bytes` bytes of v.
std::vector<uint8_t> be_bytes(uint64_t v, size_t bytes) {
    std::vector<uint8_t> out(bytes);
    for (size_t i = 0; i < bytes; ++i) out[bytes - 1 - i] = uint8_t(v >> (8 * i));
    return out;
}

// ---- simple checksums ---------------------------------------------------------------------------

class Sum8 final : public Hasher {
public:
    void init() override { s_ = 0; }
    void update(const uint8_t* p, size_t n) override {
        uint32_t s = s_;
        for (size_t i = 0; i < n; ++i) s += p[i];
        s_ = uint8_t(s);
    }
    std::vector<uint8_t> finish() override { return {s_}; }

private:
    uint8_t s_ = 0;
};

class Xor8 final : public Hasher {
public:
    void init() override { x_ = 0; }
    void update(const uint8_t* p, size_t n) override {
        uint8_t x = x_;
        for (size_t i = 0; i < n; ++i) x ^= p[i];
        x_ = x;
    }
    std::vector<uint8_t> finish() override { return {x_}; }

private:
    uint8_t x_ = 0;
};

class Adler32 final : public Hasher {
public:
    void init() override { a_ = 1, b_ = 0; }
    void update(const uint8_t* p, size_t n) override {
        constexpr size_t kNmax = 5552;  // largest n with 255n(n+1)/2 + (n+1)(65520) < 2^32
        while (n) {
            size_t k = std::min(n, kNmax);
            n -= k;
            for (size_t i = 0; i < k; ++i) {
                a_ += p[i];
                b_ += a_;
            }
            p += k;
            a_ %= 65521;
            b_ %= 65521;
        }
    }
    std::vector<uint8_t> finish() override { return be_bytes(uint64_t(b_) << 16 | a_, 4); }

private:
    uint32_t a_ = 1, b_ = 0;
};

class Fletcher16 final : public Hasher {
public:
    void init() override { a_ = 0, b_ = 0; }
    void update(const uint8_t* p, size_t n) override {
        constexpr size_t kBlock = 4096;  // modulo deferred; sums stay far below 2^32
        while (n) {
            size_t k = std::min(n, kBlock);
            n -= k;
            for (size_t i = 0; i < k; ++i) {
                a_ += p[i];
                b_ += a_;
            }
            p += k;
            a_ %= 255;
            b_ %= 255;
        }
    }
    std::vector<uint8_t> finish() override { return be_bytes(uint64_t(b_) << 8 | a_, 2); }

private:
    uint32_t a_ = 0, b_ = 0;
};

class Fnv1a32 final : public Hasher {
public:
    void init() override { h_ = 0x811c9dc5u; }
    void update(const uint8_t* p, size_t n) override {
        uint32_t h = h_;
        for (size_t i = 0; i < n; ++i) h = (h ^ p[i]) * 0x01000193u;
        h_ = h;
    }
    std::vector<uint8_t> finish() override { return be_bytes(h_, 4); }

private:
    uint32_t h_ = 0x811c9dc5u;
};

class Fnv1a64 final : public Hasher {
public:
    void init() override { h_ = 0xcbf29ce484222325ull; }
    void update(const uint8_t* p, size_t n) override {
        uint64_t h = h_;
        for (size_t i = 0; i < n; ++i) h = (h ^ p[i]) * 0x00000100000001b3ull;
        h_ = h;
    }
    std::vector<uint8_t> finish() override { return be_bytes(h_, 8); }

private:
    uint64_t h_ = 0xcbf29ce484222325ull;
};

// ---- CRCs (table driven; reflected ones use slice-by-8) -----------------------------------------
// Parameters as in the Rocksoft / reveng catalogue (refin == refout for every CRC here).

struct CrcSpec {
    int width;        // 8, 16 or 32
    uint32_t poly;    // normal (MSB-first) form
    uint32_t init;
    bool refl;
    uint32_t xorout;
};

struct CrcTables {
    CrcSpec spec;
    uint32_t mask;
    uint32_t t[8][256];  // t[1..7] only for reflected CRCs
};

uint32_t reflect(uint32_t v, int width) {
    uint32_t r = 0;
    for (int i = 0; i < width; ++i)
        if (v & (uint32_t(1) << i)) r |= uint32_t(1) << (width - 1 - i);
    return r;
}

std::unique_ptr<CrcTables> build_crc(const CrcSpec& s) {
    auto c = std::make_unique<CrcTables>();
    c->spec = s;
    c->mask = s.width == 32 ? 0xFFFFFFFFu : (uint32_t(1) << s.width) - 1;
    if (s.refl) {
        const uint32_t rp = reflect(s.poly, s.width);
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t v = i;
            for (int k = 0; k < 8; ++k) v = (v & 1) ? (v >> 1) ^ rp : v >> 1;
            c->t[0][i] = v;
        }
        for (int k = 1; k < 8; ++k)
            for (uint32_t i = 0; i < 256; ++i)
                c->t[k][i] = (c->t[k - 1][i] >> 8) ^ c->t[0][c->t[k - 1][i] & 0xFF];
    } else {
        const uint32_t top = uint32_t(1) << (s.width - 1);
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t v = i << (s.width - 8);
            for (int k = 0; k < 8; ++k) v = (v & top) ? (v << 1) ^ s.poly : v << 1;
            c->t[0][i] = v & c->mask;
        }
    }
    return c;
}

class Crc final : public Hasher {
public:
    explicit Crc(const CrcTables& t) : t_(t), crc_(t.spec.refl ? reflect(t.spec.init, t.spec.width) : t.spec.init) {}
    void init() override { crc_ = t_.spec.refl ? reflect(t_.spec.init, t_.spec.width) : t_.spec.init; }
    void update(const uint8_t* p, size_t n) override {
        const auto& t = t_.t;
        uint32_t crc = crc_;
        if (t_.spec.refl) {
            // Slice-by-8: the register (<= 32 bits, LSB-first) absorbs 8 bytes per step.
            while (n >= 8) {
                const uint32_t a = crc ^ load32le(p), b = load32le(p + 4);
                crc = t[7][a & 0xFF] ^ t[6][(a >> 8) & 0xFF] ^ t[5][(a >> 16) & 0xFF] ^ t[4][a >> 24] ^
                      t[3][b & 0xFF] ^ t[2][(b >> 8) & 0xFF] ^ t[1][(b >> 16) & 0xFF] ^ t[0][b >> 24];
                p += 8;
                n -= 8;
            }
            for (size_t i = 0; i < n; ++i) crc = t[0][(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
        } else {
            const int sh = t_.spec.width - 8;
            const uint32_t mask = t_.mask;
            for (size_t i = 0; i < n; ++i) crc = ((crc << 8) ^ t[0][((crc >> sh) ^ p[i]) & 0xFF]) & mask;
        }
        crc_ = crc;
    }
    std::vector<uint8_t> finish() override {
        return be_bytes((crc_ ^ t_.spec.xorout) & t_.mask, size_t(t_.spec.width / 8));
    }

private:
    const CrcTables& t_;
    uint32_t crc_;
};

const CrcTables& crc_tables(int which) {
    static const CrcSpec specs[] = {
        {8, 0x07, 0x00, false, 0x00},                       // 0 CRC-8 (SMBus)
        {16, 0x1021, 0xFFFF, false, 0x0000},                // 1 CRC-16/CCITT-FALSE (IBM-3740)
        {16, 0x8005, 0xFFFF, true, 0x0000},                 // 2 CRC-16/MODBUS
        {16, 0x1021, 0x0000, false, 0x0000},                // 3 CRC-16/XMODEM
        {32, 0x04C11DB7, 0xFFFFFFFF, true, 0xFFFFFFFF},     // 4 CRC-32 (ISO-HDLC)
        {32, 0x1EDC6F41, 0xFFFFFFFF, true, 0xFFFFFFFF},     // 5 CRC-32C (Castagnoli)
    };
    // Intentionally never freed: a worker thread may still hash while static destructors run at exit.
    static const CrcTables* const tables[] = {build_crc(specs[0]).release(), build_crc(specs[1]).release(),
                                              build_crc(specs[2]).release(), build_crc(specs[3]).release(),
                                              build_crc(specs[4]).release(), build_crc(specs[5]).release()};
    return *tables[which];
}

// ---- Merkle-Damgard block buffering (MD5 / SHA-1 / SHA-2) ---------------------------------------
// Derived classes provide compress(const uint8_t* block) and the state; B = block size,
// L = length field bytes, big = big-endian length field.

template <class Derived, size_t B, size_t L, bool Big>
class BlockHasher : public Hasher {
public:
    void update(const uint8_t* p, size_t n) override {
        total_ += n;
        if (used_) {
            size_t take = std::min(n, B - used_);
            std::memcpy(buf_ + used_, p, take);
            used_ += take;
            p += take;
            n -= take;
            if (used_ < B) return;
            self().compress(buf_);
            used_ = 0;
        }
        for (; n >= B; p += B, n -= B) self().compress(p);
        if (n) {
            std::memcpy(buf_, p, n);
            used_ = n;
        }
    }

protected:
    void reset_buffer() { used_ = 0, total_ = 0; }
    // Appends 0x80, zero padding and the bit length (mod 2^(8L) - only 2^64 * 8 bits matter here).
    void pad() {
        const uint64_t bits_lo = total_ << 3, bits_hi = total_ >> 61;
        uint8_t len[L] = {};
        for (size_t i = 0; i < 8; ++i) {
            const uint8_t lo = uint8_t(bits_lo >> (8 * i));
            if constexpr (Big) len[L - 1 - i] = lo;
            else len[i] = lo;
        }
        if constexpr (L == 16) len[L - 9] = uint8_t(bits_hi);  // big-endian only (SHA-512)
        static const uint8_t zeros[B] = {0x80};
        const size_t padlen = used_ < B - L ? B - L - used_ : 2 * B - L - used_;
        update(zeros, padlen);
        update(len, L);
    }

private:
    Derived& self() { return static_cast<Derived&>(*this); }
    uint8_t buf_[B] = {};
    size_t used_ = 0;
    uint64_t total_ = 0;
};

class Md5 final : public BlockHasher<Md5, 64, 8, false> {
public:
    Md5() { init(); }
    void init() override {
        reset_buffer();
        h_[0] = 0x67452301u, h_[1] = 0xefcdab89u, h_[2] = 0x98badcfeu, h_[3] = 0x10325476u;
    }
    std::vector<uint8_t> finish() override {
        pad();
        std::vector<uint8_t> out(16);
        for (int i = 0; i < 16; ++i) out[size_t(i)] = uint8_t(h_[i / 4] >> (8 * (i % 4)));
        return out;
    }
    void compress(const uint8_t* blk) {
        static const uint32_t K[64] = {
            0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu, 0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
            0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu, 0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
            0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau, 0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
            0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu, 0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
            0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu, 0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
            0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u, 0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
            0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u, 0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
            0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u, 0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u,
        };
        static const int S[16] = {7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21};
        uint32_t m[16];
        for (int i = 0; i < 16; ++i) m[i] = load32le(blk + 4 * i);
        uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
        for (int i = 0; i < 64; ++i) {
            uint32_t f;
            int g;
            if (i < 16) f = (b & c) | (~b & d), g = i;
            else if (i < 32) f = (d & b) | (~d & c), g = (5 * i + 1) & 15;
            else if (i < 48) f = b ^ c ^ d, g = (3 * i + 5) & 15;
            else f = c ^ (b | ~d), g = (7 * i) & 15;
            f += a + K[i] + m[g];
            a = d;
            d = c;
            c = b;
            b += rotl32(f, S[(i >> 4) * 4 + (i & 3)]);
        }
        h_[0] += a, h_[1] += b, h_[2] += c, h_[3] += d;
    }

private:
    uint32_t h_[4];
};

class Sha1 final : public BlockHasher<Sha1, 64, 8, true> {
public:
    Sha1() { init(); }
    void init() override {
        reset_buffer();
        h_[0] = 0x67452301u, h_[1] = 0xefcdab89u, h_[2] = 0x98badcfeu, h_[3] = 0x10325476u, h_[4] = 0xc3d2e1f0u;
    }
    std::vector<uint8_t> finish() override {
        pad();
        std::vector<uint8_t> out;
        for (uint32_t v : h_) {
            auto b = be_bytes(v, 4);
            out.insert(out.end(), b.begin(), b.end());
        }
        return out;
    }
    void compress(const uint8_t* blk) {
        uint32_t w[80];
        for (int i = 0; i < 16; ++i) w[i] = load32be(blk + 4 * i);
        for (int i = 16; i < 80; ++i) w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4];
        for (int i = 0; i < 80; ++i) {
            uint32_t f, k;
            if (i < 20) f = (b & c) | (~b & d), k = 0x5a827999u;
            else if (i < 40) f = b ^ c ^ d, k = 0x6ed9eba1u;
            else if (i < 60) f = (b & c) | (b & d) | (c & d), k = 0x8f1bbcdcu;
            else f = b ^ c ^ d, k = 0xca62c1d6u;
            const uint32_t t = rotl32(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = rotl32(b, 30);
            b = a;
            a = t;
        }
        h_[0] += a, h_[1] += b, h_[2] += c, h_[3] += d, h_[4] += e;
    }

private:
    uint32_t h_[5];
};

class Sha256 final : public BlockHasher<Sha256, 64, 8, true> {
public:
    Sha256() { init(); }
    void init() override {
        reset_buffer();
        static const uint32_t iv[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                                       0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
        std::memcpy(h_, iv, sizeof h_);
    }
    std::vector<uint8_t> finish() override {
        pad();
        std::vector<uint8_t> out;
        for (uint32_t v : h_) {
            auto b = be_bytes(v, 4);
            out.insert(out.end(), b.begin(), b.end());
        }
        return out;
    }
    void compress(const uint8_t* blk) {
        static const uint32_t K[64] = {
            0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
            0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
            0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
            0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
            0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
            0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
            0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
            0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
        };
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) w[i] = load32be(blk + 4 * i);
        for (int i = 16; i < 64; ++i) {
            const uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
            const uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4], f = h_[5], g = h_[6], h = h_[7];
        for (int i = 0; i < 64; ++i) {
            const uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
            const uint32_t ch = (e & f) ^ (~e & g);
            const uint32_t t1 = h + s1 + ch + K[i] + w[i];
            const uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
            const uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
            const uint32_t t2 = s0 + mj;
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        h_[0] += a, h_[1] += b, h_[2] += c, h_[3] += d, h_[4] += e, h_[5] += f, h_[6] += g, h_[7] += h;
    }

private:
    uint32_t h_[8];
};

class Sha512 final : public BlockHasher<Sha512, 128, 16, true> {
public:
    Sha512() { init(); }
    void init() override {
        reset_buffer();
        static const uint64_t iv[8] = {0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull, 0x3c6ef372fe94f82bull,
                                       0xa54ff53a5f1d36f1ull, 0x510e527fade682d1ull, 0x9b05688c2b3e6c1full,
                                       0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull};
        std::memcpy(h_, iv, sizeof h_);
    }
    std::vector<uint8_t> finish() override {
        pad();
        std::vector<uint8_t> out;
        for (uint64_t v : h_) {
            auto b = be_bytes(v, 8);
            out.insert(out.end(), b.begin(), b.end());
        }
        return out;
    }
    void compress(const uint8_t* blk) {
        static const uint64_t K[80] = {
            0x428a2f98d728ae22ull, 0x7137449123ef65cdull, 0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull,
            0x3956c25bf348b538ull, 0x59f111f1b605d019ull, 0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull,
            0xd807aa98a3030242ull, 0x12835b0145706fbeull, 0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
            0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull, 0x9bdc06a725c71235ull, 0xc19bf174cf692694ull,
            0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull, 0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
            0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull, 0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
            0x983e5152ee66dfabull, 0xa831c66d2db43210ull, 0xb00327c898fb213full, 0xbf597fc7beef0ee4ull,
            0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull, 0x06ca6351e003826full, 0x142929670a0e6e70ull,
            0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull, 0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
            0x650a73548baf63deull, 0x766a0abb3c77b2a8ull, 0x81c2c92e47edaee6ull, 0x92722c851482353bull,
            0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull, 0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull,
            0xd192e819d6ef5218ull, 0xd69906245565a910ull, 0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
            0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull, 0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull,
            0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull, 0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull,
            0x748f82ee5defb2fcull, 0x78a5636f43172f60ull, 0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
            0x90befffa23631e28ull, 0xa4506cebde82bde9ull, 0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull,
            0xca273eceea26619cull, 0xd186b8c721c0c207ull, 0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull,
            0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull, 0x113f9804bef90daeull, 0x1b710b35131c471bull,
            0x28db77f523047d84ull, 0x32caab7b40c72493ull, 0x3c9ebe0a15c9bebcull, 0x431d67c49c100d4cull,
            0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull, 0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull,
        };
        uint64_t w[80];
        for (int i = 0; i < 16; ++i) w[i] = load64be(blk + 8 * i);
        for (int i = 16; i < 80; ++i) {
            const uint64_t s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
            const uint64_t s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint64_t a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4], f = h_[5], g = h_[6], h = h_[7];
        for (int i = 0; i < 80; ++i) {
            const uint64_t s1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
            const uint64_t ch = (e & f) ^ (~e & g);
            const uint64_t t1 = h + s1 + ch + K[i] + w[i];
            const uint64_t s0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
            const uint64_t mj = (a & b) ^ (a & c) ^ (b & c);
            const uint64_t t2 = s0 + mj;
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        h_[0] += a, h_[1] += b, h_[2] += c, h_[3] += d, h_[4] += e, h_[5] += f, h_[6] += g, h_[7] += h;
    }

private:
    uint64_t h_[8];
};

// ---- registry -----------------------------------------------------------------------------------

template <class T>
std::unique_ptr<Hasher> make() {
    return std::make_unique<T>();
}
template <int Which>
std::unique_ptr<Hasher> make_crc() {
    return std::make_unique<Crc>(crc_tables(Which));
}

// Letters and digits only, lowercase.
std::string key_of(const std::string& s) {
    std::string k;
    for (char ch : s) {
        const unsigned char c = static_cast<unsigned char>(ch);
        if (std::isalnum(c)) k += char(std::tolower(c));
    }
    return k;
}

constexpr size_t kBlock = size_t(4) << 20;  // bytes per read

}  // namespace

const std::vector<HashAlgorithm>& hash_algorithms() {
    // Never freed (like the CRC tables): usable from worker threads during static destruction.
    static const std::vector<HashAlgorithm>* const algos = new std::vector<HashAlgorithm>{
        {"Sum-8", 1, false, &make<Sum8>},
        {"XOR-8", 1, false, &make<Xor8>},
        {"CRC-8", 1, false, &make_crc<0>},
        {"CRC-16/CCITT-FALSE", 2, false, &make_crc<1>},
        {"CRC-16/MODBUS", 2, false, &make_crc<2>},
        {"CRC-16/XMODEM", 2, false, &make_crc<3>},
        {"CRC-32", 4, true, &make_crc<4>},
        {"CRC-32C", 4, false, &make_crc<5>},
        {"Adler-32", 4, false, &make<Adler32>},
        {"Fletcher-16", 2, false, &make<Fletcher16>},
        {"FNV-1a/32", 4, false, &make<Fnv1a32>},
        {"FNV-1a/64", 8, false, &make<Fnv1a64>},
        {"MD5", 16, true, &make<Md5>},
        {"SHA-1", 20, true, &make<Sha1>},
        {"SHA-256", 32, true, &make<Sha256>},
        {"SHA-512", 64, false, &make<Sha512>},
    };
    return *algos;
}

const HashAlgorithm* find_hash_algorithm(const std::string& name) {
    static const std::pair<const char*, const char*> aliases[] = {
        {"crc8smbus", "crc8"},
        {"crc16ccitt", "crc16ccittfalse"},
        {"crc16ibm3740", "crc16ccittfalse"},
        {"crc16autosar", "crc16ccittfalse"},
        {"modbus", "crc16modbus"},
        {"xmodem", "crc16xmodem"},
        {"crc16zmodem", "crc16xmodem"},
        {"crc32isohdlc", "crc32"},
        {"crc32ieee", "crc32"},
        {"crc32castagnoli", "crc32c"},
        {"crc32iscsi", "crc32c"},
        {"castagnoli", "crc32c"},
        {"adler", "adler32"},
        {"fletcher", "fletcher16"},
        {"fnv32", "fnv1a32"},
        {"fnv64", "fnv1a64"},
        {"sha", "sha1"},
        {"sha2", "sha256"},
    };
    std::string k = key_of(name);
    for (const auto& a : aliases)
        if (k == a.first) k = a.second;
    if (k.empty()) return nullptr;
    for (const auto& a : hash_algorithms())
        if (key_of(a.name) == k) return &a;
    return nullptr;
}

std::unique_ptr<Hasher> make_hasher(const std::string& name) {
    const HashAlgorithm* a = find_hash_algorithm(name);
    return a ? a->create() : nullptr;
}

std::string to_hex(const std::vector<uint8_t>& bytes, bool uppercase) {
    const char* digits = uppercase ? "0123456789ABCDEF" : "0123456789abcdef";
    std::string s;
    s.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
        s += digits[b >> 4];
        s += digits[b & 15];
    }
    return s;
}

std::string hash_hex(const std::string& algo, const uint8_t* data, size_t len) {
    auto h = make_hasher(algo);
    if (!h) return {};
    if (len) h->update(data, len);
    return to_hex(h->finish());
}

std::string normalize_hex(const std::string& s) {
    std::string t;
    for (char ch : s) {
        const unsigned char c = static_cast<unsigned char>(ch);
        if (std::isspace(c) || c == ':' || c == '-') continue;
        t += char(std::tolower(c));
    }
    if (t.size() >= 2 && t[0] == '0' && t[1] == 'x') t.erase(0, 2);
    for (char c : t)
        if (!std::isxdigit(static_cast<unsigned char>(c))) return {};
    return t;
}

bool hex_matches(const std::string& expected, const std::string& digest_hex) {
    const std::string e = normalize_hex(expected);
    return !e.empty() && e == normalize_hex(digest_hex);
}

bool hash_range(const Snapshot& snap, uint64_t offset, uint64_t length, const std::vector<Hasher*>& hashers,
                const std::atomic<bool>* cancel, std::atomic<uint64_t>* progress, uint64_t* io_error_offset,
                bool* hole) {
    if (io_error_offset) *io_error_offset = UINT64_MAX;
    if (hole) *hole = false;
    const uint64_t size = snap.size();
    if (offset > size) offset = size;
    length = std::min(length, size - offset);
    const uint64_t end = offset + length;
    // A hole of a sparse source (unmapped process memory): refuse at once when the range starts or
    // ends in one (cheap region-map lookups), else at the first one met.
    auto refuse_hole = [&](uint64_t at) {
        if (io_error_offset) *io_error_offset = at;
        if (hole) *hole = true;
        return false;
    };
    if (length) {
        if (const uint64_t r = snap.next_readable(offset); r > offset) return refuse_hole(offset);
        if (const uint64_t e = snap.readable_end(offset, end); e < end) return refuse_hole(e);
    }
    std::vector<uint8_t> buf(size_t(std::min<uint64_t>(kBlock, length)));
    uint64_t pos = offset;
    while (pos < end) {
        if (cancel && cancel->load(std::memory_order_relaxed)) return false;
        const size_t want = size_t(std::min<uint64_t>(kBlock, end - pos));
        const size_t got = snap.read_valid(pos, buf.data(), want);
        for (Hasher* h : hashers) h->update(buf.data(), got);
        if (progress) progress->fetch_add(got, std::memory_order_relaxed);
        if (got < want) {
            const uint64_t at = pos + got;
            if (snap.next_readable(at) > at) return refuse_hole(at);
            if (io_error_offset) *io_error_offset = at;
            return false;
        }
        pos += want;
    }
    return !(cancel && cancel->load(std::memory_order_relaxed));
}

std::string hash_hole_message(uint64_t at) {
    char hex[32];
    std::snprintf(hex, sizeof hex, "0x%llX", static_cast<unsigned long long>(at));
    return std::string("the range has unreadable holes (unmapped / inaccessible memory at ") + hex +
           "); hashing a sparse address space is meaningless: select a readable region";
}

bool hash_snapshot_hex(const Snapshot& snap, const std::string& algo, uint64_t offset, uint64_t length,
                       std::string& out, std::string* err) {
    out.clear();
    auto h = make_hasher(algo);
    if (!h) {
        if (err) *err = "unknown hash algorithm '" + algo + "'";
        return false;
    }
    uint64_t bad = UINT64_MAX;
    bool hole = false;
    if (!hash_range(snap, offset, length, {h.get()}, nullptr, nullptr, &bad, &hole)) {
        if (err) *err = hole ? hash_hole_message(bad) : "read error at offset " + std::to_string(bad);
        return false;
    }
    out = to_hex(h->finish());
    return true;
}

// ---- background job -----------------------------------------------------------------------------

struct HashJob::Run {
    std::atomic<bool> cancel{false};
    std::atomic<bool> finished{false};  // worker is about to exit: joining it does not block
    std::atomic<uint64_t> done{0};
    uint64_t total = 0;
};

HashJob::~HashJob() {
    for (auto& t : threads_) t.second->cancel = true;
    for (auto& t : threads_) t.first.join();
}

std::shared_ptr<HashJob::Run> HashJob::current() const {
    std::lock_guard<std::mutex> lock(mu_);
    return run_;
}

void HashJob::cancel() {
    if (auto r = current()) r->cancel = true;
}

bool HashJob::running() const { return running_.load(); }

double HashJob::progress() const {
    auto r = current();
    const uint64_t t = r ? r->total : 0, d = r ? r->done.load() : 0;
    if (!t) return running_.load() ? 0.0 : 1.0;
    return d >= t ? 1.0 : double(d) / double(t);
}

uint64_t HashJob::generation() const { return generation_.load(); }

HashJob::Result HashJob::result() const {
    std::lock_guard<std::mutex> lock(mu_);
    return result_;
}

void HashJob::start(std::shared_ptr<const Snapshot> snap, uint64_t offset, uint64_t length,
                    std::vector<std::string> algos) {
    const uint64_t size = snap ? snap->size() : 0;
    offset = std::min(offset, size);
    length = std::min(length, size - offset);
    auto run = std::make_shared<Run>();
    run->total = length;
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (run_) run_->cancel = true;
        run_ = run;
    }
    for (auto it = threads_.begin(); it != threads_.end();) {
        if (it->second->finished) {
            it->first.join();
            it = threads_.erase(it);
        } else {
            ++it;
        }
    }
    running_ = true;
    std::thread th([this, run, snap = std::move(snap), offset, length, algos = std::move(algos)]() {
        Result r;
        r.offset = offset;
        r.length = length;
        std::vector<const HashAlgorithm*> infos;
        std::vector<std::unique_ptr<Hasher>> owned;
        std::vector<Hasher*> hs;
        for (const auto& name : algos) {
            if (const HashAlgorithm* a = find_hash_algorithm(name)) {
                infos.push_back(a);
                owned.push_back(a->create());
                hs.push_back(owned.back().get());
            }
        }
        uint64_t bad = UINT64_MAX;
        bool hole = false;
        const bool ok = !snap || hash_range(*snap, offset, length, hs, &run->cancel, &run->done, &bad, &hole);
        r.cancelled = run->cancel.load();
        r.io_error = bad != UINT64_MAX;
        r.io_error_offset = r.io_error ? bad : 0;
        r.hole = r.io_error && hole;
        if (ok && !r.cancelled)
            for (size_t i = 0; i < hs.size(); ++i) r.values.push_back({infos[i]->name, to_hex(hs[i]->finish())});
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (run_ == run) {  // superseded runs publish nothing
                result_ = std::move(r);
                run->done = run->total;
                running_ = false;
                generation_.fetch_add(1);
            }
        }
        run->finished = true;
    });
    threads_.emplace_back(std::move(th), std::move(run));
}

}  // namespace hx
