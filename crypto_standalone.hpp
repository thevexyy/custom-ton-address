// Compact SHA-256/SHA-512, HMAC/PBKDF2 and Ed25519 public-key derivation.
// Ed25519 field arithmetic is adapted from TweetNaCl (public domain).
#pragma once
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace crypto
{
using U8 = uint8_t;
using U32 = uint32_t;
using U64 = uint64_t;
using Bytes = std::vector<U8>;
inline U32 rotr(U32 x, int n)
{
    return (x >> n) | (x << (32 - n));
}
inline U64 rotr(U64 x, int n)
{
    return (x >> n) | (x << (64 - n));
}

struct Sha256
{
    std::array<U32, 8> h{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                         0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    std::array<U8, 64> buf{};
    U64 bytes = 0;
    size_t used = 0;
    static constexpr U32 K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2};
    void block(const U8 *p)
    {
        U32 w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = (U32(p[4 * i]) << 24) | (U32(p[4 * i + 1]) << 16) | (U32(p[4 * i + 2]) << 8) |
                   p[4 * i + 3];
        for (int i = 16; i < 64; ++i)
        {
            U32 a = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3),
                b = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + a + w[i - 7] + b;
        }
        auto v = h;
        for (int i = 0; i < 64; ++i)
        {
            U32 s1 = rotr(v[4], 6) ^ rotr(v[4], 11) ^ rotr(v[4], 25),
                ch = (v[4] & v[5]) ^ (~v[4] & v[6]), t1 = v[7] + s1 + ch + K[i] + w[i],
                s0 = rotr(v[0], 2) ^ rotr(v[0], 13) ^ rotr(v[0], 22),
                maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]), t2 = s0 + maj;
            for (int j = 7; j > 0; --j)
                v[j] = v[j - 1];
            v[4] += t1;
            v[0] = t1 + t2;
        }
        for (int i = 0; i < 8; ++i)
            h[i] += v[i];
    }
    void update(const U8 *p, size_t n)
    {
        bytes += n;
        while (n)
        {
            size_t k = std::min(n, 64 - used);
            std::memcpy(buf.data() + used, p, k);
            used += k;
            p += k;
            n -= k;
            if (used == 64)
            {
                block(buf.data());
                used = 0;
            }
        }
    }
    std::array<U8, 32> final()
    {
        U64 bits = bytes * 8;
        buf[used++] = 0x80;
        if (used > 56)
        {
            while (used < 64)
                buf[used++] = 0;
            block(buf.data());
            used = 0;
        }
        while (used < 56)
            buf[used++] = 0;
        for (int i = 7; i >= 0; --i)
            buf[used++] = U8(bits >> (8 * i));
        block(buf.data());
        std::array<U8, 32> o{};
        for (int i = 0; i < 8; ++i)
            for (int j = 0; j < 4; ++j)
                o[4 * i + j] = U8(h[i] >> (24 - 8 * j));
        return o;
    }
};
inline constexpr U32 Sha256::K[64];

struct Sha512
{
    std::array<U64, 8> h{0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
                         0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
                         0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};
    std::array<U8, 128> buf{};
    U64 bytes = 0;
    size_t used = 0;
    static constexpr U64 K[80] = {
        0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
        0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
        0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
        0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
        0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
        0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
        0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
        0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
        0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
        0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
        0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
        0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
        0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
        0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
        0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
        0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
        0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
        0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
        0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
        0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};
    void block(const U8 *p)
    {
        U64 w[80];
        for (int i = 0; i < 16; ++i)
        {
            w[i] = 0;
            for (int j = 0; j < 8; ++j)
                w[i] = (w[i] << 8) | p[8 * i + j];
        }
        for (int i = 16; i < 80; ++i)
        {
            U64 a = rotr(w[i - 15], 1) ^ rotr(w[i - 15], 8) ^ (w[i - 15] >> 7),
                b = rotr(w[i - 2], 19) ^ rotr(w[i - 2], 61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16] + a + w[i - 7] + b;
        }
        auto v = h;
        for (int i = 0; i < 80; ++i)
        {
            U64 s1 = rotr(v[4], 14) ^ rotr(v[4], 18) ^ rotr(v[4], 41),
                ch = (v[4] & v[5]) ^ (~v[4] & v[6]), t1 = v[7] + s1 + ch + K[i] + w[i],
                s0 = rotr(v[0], 28) ^ rotr(v[0], 34) ^ rotr(v[0], 39),
                maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]), t2 = s0 + maj;
            for (int j = 7; j > 0; --j)
                v[j] = v[j - 1];
            v[4] += t1;
            v[0] = t1 + t2;
        }
        for (int i = 0; i < 8; ++i)
            h[i] += v[i];
    }
    void update(const U8 *p, size_t n)
    {
        bytes += n;
        while (n)
        {
            size_t k = std::min(n, 128 - used);
            std::memcpy(buf.data() + used, p, k);
            used += k;
            p += k;
            n -= k;
            if (used == 128)
            {
                block(buf.data());
                used = 0;
            }
        }
    }
    std::array<U8, 64> final()
    {
        U64 bits = bytes * 8;
        buf[used++] = 0x80;
        if (used > 112)
        {
            while (used < 128)
                buf[used++] = 0;
            block(buf.data());
            used = 0;
        }
        while (used < 120)
            buf[used++] = 0;
        for (int i = 7; i >= 0; --i)
            buf[used++] = U8(bits >> (8 * i));
        block(buf.data());
        std::array<U8, 64> o{};
        for (int i = 0; i < 8; ++i)
            for (int j = 0; j < 8; ++j)
                o[8 * i + j] = U8(h[i] >> (56 - 8 * j));
        return o;
    }
};
inline constexpr U64 Sha512::K[80];
inline std::array<U8, 32> sha256(const U8 *p, size_t n)
{
    Sha256 s;
    s.update(p, n);
    return s.final();
}
inline std::array<U8, 64> sha512(const U8 *p, size_t n)
{
    Sha512 s;
    s.update(p, n);
    return s.final();
}

struct Hmac512
{
    Sha512 inner, outer;
    Hmac512(const U8 *key, size_t n)
    {
        std::array<U8, 128> k{};
        if (n > 128)
        {
            auto h = sha512(key, n);
            std::copy(h.begin(), h.end(), k.begin());
        }
        else if (n)
            std::copy(key, key + n, k.begin());
        std::array<U8, 128> a{}, b{};
        for (size_t i = 0; i < 128; ++i)
        {
            a[i] = k[i] ^ 0x36;
            b[i] = k[i] ^ 0x5c;
        }
        inner.update(a.data(), a.size());
        outer.update(b.data(), b.size());
    }
    std::array<U8, 64> run(const U8 *p, size_t n) const
    {
        auto i = inner;
        i.update(p, n);
        auto ih = i.final();
        auto o = outer;
        o.update(ih.data(), ih.size());
        return o.final();
    }
};
inline std::array<U8, 64> hmac512(const U8 *k, size_t kn, const U8 *m, size_t mn)
{
    return Hmac512(k, kn).run(m, mn);
}
template <size_t N>
inline std::array<U8, N> pbkdf2_fixed(const U8 *pass, size_t pn, const U8 *salt, size_t sn,
                                      U32 rounds)
{
    Hmac512 hm(pass, pn);
    std::array<U8, N> out{};
    size_t done = 0;
    U32 block = 1;
    while (done < N)
    {
        std::array<U8, 260> msg{};
        if (sn > 256)
            throw std::runtime_error("PBKDF2 salt too long");
        std::memcpy(msg.data(), salt, sn);
        msg[sn] = U8(block >> 24);
        msg[sn + 1] = U8(block >> 16);
        msg[sn + 2] = U8(block >> 8);
        msg[sn + 3] = U8(block);
        auto u = hm.run(msg.data(), sn + 4), t = u;
        for (U32 i = 1; i < rounds; ++i)
        {
            u = hm.run(u.data(), u.size());
            for (size_t j = 0; j < 64; ++j)
                t[j] ^= u[j];
        }
        size_t k = std::min<size_t>(64, N - done);
        std::copy_n(t.data(), k, out.data() + done);
        done += k;
        ++block;
    }
    return out;
}

using GF = int64_t[16];
inline void set25519(GF r, const GF a)
{
    for (int i = 0; i < 16; ++i)
        r[i] = a[i];
}
inline void car25519(GF o)
{
    for (int i = 0; i < 16; ++i)
    {
        o[i] += (1LL << 16);
        int64_t c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}
inline void sel25519(GF p, GF q, int b)
{
    int64_t t, c = ~(int64_t(b) - 1);
    for (int i = 0; i < 16; ++i)
    {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}
inline void pack25519(U8 *o, const GF n)
{
    GF m, t;
    set25519(t, n);
    car25519(t);
    car25519(t);
    car25519(t);
    for (int j = 0; j < 2; ++j)
    {
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; ++i)
        {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        int b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        sel25519(t, m, 1 - b);
    }
    for (int i = 0; i < 16; ++i)
    {
        o[2 * i] = U8(t[i]);
        o[2 * i + 1] = U8(t[i] >> 8);
    }
}
inline void A(GF o, const GF a, const GF b)
{
    for (int i = 0; i < 16; ++i)
        o[i] = a[i] + b[i];
}
inline void Z(GF o, const GF a, const GF b)
{
    for (int i = 0; i < 16; ++i)
        o[i] = a[i] - b[i];
}
inline void M(GF o, const GF a, const GF b)
{
    int64_t t[31]{};
    for (int i = 0; i < 16; ++i)
        for (int j = 0; j < 16; ++j)
            t[i + j] += a[i] * b[j];
    for (int i = 0; i < 15; ++i)
        t[i] += 38 * t[i + 16];
    for (int i = 0; i < 16; ++i)
        o[i] = t[i];
    car25519(o);
    car25519(o);
}
inline void S(GF o, const GF a)
{
    M(o, a, a);
}
inline void inv25519(GF o, const GF i)
{
    GF c;
    set25519(c, i);
    for (int a = 253; a >= 0; --a)
    {
        S(c, c);
        if (a != 2 && a != 4)
            M(c, c, i);
    }
    set25519(o, c);
}
inline void add(GF p[4], GF q[4], const GF D2)
{
    GF a, b, c, d, t, e, f, g, h;
    Z(a, p[1], p[0]);
    Z(t, q[1], q[0]);
    M(a, a, t);
    A(b, p[0], p[1]);
    A(t, q[0], q[1]);
    M(b, b, t);
    M(c, p[3], q[3]);
    M(c, c, D2);
    M(d, p[2], q[2]);
    A(d, d, d);
    Z(e, b, a);
    Z(f, d, c);
    A(g, d, c);
    A(h, b, a);
    M(p[0], e, f);
    M(p[1], h, g);
    M(p[2], g, f);
    M(p[3], e, h);
}
inline void cswap(GF p[4], GF q[4], U8 b)
{
    for (int i = 0; i < 4; ++i)
        sel25519(p[i], q[i], b);
}
inline U8 parity(const GF a)
{
    U8 d[32];
    pack25519(d, a);
    return d[0] & 1;
}
inline void packpoint(U8 *r, GF p[4], int)
{
    GF tx, ty, zi;
    inv25519(zi, p[2]);
    M(tx, p[0], zi);
    M(ty, p[1], zi);
    pack25519(r, ty);
    r[31] ^= U8(parity(tx) << 7);
}
inline void scalarmult(GF p[4], GF q[4], const U8 *s, const GF X, const GF Y, const GF gf0,
                       const GF gf1, const GF D2)
{
    set25519(p[0], gf0);
    set25519(p[1], gf1);
    set25519(p[2], gf1);
    set25519(p[3], gf0);
    for (int i = 255; i >= 0; --i)
    {
        U8 b = (s[i / 8] >> (i & 7)) & 1;
        cswap(p, q, b);
        add(q, p, D2);
        add(p, p, D2);
        cswap(p, q, b);
    }
}
inline std::array<U8, 32> ed25519_public(const U8 *seed, size_t n)
{
    if (n != 32)
        throw std::runtime_error("Ed25519 seed must be 32 bytes");
    auto d = sha512(seed, n);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;
    GF X = {0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
            0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169},
       Y = {0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
            0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666},
       gf0 = {}, gf1 = {1}, D2 = {0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
                                  0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406};
    GF q[4], p[4];
    set25519(q[0], X);
    set25519(q[1], Y);
    set25519(q[2], gf1);
    M(q[3], X, Y);
    scalarmult(p, q, d.data(), X, Y, gf0, gf1, D2);
    std::array<U8, 32> out{};
    packpoint(out.data(), p, 0);
    return out;
}
} // namespace crypto
