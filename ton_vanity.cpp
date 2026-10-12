#define NOMINMAX
#include "bip39_embedded.hpp"
#include "crypto_standalone.hpp"
#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <deque>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#else
#include <random>
#endif

using U8 = uint8_t;
using U16 = uint16_t;
using U32 = uint32_t;
static constexpr char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
static std::vector<std::string> words;
static std::mutex output_mutex;
static void require(bool ok, const char *msg)
{
    if (!ok)
        throw std::runtime_error(msg);
}

struct Phrase
{
    std::array<char, 512> bytes{};
    size_t size = 0;
    const U8 *data() const
    {
        return reinterpret_cast<const U8 *>(bytes.data());
    }
    std::string str() const
    {
        return std::string(bytes.data(), size);
    }
};
#include "opencl_ton_kdf.hpp"
struct Address
{
    std::array<char, 49> bytes{};
    const char *c_str() const
    {
        return bytes.data();
    }
};
static bool interactive_mode = false;
void random_bytes(U8 *p, size_t n)
{
    struct RandomBuffer
    {
        std::array<U8, 65536> bytes{};
        size_t offset = bytes.size();
    };
    thread_local RandomBuffer rng;
    while (n)
    {
        if (rng.offset == rng.bytes.size())
        {
#ifdef _WIN32
            require(BCryptGenRandom(nullptr, rng.bytes.data(), ULONG(rng.bytes.size()),
                                    BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0,
                    "BCryptGenRandom failed");
#else
            std::random_device rd;
            for (auto &b : rng.bytes)
                b = static_cast<U8>(rd());
#endif
            rng.offset = 0;
        }
        size_t take = std::min(n, rng.bytes.size() - rng.offset);
        std::memcpy(p, rng.bytes.data() + rng.offset, take);
        p += take;
        n -= take;
        rng.offset += take;
    }
}
std::string hex(const U8 *p, size_t n)
{
    static constexpr char h[] = "0123456789abcdef";
    std::string s;
    s.resize(2 * n);
    for (size_t i = 0; i < n; ++i)
    {
        s[2 * i] = h[p[i] >> 4];
        s[2 * i + 1] = h[p[i] & 15];
    }
    return s;
}
Phrase generate_phrase()
{
    std::array<U8, 33> entropy{};
    random_bytes(entropy.data(), entropy.size());
    Phrase p;
    for (int i = 0; i < 24; ++i)
    {
        unsigned ix = 0;
        for (int j = 0; j < 11; ++j)
        {
            size_t bit = size_t(i) * 11 + j;
            ix = (ix << 1) | ((entropy[bit / 8] >> (7 - (bit % 8))) & 1);
        }
        if (i)
            p.bytes[p.size++] = ' ';
        const auto &w = words[ix];
        std::copy(w.begin(), w.end(), p.bytes.begin() + p.size);
        p.size += w.size();
    }
    return p;
}
bool derive_secret(const Phrase &phrase, std::array<U8, 32> &secret)
{
    static const U8 empty = 0;
    auto hk = crypto::hmac512(phrase.data(), phrase.size, &empty, 0);
    auto version =
        crypto::pbkdf2_fixed<1>(hk.data(), hk.size(), (const U8 *)"TON seed version", 16, 390);
    if (version[0] != 0)
        return false;
    secret =
        crypto::pbkdf2_fixed<32>(hk.data(), hk.size(), (const U8 *)"TON default seed", 16, 100000);
    return true;
}
Address address(const std::array<U8, 32> &pk, bool bounce)
{
    static constexpr U8 code[] = {0xfe, 0xb5, 0xff, 0x68, 0x20, 0xe2, 0xff, 0x0d, 0x94, 0x83, 0xe7,
                                  0xe0, 0xd6, 0x2c, 0x81, 0x7d, 0x84, 0x67, 0x89, 0xfb, 0x4a, 0xe5,
                                  0x80, 0xc8, 0x78, 0x86, 0x6d, 0x95, 0x9d, 0xab, 0xd5, 0xc0};
    std::array<U8, 43> data = {0x00, 0x51, 0, 0, 0, 0, 0x29, 0xa9, 0xa3, 0x17};
    std::copy(pk.begin(), pk.end(), data.begin() + 10);
    data[42] = 0x40;
    auto dh = crypto::sha256(data.data(), data.size());
    std::array<U8, 71> state{};
    state[0] = 2;
    state[1] = 1;
    state[2] = 0x34;
    state[4] = 7;
    std::copy(std::begin(code), std::end(code), state.begin() + 7);
    std::copy(dh.begin(), dh.end(), state.begin() + 39);
    auto ah = crypto::sha256(state.data(), state.size());
    std::array<U8, 36> raw{};
    raw[0] = bounce ? 0x11 : 0x51;
    raw[1] = 0;
    std::copy(ah.begin(), ah.end(), raw.begin() + 2);
    uint16_t crc = 0;
    for (U8 b : std::array<U8, 34>{raw[0],  raw[1],  raw[2],  raw[3],  raw[4],  raw[5],  raw[6],
                                   raw[7],  raw[8],  raw[9],  raw[10], raw[11], raw[12], raw[13],
                                   raw[14], raw[15], raw[16], raw[17], raw[18], raw[19], raw[20],
                                   raw[21], raw[22], raw[23], raw[24], raw[25], raw[26], raw[27],
                                   raw[28], raw[29], raw[30], raw[31], raw[32], raw[33]})
    {
        crc ^= uint16_t(b) << 8;
        for (int j = 0; j < 8; ++j)
            crc = (crc & 0x8000) ? uint16_t((crc << 1) ^ 0x1021) : uint16_t(crc << 1);
    }
    raw[34] = U8(crc >> 8);
    raw[35] = U8(crc);
    Address out;
    size_t k = 0;
    for (size_t i = 0; i < 36; i += 3)
    {
        unsigned v = (unsigned(raw[i]) << 16) | (unsigned(raw[i + 1]) << 8) | raw[i + 2];
        out.bytes[k++] = B64[(v >> 18) & 63];
        out.bytes[k++] = B64[(v >> 12) & 63];
        out.bytes[k++] = B64[(v >> 6) & 63];
        out.bytes[k++] = B64[v & 63];
    }
    return out;
}
void load_words()
{
    std::istringstream f(bip39::english);
    std::string w;
    while (std::getline(f, w))
    {
        if (!w.empty() && w.back() == '\r')
            w.pop_back();
        if (!w.empty())
            words.push_back(w);
    }
    require(words.size() == 2048, "embedded BIP-39 wordlist must contain exactly 2048 words");
}
struct GpuInfo
{
    bool runtime = false;
    std::string name = "No OpenCL GPU found";
};
GpuInfo detect_opencl();
std::array<U8, 2048 * 17> make_word_table()
{
    std::array<U8, 2048 * 17> table{};
    for (size_t i = 0; i < words.size(); ++i)
    {
        require(words[i].size() <= 16, "BIP-39 word exceeds GPU word-table width");
        size_t at = i * 17;
        table[at] = U8(words[i].size());
        std::copy(words[i].begin(), words[i].end(), table.begin() + at + 1);
    }
    return table;
}
toncl::Prefix random_prefix()
{
    std::array<U8, 46> bytes{};
    random_bytes(bytes.data(), bytes.size());
    toncl::Prefix p{};
    for (size_t i = 0; i < 23; ++i)
    {
        U16 ix = U16(((U16(bytes[i * 2]) << 8) | bytes[i * 2 + 1]) & 0x7ff);
        p[i * 2] = U8(ix >> 8);
        p[i * 2 + 1] = U8(ix);
    }
    return p;
}
std::array<uint16_t, 24> indices_from_phrase(const std::string &s)
{
    std::array<uint16_t, 24> out{};
    std::istringstream in(s);
    std::string w;
    size_t n = 0;
    while (in >> w)
    {
        auto it = std::find(words.begin(), words.end(), w);
        require(it != words.end() && n < out.size(),
                "GPU self-test phrase does not map to the embedded list");
        out[n++] = uint16_t(it - words.begin());
    }
    require(n == 24, "GPU self-test phrase must contain 24 words");
    return out;
}
Phrase phrase_from_indices(const std::array<uint16_t, 24> &ix)
{
    Phrase p;
    for (size_t i = 0; i < ix.size(); ++i)
    {
        if (i)
            p.bytes[p.size++] = ' ';
        const auto &w = words[ix[i]];
        std::copy(w.begin(), w.end(), p.bytes.begin() + p.size);
        p.size += w.size();
    }
    return p;
}
struct Opt
{
    bool bounce = false, strict = false, use_gpu = false, smoke_test = false,
         benchmark_only = false;
    int gpu_index = -1;
    std::string prefix, suffix, preset = "custom";
    unsigned threads = std::max(1u, std::thread::hardware_concurrency());
};
Opt parse(int argc, char **argv)
{
    Opt o;
    bool any = argc > 1;
    if (!any)
    {
        interactive_mode = true;
        unsigned n = std::max(1u, std::thread::hardware_concurrency());
        GpuInfo detected = detect_opencl();
        int default_choice = detected.runtime ? 4 : 3;
        std::string line;
        std::cout << "TON Vanity 24-word TON-native\nTarget prefix after UQ [skip]: ";
        std::getline(std::cin, o.prefix);
        if (o.prefix.rfind("UQ", 0) == 0)
            o.prefix.erase(0, 2);
        std::cout << "Target suffix [skip]: ";
        std::getline(std::cin, o.suffix);
        std::cout << "Case-sensitive? [y/N]: ";
        std::getline(std::cin, line);
        o.strict = !line.empty() && (line[0] == 'y' || line[0] == 'Y');
        std::cout
            << "Resource preset: 1 low (25%), 2 medium (50%), 3 max CPU (100%), 4 hybrid CPU+GPU"
            << (detected.runtime ? " (OpenCL GPU detected)" : "") << " [" << default_choice
            << "]: ";
        std::getline(std::cin, line);
        int choice = line.empty() ? default_choice : std::stoi(line);
        if (choice == 1)
            o.threads = std::max(1u, n / 4);
        else if (choice == 2)
            o.threads = std::max(1u, n / 2);
        else if (choice == 3)
            o.threads = n;
        else if (choice == 4)
        {
            o.threads = n;
            o.use_gpu = true;
        }
        else
            throw std::runtime_error("invalid resource preset");
    }
    for (int i = 1; i < argc; ++i)
    {
        std::string a = argv[i];
        auto val = [&]() {
            require(i + 1 < argc, "missing option value");
            return std::string(argv[++i]);
        };
        if (a == "--prefix")
            o.prefix = val();
        else if (a == "--suffix")
            o.suffix = val();
        else if (a == "--strict")
            o.strict = true;
        else if (a == "--bounceable")
            o.bounce = true;
        else if (a == "--cpu-threads")
            o.threads = std::stoul(val());
        else if (a == "--gpu-index")
            o.gpu_index = std::stoi(val());
        else if (a == "--preset")
        {
            o.preset = val();
            unsigned n = std::max(1u, std::thread::hardware_concurrency());
            if (o.preset == "low")
                o.threads = std::max(1u, n / 4);
            else if (o.preset == "medium")
                o.threads = std::max(1u, n / 2);
            else if (o.preset == "max")
                o.threads = n;
            else
                throw std::runtime_error("--preset must be low, medium, or max");
        }
        else if (a == "--use-gpu")
            o.use_gpu = true;
        else if (a == "--benchmark-only")
            o.benchmark_only = true;
        else if (a == "--smoke-test")
            o.smoke_test = true;
        else if (a == "--words" || a == "--bip39" || a == "--fast-bip39" || a == "--slip-path")
            throw std::runtime_error("this build supports only 24-word TON-native mnemonics");
        else if (a == "--help")
        {
            std::cout
                << "ton_vanity [--cpu-threads N] [--preset low|medium|max] [--use-gpu] "
                   "[--gpu-index N] [--prefix TEXT] [--suffix TEXT] [--strict] [--smoke-test] "
                   "[--benchmark-only]\nOnly 24-word TON-native phrases are generated.\n";
            std::exit(0);
        }
        else
            throw std::runtime_error("unknown option: " + a);
    }
    require(o.threads > 0 && o.threads <= 1024, "invalid CPU thread count");
    if (o.prefix.rfind("UQ", 0) == 0 || o.prefix.rfind("EQ", 0) == 0)
        o.prefix.erase(0, 2);
    return o;
}
double difficulty(const Opt &o)
{
    double p = 1;
    for (size_t i = 0; i < o.prefix.size(); ++i)
    {
        char c = o.prefix[i];
        if (i == 0)
        {
            if (!o.strict)
                c = char(std::toupper((unsigned char)c));
            require(c >= 'A' && c <= 'D', "prefix first char after UQ/EQ must be A-D");
            p *= .25;
        }
        else
            p *= (!o.strict && std::isalpha((unsigned char)c)) ? 2.0 / 64 : 1.0 / 64;
    }
    for (char c : o.suffix)
        p *= (!o.strict && std::isalpha((unsigned char)c)) ? 2.0 / 64 : 1.0 / 64;
    return p;
}
bool matches(const Address &a, const Opt &o)
{
    const char *b = a.bytes.data() + 2;
    size_t n = 46;
    if (n < o.prefix.size() + o.suffix.size())
        return false;
    auto eq = [&](char x, char y) {
        if (!o.strict)
        {
            x = char(std::toupper((unsigned char)x));
            y = char(std::toupper((unsigned char)y));
        }
        return x == y;
    };
    for (size_t i = 0; i < o.prefix.size(); ++i)
        if (!eq(b[i], o.prefix[i]))
            return false;
    for (size_t i = 0; i < o.suffix.size(); ++i)
        if (!eq(b[n - o.suffix.size() + i], o.suffix[i]))
            return false;
    return true;
}
std::string duration(double s)
{
    if (!std::isfinite(s))
        return "n/a";
    long double t = std::ceil((long double)s);
    if (t > 9e18L)
        return "over 292 billion years";
    long long n = (long long)t;
    if (n < 60)
        return std::to_string(n) + "s";
    if (n < 3600)
        return std::to_string(n / 60) + "m " + std::to_string(n % 60) + "s";
    if (n < 86400)
        return std::to_string(n / 3600) + "h " + std::to_string((n / 60) % 60) + "m";
    return std::to_string(n / 86400) + "d " + std::to_string((n / 3600) % 24) + "h";
}
std::string cpu_name()
{
#ifdef _WIN32
    HKEY k;
    char b[256]{};
    DWORD n = sizeof(b);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", 0,
                      KEY_READ, &k) == ERROR_SUCCESS)
    {
        RegQueryValueExA(k, "ProcessorNameString", nullptr, nullptr, (BYTE *)b, &n);
        RegCloseKey(k);
    }
    return *b ? b : "Unknown CPU";
#else
    return "CPU model unavailable";
#endif
}
unsigned physical_cores()
{
#ifdef _WIN32
    DWORD b = 0;
    GetLogicalProcessorInformation(nullptr, &b);
    if (!b)
        return 0;
    std::vector<U8> v(b);
    auto *p = reinterpret_cast<SYSTEM_LOGICAL_PROCESSOR_INFORMATION *>(v.data());
    if (!GetLogicalProcessorInformation(p, &b))
        return 0;
    unsigned n = 0;
    for (size_t i = 0; i < b / sizeof(*p); ++i)
        if (p[i].Relationship == RelationProcessorCore)
            ++n;
    return n;
#else
    return 0;
#endif
}
GpuInfo detect_opencl()
{
#ifdef _WIN32
    using Plat = void *;
    using Dev = void *;
    using GetPlatforms = int(__stdcall *)(unsigned, Plat *, unsigned *);
    using GetDevices = int(__stdcall *)(Plat, unsigned, unsigned, Dev *, unsigned *);
    using GetInfo = int(__stdcall *)(Dev, unsigned, size_t, void *, size_t *);
    GpuInfo r;
    HMODULE h = LoadLibraryA("OpenCL.dll");
    if (!h)
    {
        r.name = "OpenCL runtime unavailable";
        return r;
    }
    auto gp = (GetPlatforms)GetProcAddress(h, "clGetPlatformIDs");
    auto gd = (GetDevices)GetProcAddress(h, "clGetDeviceIDs");
    auto gi = (GetInfo)GetProcAddress(h, "clGetDeviceInfo");
    if (!gp || !gd || !gi)
    {
        r.name = "OpenCL loader missing required entry points";
        return r;
    }
    unsigned np = 0;
    if (gp(0, nullptr, &np) != 0 || !np)
        return r;
    std::array<Plat, 16> platforms{};
    np = std::min(np, (unsigned)platforms.size());
    if (gp(np, platforms.data(), nullptr) != 0)
        return r;
    for (unsigned i = 0; i < np; ++i)
    {
        unsigned nd = 0;
        if (gd(platforms[i], 4, 0, nullptr, &nd) != 0 || !nd)
            continue;
        std::array<Dev, 16> devices{};
        nd = std::min(nd, (unsigned)devices.size());
        if (gd(platforms[i], 4, nd, devices.data(), nullptr) != 0)
            continue;
        char name[256]{};
        size_t got = 0;
        gi(devices[0], 0x102b, sizeof(name) - 1, name, &got);
        r.runtime = true;
        r.name = name;
        return r;
    }
    return r;
#else
    return {};
#endif
}
void self_test()
{
    auto a = crypto::sha256((const U8 *)"abc", 3);
    require(hex(a.data(), a.size()) ==
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "SHA-256 test failed");
    auto b = crypto::sha512((const U8 *)"abc", 3);
    require(hex(b.data(), b.size()) ==
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836"
                "ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            "SHA-512 test failed");
    auto pb = crypto::pbkdf2_fixed<64>((const U8 *)"password", 8, (const U8 *)"salt", 4, 1);
    require(hex(pb.data(), pb.size()) ==
                "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501ba"
                "d999bfe943c08f050235d7d68b1da55e63f73b60a57fce",
            "PBKDF2 test failed");
    const U8 known_pk[32] = {0x88, 0x41, 0x11, 0xe5, 0x94, 0x72, 0x30, 0xf5, 0x74, 0xa5, 0x36,
                             0xb2, 0x70, 0xf0, 0x73, 0x9e, 0x99, 0x2c, 0x1f, 0xc9, 0x09, 0x4e,
                             0x11, 0x52, 0x17, 0x17, 0x0b, 0x71, 0x17, 0x51, 0x70, 0x70};
    std::array<U8, 32> checkpk{};
    std::copy(std::begin(known_pk), std::end(known_pk), checkpk.begin());
    const std::string phrase =
        "reveal pair october art leave weekend setup boss image manual side enact flee enter "
        "hazard pride history lazy under fox beauty supply allow goat";
    auto hk = crypto::hmac512((const U8 *)phrase.data(), phrase.size(), (const U8 *)"", 0);
    auto version =
        crypto::pbkdf2_fixed<1>(hk.data(), hk.size(), (const U8 *)"TON seed version", 16, 390);
    require(version[0] == 0, "TON basic-seed version vector failed");
    auto expected = "UQDNnD8-Mz0Owrp6ijBAU-L-LKR0Nactf76BEjB5djcHJNOO";
    auto got = address(checkpk, false);
    std::cout << "V4R2 depth-7 address vector: " << got.c_str() << "\n";
    require(std::string(got.c_str()) == expected, "V4R2 StateInit/address vector failed");
}
void gpu_self_test(toncl::OpenCLGpu &gpu)
{
    const std::string s =
        "reveal pair october art leave weekend setup boss image manual side enact flee enter "
        "hazard pride history lazy under fox beauty supply allow goat";
    auto ix = indices_from_phrase(s);
    Phrase p = phrase_from_indices(ix);
    std::array<U8, 32> cpu{};
    require(derive_secret(p, cpu), "CPU TON fixture unexpectedly failed filter");
    toncl::Prefix prefix{};
    for (size_t i = 0; i < 23; i++)
    {
        prefix[i * 2] = U8(ix[i] >> 8);
        prefix[i * 2 + 1] = U8(ix[i]);
    }
    std::vector<toncl::MutatedCandidate> candidates;
    require(gpu.mutate_filter(std::vector<toncl::Prefix>{prefix}, candidates), gpu.error().c_str());
    auto it = std::find_if(candidates.begin(), candidates.end(), [&](const auto &c) {
        return c.prefix_id == 0 && c.word24 == ix[23];
    });
    require(it != candidates.end(),
            "GPU phrase assembly or TON version filter rejected known fixture");
    auto cpu_state = toncl::OpenCLGpu::states_from_phrase(p);
    require(it->state == cpu_state,
            "GPU phrase assembly produced different TON-KDF midstates than CPU");
    std::vector<std::array<U8, 128>> states{it->state};
    std::vector<std::array<U8, 32>> out;
    require(gpu.run_derive(states, out), gpu.error().c_str());
    require(out.size() == 1 && out[0] == cpu,
            "GPU phrase assembly/filter/derive differs from CPU result");
    std::cout << "OpenCL kernel self-test: passed (GPU 24th-word assembly + 390 filter + "
                 "100000-round seed parity)\n";
}
void gpu_pipeline(toncl::OpenCLGpu &gpu, std::atomic<bool> &run, std::atomic<uint64_t> &raw,
                  std::atomic<uint64_t> &valid, unsigned worker_count,
                  const std::function<void(const Phrase &, const std::array<U8, 32> &)> &consume)
{
    struct Pending
    {
        std::array<U8, 128> state{};
        std::array<uint16_t, 24> words{};
    };
    struct Result
    {
        std::vector<std::array<U8, 32>> seeds;
        std::vector<std::array<uint16_t, 24>> words;
    };
    std::mutex mutex;
    std::condition_variable cv;
    std::deque<Result> slots;
    bool worker_done = false;
    std::exception_ptr worker_error, consumer_error;
    std::thread gpu_worker([&] {
        try
        {
            std::vector<Pending> pending;
            pending.reserve(gpu.derive_target() + 128);
            auto derive_pending = [&]() {
                if (pending.empty())
                    return;
                std::vector<std::array<U8, 128>> states;
                states.reserve(pending.size());
                Result result;
                result.words.reserve(pending.size());
                for (auto &x : pending)
                {
                    states.push_back(x.state);
                    result.words.push_back(x.words);
                }
                if (!gpu.run_derive(states, result.seeds))
                    throw std::runtime_error(gpu.error());
                std::unique_lock<std::mutex> lock(mutex);
                cv.wait(lock, [&] {
                    return slots.size() < 2;
                });
                slots.push_back(std::move(result));
                lock.unlock();
                cv.notify_all();
                pending.clear();
            };
            while (run.load(std::memory_order_relaxed))
            {
                std::vector<toncl::Prefix> prefixes(toncl::Batch / 2048);
                for (auto &p : prefixes)
                    p = random_prefix();
                std::vector<toncl::MutatedCandidate> found;
                if (!gpu.mutate_filter(prefixes, found))
                    throw std::runtime_error(gpu.error());
                raw.fetch_add(prefixes.size() * 2048, std::memory_order_relaxed);
                for (auto &c : found)
                {
                    if (c.prefix_id >= prefixes.size() || c.word24 >= 2048)
                        throw std::runtime_error("GPU mutator returned invalid word indices");
                    Pending x;
                    x.state = c.state;
                    for (size_t j = 0; j < 23; j++)
                        x.words[j] = uint16_t((U16(prefixes[c.prefix_id][j * 2]) << 8) |
                                              prefixes[c.prefix_id][j * 2 + 1]);
                    x.words[23] = uint16_t(c.word24);
                    pending.push_back(std::move(x));
                }
                if (pending.size() >= gpu.derive_target())
                    derive_pending();
            }
            derive_pending();
        }
        catch (...)
        {
            worker_error = std::current_exception();
            run = false;
        }
        {
            {
                std::lock_guard<std::mutex> lock(mutex);
                worker_done = true;
            }
            cv.notify_all();
        }
    });
    for (;;)
    {
        Result result;
        {
            std::unique_lock<std::mutex> lock(mutex);
            cv.wait(lock, [&] {
                return worker_done || !slots.empty();
            });
            if (slots.empty() && worker_done)
                break;
            result = std::move(slots.front());
            slots.pop_front();
        }
        cv.notify_all();
        std::atomic<size_t> next{0};
        unsigned nworkers =
            std::max(1u, std::min<unsigned>(worker_count, unsigned(result.seeds.size())));
        std::vector<std::thread> workers;
        workers.reserve(nworkers);
        for (unsigned t = 0; t < nworkers; t++)
            workers.emplace_back([&] {
                try
                {
                    for (;;)
                    {
                        size_t i = next.fetch_add(1, std::memory_order_relaxed);
                        if (i >= result.seeds.size())
                            break;
                        Phrase phrase = phrase_from_indices(result.words[i]);
                        consume(phrase, result.seeds[i]);
                        valid.fetch_add(1, std::memory_order_relaxed);
                    }
                }
                catch (...)
                {
                    std::lock_guard<std::mutex> lock(mutex);
                    if (!consumer_error)
                        consumer_error = std::current_exception();
                    run = false;
                    cv.notify_all();
                }
            });
        for (auto &t : workers)
            t.join();
    }
    gpu_worker.join();
    if (worker_error)
        std::rethrow_exception(worker_error);
    if (consumer_error)
        std::rethrow_exception(consumer_error);
}
int main(int argc, char **argv)
{
    int rc = 1;
    try
    {
        Opt o = parse(argc, argv);
        load_words();
        self_test();
        std::cout << "Startup crypto self-test: passed\n";
        toncl::OpenCLGpu gpu;
        bool gpu_active = false;
        if (o.use_gpu)
        {
            auto word_table = make_word_table();
            gpu_active = gpu.init(o.gpu_index, word_table.data(), word_table.size());
            require(gpu_active, gpu.error().c_str());
            gpu_self_test(gpu);
        }
        else if (o.gpu_index >= 0)
            throw std::runtime_error("--gpu-index requires --use-gpu");
        if (o.smoke_test)
        {
            Phrase ph;
            std::array<U8, 32> sk{};
            uint64_t attempts = 0;
            do
            {
                ph = generate_phrase();
                ++attempts;
            } while (!derive_secret(ph, sk));
            auto pk = crypto::ed25519_public(sk.data(), sk.size());
            Address ad = address(pk, o.bounce);
            std::cout << "Smoke test: accepted a TON-native 24-word phrase after " << attempts
                      << " candidates.\nAddress: " << ad.c_str()
                      << "\nPattern matched: " << (matches(ad, o) ? "yes" : "no")
                      << "\nRecovery phrase suppressed.\n";
            return 0;
        }
        double p = difficulty(o), expected = 1.0 / p;
        std::atomic<bool> bench{true};
        std::atomic<uint64_t> valid{0}, raw{0};
        std::vector<std::thread> pool;
        pool.reserve(o.threads);
        if (!gpu_active)
            for (unsigned i = 0; i < o.threads; ++i)
                pool.emplace_back([&] {
                    uint64_t v = 0, r = 0;
                    while (bench)
                    {
                        Phrase ph = generate_phrase();
                        ++r;
                        std::array<U8, 32> sk{};
                        if (!derive_secret(ph, sk))
                            continue;
                        auto pk = crypto::ed25519_public(sk.data(), sk.size());
                        (void)address(pk, o.bounce);
                        ++v;
                    }
                    valid.fetch_add(v, std::memory_order_relaxed);
                    raw.fetch_add(r, std::memory_order_relaxed);
                });
        std::atomic<uint64_t> gpu_valid{0}, gpu_raw{0};
        std::atomic<bool> gpu_bench_done{false};
        std::exception_ptr gpu_bench_exception;
        std::thread gpu_bench;
        if (gpu_active)
            gpu_bench = std::thread([&] {
                try
                {
                    gpu_pipeline(gpu, bench, gpu_raw, gpu_valid, o.threads,
                                 [&](const Phrase &, const std::array<U8, 32> &seed) {
                                     auto pk = crypto::ed25519_public(seed.data(), seed.size());
                                     (void)address(pk, o.bounce);
                                 });
                }
                catch (...)
                {
                    gpu_bench_exception = std::current_exception();
                    bench = false;
                }
                gpu_bench_done = true;
            });
        auto benchmark_start = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() - benchmark_start < std::chrono::seconds(2) ||
               (gpu_active && !gpu_bench_done && gpu_valid.load() < gpu.derive_target()))
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        bench = false;
        for (auto &t : pool)
            t.join();
        if (gpu_bench.joinable())
            gpu_bench.join();
        if (gpu_bench_exception)
            std::rethrow_exception(gpu_bench_exception);
        double elapsed =
                   std::chrono::duration<double>(std::chrono::steady_clock::now() - benchmark_start)
                       .count(),
               speed = (valid.load() + gpu_valid.load()) / elapsed,
               rawspeed = (raw.load() + gpu_raw.load()) / elapsed;
        std::cout << "+----------------------+------------------------------------------+\n| CPU   "
                     "               | "
                  << cpu_name() << "\n| CPU cores / workers  | "
                  << (physical_cores() ? std::to_string(physical_cores()) : "unknown")
                  << " physical / " << std::thread::hardware_concurrency() << " logical / "
                  << o.threads << " workers\n| GPU                  | "
                  << (gpu_active ? gpu.name() : "OpenCL not enabled")
                  << "\n| GPU Mode             | " << (gpu_active ? gpu.mode() : "n/a")
                  << "\n| Mode                 | 24-word TON-native / HMAC filter 390 + PBKDF2 "
                     "100000\n| Benchmark duration   | "
                  << std::fixed << std::setprecision(2) << elapsed
                  << " seconds\n| Benchmark            | " << speed << " valid wallets/sec ("
                  << (gpu_active ? "GPU KDF + CPU Ed/address" : "CPU")
                  << ")\n| Raw phrases checked  | " << rawspeed
                  << " phrases/sec\n| Expected combinations| " << std::setprecision(0) << expected
                  << "\n| ETA 50%              | " << duration(.693 * expected / speed)
                  << "\n| ETA 63.2%            | " << duration(expected / speed)
                  << "\n| ETA 90%              | " << duration(2.302 * expected / speed)
                  << "\n+----------------------+------------------------------------------+\n";
        if (o.benchmark_only)
            return 0;
        std::atomic<bool> run{true}, found{false};
        std::atomic<uint64_t> checked{0}, search_raw{0};
        auto save_match = [&](const Phrase &ph, const std::array<U8, 32> &sk) {
            auto pk = crypto::ed25519_public(sk.data(), sk.size());
            Address ad = address(pk, o.bounce);
            uint64_t n = checked.fetch_add(1, std::memory_order_relaxed) + 1;
            if (matches(ad, o))
            {
                bool no = false;
                if (found.compare_exchange_strong(no, true))
                {
                    std::string rec =
                        "Address: " + std::string(ad.c_str()) +
                        "\nMode: 24 words (TON-native)\nPublic Key: " + hex(pk.data(), pk.size()) +
                        "\nSeed Phrase: " + ph.str() + "\n";
                    std::lock_guard<std::mutex> g(output_mutex);
                    std::cout << "\nMATCH FOUND\n" << rec << std::flush;
                    std::ofstream f("found_wallets.txt", std::ios::app);
                    require(bool(f), "cannot open found_wallets.txt");
                    f << rec << "---\n";
                    f.flush();
                    require(bool(f), "could not append result");
                }
                (void)n;
            }
        };
        pool.clear();
        if (!gpu_active)
            for (unsigned i = 0; i < o.threads; ++i)
                pool.emplace_back([&] {
                    while (run && !found)
                    {
                        Phrase ph = generate_phrase();
                        search_raw.fetch_add(1, std::memory_order_relaxed);
                        std::array<U8, 32> sk{};
                        if (derive_secret(ph, sk))
                            save_match(ph, sk);
                    }
                });
        std::exception_ptr gpu_search_exception;
        std::thread gpu_search;
        if (gpu_active)
            gpu_search = std::thread([&] {
                try
                {
                    gpu_pipeline(gpu, run, search_raw, checked, o.threads,
                                 [&](const Phrase &ph, const std::array<U8, 32> &seed) {
                                     save_match(ph, seed);
                                 });
                }
                catch (...)
                {
                    gpu_search_exception = std::current_exception();
                    run = false;
                }
            });
        auto start = std::chrono::steady_clock::now();
        while (run && !found)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            auto n = checked.load();
            double sec = std::chrono::duration<double>(std::chrono::steady_clock::now() - start)
                             .count(),
                   rate = n / std::max(sec, .001),
                   progress = 100.0 * (1 - std::exp(-double(n) / expected));
            std::cout << "\r[Checked: " << n << " | Speed: " << std::fixed << std::setprecision(2)
                      << rate << " valid H/s | Progress: " << std::setprecision(1) << progress
                      << "% | ETA (avg): "
                      << duration(std::max(0.0, expected - n) / std::max(rate, .001)) << "]"
                      << std::flush;
        }
        run = false;
        for (auto &t : pool)
            t.join();
        if (gpu_search.joinable())
            gpu_search.join();
        if (gpu_search_exception)
            std::rethrow_exception(gpu_search_exception);
        if (found)
            std::cout << "\n";
        rc = 0;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << "\n";
        rc = 1;
    }
    if (interactive_mode)
    {
        std::cout << "Press Enter to exit...";
        std::string ignored;
        std::getline(std::cin, ignored);
    }
    return rc;
}
