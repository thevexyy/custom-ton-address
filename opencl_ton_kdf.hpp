#pragma once

// OpenCL 1.2 runtime binding and the TON PBKDF2 kernels. No vendor SDK headers.
#include "crypto_standalone.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#ifdef _WIN32
#include <windows.h>
#endif

namespace toncl
{
using U8 = uint8_t;
using U32 = uint32_t;
using U64 = uint64_t;
inline constexpr size_t Batch = 65536;
using Prefix = std::array<U8, 46>;
struct MutatedCandidate
{
    std::array<U8, 128> state{};
    U32 prefix_id = 0;
    U32 word24 = 0;
};
inline const char *kernel_source = R"CLC(
typedef ulong u64;
#define RR(x,n) rotate((x),(u64)(64-(n)))
__constant u64 K[80]={
0x428a2f98d728ae22UL,0x7137449123ef65cdUL,0xb5c0fbcfec4d3b2fUL,0xe9b5dba58189dbbcUL,0x3956c25bf348b538UL,0x59f111f1b605d019UL,0x923f82a4af194f9bUL,0xab1c5ed5da6d8118UL,
0xd807aa98a3030242UL,0x12835b0145706fbeUL,0x243185be4ee4b28cUL,0x550c7dc3d5ffb4e2UL,0x72be5d74f27b896fUL,0x80deb1fe3b1696b1UL,0x9bdc06a725c71235UL,0xc19bf174cf692694UL,
0xe49b69c19ef14ad2UL,0xefbe4786384f25e3UL,0x0fc19dc68b8cd5b5UL,0x240ca1cc77ac9c65UL,0x2de92c6f592b0275UL,0x4a7484aa6ea6e483UL,0x5cb0a9dcbd41fbd4UL,0x76f988da831153b5UL,
0x983e5152ee66dfabUL,0xa831c66d2db43210UL,0xb00327c898fb213fUL,0xbf597fc7beef0ee4UL,0xc6e00bf33da88fc2UL,0xd5a79147930aa725UL,0x06ca6351e003826fUL,0x142929670a0e6e70UL,
0x27b70a8546d22ffcUL,0x2e1b21385c26c926UL,0x4d2c6dfc5ac42aedUL,0x53380d139d95b3dfUL,0x650a73548baf63deUL,0x766a0abb3c77b2a8UL,0x81c2c92e47edaee6UL,0x92722c851482353bUL,
0xa2bfe8a14cf10364UL,0xa81a664bbc423001UL,0xc24b8b70d0f89791UL,0xc76c51a30654be30UL,0xd192e819d6ef5218UL,0xd69906245565a910UL,0xf40e35855771202aUL,0x106aa07032bbd1b8UL,
0x19a4c116b8d2d0c8UL,0x1e376c085141ab53UL,0x2748774cdf8eeb99UL,0x34b0bcb5e19b48a8UL,0x391c0cb3c5c95a63UL,0x4ed8aa4ae3418acbUL,0x5b9cca4f7763e373UL,0x682e6ff3d6b2b8a3UL,
0x748f82ee5defb2fcUL,0x78a5636f43172f60UL,0x84c87814a1f0ab72UL,0x8cc702081a6439ecUL,0x90befffa23631e28UL,0xa4506cebde82bde9UL,0xbef9a3f7b2c67915UL,0xc67178f2e372532bUL,
0xca273eceea26619cUL,0xd186b8c721c0c207UL,0xeada7dd6cde0eb1eUL,0xf57d4f7fee6ed178UL,0x06f067aa72176fbaUL,0x0a637dc5a2c898a6UL,0x113f9804bef90daeUL,0x1b710b35131c471bUL,
0x28db77f523047d84UL,0x32caab7b40c72493UL,0x3c9ebe0a15c9bebcUL,0x431d67c49c100d4cUL,0x4cc5d4becb3e42b6UL,0x597f299cfc657e2aUL,0x5fcb6fab3ad6faecUL,0x6c44198c4a475817UL};
__constant u64 IV[8]={0x6a09e667f3bcc908UL,0xbb67ae8584caa73bUL,0x3c6ef372fe94f82bUL,0xa54ff53a5f1d36f1UL,0x510e527fade682d1UL,0x9b05688c2b3e6c1fUL,0x1f83d9abfb41bd6bUL,0x5be0cd19137e2179UL};
inline u64 load64be(__private const uchar *p){u64 x=0;for(int i=0;i<8;i++)x=(x<<8)|p[i];return x;}
inline void store64be(__private uchar *p,u64 x){for(int i=7;i>=0;i--){p[i]=(uchar)x;x>>=8;}}
inline u64 load64be_g(__global const uchar *p){u64 x=0;for(int i=0;i<8;i++)x=(x<<8)|p[i];return x;}
inline void store64be_g(__global uchar *p,u64 x){for(int i=7;i>=0;i--){p[i]=(uchar)x;x>>=8;}}
#ifdef NVIDIA_RTX_PTX
inline uint lut_ca(uint a,uint b,uint c){uint r;asm volatile("lop3.b32 %0, %1, %2, %3, 0xCA;":"=r"(r):"r"(a),"r"(b),"r"(c));return r;}
inline uint lut_e8(uint a,uint b,uint c){uint r;asm volatile("lop3.b32 %0, %1, %2, %3, 0xE8;":"=r"(r):"r"(a),"r"(b),"r"(c));return r;}
inline uint lut_96(uint a,uint b,uint c){uint r;asm volatile("lop3.b32 %0, %1, %2, %3, 0x96;":"=r"(r):"r"(a),"r"(b),"r"(c));return r;}
inline u64 choose64(u64 x,u64 y,u64 z){uint lo=lut_ca((uint)x,(uint)y,(uint)z),hi=lut_ca((uint)(x>>32),(uint)(y>>32),(uint)(z>>32));return ((u64)hi<<32)|lo;}
inline u64 majority64(u64 x,u64 y,u64 z){uint lo=lut_e8((uint)x,(uint)y,(uint)z),hi=lut_e8((uint)(x>>32),(uint)(y>>32),(uint)(z>>32));return ((u64)hi<<32)|lo;}
inline u64 xor3_64(u64 x,u64 y,u64 z){uint lo=lut_96((uint)x,(uint)y,(uint)z),hi=lut_96((uint)(x>>32),(uint)(y>>32),(uint)(z>>32));return ((u64)hi<<32)|lo;}
#else
inline u64 choose64(u64 x,u64 y,u64 z){return bitselect(z,y,x);}
inline u64 majority64(u64 x,u64 y,u64 z){return (x&y)|(x&z)|(y&z);}
inline u64 xor3_64(u64 x,u64 y,u64 z){return x^y^z;}
#endif
inline void compress_w(__private u64 *h,__private u64 *w,uint first_only){u64 v[8];for(int i=0;i<8;i++)v[i]=h[i];
#pragma unroll 16
for(int i=0;i<80;i++){uint j=i&15;if(i>=16){u64 x=w[(i-15)&15],y=w[(i-2)&15];u64 s0=xor3_64(RR(x,1),RR(x,8),x>>7);u64 s1=xor3_64(RR(y,19),RR(y,61),y>>6);w[j]+=s0+w[(i-7)&15]+s1;}u64 s1=xor3_64(RR(v[4],14),RR(v[4],18),RR(v[4],41));u64 ch=choose64(v[4],v[5],v[6]);u64 t1=v[7]+s1+ch+K[i]+w[j];u64 s0=xor3_64(RR(v[0],28),RR(v[0],34),RR(v[0],39));u64 maj=majority64(v[0],v[1],v[2]);u64 t2=s0+maj;for(int k=7;k>0;k--)v[k]=v[k-1];v[4]+=t1;v[0]=t1+t2;}h[0]+=v[0];if(!first_only)for(int i=1;i<8;i++)h[i]+=v[i];}
inline void compress(__private u64 *h,__private const uchar *b){u64 w[16];for(int i=0;i<16;i++)w[i]=load64be(b+8*i);compress_w(h,w,0);}
inline void hmac(__private const u64 *ipad,__private const u64 *opad,__private const uchar *m,uint len,__private uchar *out){
 uchar b[128];for(int i=0;i<128;i++)b[i]=0;for(uint i=0;i<len;i++)b[i]=m[i];b[len]=0x80;u64 bits=(u64)(128+len)*8;store64be(b+120,bits);u64 ih[8];for(int i=0;i<8;i++)ih[i]=ipad[i];compress(ih,b);uchar d[64];for(int i=0;i<8;i++)store64be(d+8*i,ih[i]);
 for(int i=0;i<128;i++)b[i]=0;for(int i=0;i<64;i++)b[i]=d[i];b[64]=0x80;store64be(b+120,1536);u64 oh[8];for(int i=0;i<8;i++)oh[i]=opad[i];compress(oh,b);for(int i=0;i<8;i++)store64be(out+8*i,oh[i]);}
inline void hmac_u64(__private const u64 *ipad,__private const u64 *opad,__private const u64 *u,__private u64 *out,uint first_only){u64 ih[8],oh[8],w[16];for(int i=0;i<8;i++){ih[i]=ipad[i];w[i]=u[i];}w[8]=0x8000000000000000UL;for(int i=9;i<15;i++)w[i]=0;w[15]=1536;compress_w(ih,w,0);for(int i=0;i<8;i++){oh[i]=opad[i];w[i]=ih[i];}w[8]=0x8000000000000000UL;for(int i=9;i<15;i++)w[i]=0;w[15]=1536;compress_w(oh,w,first_only);out[0]=oh[0];if(!first_only)for(int i=1;i<8;i++)out[i]=oh[i];}
inline void sha512_private(__private const uchar *m,uint len,__private uchar *out){
 u64 h[8];for(int i=0;i<8;i++)h[i]=IV[i];uint off=0;
 while(len-off>=128){compress(h,m+off);off+=128;}
 uchar b[128];uint rem=len-off;for(uint i=0;i<rem;i++)b[i]=m[off+i];b[rem]=0x80;
 if(rem>=112){for(uint i=rem+1;i<128;i++)b[i]=0;compress(h,b);for(int i=0;i<120;i++)b[i]=0;store64be(b+120,(u64)len*8);compress(h,b);}
 else{for(uint i=rem+1;i<120;i++)b[i]=0;store64be(b+120,(u64)len*8);compress(h,b);}
 for(int i=0;i<8;i++)store64be(out+8*i,h[i]);
}
inline void hmac_phrase(__private const uchar *phrase,uint len,__private u64 *ip,__private u64 *op,__private uchar *hk){
 uchar key[128];for(int i=0;i<128;i++)key[i]=0;
 if(len>128)sha512_private(phrase,len,key);else for(uint i=0;i<len;i++)key[i]=phrase[i];
 u64 w[16],phrase_ip[8],phrase_op[8],ih[8],oh[8];for(int i=0;i<16;i++){u64 x=load64be(key+8*i);w[i]=x^0x3636363636363636UL;}for(int i=0;i<8;i++)ih[i]=IV[i];compress_w(ih,w,0);
 for(int i=0;i<16;i++)w[i]=load64be(key+8*i)^0x5c5c5c5c5c5c5c5cUL;for(int i=0;i<8;i++)oh[i]=IV[i];compress_w(oh,w,0);for(int i=0;i<8;i++){phrase_ip[i]=ih[i];phrase_op[i]=oh[i];}
 uchar empty=0;hmac(phrase_ip,phrase_op,&empty,0,hk);
 // TON PBKDF2 uses hk = HMAC-SHA512(phrase, "") as its password.
 // The PBKDF2 midstates therefore belong to hk, not to phrase itself.
 for(int i=0;i<16;i++){u64 x=i<8?load64be(hk+8*i):0;w[i]=x^0x3636363636363636UL;}for(int i=0;i<8;i++)ih[i]=IV[i];compress_w(ih,w,0);for(int i=0;i<8;i++)ip[i]=ih[i];
 for(int i=0;i<16;i++){u64 x=i<8?load64be(hk+8*i):0;w[i]=x^0x5c5c5c5c5c5c5c5cUL;}for(int i=0;i<8;i++)oh[i]=IV[i];compress_w(oh,w,0);for(int i=0;i<8;i++)op[i]=oh[i];
}
inline void pbkdf(__private const u64 *ip,__private const u64 *op,uint rounds,uint seed_salt,uint filter_only,uint output_words,__private u64 *T){
 uchar msg[20],bytes[64];const uchar version_salt[16]={'T','O','N',' ','s','e','e','d',' ','v','e','r','s','i','o','n'};const uchar default_salt[16]={'T','O','N',' ','d','e','f','a','u','l','t',' ','s','e','e','d'};for(int i=0;i<16;i++)msg[i]=seed_salt?default_salt[i]:version_salt[i];msg[16]=0;msg[17]=0;msg[18]=0;msg[19]=1;hmac(ip,op,msg,20,bytes);u64 u[8],next[8];for(int i=0;i<8;i++)u[i]=load64be(bytes+8*i);for(uint i=0;i<output_words;i++)T[i]=u[i];
 for(uint r=1;r<rounds;r++){uint last=(filter_only&&r==rounds-1);hmac_u64(ip,op,u,next,last);for(int i=0;i<8;i++)u[i]=next[i];for(uint i=0;i<output_words;i++)T[i]^=next[i];}}
__kernel void ton_filter_390(__global const uchar *states,__global uchar *valid,uint n){uint gid=get_global_id(0);if(gid>=n)return;u64 ip[8],op[8],T[8];for(int i=0;i<8;i++){ip[i]=load64be_g(states+gid*128+i*8);op[i]=load64be_g(states+gid*128+64+i*8);}pbkdf(ip,op,390,0,1,1,T);valid[gid]=(T[0]>>56)==0;}
__kernel void ton_filter_mutate_390(__global const uchar *prefixes,__global const uchar *wordtable,__global uchar *states,__global uint *metadata,__global volatile uint *count,uint prefix_count){
 uint gid=get_global_id(0),total=prefix_count*2048U;if(gid>=total)return;uint pid=gid>>11,tail=gid&2047U;uchar phrase[448];uint len=0;
 for(uint j=0;j<24;j++){uint ix;if(j<23){uint q=pid*46U+j*2U;ix=((uint)prefixes[q]<<8)|prefixes[q+1];}else ix=tail;uint row=ix*17U,wlen=wordtable[row];if(j){phrase[len++]=' ';}for(uint k=0;k<wlen;k++)phrase[len++]=wordtable[row+1+k];}
 u64 ip[8],op[8],T[8];uchar hk[64];hmac_phrase(phrase,len,ip,op,hk);pbkdf(ip,op,390,0,1,1,T);if((T[0]>>56)==0){uint out=atomic_inc(count);for(int i=0;i<8;i++){store64be_g(states+out*128U+i*8U,ip[i]);store64be_g(states+out*128U+64U+i*8U,op[i]);}metadata[out*2U]=pid;metadata[out*2U+1U]=tail;}
}
__kernel void ton_derive_100k(__global const uchar *states,__global uchar *secrets,uint n){uint gid=get_global_id(0);if(gid>=n)return;u64 ip[8],op[8],T[4];for(int i=0;i<8;i++){ip[i]=load64be_g(states+gid*128+i*8);op[i]=load64be_g(states+gid*128+64+i*8);}pbkdf(ip,op,100000,1,0,4,T);for(int i=0;i<4;i++)store64be_g(secrets+gid*32+i*8,T[i]);}
)CLC";

#ifdef _WIN32
class OpenCLGpu
{
    using Int = int;
    using UInt = uint32_t;
    using ULong = uint64_t;
    using Size = size_t;
    using Props = intptr_t;
    using Platform = void *;
    using Device = void *;
    using Context = void *;
    using Queue = void *;
    using Program = void *;
    using Kernel = void *;
    using Mem = void *;
    using Event = void *;
    HMODULE dll_ = nullptr;
    std::vector<Device> devices_;
    Device dev_ = nullptr;
    Context ctx_ = nullptr;
    Queue q_ = nullptr;
    Program program_ = nullptr;
    Kernel filter_ = nullptr, mutate_ = nullptr, derive_ = nullptr;
    Mem input_ = nullptr, valid_ = nullptr, output_ = nullptr, prefixes_ = nullptr,
        wordtable_ = nullptr, mutated_ = nullptr, metadata_ = nullptr, count_ = nullptr;
    size_t local_ = 1;
    UInt compute_units_ = 1;
    bool rtx_ptx_ = false;
    std::string name_, vendor_, gpu_mode_ = "Universal Standard OpenCL 1.2", error_;
    using GetPlatforms = Int(__stdcall *)(UInt, Platform *, UInt *);
    using GetDevices = Int(__stdcall *)(Platform, ULong, UInt, Device *, UInt *);
    using GetDeviceInfo = Int(__stdcall *)(Device, UInt, Size, void *, Size *);
    using CreateContext = Context(__stdcall *)(const Props *, UInt, const Device *,
                                               void(__stdcall *)(const char *, const void *, Size,
                                                                 void *),
                                               void *, Int *);
    using CreateQueue = Queue(__stdcall *)(Context, Device, ULong, Int *);
    using CreateProgram = Program(__stdcall *)(Context, UInt, const char **, const Size *, Int *);
    using BuildProgram = Int(__stdcall *)(Program, UInt, const Device *, const char *,
                                          void(__stdcall *)(Program, void *), void *);
    using GetBuildInfo = Int(__stdcall *)(Program, Device, UInt, Size, void *, Size *);
    using CreateKernel = Kernel(__stdcall *)(Program, const char *, Int *);
    using CreateBuffer = Mem(__stdcall *)(Context, ULong, Size, void *, Int *);
    using SetArg = Int(__stdcall *)(Kernel, UInt, Size, const void *);
    using WriteBuffer = Int(__stdcall *)(Queue, Mem, UInt, Size, Size, const void *, UInt,
                                         const Event *, Event *);
    using ReadBuffer = Int(__stdcall *)(Queue, Mem, UInt, Size, Size, void *, UInt, const Event *,
                                        Event *);
    using EnqueueKernel = Int(__stdcall *)(Queue, Kernel, UInt, const Size *, const Size *,
                                           const Size *, UInt, const Event *, Event *);
    using Finish = Int(__stdcall *)(Queue);
    using Release = Int(__stdcall *)(void *);
    using GetKernelInfo = Int(__stdcall *)(Kernel, Device, UInt, Size, void *, Size *);
    GetPlatforms gp_{};
    GetDevices gd_{};
    GetDeviceInfo gi_{};
    CreateContext cc_{};
    CreateQueue cq_{};
    CreateProgram cp_{};
    BuildProgram bp_{};
    GetBuildInfo gbi_{};
    CreateKernel ck_{};
    CreateBuffer cb_{};
    SetArg sa_{};
    WriteBuffer wb_{};
    ReadBuffer rb_{};
    EnqueueKernel ek_{};
    Finish fin_{};
    Release relmem_{}, relkernel_{}, relprogram_{}, relqueue_{}, relcontext_{};
    GetKernelInfo gki_{};
    template <class F> bool sym(F &f, const char *s)
    {
        f = reinterpret_cast<F>(GetProcAddress(dll_, s));
        if (!f)
        {
            error_ = std::string("missing OpenCL symbol ") + s;
            return false;
        }
        return true;
    }
    bool ok(Int e, const char *where)
    {
        if (e != 0)
        {
            error_ = std::string(where) + " failed with OpenCL error " + std::to_string(e);
            return false;
        }
        return true;
    }
    static void append_state(std::array<U8, 128> &out, size_t off, const std::array<U64, 8> &h)
    {
        for (size_t i = 0; i < 8; i++)
            for (size_t j = 0; j < 8; j++)
                out[off + i * 8 + j] = U8(h[i] >> (56 - 8 * j));
    }
    void cleanup()
    {
        if (relmem_)
        {
            if (input_)
                relmem_(input_);
            if (valid_)
                relmem_(valid_);
            if (output_)
                relmem_(output_);
            if (prefixes_)
                relmem_(prefixes_);
            if (wordtable_)
                relmem_(wordtable_);
            if (mutated_)
                relmem_(mutated_);
            if (metadata_)
                relmem_(metadata_);
            if (count_)
                relmem_(count_);
        }
        if (relkernel_)
        {
            if (filter_)
                relkernel_(filter_);
            if (mutate_)
                relkernel_(mutate_);
            if (derive_)
                relkernel_(derive_);
        }
        if (relprogram_ && program_)
            relprogram_(program_);
        if (relqueue_ && q_)
            relqueue_(q_);
        if (relcontext_ && ctx_)
            relcontext_(ctx_);
        input_ = valid_ = output_ = prefixes_ = wordtable_ = mutated_ = metadata_ = count_ =
            nullptr;
        filter_ = mutate_ = derive_ = nullptr;
        program_ = nullptr;
        q_ = nullptr;
        ctx_ = nullptr;
    }

  public:
    ~OpenCLGpu()
    {
        cleanup();
        if (dll_)
            FreeLibrary(dll_);
    }
    const std::string &name() const
    {
        return name_;
    }
    const std::string &vendor() const
    {
        return vendor_;
    }
    const std::string &mode() const
    {
        return gpu_mode_;
    }
    const std::string &error() const
    {
        return error_;
    }
    bool ready() const
    {
        return dev_ && filter_ && derive_;
    }
    bool rtx_ptx() const
    {
        return rtx_ptx_;
    }
    size_t local_size() const
    {
        return local_;
    }
    size_t derive_target() const
    {
        return std::min(Batch, std::max<size_t>(4096, size_t(compute_units_) * 64));
    }
    bool init(int requested = -1, const U8 *word_table = nullptr, size_t word_table_size = 0)
    {
        dll_ = LoadLibraryA("OpenCL.dll");
        if (!dll_)
        {
            error_ = "OpenCL.dll not found";
            return false;
        }
        if (!sym(gp_, "clGetPlatformIDs") || !sym(gd_, "clGetDeviceIDs") ||
            !sym(gi_, "clGetDeviceInfo") || !sym(cc_, "clCreateContext") ||
            !sym(cq_, "clCreateCommandQueue") || !sym(cp_, "clCreateProgramWithSource") ||
            !sym(bp_, "clBuildProgram") || !sym(gbi_, "clGetProgramBuildInfo") ||
            !sym(ck_, "clCreateKernel") || !sym(cb_, "clCreateBuffer") ||
            !sym(sa_, "clSetKernelArg") || !sym(wb_, "clEnqueueWriteBuffer") ||
            !sym(rb_, "clEnqueueReadBuffer") || !sym(ek_, "clEnqueueNDRangeKernel") ||
            !sym(fin_, "clFinish") || !sym(gki_, "clGetKernelWorkGroupInfo") ||
            !sym(relmem_, "clReleaseMemObject") || !sym(relkernel_, "clReleaseKernel") ||
            !sym(relprogram_, "clReleaseProgram") || !sym(relqueue_, "clReleaseCommandQueue") ||
            !sym(relcontext_, "clReleaseContext"))
            return false;
        UInt np = 0;
        if (!ok(gp_(0, nullptr, &np), "clGetPlatformIDs(count)") || np == 0)
        {
            error_ = "No OpenCL platforms";
            return false;
        }
        std::vector<Platform> plats(np);
        if (!ok(gp_(np, plats.data(), nullptr), "clGetPlatformIDs(list)"))
            return false;
        struct Candidate
        {
            Device d;
            UInt cu;
            std::string n, v;
            bool discrete;
        };
        std::vector<Candidate> cand;
        auto device_string = [&](Device d, UInt key) {
            Size need = 0;
            if (gi_(d, key, 0, nullptr, &need) != 0 || !need)
                return std::string{};
            std::string s(need, '\0');
            if (gi_(d, key, need, s.data(), nullptr) != 0)
                return std::string{};
            while (!s.empty() && s.back() == '\0')
                s.pop_back();
            return s;
        };
        for (auto p : plats)
        {
            UInt nd = 0;
            Int e = gd_(p, 4, 0, nullptr, &nd);
            if (e != 0 || !nd)
                continue;
            std::vector<Device> ds(nd);
            if (gd_(p, 4, nd, ds.data(), nullptr) != 0)
                continue;
            for (auto d : ds)
            {
                UInt cu = 0, unified = 0;
                gi_(d, 0x1002, sizeof(cu), &cu, nullptr);
                gi_(d, 0x1035, sizeof(unified), &unified, nullptr);
                cand.push_back(
                    {d, cu, device_string(d, 0x102b), device_string(d, 0x102c), unified == 0});
            }
        }
        if (cand.empty())
        {
            error_ = "No CL_DEVICE_TYPE_GPU devices found";
            return false;
        }
        size_t pick = 0;
        if (requested >= 0)
        {
            if (size_t(requested) >= cand.size())
            {
                error_ = "--gpu-index is outside the GPU device list";
                return false;
            }
            pick = size_t(requested);
        }
        else
            for (size_t i = 1; i < cand.size(); i++)
                if ((cand[i].discrete && !cand[pick].discrete) ||
                    (cand[i].discrete == cand[pick].discrete && cand[i].cu > cand[pick].cu))
                    pick = i;
        dev_ = cand[pick].d;
        name_ = cand[pick].n;
        vendor_ = cand[pick].v;
        compute_units_ = std::max<UInt>(1, cand[pick].cu);
        Int e = 0;
        ctx_ = cc_(nullptr, 1, &dev_, nullptr, nullptr, &e);
        if (!ctx_ || !ok(e, "clCreateContext"))
            return false;
        q_ = cq_(ctx_, dev_, 0, &e);
        if (!q_ || !ok(e, "clCreateCommandQueue"))
            return false;
        std::string vend = vendor_, devname = name_;
        std::transform(vend.begin(), vend.end(), vend.begin(), [](unsigned char c) {
            return char(std::tolower(c));
        });
        std::transform(devname.begin(), devname.end(), devname.begin(), [](unsigned char c) {
            return char(std::tolower(c));
        });
        bool try_ptx =
            vend.find("nvidia") != std::string::npos && devname.find("rtx") != std::string::npos;
        const char *src = kernel_source;
        Size len = std::strlen(src);
        auto build = [&](const char *options, std::string &log) {
            Program pr = cp_(ctx_, 1, &src, &len, &e);
            if (!pr)
            {
                error_ = "clCreateProgramWithSource failed with OpenCL error " + std::to_string(e);
                return false;
            }
            Int result = bp_(pr, 1, &dev_, options, nullptr, nullptr);
            if (result != 0)
            {
                Size z = 0;
                gbi_(pr, dev_, 0x1183, 0, nullptr, &z);
                log.assign(z ? z : 1, '\0');
                gbi_(pr, dev_, 0x1183, log.size(), log.data(), nullptr);
                while (!log.empty() && log.back() == '\0')
                    log.pop_back();
                relprogram_(pr);
                return false;
            }
            program_ = pr;
            return true;
        };
        std::string buildlog;
        if (try_ptx)
        {
            if (build("-D NVIDIA_RTX_PTX=1 -cl-std=CL1.2 -cl-mad-enable", buildlog))
            {
                rtx_ptx_ = true;
                gpu_mode_ = "NVIDIA RTX CUDA-PTX (lop3.b32)";
            }
            else
            {
                std::string ptx_error = buildlog;
                buildlog.clear();
                if (!build("-cl-std=CL1.2", buildlog))
                {
                    error_ = "RTX PTX build failed: " + ptx_error +
                             "; standard OpenCL fallback failed: " + buildlog;
                    return false;
                }
                gpu_mode_ = "Universal Standard OpenCL 1.2";
            }
        }
        else
        {
            if (!build("-cl-std=CL1.2", buildlog))
            {
                error_ = "OpenCL kernel build failed: " + buildlog;
                return false;
            }
            gpu_mode_ = "Universal Standard OpenCL 1.2";
        }
        filter_ = ck_(program_, "ton_filter_390", &e);
        if (!filter_ || !ok(e, "clCreateKernel(filter)"))
            return false;
        mutate_ = ck_(program_, "ton_filter_mutate_390", &e);
        if (!mutate_ || !ok(e, "clCreateKernel(mutator)"))
            return false;
        derive_ = ck_(program_, "ton_derive_100k", &e);
        if (!derive_ || !ok(e, "clCreateKernel(derive)"))
            return false;
        if (!word_table || word_table_size != 2048 * 17)
        {
            error_ = "invalid embedded word-table size";
            return false;
        }
        input_ = cb_(ctx_, 1, Batch * 128, nullptr, &e);
        if (!input_ || !ok(e, "clCreateBuffer(states)"))
            return false;
        valid_ = cb_(ctx_, 1, Batch, nullptr, &e);
        if (!valid_ || !ok(e, "clCreateBuffer(valid)"))
            return false;
        output_ = cb_(ctx_, 1, Batch * 32, nullptr, &e);
        if (!output_ || !ok(e, "clCreateBuffer(secrets)"))
            return false;
        prefixes_ = cb_(ctx_, 1, (Batch / 2048) * 46, nullptr, &e);
        if (!prefixes_ || !ok(e, "clCreateBuffer(prefixes)"))
            return false;
        wordtable_ = cb_(ctx_, 1, word_table_size, nullptr, &e);
        if (!wordtable_ || !ok(e, "clCreateBuffer(word table)"))
            return false;
        mutated_ = cb_(ctx_, 1, Batch * 128, nullptr, &e);
        if (!mutated_ || !ok(e, "clCreateBuffer(mutated states)"))
            return false;
        metadata_ = cb_(ctx_, 1, Batch * 2 * sizeof(UInt), nullptr, &e);
        if (!metadata_ || !ok(e, "clCreateBuffer(mutated metadata)"))
            return false;
        count_ = cb_(ctx_, 1, sizeof(UInt), nullptr, &e);
        if (!count_ || !ok(e, "clCreateBuffer(mutated count)"))
            return false;
        if (!ok(wb_(q_, wordtable_, 1, 0, word_table_size, word_table, 0, nullptr, nullptr),
                "clEnqueueWriteBuffer(word table)"))
            return false;
        Size devmax = 1, kfilter = 1, kmutate = 1, kderive = 1;
        gi_(dev_, 0x1004, sizeof(devmax), &devmax, nullptr);
        gki_(filter_, dev_, 0x11b0, sizeof(kfilter), &kfilter, nullptr);
        gki_(mutate_, dev_, 0x11b0, sizeof(kmutate), &kmutate, nullptr);
        gki_(derive_, dev_, 0x11b0, sizeof(kderive), &kderive, nullptr);
        local_ = std::max<size_t>(1, std::min<Size>({devmax, kfilter, kmutate, kderive, 256}));
        return true;
    }
    bool mutate_filter(const std::vector<Prefix> &prefixes, std::vector<MutatedCandidate> &out)
    {
        if (prefixes.size() > Batch / 2048)
        {
            error_ = "GPU prefix batch too large";
            return false;
        }
        out.clear();
        if (prefixes.empty())
            return true;
        UInt zero = 0, n = UInt(prefixes.size());
        Size bytes = prefixes.size() * sizeof(Prefix);
        Int e = 0;
        if (!ok(wb_(q_, prefixes_, 1, 0, bytes, prefixes.data(), 0, nullptr, nullptr),
                "clEnqueueWriteBuffer(prefixes)") ||
            !ok(wb_(q_, count_, 1, 0, sizeof(zero), &zero, 0, nullptr, nullptr),
                "clEnqueueWriteBuffer(count)"))
            return false;
        if (!ok(sa_(mutate_, 0, sizeof(prefixes_), &prefixes_),
                "clSetKernelArg(mutator prefixes)") ||
            !ok(sa_(mutate_, 1, sizeof(wordtable_), &wordtable_),
                "clSetKernelArg(mutator word table)") ||
            !ok(sa_(mutate_, 2, sizeof(mutated_), &mutated_), "clSetKernelArg(mutator states)") ||
            !ok(sa_(mutate_, 3, sizeof(metadata_), &metadata_),
                "clSetKernelArg(mutator metadata)") ||
            !ok(sa_(mutate_, 4, sizeof(count_), &count_), "clSetKernelArg(mutator count)") ||
            !ok(sa_(mutate_, 5, sizeof(n), &n), "clSetKernelArg(mutator prefix count)"))
            return false;
        Size global = Size(prefixes.size()) * 2048, local = std::min(local_, global);
        global = ((global + local - 1) / local) * local;
        if (!ok(ek_(q_, mutate_, 1, nullptr, &global, &local, 0, nullptr, nullptr),
                "clEnqueueNDRangeKernel(mutator)"))
            return false;
        UInt found = 0;
        if (!ok(rb_(q_, count_, 1, 0, sizeof(found), &found, 0, nullptr, nullptr),
                "clEnqueueReadBuffer(mutator count)"))
            return false;
        if (found > prefixes.size() * 2048)
        {
            error_ = "GPU mutator reported an invalid candidate count";
            return false;
        }
        if (!found)
            return true;
        // Read state and metadata through contiguous staging arrays; struct padding is not part of
        // the device ABI.
        std::vector<U8> raw(size_t(found) * 128);
        std::vector<UInt> meta(size_t(found) * 2);
        if (!ok(rb_(q_, mutated_, 1, 0, raw.size(), raw.data(), 0, nullptr, nullptr),
                "clEnqueueReadBuffer(mutated states)") ||
            !ok(rb_(q_, metadata_, 1, 0, meta.size() * sizeof(UInt), meta.data(), 0, nullptr,
                    nullptr),
                "clEnqueueReadBuffer(mutated metadata)"))
            return false;
        out.resize(found);
        for (size_t i = 0; i < found; i++)
        {
            std::copy_n(raw.data() + i * 128, 128, out[i].state.data());
            out[i].prefix_id = meta[2 * i];
            out[i].word24 = meta[2 * i + 1];
        }
        return true;
    }
    bool run_filter(const std::vector<std::array<U8, 128>> &states, std::vector<U8> &flags)
    {
        if (states.size() > Batch)
        {
            error_ = "GPU batch too large";
            return false;
        }
        if (states.empty())
        {
            flags.clear();
            return true;
        }
        Size bytes = states.size() * 128;
        Int e = 0;
        if (!ok(wb_(q_, input_, 1, 0, bytes, states.data(), 0, nullptr, nullptr),
                "clEnqueueWriteBuffer(filter)"))
            return false;
        UInt n = UInt(states.size());
        if (!ok(sa_(filter_, 0, sizeof(input_), &input_), "clSetKernelArg(filter states)") ||
            !ok(sa_(filter_, 1, sizeof(valid_), &valid_), "clSetKernelArg(filter flags)") ||
            !ok(sa_(filter_, 2, sizeof(n), &n), "clSetKernelArg(filter count)"))
            return false;
        Size local = std::min(local_, states.size()),
             global = ((states.size() + local - 1) / local) * local;
        if (!ok(ek_(q_, filter_, 1, nullptr, &global, &local, 0, nullptr, nullptr),
                "clEnqueueNDRangeKernel(filter)"))
            return false;
        flags.resize(states.size());
        return ok(rb_(q_, valid_, 1, 0, flags.size(), flags.data(), 0, nullptr, nullptr),
                  "clEnqueueReadBuffer(filter)") &&
               ok(fin_(q_), "clFinish(filter)");
    }
    bool run_derive(const std::vector<std::array<U8, 128>> &states,
                    std::vector<std::array<U8, 32>> &out)
    {
        if (states.empty())
        {
            out.clear();
            return true;
        }
        if (states.size() > Batch)
        {
            error_ = "GPU derive batch too large";
            return false;
        }
        Size bytes = states.size() * 128;
        if (!ok(wb_(q_, input_, 1, 0, bytes, states.data(), 0, nullptr, nullptr),
                "clEnqueueWriteBuffer(derive)"))
            return false;
        UInt n = UInt(states.size());
        if (!ok(sa_(derive_, 0, sizeof(input_), &input_), "clSetKernelArg(derive states)") ||
            !ok(sa_(derive_, 1, sizeof(output_), &output_), "clSetKernelArg(derive output)") ||
            !ok(sa_(derive_, 2, sizeof(n), &n), "clSetKernelArg(derive count)"))
            return false;
        Size local = std::min(local_, states.size()),
             global = ((states.size() + local - 1) / local) * local;
        if (!ok(ek_(q_, derive_, 1, nullptr, &global, &local, 0, nullptr, nullptr),
                "clEnqueueNDRangeKernel(derive)"))
            return false;
        out.resize(states.size());
        return ok(rb_(q_, output_, 1, 0, out.size() * 32, out.data(), 0, nullptr, nullptr),
                  "clEnqueueReadBuffer(derive)") &&
               ok(fin_(q_), "clFinish(derive)");
    }
    static std::array<U8, 128> states_from_phrase(const Phrase &phrase)
    {
        static const U8 empty = 0;
        auto hk = crypto::hmac512(phrase.data(), phrase.size, &empty, 0);
        crypto::Hmac512 hm(hk.data(), hk.size());
        std::array<U8, 128> s{};
        append_state(s, 0, hm.inner.h);
        append_state(s, 64, hm.outer.h);
        return s;
    }
    bool derive_batch(const std::vector<std::array<U8, 128>> &states,
                      std::vector<size_t> &valid_indices, std::vector<std::array<U8, 32>> &secrets)
    {
        std::vector<U8> flags;
        if (!run_filter(states, flags))
            return false;
        std::vector<std::array<U8, 128>> compact;
        valid_indices.clear();
        for (size_t i = 0; i < flags.size(); ++i)
            if (flags[i])
            {
                compact.push_back(states[i]);
                valid_indices.push_back(i);
            }
        return run_derive(compact, secrets);
    }
};
#else
class OpenCLGpu
{
  public:
    bool ready() const
    {
        return false;
    }
    bool init(int = -1, const U8 * = nullptr, size_t = 0)
    {
        return false;
    }
    size_t derive_target() const
    {
        return 4096;
    }
    bool mutate_filter(const std::vector<Prefix> &, std::vector<MutatedCandidate> &)
    {
        return false;
    }
    bool run_filter(const std::vector<std::array<U8, 128>> &, std::vector<U8> &)
    {
        return false;
    }
    bool run_derive(const std::vector<std::array<U8, 128>> &, std::vector<std::array<U8, 32>> &)
    {
        return false;
    }
    const std::string &name() const
    {
        static std::string s = "OpenCL GPU backend is Windows-only";
        return s;
    }
    const std::string &mode() const
    {
        static std::string s = "Universal Standard OpenCL 1.2";
        return s;
    }
    const std::string &error() const
    {
        return name();
    }
};
#endif
} // namespace toncl
