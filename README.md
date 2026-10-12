# ⚡ TON Vanity CLI (V4R2 · 24-Word Native GPU/CPU Generator)

High-throughput, 100% standalone vanity wallet address generator for **TON (`wallet_v4r2`)** written in C++20 and OpenCL 1.2. Generates standard **24-word TON-native recovery phrases** compatible with **Tonkeeper**, **MyTonWallet**, and **Tonhub**.

* **Zero External Dependencies:** Single-file static executable (`.exe`). The 2,048-word BIP-39 English dictionary and all C++/threading runtimes are embedded directly into the binary.
* **100% Offline & Cryptographically Secure:** Uses OS kernel CSPRNG (`BCryptGenRandom` on Windows) for 264-bit seed entropy.

---

## 🚀 Key Architecture & Optimizations

1. **On-GPU 24th-Word Mutator (`ton_filter_mutate_390`):**
   Instead of generating and transferring every 24-word string over PCIe, the CPU generates random 23-word prefixes while the GPU sweeps all **2,048** possible 24th words in registers, computes `HMAC-SHA512(phrase, "")`, and executes the 390-round `"TON seed version"` PBKDF2 filter (`byte[0] == 0`), cutting CPU feeder and PCIe overhead by **2,048×**.
2. **100,000-Round PBKDF2-HMAC-SHA512 Kernel (`ton_derive_100k`):**
   Uses a 16-word circular message schedule in private registers and accumulates only the required upper 256 bits (`T[0..3]`) of the `"TON default seed"` digest.
3. **Automatic NVIDIA RTX Inline PTX (`lop3.b32`) + Universal OpenCL 1.2 Fallback:**
   * **NVIDIA RTX GPUs:** Automatically compiles inline CUDA PTX `lop3.b32` 3-input logic instructions (`Ch`, `Maj`, `XOR3`).
   * **GTX / AMD Radeon / Intel GPUs:** Automatically falls back to standard OpenCL C 1.2 (`bitselect`).
4. **Asynchronous Double-Buffered GPU ↔ CPU Pipeline:**
   A two-slot result queue overlaps GPU PBKDF2 waves with multi-threaded CPU `Ed25519` public key derivation, `wallet_v4r2` StateInit cell hashing, and `CRC16` Base64URL encoding.
5. **Startup Known-Answer Self-Tests:**
   Verifies `SHA-256`, `SHA-512`, `PBKDF2`, `wallet_v4r2` StateInit address derivation, and byte-for-byte GPU/CPU seed parity before starting any search.

---

## 📊 Performance Benchmark

Tested on **Lenovo LOQ 15ARP10E** (`AMD Ryzen 7 7735HS` 8C/16T + `NVIDIA GeForce RTX 4050 Laptop GPU` in `NVIDIA RTX CUDA-PTX (lop3.b32)` mode):

* **Sustained Speed:** **`3,600 – 3,700 valid wallets/sec`** (`~945,000 raw 24-word phrases/sec`)

| Target Pattern | Case Mode | Expected Combinations | ETA (50% Chance) | ETA (Average / 63.2%) |
| :--- | :--- | :--- | :--- | :--- |
| **3 letters** (e.g. `TON`) | Case-insensitive | `32,768` | **~6 sec** | **~9 sec** |
| **3 letters** (e.g. `TON`) | Exact case (`--strict`) | `262,144` | **~49 sec** | **~1 min 11 sec** |
| **4 letters** (e.g. `VEXY`) | Case-insensitive | `1,048,576` | **~3 min 15 sec** | **~4 min 45 sec** |
| **4 letters** (e.g. `VEXY`) | Exact case (`--strict`) | `16,777,216` | **~52 min** | **~1 hr 15 min** |
| **5 letters** (e.g. `SPLIT`) | Case-insensitive | `33,554,432` | **~1 hr 45 min** | **~2 hr 30 min** |

---

## 💻 Quick Start

### Interactive Mode
Simply double-click `ton_vanity_24.exe` (or run without arguments) and follow the prompts:
```text
TON Vanity — 24-word TON-native
Target prefix after UQ [skip]: 
Target suffix [skip]: VEXY
Case-sensitive? [y/N]: y
Resource preset: 1 low (25%), 2 medium (50%), 3 max CPU (100%), 4 hybrid CPU+GPU (OpenCL GPU detected) [4]: 4

# Hybrid GPU + 16 CPU threads, case-sensitive suffix "VEXY"
./ton_vanity_24.exe --use-gpu --cpu-threads 16 --suffix VEXY --strict

# Case-insensitive search
./ton_vanity_24.exe --use-gpu --suffix VEXY

# Run hardware benchmark only and exit
./ton_vanity_24.exe --use-gpu --benchmark-only --cpu-threads 16

🛠️ Build from Source (MinGW-w64)

g++ -std=c++20 -O3 -mtune=generic -s -static -static-libgcc -static-libstdc++ -pthread t