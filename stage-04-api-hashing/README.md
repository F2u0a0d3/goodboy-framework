# Stage 04: API Hashing — Dynamic Resolution & Rainbow Tables

> Part of the **Goodboy Framework** — a 15-stage progressive Windows malware development & analysis course written in Rust.

## What This Is

The deep dive into the mechanism that powers ALL 15 Goodboy binaries — PEB-walking hash-based API resolution. This is the first stage to:
- Resolve APIs from **three DLLs** (kernel32, user32, ntdll) using the same hash algorithm
- Call `MessageBoxW` **directly** via resolved function pointer — no shellcode needed
- Resolve ntdll Nt* APIs (foreshadowing Stage 07 direct syscalls)
- Expose **13 hash constants** in `.rdata` for rainbow table exercises
- Use operational binary naming (`netdiag.exe` — mimics a system utility)

**This binary achieved 0/76 on VirusTotal** (March 2026, all 76 AV engines clean).

---

## What You'll Learn

| Red Team | Blue Team |
|----------|-----------|
| Additive hash algorithm internals (seed, multiplier, shift) | Rainbow table construction from DLL exports |
| Cross-DLL resolution via LoadLibraryA pivot | YARA rules targeting hash seed + multiplier in machine code |
| PEB module list dynamics (LoadLibraryA adds modules) | The `gs:[0x60]` detection invariant (catches all 15 stages) |
| ntdll API resolution (foreshadows syscalls) | Reversing all 13 hash constants to API names |
| Operational binary naming tradecraft | Known-hash constant YARA rules |

---

## What's New vs Stages 01-03

| Concept | Stages 01-03 | Stage 04 Adds |
|---------|-------------|---------------|
| Hash algorithm | Used but unexplained | Full deep dive — seed, multiplier, shift, disassembly patterns |
| DLLs resolved | kernel32 only (6 constants) | 3 DLLs: kernel32 (6 fn + 1 DLL) + user32 (1 fn + 1 DLL) + ntdll (3 fn + 1 DLL) = 13 |
| Rainbow tables | Never built | Build table for ~5,000 exports, reverse all 13 constants |
| PEB internals | Shallow | Full TEB → PEB → Ldr → module list chain with offsets |
| Export table | Implicit | Three parallel arrays, ordinal lookup explained |
| Direct API call | Never | MessageBoxW called directly — no shellcode for this call |
| Detection | Generic RW→RX Sigma | YARA for seed+multiplier, `gs:[0x60]` invariant |

---

## Files

| File | Description |
|------|-------------|
| `LEARNING_PATH.md` | **~1,200 lines** of guided analysis — hash algorithm deep dive, PEB internals, rainbow table construction, cross-DLL resolution, detection engineering |
| `netdiag.exe` | The compiled binary (~290 KB, Rust, PE64) — open in Ghidra/x64dbg and follow along |

---

## Quick Start

1. **Complete Stages 01-03 first** — this stage assumes you understand the loader pipeline
2. **Download** `netdiag.exe` and `LEARNING_PATH.md`
3. **Open** `LEARNING_PATH.md` and follow Section 1 (Why API Hashing Exists)
4. **Reverse** the hash algorithm in Ghidra (Section 3)
5. **Build** a rainbow table in Python (Section 6)
6. **Reverse** all 13 hash constants (Section 6, Exercise 7)
7. **Write** YARA detection rules (Section 7)

---

## The Execution Flow

```
main()
  |
  +-- Gate 1-5 (same as Stages 01-03)
  |
  +-- Phase 1: Cross-DLL Resolution (NEW)
  |     resolve_api(kernel32, LoadLibraryA)
  |     LoadLibraryA("user32.dll") → user32 enters PEB module list
  |     resolve_api(user32, MessageBoxW)
  |     MessageBoxW("GoodBoy", "Stage 04") → dialog #1
  |
  +-- Phase 2: ntdll Enumeration (NEW, foreshadows Stage 07)
  |     resolve_api(ntdll, NtAllocateVirtualMemory) → stored
  |     resolve_api(ntdll, NtProtectVirtualMemory)  → stored
  |     resolve_api(ntdll, NtCreateThreadEx)        → stored
  |
  +-- Phase 3: Shellcode Execution (same pipeline)
        XOR decrypt → VirtualAlloc(RW) → copy → scrub
        → VirtualProtect(RX) → CreateThread → dialog #2
```

The user sees **two MessageBoxes**: first from the direct API call ("Stage 04"), then from the shellcode ("OK").

---

## Technical Details

| Property | Value |
|----------|-------|
| Language | Rust (self-contained, no shared library) |
| Hash Algorithm | Additive hash (seed `0x1F2E3D4C`, mul `0x1003F`, shift `>>11`) |
| Hash Variants | Case-sensitive (functions) + case-insensitive (DLL names) |
| PEB List | InLoadOrderModuleList |
| DLLs Resolved | kernel32.dll (7 APIs), user32.dll (1 API), ntdll.dll (3 APIs) |
| Hash Constants | 13 total (3 DLL + 10 function) |
| Shellcode | 302-byte MessageBox("GoodBoy","OK") + ExitThread, XOR encrypted |
| XOR Key | 16-byte repeating key |
| Memory | W^X discipline (PAGE_READWRITE → PAGE_EXECUTE_READ) |
| Binary Size | ~290 KB |
| Binary Name | `netdiag.exe` (operational naming) |
| VT Score | 0/76 achieved (March 2026) |

---

## The 13 Hash Constants

| Hash | API |
|------|-----|
| `0x0B6D79E7` | `kernel32.dll` (DLL name) |
| `0x090DD676` | `user32.dll` (DLL name) |
| `0x0EC9AE0F` | `ntdll.dll` (DLL name) |
| `0x1C02DEBA` | `VirtualAlloc` |
| `0xA234F8D5` | `VirtualProtect` |
| `0x9257966A` | `CreateThread` |
| `0xA63CFCB1` | `WaitForSingleObject` |
| `0xE95098B3` | `CloseHandle` |
| `0xE8EBE5AB` | `LoadLibraryA` |
| `0x7AC89F36` | `MessageBoxW` |
| `0x4C5F6FA9` | `NtAllocateVirtualMemory` |
| `0x4FA8A779` | `NtProtectVirtualMemory` |
| `0xC0E8DF85` | `NtCreateThreadEx` |

Build the rainbow table in the Learning Path to reverse these yourself.

---

## Course Progression

This is **Stage 04** of 15:

```
  EASY              MEDIUM            HARD              INSANE
  ............      ............      ............      ............
  Stage 01          Stage 04 (this)   Stage 07          Stage 14
  Stage 02          Stage 05          Stage 08          Stage 15
  Stage 03          Stage 06          Stage 09
                    Stage 11          Stage 10
                                      Stage 12
                                      Stage 13
```

| Stage | Technique | What's New |
|-------|-----------|------------|
| 01 | Basic Loader | XOR decrypt, PEB-walk, VirtualAlloc→VirtualProtect→CreateThread |
| 02 | XOR Cryptanalysis | Known-plaintext attack, IC key-length detection, memory scrubbing |
| 03 | AES + Jigsaw | Entropy normalization, payload fragmentation, RC4 stream cipher |
| **04** | **API Hashing** | **Hash algorithm deep dive, cross-DLL resolution, rainbow tables, detection invariant** |
| 05 | APC Injection | Early Bird, cross-process execution |
| 06 | Variant Analysis | Same technique, different keys — family clustering |
| 07 | Direct Syscalls | The name is a lie — and that's the lesson |
| 08 | Indirect Syscalls | Call stack forensics, gadget scanning |
| 09 | Anti-Debug | 7 techniques: PEB, NtQueryInfo, RDTSC, hardware breakpoints |
| 10 | Anti-Sandbox | Hardware fingerprinting, weighted scoring |
| 11 | Persistence | Registry Run key, scheduled tasks, COM hijacking |
| 12 | Module Stomping | Overwrite legitimate DLL .text section |
| 13 | Sleep Obfuscation | Encrypt payload during sleep |
| 14 | Combined Loader | 8-layer evasion stack |
| 15 | C2 Agent | Full command-and-control with encrypted HTTPS beaconing |

---

## Safety

> **EDUCATIONAL USE ONLY**

- This binary is a proof-of-concept for authorized security training, research, and CTF competitions
- **Payload**: Two `MessageBox("GoodBoy")` dialogs — one from direct API call, one from shellcode
- No network activity, no persistence, no system modifications
- **WRITE** code on your host machine. **EXECUTE** only in isolated VMs

**Do NOT submit this binary to VirusTotal** — doing so trains AV engines against it.

---

## Requirements

| Tool | Purpose | Link |
|------|---------|------|
| Windows 10/11 x64 VM | Execution environment | [FlareVM](https://github.com/mandiant/flare-vm) recommended |
| Ghidra 11.x | Static analysis / disassembly | [ghidra-sre.org](https://ghidra-sre.org/) |
| x64dbg + ScyllaHide | Dynamic analysis / debugging | [x64dbg.com](https://x64dbg.com/) |
| Python 3.10+ | Rainbow table scripts, hash verification | [python.org](https://python.org/) |
| PE-bear | PE structure viewer | [GitHub](https://github.com/hasherezade/pe-bear) |
| WinDbg (optional) | Live PEB exploration | [Microsoft](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/) |

**Recommended VM Configuration** (for sandbox detection gates to pass):
- 4+ CPU cores, 8+ GB RAM, 100+ GB disk
- Let the VM run for 30+ minutes before executing
- Screen resolution 1920x1080 or higher

---

## About the Goodboy Framework

A comprehensive malware development & analysis course with:
- **15 progressive stages** from basic loader to full C2 agent
- **Dual perspective** — every technique taught from both offense and defense
- **Empirical AV/ML evasion data** from testing against 76+ antivirus engines
- **Production-grade Rust code** — not toy demos

All 15 binaries achieved 0/76 on VirusTotal.

---

## License

This material is provided for educational purposes in authorized security training, research, penetration testing, and CTF competitions. Not for unauthorized access or operational deployment against systems without explicit written permission.

## Author

Built with Rust 1.93.1 MSVC | Tested against 76+ AV engines | March 2026
