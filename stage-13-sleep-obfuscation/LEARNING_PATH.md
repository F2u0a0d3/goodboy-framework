# Module 13: Sleep Obfuscation — Encrypting Payloads Between Heartbeats

## Module Metadata

| Field | Value |
|---|---|
| **Topic** | Sleep Obfuscation / Payload Encryption at Rest |
| **Difficulty** | Advanced |
| **Duration** | 3-4 hours |
| **Prerequisites** | Stage 09-12 (7-gate architecture, apihash, anti-debug, anti-sandbox, module-stomping) |
| **Tools Required** | x64dbg, Process Hacker, PE-bear, custom memory scanner |
| **MITRE ATT&CK** | T1027.013 (Encrypted/Encoded File), T1497.003 (Time Based Evasion), T1055 (Process Injection) |
| **Binary** | `sleep-obfuscation.exe` (~380KB, Rust, PE64, uses common library) |

### Key Evasion Lesson

```
 The original used common library sleep modules (RC4/FluctuationGuard/
 SleepObfuscator with 256-byte S-box, timer queue callbacks). Rising's TFE
 signature flagged the pattern. Fix: INLINE XOR sleep obfuscation — simple
 for loop + direct Sleep() import. No RC4 S-box, no timer callbacks.
 XOR loop is indistinguishable from generic data processing.
```

---

## Why This Stage Exists — The Bridge from Stage 12

Stage 12 hides shellcode inside a legitimate DLL's memory region (module stomping), defeating VAD-based memory scanners. But the shellcode sits in **cleartext RX memory while sleeping**. An implant with a 60-second beacon interval is idle 99.9% of the time — that is a massive window for periodic memory scanners to find decrypted shellcode.

Stage 13 solves this by **encrypting the payload and dropping execute permissions during sleep**. The memory scanner sees non-executable (RW) encrypted noise instead of cleartext shellcode. The payload only exists in decrypted RX form for the brief execution window.

**What's new in this binary compared to Stage 12:**
1. **Sleep obfuscation** — XOR-encrypt payload + VirtualProtect to RW during sleep, decrypt + RX before execution
2. **Dual-key architecture** — XOR_KEY decrypts the on-disk payload, SLEEP_KEY encrypts/decrypts during sleep cycles
3. **Inline XOR** — simple for-loop, no RC4 S-box, no FluctuationGuard, no timer callbacks
4. **Direct Sleep() import** — benign IAT entry, no apihash resolution for Sleep
5. **opt-level=2** — killed CrowdStrike ML classifier that detected opt-level="z" instruction patterns

### Real-World Context (2025-2026)

- **Cobalt Strike 4.11 Sleepmask** ([May 2025](https://www.cobaltstrike.com/blog)) — CS 4.11 integrates Ekko/Zilean timer-based sleep obfuscation into the beacon, encrypting the entire beacon image during sleep with stack spoofing
- **OLDBOY21 SWAPPALA** ([2025](https://github.com/OLDBOY21/SWAPPALA)) — Advanced sleep obfuscation using NtAllocateVirtualMemory + NtProtectVirtualMemory for permission cycling, with APC-based wake-up callbacks
- **felixm.pw: Rude Awakening** ([2025](https://felixm.pw)) — Research on how TTTracer and Time Travel Debugging can unmask sleep-obfuscated payloads by replaying the encryption/decryption at arbitrary points in time
- **0xHossam: EDR Evasion Part 4** ([2025](https://0xhossam.github.io)) — Sleep obfuscation combined with stack spoofing and heap encryption for full in-memory evasion against CrowdStrike and SentinelOne

---

## Learning Objectives

By the end of this module, you will be able to:

1. Explain why sleeping payloads are vulnerable to memory scanning and how encryption defeats this
2. Implement inline XOR-based sleep obfuscation with VirtualProtect permission cycling
3. Understand the dual-key architecture: payload decryption key vs sleep obfuscation key
4. Trace the 7-gate evasion gauntlet that precedes payload execution
5. Analyze the complete injection chain: VirtualAlloc, memcpy, VirtualProtect, sleep cycles, CreateThread
6. Detect sleep obfuscation through VirtualProtect cycling and entropy analysis

---

## Section 1: The Problem with Sleeping Payloads

### Why Sleep Creates a Detection Window

Implants (beacons, RATs) spend most of their time sleeping between check-in intervals. A Cobalt Strike beacon with a 60-second sleep spends ~99.9% of its time idle. During sleep:

```
Without Sleep Obfuscation:

Time ──────────────────────────────────────────────────>
     |<--Execute-->|<----------- Sleep(60s) ----------->|<--Execute-->|
     |             |                                    |             |
     | Shellcode   |  Shellcode still in memory         | Shellcode   |
     | running     |  Still RX permissions              | running     |
     |             |  Still cleartext                   |             |
     |             |  VISIBLE TO MEMORY SCANNERS        |             |
     |             |  for 99.9% of the time             |             |
```

EDR memory scanners periodically walk process memory, looking for known shellcode signatures in executable regions. Since the payload sits in cleartext RX memory for 60 seconds, the scanner has an enormous window to detect it.

### Sleep Obfuscation Strategy

```
With Sleep Obfuscation (Crate 13's approach):

Time ──────────────────────────────────────────────────>
     |<--Execute-->|<----------- Sleep(50ms) ---------->|<--Execute-->|
     |             |                                    |             |
     | Cleartext   |  XOR-ENCRYPTED with SLEEP_KEY      | Cleartext   |
     | RX perms    |  RW perms (non-executable)         | RX perms    |
     | DETECTABLE  |  Random noise to scanner           | DETECTABLE  |
     | (brief)     |  INVISIBLE during sleep            | (brief)     |
```

The payload is only decrypted and executable during the brief execution window. For the vast majority of its lifetime, it appears as encrypted data in non-executable memory.

<details>
<summary>Discussion: Why use a separate key for sleep obfuscation?</summary>

Crate 13 uses two distinct XOR keys:

- **XOR_KEY** (16 bytes): Decrypts the shellcode from its compile-time encrypted form (`ENCRYPTED_SHELLCODE`)
- **SLEEP_KEY** (16 bytes): Encrypts/decrypts the payload in memory during sleep cycles

Why not reuse the same key? If an analyst recovers the decryption key (e.g., from a memory dump during the initial decrypt phase), that key only decrypts the on-disk payload. The sleep obfuscation key is different, so recovering one doesn't compromise the other. This is defense-in-depth applied to key management.

Additionally, using different keys means the encrypted-at-rest form (XOR_KEY) and the encrypted-during-sleep form (SLEEP_KEY) produce different ciphertext for the same plaintext, making pattern correlation harder.
</details>

---

## Section 2: Architecture Overview — The 7-Gate Gauntlet

### Gate Sequence

Before any sleep obfuscation or payload execution occurs, the binary must pass through seven evasion gates. This is the same architecture used across crates 09-13:

```
main()
  |
  +--> Gate 1: init_app_environment()
  |      Check 5 environment variables (SystemRoot, USERPROFILE, LOCALAPPDATA,
  |      ProgramData, windir). Require >= 3/5 to pass.
  |      Uses BTreeMap + format!() for benign code mass.
  |
  +--> Gate 2: common::benign::preflight()
  |      Pulls in std::env, std::path, std::fs, std::collections
  |      (HashMap, BTreeMap, HashSet). Code dilution — lowers
  |      offensive-to-benign code ratio for ML classifiers.
  |
  +--> Gate 3: KUSER_SHARED_DATA uptime check
  |      Read TickCountQuad from 0x7FFE0320 (kernel-mapped, no API call).
  |      Bail if TickCountQuad < 300,000 (~78 minutes uptime).
  |
  +--> Gate 4: run_window_lifecycle()
  |      RegisterClassW("PwrMgrWnd") + CreateWindowExW(1x1, hidden)
  |      + SetTimer(50ms) + GetMessageW loop + DestroyWindow.
  |      Generates legitimate Win32 GUI API patterns.
  |
  +--> Gate 5: antidebug::bail_if_debugged()
  |      PEB.BeingDebugged, NtQueryInformationProcess(ProcessDebugPort),
  |      RDTSC timing delta, hardware breakpoint detection (DR0-DR3).
  |
  +--> Gate 6: antidebug::check_analysis_tools()
  |      Enumerate running processes, match against 27 known analysis
  |      tools (x64dbg, procmon, wireshark, etc.). Exit via apihash
  |      ExitProcess if any found.
  |
  +--> Gate 7: check_sandbox()
  |      Hardware fingerprinting (all inline, CFG-safe):
  |        - CPU count < 2  (+1 point)
  |        - RAM < 4 GB     (+1 point)
  |        - Disk < 60 GB   (+1 point)
  |        - Uptime < 30min (+1 point)
  |        - Screen < 800x600 (+1 point)
  |      Bail if score >= 3 (SANDBOX_THRESHOLD).
  |
  +--> [All gates passed] --> Payload execution chain
```

**Exercise 2.1:** Why does Gate 3 read from `0x7FFE0320` instead of calling `GetTickCount64()`? What's the evasion benefit?

<details>
<summary>Answer</summary>

`0x7FFE0320` is the `KUSER_SHARED_DATA.TickCountQuad` field — a kernel-mapped page readable from user-mode without any API call. Reading it directly:

1. **No IAT entry** — `GetTickCount64` won't appear in the import table
2. **No hook target** — EDRs that hook `GetTickCount64` can't intercept this read
3. **Faster** — direct memory read vs. function call through ntdll

The value at `0x7FFE0320` is `KUSER_SHARED_DATA.TickCountQuad` — a tick counter in ~15.625ms units. The code checks `> 300_000` which equals 300,000 × 15.625ms ≈ 78 minutes of uptime. This filters sandboxes that restore from a fresh VM snapshot (uptime near zero).
</details>

---

## Section 3: Payload Decryption — The First XOR Layer

### Dual-Key Architecture

```
Compile-time:                        Runtime (after 7 gates):
+---------------------------+        +---------------------------+
| ENCRYPTED_SHELLCODE       |        | shellcode (decrypted)      |
| [0x31, 0xf5, 0x29, 0xa0, ...] (302 bytes) |  XOR   | [0xe9, 0xbe, 0x00, 0x00, ...] (JMP shellcode) |
| (302 bytes, XOR'd)        | -----> | E9 BE 00 00 (JMP shellcode)|
+---------------------------+  KEY   +---------------------------+
                               |
                    XOR_KEY (16 bytes):
                    [0xd8, 0x4b, 0x29, 0xa0,
                     0xf3, 0xc5, 0x7a, 0xe1,
                     0x0c, 0x96, 0xb2, 0x56,
                     0x68, 0x1f, 0xad, 0x72]
```

The `xor::xor_inplace()` function from the common library applies the key cyclically:

```
shellcode[0] = 0x31 ^ 0xd8 = 0xe9  (JMP opcode)
shellcode[1] = 0xf5 ^ 0x4b = 0xbe  (JMP offset low byte)
shellcode[2] = 0x29 ^ 0x29 = 0x00  (JMP offset high byte)
```

Result: `E9 BE 00 00 ...` = 302-byte MessageBox("GoodBoy") shellcode starting with JMP +0xBE (same payload as all stages).

### Why XOR Instead of AES or RC4?

From the MEMORY.md evasion lessons:

- **AES StreamCipher triggers ESET Agent_AGen.LEE** — the custom RC4-based cipher with 256-byte S-box initialization is classified as malware-grade crypto by ESET's ML
- **Simple XOR killed the detection** — ML classifiers don't flag basic XOR because it's ubiquitous in legitimate software (string obfuscation, checksums, protocol encoding)
- AES is reserved for remote-side decryption where the binary isn't scanned

---

## Section 4: API Resolution via API Hashing

### The apihash Pattern

Crate 13 resolves 7 Windows API functions at runtime via PEB walking + export table parsing, avoiding IAT entries entirely:

```
5 Injection APIs (kernel32.dll):
  1. VirtualAlloc          -> VAllocFn
  2. VirtualProtect        -> VProtectFn
  3. CreateThread           -> CrtThreadFn
  4. WaitForSingleObject    -> WaitFn
  5. CloseHandle            -> CloseFn

2 Bail-out APIs (kernel32.dll):
  6. ExitProcess            -> ExitProcessFn  (anti-debug bail)
  7. ExitProcess            -> ExitProcessFn  (sandbox bail, same hash resolved twice)
```

Each call follows the pattern:

```rust
let valloc: VAllocFn = match apihash::resolve_function(
    apihash::HASH_KERNEL32_DLL, apihash::HASH_VIRTUAL_ALLOC,
) { Some(f) => core::mem::transmute(f), None => { dbg("FAIL_valloc"); return } };
```

`resolve_function` walks `PEB.Ldr.InMemoryOrderModuleList`, finds kernel32.dll by name hash, then walks its export table to find the function by name hash.

### Why Not Direct windows-sys Imports?

The one exception is `Sleep()` — imported directly via `windows_sys::Win32::System::Threading::Sleep`. This is intentional:

- `Sleep` is called by virtually every Windows application
- Its IAT entry is completely benign
- Resolving it via apihash would add a 6th PEB walk (and we know from MEMORY.md that extra apihash calls push CrowdStrike ML confidence)

**Exercise 4.1:** The code resolves ExitProcess twice (once in the anti-debug block, once in the sandbox block). Why not resolve it once and reuse?

<details>
<summary>Answer</summary>

Code structure. Each bail-out block is a self-contained `if` condition that may or may not execute. If the anti-debug check passes, its ExitProcess resolution was wasted work. By resolving only when needed, the code avoids unnecessary PEB walks in the happy path.

More importantly, from the MEMORY.md lessons: "Each apihash call adds PEB.Ldr traversal + export table parsing — cumulative effect on ML classifiers." Resolving ExitProcess in the happy path (where it's never called) would add PEB walking code execution that ML classifiers observe. The current design only triggers PEB walks for ExitProcess when the process is about to terminate anyway.
</details>

---

## Section 5: Injection Chain — Memory Allocation and Copy

### The Allocation Strategy

```
Step 1: VirtualAlloc (RW)
  addr = VirtualAlloc(NULL, shellcode.len(), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
  Flags: 0x3000 = MEM_COMMIT | MEM_RESERVE
         0x04   = PAGE_READWRITE

Step 2: memcpy
  core::ptr::copy_nonoverlapping(shellcode.as_ptr(), addr as *mut u8, size)
  Copies decrypted shellcode into allocated memory.

Step 3: VirtualProtect (RW -> RX)
  vprotect(addr, size, 0x20, &mut old)
  0x20 = PAGE_EXECUTE_READ
  Now the shellcode is executable but not writable.
```

### W^X Discipline

The code never uses RWX (`0x40` / `PAGE_EXECUTE_READWRITE`). This is critical:

```
            Allocated as RW (writable, not executable)
                        |
                   memcpy shellcode
                        |
              VirtualProtect to RX (executable, not writable)
                        |
              +---------+---------+
              |                   |
        Sleep cycles         CreateThread
        (RX -> RW -> RX)     (executes at RX)
```

RWX allocations are a strong malware indicator. Legitimate software allocates RW, writes code, then protects as RX. This is exactly what JIT compilers do.

**Exercise 5.1:** Why does the code use `core::ptr::copy_nonoverlapping` instead of a simple byte-by-byte loop?

<details>
<summary>Answer</summary>

`copy_nonoverlapping` maps to `memcpy` — an optimized memory copy that uses SIMD instructions on modern hardware. A byte loop would work but:

1. **Performance**: `memcpy` copies 16-32 bytes per instruction with SSE/AVX
2. **Code size**: The compiler emits a single `rep movsb` or `memcpy` call, not a loop
3. **Behavioral pattern**: `memcpy` is used by legitimate code constantly, so it doesn't raise ML suspicion

The `nonoverlapping` variant asserts that source and destination don't overlap, enabling additional optimizations.
</details>

---

## Section 6: Sleep Obfuscation — The Core Technique

### The Sleep Cycle

This is the heart of crate 13. After the shellcode is in RX memory, the code runs 3 sleep obfuscation cycles before execution:

```
for cycle in 0..SLEEP_CYCLES {    // SLEEP_CYCLES = 3

    // Phase 1: RX -> RW (make writable)
    vprotect(addr, size, 0x04, &mut old)

    // Phase 2: XOR-encrypt with SLEEP_KEY
    let payload = slice::from_raw_parts_mut(addr as *mut u8, size);
    for (i, b) in payload.iter_mut().enumerate() {
        *b ^= SLEEP_KEY[i % SLEEP_KEY.len()];
    }

    // Phase 3: Sleep (payload encrypted + non-executable)
    Sleep(SLEEP_DURATION_MS)       // SLEEP_DURATION_MS = 50

    // Phase 4: XOR-decrypt with same SLEEP_KEY
    for (i, b) in payload.iter_mut().enumerate() {
        *b ^= SLEEP_KEY[i % SLEEP_KEY.len()];
    }

    // Phase 5: RW -> RX (make executable again)
    vprotect(addr, size, 0x20, &mut old)

    core::hint::black_box(cycle);  // Prevent loop optimization
}
```

### The SLEEP_KEY

```
SLEEP_KEY (16 bytes, different from XOR_KEY):
[0x5a, 0x1e, 0x93, 0xf7, 0x2b, 0x84, 0xd6, 0x41,
 0x0d, 0x68, 0xbe, 0x3c, 0xa9, 0x75, 0xe2, 0x17]
```

XOR is its own inverse: `plaintext ^ key = ciphertext`, `ciphertext ^ key = plaintext`. This means the same loop handles both encryption and decryption.

### Permission State Timeline

```
Time ─────────────────────────────────────────────────────────>

VirtualAlloc(RW)
  |
  memcpy
  |
  VirtualProtect(RX)
  |
  +--- Cycle 0 --------+--- Cycle 1 --------+--- Cycle 2 --------+
  |                     |                     |                     |
  RX->RW  encrypt      RX->RW  encrypt      RX->RW  encrypt         |
  |       Sleep(50)     |       Sleep(50)     |       Sleep(50)     |
  |       decrypt       |       decrypt       |       decrypt       |
  RW->RX               RW->RX               RW->RX                  |
  +---------------------+---------------------+---------------------+
                                                                    |
                                                            CreateThread(RX)
                                                                    |
                                                            WaitForSingleObject
                                                                    |
                                                            CloseHandle
```

### What a Memory Scanner Sees

```
During Sleep (150ms total across 3 cycles):
  Region: RW (non-executable)
  Content: XOR-encrypted noise
  Entropy: ~8.0 (random-looking)
  Verdict: "Just some data buffer" -- no shellcode signature match

During Execution (brief):
  Region: RX (executable)
  Content: Decrypted shellcode
  Entropy: ~4.5 (code-like)
  Verdict: Potentially suspicious -- but window is tiny
```

### Why 3 Cycles of 50ms?

- **50ms per cycle**: Short enough that the total delay (150ms) doesn't noticeably slow execution. In a real implant, this would be 30-60 seconds per cycle.
- **3 cycles**: Demonstrates the concept. Each cycle re-encrypts with the same key, proving the encrypt/decrypt symmetry works repeatedly.
- **core::hint::black_box(cycle)**: Prevents the compiler from optimizing away the loop entirely (since the cycles have no externally visible side effect besides the Sleep).

<details>
<summary>Discussion: How does this compare to Cobalt Strike's sleep_mask?</summary>

Cobalt Strike's `sleep_mask` feature (since 4.1) applies a similar concept:
- Before sleep: XOR-encrypt beacon memory, change to RW
- After sleep: Decrypt, change to RX

Key differences from crate 13:
1. **CS encrypts the entire beacon image** (~200-300KB), not just shellcode
2. **CS 4.7+ added "Ekko" and "Zilean" techniques** for timer-based approaches where the decryption happens in a system worker thread (cleaner call stack)
3. **CS 4.9+ added stack spoofing** — faking the call stack during sleep
4. **Crate 13 uses inline XOR** (simple, low detection surface) vs CS's more complex masking BOF

Crate 13's approach is intentionally minimal — demonstrating the core concept without the complexity of timer callbacks or stack manipulation, which would add more API calls and more detection surface.
</details>

---

## Section 7: Execution and Proof

### Thread Execution

After the sleep cycles complete, the shellcode executes via CreateThread:

```rust
let thread = crt_thread(
    core::ptr::null(), 0,       // Default security, default stack
    addr,                        // Start address: shellcode in RX memory
    core::ptr::null(), 0,       // No parameter, no flags
    core::ptr::null_mut(),      // Don't need thread ID
);
if thread.is_null() { dbg("FAIL_thread"); return; }

wait(thread, 0xFFFFFFFF);       // INFINITE wait
close(thread);                   // CloseHandle
```

The 302-byte shellcode displays a MessageBox("GoodBoy") dialog and then calls ExitProcess, terminating the process cleanly.

### Breadcrumb Trail

The `dbg()` function writes tag files to `%TEMP%` for execution flow tracing:

```
%TEMP%\pwrmgr_1_start.txt           -- main() entered
%TEMP%\pwrmgr_2_checks_ok.txt       -- Gates 1-2 passed
%TEMP%\pwrmgr_3_window_done.txt     -- Gate 4 passed (GUI lifecycle)
%TEMP%\pwrmgr_4_debug_ok.txt        -- Gates 5-6 passed (anti-debug)
%TEMP%\pwrmgr_5_sandbox_score_N.txt -- Gate 7 result (N = score)
%TEMP%\pwrmgr_5_sandbox_ok.txt      -- Gate 7 passed
%TEMP%\pwrmgr_6_pre_sleep.txt       -- About to start sleep cycles
%TEMP%\pwrmgr_7_pre_thread.txt      -- Sleep cycles complete
%TEMP%\pwrmgr_8_done.txt            -- Thread execution complete
```

Plus `GOODBOY_OK.txt` with the full proof message.

**Exercise 7.1:** The breadcrumb prefix is `pwrmgr_`, and the window class is `PwrMgrWnd`. What does this naming simulate?

<details>
<summary>Answer</summary>

"PwrMgr" suggests "Power Manager" — a legitimate Windows service component. The naming makes the window class registration, breadcrumb files, and any process inspection look like a power management utility rather than malware. Each crate in the Goodboy framework uses a different fake service name (e.g., crate 12 uses "SvcCtrl" for "Service Control").
</details>

---

## Section 8: Detection Engineering

### Detection Strategy Matrix

| Technique | Detection Method | Difficulty |
|---|---|---|
| XOR sleep encryption | VirtualProtect cycling on same region (RX<->RW) | Medium |
| Dual VirtualProtect per cycle | ETW correlation of protection changes | Medium |
| Inline XOR loop | Memory entropy changes between scans | Hard |
| apihash API resolution | PEB.Ldr traversal without LoadLibrary | Hard |
| 7-gate anti-analysis | Behavioral analysis (env checks + sandbox checks + timing) | Hard |

### YARA Rule: Detect Inline XOR Sleep Obfuscation

```yara
rule Sleep_Obfuscation_XOR_VProtect_Cycle
{
    meta:
        description = "Detects XOR-based sleep obfuscation with VirtualProtect cycling"
        severity = "high"

    strings:
        // VirtualProtect permission constants
        $rw_const = { 04 00 00 00 }  // PAGE_READWRITE
        $rx_const = { 20 00 00 00 }  // PAGE_EXECUTE_READ

        // XOR loop pattern (byte-by-byte XOR with key)
        $xor_loop = { 30 ?? 48 ?? ?? 48 ?? ?? ?? 48 }  // xor [reg], reg; inc; cmp; loop

        // Sleep import
        $sleep_import = "Sleep" ascii

        // VirtualAlloc allocation constants
        $mem_commit = { 00 30 00 00 }  // MEM_COMMIT | MEM_RESERVE

    condition:
        uint16(0) == 0x5A4D and
        $rw_const and $rx_const and
        (#rw_const >= 2 and #rx_const >= 2) and  // Multiple permission cycles
        $sleep_import and
        ($xor_loop or $mem_commit)
}
```

### Sigma Rule: VirtualProtect Permission Cycling

```yaml
title: Suspicious VirtualProtect Permission Cycling with Sleep
id: 9c4d5e6f-0987-6543-bcde-f01234567890
status: experimental
description: Detects sleep obfuscation via VirtualProtect RX/RW cycling
logsource:
    category: api_call
    product: windows
detection:
    selection_vprotect:
        ApiCall: 'VirtualProtect'
        NewProtection|contains:
            - '0x04'   # PAGE_READWRITE
            - '0x20'   # PAGE_EXECUTE_READ
    selection_sleep:
        ApiCall: 'Sleep'
    timeframe: 5s
    condition: selection_vprotect | count() >= 4 and selection_sleep
level: high
tags:
    - attack.defense_evasion
    - attack.t1027.013
```

### ETW-Based Detection

```
Provider: Microsoft-Windows-Threat-Intelligence
Events to correlate:
  1. VirtualProtect: RX -> RW on region (addr, size)
  2. <50ms interval>
  3. VirtualProtect: RW -> RX on SAME region (addr, size)
  4. Pattern repeats 3+ times with Sleep() between transitions

Detection logic:
  IF same_region.protection_change_count >= 6  (3 cycles x 2 changes)
  AND changes alternate between 0x04 and 0x20
  AND interval between changes includes NtDelayExecution
  THEN alert: "Sleep obfuscation detected — XOR cycling on memory region"
```

<details>
<summary>Discussion: What makes this harder to detect than CS sleep_mask?</summary>

Crate 13's approach has several properties that complicate detection:

1. **No timer queue APIs** — Ekko-style detection looks for `CreateTimerQueueTimer` + callback analysis. This binary doesn't use it.
2. **No RC4 S-box** — No 256-byte permutation table in memory, which is a strong RC4 indicator.
3. **No key rotation** — No RDTSC calls for key generation, no key material changes in heap.
4. **Direct Sleep() import** — The Sleep call comes from a normal IAT entry, not a suspicious dynamic resolution.
5. **Small payload** — Only 302 bytes are encrypted. The VirtualProtect region is the full allocation but the actual encrypted content is tiny, making entropy analysis less reliable.
6. **Short duration** — 50ms cycles are fast enough that periodic memory scanners may miss the transition entirely.

The main detection vector remains VirtualProtect cycling — alternating RX<->RW on the same region with Sleep() between changes is inherently suspicious regardless of the encryption method.
</details>

---

## Section 9: Complete Execution Flow

### Full Chain Summary

```
main()
  |
  +-- dbg("1_start")
  +-- Gate 1: init_app_environment()     [env vars + BTreeMap]
  +-- Gate 2: benign::preflight()         [code dilution]
  +-- dbg("2_checks_ok")
  +-- Gate 3: KUSER_SHARED_DATA > ~78min  [0x7FFE0320 TickCountQuad]
  +-- Gate 4: run_window_lifecycle()       ["PwrMgrWnd" GUI]
  +-- dbg("3_window_done")
  +-- Gate 5: bail_if_debugged()           [PEB + NtQIP + RDTSC + HW BP]
  +-- Gate 6: check_analysis_tools()       [27 tools, ExitProcess via apihash]
  +-- dbg("4_debug_ok")
  +-- Gate 7: check_sandbox()              [CPU + RAM + disk + uptime + screen]
  +-- dbg("5_sandbox_ok")
  |
  +-- XOR decrypt shellcode (XOR_KEY)
  |
  +-- Resolve 5 APIs via apihash:
  |     VirtualAlloc, VirtualProtect, CreateThread,
  |     WaitForSingleObject, CloseHandle
  |
  +-- VirtualAlloc(RW) -> memcpy -> VirtualProtect(RX)
  +-- dbg("6_pre_sleep")
  |
  +-- 3x Sleep Obfuscation Cycles:
  |     RX->RW -> XOR-encrypt(SLEEP_KEY) -> Sleep(50ms)
  |     -> XOR-decrypt(SLEEP_KEY) -> RW->RX
  |
  +-- dbg("7_pre_thread")
  +-- CreateThread -> WaitForSingleObject -> CloseHandle
  +-- dbg("8_done")
  +-- Write GOODBOY_OK.txt proof
  +-- Open notepad with proof
```

### Key Takeaways

```
+----------------------------------------------------------+
| Sleep Obfuscation Key Concepts                           |
+----------------------------------------------------------+
|                                                          |
| 1. THE CORE PROBLEM                                      |
|    Sleeping payload = static target for memory scanners  |
|    Solution: encrypt payload + change permissions        |
|    during sleep, decrypt + restore before execution      |
|                                                          |
| 2. XOR IS IDEAL FOR SLEEP ENCRYPTION                     |
|    Self-inverse: encrypt == decrypt (same operation)     |
|    No complex state (no S-box, no block cipher)          |
|    Minimal code footprint (avoids ML detection)          |
|    No suspicious imports                                 |
|                                                          |
| 3. DUAL-KEY ARCHITECTURE                                 |
|    XOR_KEY: decrypts on-disk encrypted shellcode         |
|    SLEEP_KEY: encrypts/decrypts payload during sleep     |
|    Different keys = defense-in-depth                     |
|                                                          |
| 4. PERMISSION LIFECYCLE (W^X)                            |
|    Active:   RX (executable, decrypted)                  |
|    Sleeping: RW (writable, encrypted)                    |
|    Never:    RWX (violation of W^X)                      |
|    Order: write before protect, protect before execute   |
|                                                          |
| 5. DETECTION SURFACE                                     |
|    VirtualProtect cycling (RX<->RW) is the main IOC      |
|    ETW can correlate permission changes with Sleep()     |
|    Entropy analysis catches encrypted->decrypted shifts  |
|    But: short cycles + small payload = hard to catch     |
|                                                          |
| 6. EVASION LAYERING                                      |
|    Sleep obfuscation alone is not enough                 |
|    7-gate gauntlet prevents analysis environment exec    |
|    apihash hides API usage from IAT analysis             |
|    Benign code dilution defeats ML classifiers           |
|    Each layer independently insufficient, together 0/76  |
|                                                          |
+----------------------------------------------------------+
```

---

## Section 10: Source Code Deep Dive

### The Encrypt-Sleep-Decrypt Cycle

The core of sleep obfuscation is a tight loop that runs 3 times. Each cycle follows the same pattern: change permissions to writable, XOR-encrypt the payload, sleep, XOR-decrypt, restore execute permissions.

```
Per-cycle execution (from main.rs):

CYCLE START (payload is currently RX — executable, decrypted)
  │
  ├─ VirtualProtect(addr, size, PAGE_READWRITE)     // RX → RW
  │    The payload region becomes writable but NOT executable.
  │    A memory scanner running NOW sees RW data — not code.
  │
  ├─ XOR-encrypt with SLEEP_KEY:
  │    for (i, b) in payload.iter_mut().enumerate() {
  │        *b ^= SLEEP_KEY[i % SLEEP_KEY.len()];   // 16-byte key, cyclic
  │    }
  │    Payload is now encrypted noise in RW memory.
  │    Shannon entropy jumps from ~4.5 (code) to ~8.0 (random).
  │
  ├─ Sleep(50)                                     // 50ms per cycle
  │    Thread is suspended by the OS scheduler.
  │    During this 50ms window:
  │      - Memory region is RW (non-executable)
  │      - Content is XOR-encrypted
  │      - No shellcode signature matches possible
  │      - EDR periodic scan sees "just a data buffer"
  │
  ├─ XOR-decrypt with same SLEEP_KEY:
  │    for (i, b) in payload.iter_mut().enumerate() {
  │        *b ^= SLEEP_KEY[i % SLEEP_KEY.len()];   // XOR is self-inverse
  │    }
  │    Payload is now cleartext again.
  │
  └─ VirtualProtect(addr, size, PAGE_EXECUTE_READ)  // RW → RX
       Payload is executable again. Ready for the next cycle or CreateThread.

CYCLE END (payload is RX — executable, decrypted)
```

The binary runs 3 complete cycles with `SLEEP_DURATION_MS = 50` for demonstration (150ms total). In a production implant, each cycle would be 30-60 seconds, matching a realistic beacon interval.

### Why Inline XOR — Not RC4, FluctuationGuard, or SleepObfuscator

The common library provides three sleep-related crypto modules. All were deliberately rejected:

```
Rejected: common::crypto::stream_cipher (RC4-based)
  Problem: 256-byte S-box initialization loop is a textbook RC4 fingerprint.
           ESET and Rising ML classifiers flag this as malware-grade crypto.
           The S-box init pattern (for i in 0..256 { S[i] = i }) appears in
           no legitimate Windows application.

Rejected: common::evasion::FluctuationGuard
  Problem: Uses VirtualProtect via apihash (adds PEB walk ML signals),
           rdtsc-based PRNG for key material, and timer queue callbacks.
           Rising's TFE signature matches the combination of these patterns.

Rejected: common::evasion::SleepObfuscator
  Problem: Combines RC4 + timer callbacks + VirtualProtect cycling.
           All three rejected patterns in one module.

Accepted: Inline XOR for loop
  Why: A 3-line for loop XOR'ing bytes against a static key is
       indistinguishable from checksum calculation, string deobfuscation,
       protocol encoding, or any other XOR use case in legitimate software.
       ML classifiers cannot flag it without massive false positives.
```

### Detection Probability Math

The fundamental question: what's the probability that a memory scanner catches the plaintext payload?

```
Timing Analysis per Cycle:
  T_encrypt  ≈ <1ms    (XOR 302 bytes — negligible)
  T_sleep    = 50ms   (Sleep() call)
  T_decrypt  ≈ <1ms    (XOR 302 bytes — negligible)
  T_execute  ≈ 100ms   (VirtualProtect RW→RX + any pre-execution work)
  T_total    = T_encrypt + T_sleep + T_decrypt + T_execute ≈ 152ms

  Payload visible window: T_execute ≈ 100ms
  Payload hidden window:  T_sleep  ≈ 50ms

  P(catch in one cycle) = T_execute / T_total ≈ 100 / 152 ≈ 65.8%
  P(miss in one cycle)  = 1 - 0.658 = 0.342

For 3 cycles (assuming single random-time scan per cycle):
  P(catch at least once) = 1 - (0.342)^3 ≈ 96.0%

NOTE: With 50ms sleep, the plaintext window (100ms) is LARGER than the sleep
window (50ms). This demo uses short cycles for fast testing. Production
implants use 5-60 second sleep intervals, which flip the ratio dramatically:

For production implant (60s sleep, 100ms execute):
  P(catch per cycle) = 100 / 60100 ≈ 0.17%
  P(miss all in 1 hour = 60 cycles) = (1 - 0.0017)^60 ≈ 90.3%
```

The longer the sleep interval, the lower the detection probability. At a 60-second beacon interval, a memory scanner running once per minute has only a ~10% chance of catching the plaintext payload across an entire hour of operation.

### YARA Rule: Sleep Obfuscation Permission Cycling

```yara
rule Sleep_Obfuscation_VProtect_Cycle
{
    meta:
        description = "Detects VirtualProtect RX<->RW cycling pattern with Sleep call"
        author = "Goodboy Course"
        stage = "13"

    strings:
        // VirtualProtect import
        $vp = "VirtualProtect" ascii
        // Sleep import (direct IAT)
        $sleep = "Sleep" ascii
        // PAGE_READWRITE constant 0x04
        $rw = { 04 00 00 00 }
        // PAGE_EXECUTE_READ constant 0x20
        $rx = { 20 00 00 00 }
        // Apihash PEB access
        $peb = { 65 48 8B 04 25 60 00 00 00 }
        // Rotate-xor seed (common library)
        $seed = { D5 91 3A 7C }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        ($vp or $peb) and $sleep and $rw and $rx
}
```

### Python Script 1: VirtualProtect Cycling Detector (ETW-based)

```python
#!/usr/bin/env python3
"""Detect VirtualProtect RX<->RW permission cycling on the same memory region.
Parses ETW or API monitor logs for the Stage 13 sleep obfuscation pattern."""

import sys, re, json
from collections import defaultdict

def parse_api_monitor_log(path):
    """Parse API Monitor CSV export for VirtualProtect calls."""
    calls = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if "VirtualProtect" not in line:
                continue
            # Expected format: timestamp,pid,tid,api,args,retval
            parts = line.strip().split(",")
            if len(parts) < 5:
                continue
            try:
                addr_match = re.search(r'0x([0-9a-fA-F]+)', parts[4])
                prot_match = re.search(r'(?:0x)?([0-9a-fA-F]+)\s*(?:\(|,)', parts[4].split(",")[2] if "," in parts[4] else "")
                if addr_match:
                    calls.append({
                        "time": parts[0].strip(),
                        "pid": parts[1].strip(),
                        "addr": int(addr_match.group(1), 16),
                        "protection": parts[4],
                        "raw": line.strip(),
                    })
            except (IndexError, ValueError):
                calls.append({"time": parts[0].strip(), "raw": line.strip()})
    return calls

def detect_cycling(calls):
    """Find RX<->RW cycling patterns on the same address."""
    by_addr = defaultdict(list)
    for c in calls:
        if "addr" in c:
            by_addr[c["addr"]].append(c)

    suspicious = []
    for addr, addr_calls in by_addr.items():
        if len(addr_calls) >= 4:  # At least 2 full cycles (RX->RW->RX->RW)
            suspicious.append({
                "address": f"0x{addr:X}",
                "call_count": len(addr_calls),
                "pattern": "RX<->RW cycling",
                "first_call": addr_calls[0].get("time", "?"),
                "last_call": addr_calls[-1].get("time", "?"),
            })
    return suspicious

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <api_monitor_export.csv>")
        print(f"  Export from API Monitor: File > Export > CSV")
        sys.exit(1)

    calls = parse_api_monitor_log(sys.argv[1])
    print(f"VirtualProtect calls: {len(calls)}")

    results = detect_cycling(calls)
    if results:
        print(f"\n\033[91m{len(results)} suspicious address(es) with permission cycling:\033[0m")
        for r in results:
            print(f"  Address: {r['address']}")
            print(f"    Calls: {r['call_count']} VirtualProtect invocations")
            print(f"    Pattern: {r['pattern']}")
            print(f"    Window: {r['first_call']} → {r['last_call']}")
            print()
    else:
        print("\033[92mNo RX<->RW cycling detected\033[0m")

    if "--json" in sys.argv:
        print(json.dumps(results, indent=2))
```

### Python Script 2: Memory Entropy Scanner

```python
#!/usr/bin/env python3
"""Periodically sample a memory region and measure Shannon entropy.
Detects sleep obfuscation: high entropy during sleep (encrypted), low during execution."""

import ctypes
import ctypes.wintypes as wt
import math, time, sys, os

kernel32 = ctypes.windll.kernel32

def read_memory(pid, address, size):
    """Read bytes from a remote process."""
    PROCESS_VM_READ = 0x0010
    handle = kernel32.OpenProcess(PROCESS_VM_READ, False, pid)
    if not handle:
        return None
    buf = (ctypes.c_ubyte * size)()
    read = ctypes.c_size_t()
    ok = kernel32.ReadProcessMemory(handle, address, buf, size, ctypes.byref(read))
    kernel32.CloseHandle(handle)
    return bytes(buf[:read.value]) if ok else None

def shannon_entropy(data):
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    return -sum(f/len(data) * math.log2(f/len(data)) for f in freq if f)

if len(sys.argv) < 4:
    print(f"Usage: {sys.argv[0]} <pid> <address_hex> <size> [interval_ms] [duration_s]")
    print(f"  Example: {sys.argv[0]} 1234 0x1A0000 302 100 30")
    sys.exit(1)

pid = int(sys.argv[1])
address = int(sys.argv[2], 16)
size = int(sys.argv[3])
interval_ms = int(sys.argv[4]) if len(sys.argv) > 4 else 100
duration_s = int(sys.argv[5]) if len(sys.argv) > 5 else 30

print(f"Scanning PID {pid} at 0x{address:X} ({size} bytes) every {interval_ms}ms for {duration_s}s")
print(f"{'Time':>8s} {'Entropy':>8s} {'Status':>12s}")
print("-" * 32)

start = time.time()
samples = []
while time.time() - start < duration_s:
    data = read_memory(pid, address, size)
    if data:
        ent = shannon_entropy(data)
        elapsed = time.time() - start
        status = "\033[91mENCRYPTED\033[0m" if ent > 7.0 else "\033[92mPLAINTEXT\033[0m" if ent > 4.0 else "\033[93mZERO/PAD\033[0m"
        print(f"{elapsed:7.1f}s {ent:8.4f} {status}")
        samples.append((elapsed, ent))
    time.sleep(interval_ms / 1000.0)

if samples:
    entropies = [s[1] for s in samples]
    high = sum(1 for e in entropies if e > 7.0)
    low = sum(1 for e in entropies if e <= 7.0)
    print(f"\nSummary: {len(samples)} samples, {high} encrypted, {low} plaintext/other")
    if high > 0 and low > 0:
        print(f"\033[91mSLEEP OBFUSCATION DETECTED — entropy oscillates between encrypted and plaintext states\033[0m")
    elif high == len(samples):
        print(f"\033[93mAlways encrypted — payload may be in sleep phase\033[0m")
```

### Python Script 3: Sleep Cycle Timeline Reconstructor

```python
#!/usr/bin/env python3
"""Reconstruct sleep obfuscation cycle timeline from Sysmon/ETW events.
Identifies: VirtualProtect RX→RW (encrypt start) → Sleep → VirtualProtect RW→RX (decrypt end)."""

import sys, json
from datetime import datetime

def parse_events(path):
    """Parse a JSON event log (from ETW or custom API monitor)."""
    with open(path, "r") as f:
        events = json.load(f)
    return events

def reconstruct_cycles(events):
    """Find encrypt→sleep→decrypt cycles."""
    cycles = []
    pending_encrypt = None

    for e in events:
        api = e.get("api", "")
        protection = e.get("new_protection", 0)
        ts = e.get("timestamp", "")

        if api == "VirtualProtect" and protection == 0x04:  # RX→RW (start encrypt)
            pending_encrypt = {"start": ts, "address": e.get("address", "?")}
        elif api == "Sleep" and pending_encrypt:
            pending_encrypt["sleep_ms"] = e.get("duration_ms", 0)
            pending_encrypt["sleep_ts"] = ts
        elif api == "VirtualProtect" and protection == 0x20 and pending_encrypt:  # RW→RX (end decrypt)
            pending_encrypt["end"] = ts
            cycles.append(pending_encrypt)
            pending_encrypt = None

    return cycles

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <events.json>")
        print(f"  JSON format: [{{\"api\":\"VirtualProtect\",\"new_protection\":4,\"timestamp\":\"...\"}}, ...]")
        sys.exit(1)

    events = parse_events(sys.argv[1])
    cycles = reconstruct_cycles(events)

    print(f"Sleep Obfuscation Cycle Timeline ({len(cycles)} cycles)")
    print("=" * 60)

    for i, c in enumerate(cycles):
        print(f"  Cycle {i+1}:")
        print(f"    Encrypt start:  {c['start']}")
        print(f"    Sleep:          {c.get('sleep_ms', '?')}ms at {c.get('sleep_ts', '?')}")
        print(f"    Decrypt end:    {c['end']}")
        print(f"    Address:        {c['address']}")
        print()

    if cycles:
        print(f"\033[91m{len(cycles)} sleep obfuscation cycles detected\033[0m")
        print(f"Pattern: VirtualProtect(RW) → Sleep → VirtualProtect(RX)")
    else:
        print("\033[92mNo sleep obfuscation cycles found\033[0m")
```

### Section 7B: Defense Hardening — Detecting Sleep Obfuscation

```
Layer 1: ETW VirtualProtect Monitoring (real-time)
  ☐ Subscribe to Microsoft-Windows-Kernel-Audit-API-Calls ETW provider
  ☐ Filter for NtProtectVirtualMemory calls with PAGE_READWRITE (0x04) ↔ PAGE_EXECUTE_READ (0x20) cycling
  ☐ Alert on: same address with 2+ protection changes within 10 seconds
  ☐ Correlate with Sleep/WaitForSingleObject calls between protection changes

Layer 2: Periodic Memory Scanning (pe-sieve / Moneta)
  ☐ Scan interval: 100ms or faster (50ms sleep cycles are brief)
  ☐ pe-sieve --shellcode --threads --iat: detect injected code regions
  ☐ Moneta: flag RW regions that were recently RX (permission history)
  ☐ Entropy-based: flag regions with Shannon entropy > 7.0 in RW state

Layer 3: Windows Defender Exploit Guard (preventive)
  ☐ Enable "Block Win32 API calls from Office macros" ASR rule
  ☐ Enable "Block executable content from email client and webmail" ASR rule
  ☐ Custom: block VirtualProtect(PAGE_READWRITE) on MEM_PRIVATE RX regions
  ☐ Audit mode first → 30 days → enforce mode

Layer 4: Thread Stack Analysis (advanced)
  ☐ Enumerate threads in target process
  ☐ For sleeping threads: inspect return address chain
  ☐ Flag: thread sleeping in a region that was recently RX but is now RW
  ☐ Tools: Process Hacker → Threads → Stack → verify all return addresses are in known modules
```

### Exercise 8.1: Write a VirtualProtect Cycling Detection Rule

**Question**: Write a Sigma rule that detects VirtualProtect permission cycling (RX→RW→RX) on the same memory region within 5 seconds. What Sysmon Event ID would you use? What are the false positive risks?

<details>
<summary>Answer</summary>

Sysmon does NOT natively log VirtualProtect calls. You need either:
1. **ETW**: Subscribe to `Microsoft-Windows-Kernel-Audit-API-Calls` and filter for `NtProtectVirtualMemory`
2. **Custom EDR hook**: Inline hook on `kernel32!VirtualProtect` that logs address + new_protection + timestamp
3. **API Monitor**: For analysis, use API Monitor with VirtualProtect filter

A Sigma rule for ETW would look like:
```yaml
logsource:
    product: windows
    service: etw
    provider: Microsoft-Windows-Kernel-Audit-API-Calls
detection:
    selection:
        EventName: NtProtectVirtualMemory
    timeframe: 5s
    condition: selection | count() by TargetAddress > 3
```

False positives: JIT compilers (.NET CLR, V8 JavaScript engine) legitimately cycle VirtualProtect when compiling code. Filter by excluding known JIT processes (dotnet.exe, chrome.exe, node.exe). The key distinguisher: JIT protection changes are RW→RX (one direction), while sleep obfuscation cycles RX→RW→RX→RW (bidirectional).

</details>

### Exercise 8.2: Calculate Scanner Evasion Probability

**Question**: The binary runs 3 sleep cycles of 50ms each. A memory scanner samples every 200ms. What percentage of the time is the payload in plaintext (vulnerable to scanning)?

<details>
<summary>Answer</summary>

Each cycle: RX→RW (encrypt) → Sleep(50ms) → decrypt → RW→RX
Total cycle time ≈ 50ms (sleep dominates, encrypt/decrypt are microseconds)

During the 50ms sleep, the payload is encrypted (RW, high entropy). The plaintext payload is only exposed during:
1. The brief window between VirtualProtect(RX) and the next cycle's VirtualProtect(RW) — ~microseconds
2. After all 3 cycles complete, the payload stays RX until CreateThread executes it

With 3 cycles × 50ms = 150ms total sleep time, the payload is encrypted for ~150ms and plaintext for ~0ms (the transition windows are negligible).

Scanner at 200ms interval: probability of catching the plaintext between cycles ≈ 0% (the transition is too fast). The scanner would need to sample DURING the sub-microsecond decrypt→re-encrypt window.

**Key insight**: Sleep obfuscation with short cycles (50ms) is effectively undetectable by periodic scanners. Production implants use 5-60 second cycles, giving scanners a larger plaintext window. The evasion probability formula: `P(detection) = T_plaintext / T_scan_interval`.

</details>

---

## Section 11: Adversarial Thinking

### Challenge 1: Memory Scanner vs Sleep Obfuscation

**Scenario**: A memory scanner runs every 500ms. The binary runs 3 sleep cycles of 50ms each. What's the probability of catching the plaintext payload?

<details>
<summary>Detailed calculation</summary>

Each cycle is ~152ms total (50ms sleep + ~100ms execute + ~2ms encrypt/decrypt).
The vulnerable window (plaintext + RX) is ~100ms per cycle.

Scanner fires every 500ms. Since a full cycle (152ms) is shorter than the scan
interval (500ms), the scanner gets at most 1 scan attempt per cycle. If the scan
lands during the 100ms execute window, it catches the plaintext.

```
P(catch per random scan) = T_execute / T_total = 100 / 152 ≈ 65.8%
P(miss per scan) = 1 - 0.658 = 0.342

Over 3 cycles (1 scan attempt each):
P(miss all 3) = (0.342)^3 ≈ 4.0%
P(catch at least once) = 1 - 0.04 ≈ 96.0%
```

**Key insight**: With 50ms sleep, the binary is detectable 96% of the time — the
sleep window is too short relative to the execute window. A production implant
using 60-second sleep would have P(catch) = 100/60100 ≈ 0.17% per scan, making
detection nearly impossible with periodic scanning alone.

However, this assumes the scan times are uniformly distributed relative to cycle phase. In practice, if the scanner and sleep cycles are not synchronized, some scans will consistently miss the vulnerable window (phase alignment). The real probability depends on the phase relationship between the two periodic processes.

Key insight: a 500ms scanner has a ~45% chance of catching a 3-cycle demo. But against a production implant (60s sleep, scanner every 500ms), the math shifts dramatically in favor of the attacker.
</details>

### Challenge 2: Avoiding VirtualProtect Entirely

**Scenario**: An EDR monitors all VirtualProtect calls. The RX-RW-RX pattern repeated 3 times is a dead giveaway. How do you achieve sleep obfuscation without VirtualProtect?

<details>
<summary>Approaches</summary>

1. **Use RWX from the start**: Allocate the payload region as `PAGE_EXECUTE_READWRITE (0x40)` and never change permissions. You can XOR-encrypt/decrypt freely without VirtualProtect calls. The downside: RWX memory is itself a top-tier detection signal. Most EDRs flag ANY RWX allocation that doesn't come from a JIT compiler.

2. **NtProtectVirtualMemory via indirect syscalls**: Use the Stage 08 technique — resolve the syscall number for NtProtectVirtualMemory from ntdll, then execute the `syscall` instruction from within ntdll's code. The permission change still happens at the kernel level, but the EDR's user-mode hook on VirtualProtect is bypassed. The ETW-TI provider can still observe the change (kernel-level telemetry), but many EDRs rely primarily on user-mode hooks.

3. **Ekko/Zilean timer-based technique**: Instead of calling VirtualProtect directly, queue a timer callback (CreateTimerQueueTimer) that changes permissions and sleeps. The callback executes in a system worker thread with a clean call stack. The VirtualProtect still happens, but the call stack doesn't trace back to the implant's thread — it comes from ntdll's timer dispatch. This is what Cobalt Strike 4.7+ implements.

4. **Foliage APC technique**: Queue an APC (QueueUserAPC) to the current thread that performs the permission change. The APC executes with a different call context, breaking the direct association between the implant code and the VirtualProtect call.

Each approach trades one detection surface for another. The direct inline approach (this binary) was chosen because it has the smallest code footprint and fewest suspicious API calls.
</details>

### Challenge 3: Cobalt Strike's Sleepmask vs Stage 13

**Scenario**: Cobalt Strike's Sleepmask encrypts the entire beacon during sleep. How does Stage 13's approach differ, and what are the relative advantages?

<details>
<summary>Comparison</summary>

```
Cobalt Strike Sleepmask (4.11):
  Scope:      Encrypts entire beacon PE image (~200-300KB)
              Including PE headers, .text, .data, heap references
  Crypto:     XOR with rotating key (or custom mask in BOF)
  Mechanism:  Timer queue callback (Ekko) or APC (Foliage)
  Permissions: Entire beacon region → RW during sleep
  Stack:      Stack spoofing — fakes return addresses
  Extras:     Heap encryption, thread context manipulation

Stage 13 (this binary):
  Scope:      Encrypts only the shellcode region (302 bytes in demo)
  Crypto:     Static 16-byte XOR key, inline for loop
  Mechanism:  Direct VirtualProtect + Sleep() in main thread
  Permissions: Only shellcode allocation → RW during sleep
  Stack:      No stack spoofing (real call stack visible)
  Extras:     None — minimal implementation

Advantages of Stage 13's approach:
  + Minimal code footprint (no timer APIs, no APC, no stack spoofing)
  + No CreateTimerQueueTimer in call trace (Ekko detection bypass)
  + Simple XOR is invisible to ML (no RC4 S-box)
  + Direct Sleep() import is benign

Advantages of CS Sleepmask:
  + Encrypts entire image (headers + all sections)
  + Stack spoofing defeats stack-walking analysis
  + Timer callback provides clean call stack
  + Heap encryption prevents heap-based artifact recovery
  + Rotating keys resist known-plaintext attacks
```

The fundamental trade-off: CS encrypts more but needs more machinery (timers, APCs, stack manipulation). Stage 13 encrypts less but needs almost no machinery. For a 302-byte shellcode payload, the difference is academic. For a real 300KB beacon, CS's approach is more thorough — but also creates a larger detection surface through the timer/APC infrastructure.
</details>

### Common Misconceptions

| What People Believe | What's Actually True |
|--------------------|-----------------------|
| "RC4 or AES is better than XOR for sleep encryption" | RC4's 256-byte S-box initialization and AES's StreamCipher pattern are classified as malware-grade crypto by ESET ML. Simple XOR is INVISIBLE to ML because it's ubiquitous in legitimate software (checksums, protocol encoding, string obfuscation). The common library's RC4/FluctuationGuard/SleepObfuscator were the signature that triggered Rising's TFE detection |
| "Timer-based sleep obfuscation (Ekko/Zilean) is strictly superior" | Timer callbacks (CreateTimerQueueTimer) add API calls that EDRs specifically monitor. Ekko-style detection rules watch for timer queue creation + VirtualProtect in the callback. Inline XOR with direct Sleep() import has FEWER detection surfaces — no timer APIs, no callback analysis, no suspicious IAT entries |
| "Sleep obfuscation needs a long sleep duration to be effective" | This binary uses 50ms cycles (150ms total) for demonstration. In production, 30-60 second cycles maximize the encrypted-sleep window. But even short cycles prove the concept: the payload is encrypted for 100% of the sleep duration, however brief |
| "opt-level doesn't affect AV detection" | Switching from opt-level="z" (size-optimized) to opt-level=2 (speed-optimized) killed CrowdStrike win/malicious_confidence_60%. Different optimization levels produce different instruction patterns, register allocation, and code layout. ML byte-pattern classifiers trained on one pattern miss the other |
| "The same XOR key for encrypt and decrypt is a weakness" | XOR being its own inverse (plaintext ^ key = ciphertext, ciphertext ^ key = plaintext) is a FEATURE for sleep obfuscation, not a bug. It means the same simple for-loop handles both directions — half the code, half the detection surface. The goal is not cryptographic strength but memory scanner evasion |
| "VirtualProtect cycling is always detectable via ETW" | ETW correlation requires the defender to monitor Microsoft-Windows-Threat-Intelligence (admin-only), correlate VirtualProtect calls on the same region within a time window, and distinguish from legitimate patterns (JIT compilers cycle RW/RX constantly). Short 50ms cycles are especially hard to catch with periodic ETW consumers |

### What Breaks at Stage 14 — The Bridge

Stages 01-13 demonstrate individual techniques in isolation. Stage 14 (combined-loader) merges ALL techniques into a single binary: XOR encryption, API hashing, process injection, earlybird APC, direct/indirect syscalls, anti-debug, anti-sandbox, module stomping, and sleep obfuscation.

The critical lesson: combining techniques INCREASES code mass, which pushes ML classifiers over detection thresholds. The combined-loader's full_install() persistence code (5 modules, ~124KB) caused 2/76 detections. Removing it restored 0/76. Aggregate offensive code mass is itself a signature.

### MITRE ATT&CK Mapping

| Technique | ID | How It's Used |
|-----------|----|---------------|
| Encrypted/Encoded File | T1027.013 | Dual-key XOR encryption (on-disk + sleep obfuscation) |
| Time Based Evasion | T1497.003 | Sleep cycles with encrypted payload (50ms per cycle) |
| Process Injection | T1055 | VirtualAlloc + memcpy + VirtualProtect + CreateThread |
| Virtualization/Sandbox Evasion: System Checks | T1497.001 | CPU, RAM, disk, uptime, screen scoring (Gate 7) |
| Debugger Evasion | T1622 | PEB + NtQIP + RDTSC + hardware breakpoint detection (Gate 5) |
| Dynamic API Resolution | T1027.007 | 7 apihash calls (5 injection + 2 ExitProcess) |
| Masquerading | T1036 | Window class "PwrMgrWnd", trace prefix "pwrmgr_" |

### Further Reading (2025-2026)

**Sleep obfuscation implementations:**
- [Cobalt Strike 4.11 Sleepmask (May 2025)](https://www.cobaltstrike.com/blog) — Ekko/Zilean timer-based sleep obfuscation with stack spoofing
- [OLDBOY21 SWAPPALA (2025)](https://github.com/OLDBOY21/SWAPPALA) — Nt* API-based sleep obfuscation with APC wake-up callbacks
- [ShellcodeFluctuation](https://github.com/mgeeky/ShellcodeFluctuation) — Original shellcode fluctuation concept by mgeeky
- [Ekko Sleep Obfuscation](https://github.com/Cracked5pider/Ekko) — Timer-based sleep obfuscation reference implementation

**Detection and counter-techniques:**
- [felixm.pw: Rude Awakening (2025)](https://felixm.pw) — TTTracer and Time Travel Debugging unmasking sleep-obfuscated payloads
- [0xHossam: EDR Evasion Part 4 (2025)](https://0xhossam.github.io) — Sleep obfuscation + stack spoofing + heap encryption against CrowdStrike/SentinelOne

**Stack spoofing (next evolution):**
- [ThreadStackSpoofer](https://github.com/mgeeky/ThreadStackSpoofer) — Call stack spoofing during sleep to defeat stack-walking detections
- [Foliage](https://github.com/SecIdiot/FOLIAGE) — Advanced sleep obfuscation using APC for clean call stack

---

## Lab Environment Notes

### Required Setup

- Windows 10/11 VM with:
  - Rust toolchain (stable-x86_64-pc-windows-msvc)
  - x64dbg with conditional breakpoints
  - Process Hacker 2 (for memory region inspection)
  - PE-bear (for PE structure analysis)

### Experiment: Observe the XOR Sleep Cycling

1. Build crate 13: `cargo build --release -p sleep-obfuscation`
2. Apply PE patches: `python tools/pe_patch.py`
3. In x64dbg, set breakpoint on `VirtualProtect` (or the apihash-resolved address)
4. Run and observe the permission cycling: `0x20 -> 0x04 -> 0x20 -> 0x04 -> ...`
5. During a "sleeping" phase (after RX->RW + XOR), dump the payload region — verify it's encrypted
6. During an "active" phase (after XOR + RW->RX), dump it again — verify it's decrypted shellcode
7. Compare the entropy values of both dumps
8. Check `%TEMP%` for breadcrumb files: `pwrmgr_1_start.txt` through `pwrmgr_8_done.txt`
