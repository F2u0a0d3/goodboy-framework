# Module 14: The Combined Loader — Orchestrating a Multi-Phase Attack Chain

## Module Metadata

| Field | Value |
|---|---|
| **Topic** | Combined Evasion Chain / Operational Loader Architecture |
| **Difficulty** | Expert |
| **Duration** | 4-6 hours |
| **Prerequisites** | All previous modules (01-13) |
| **Tools Required** | Ghidra/IDA, x64dbg with ScyllaHide, Process Monitor, API Monitor, Wireshark |
| **MITRE ATT&CK** | T1055.001, T1027, T1027.013, T1497, T1562.001, T1574.002, T1622 |
| **Binary** | `combined-loader.exe` (~335KB, Rust, PE64, uses common library) |

### Key Evasion Lesson

```
 This binary carries the MOST offensive code mass in the project — 7 phases,
 MBA XOR key derivation, module stomping with 4-DLL fallback, user interaction
 gate, ETW/AMSI bypass, anti-disassembly barriers. This density creates the
 highest aggregate ML classifier signal.

 The full_install() persistence code was removed — 5 persistence modules
 (registry + schtask + startup + COM hijack + WMI) added ~124KB of offensive
 code that pushed ML classifiers over detection thresholds. Less code = fewer
 ML features = better evasion.
```

---

## Why This Stage Exists — The Bridge from Stage 13

Stage 13 (sleep obfuscation) solved a single problem: encrypting the payload during sleep to evade memory scanners. But each stage so far demonstrates one technique in isolation. Real-world implants need ALL of them working together — and that combination creates new problems.

**What broke after Stage 13:**
- Individual techniques work in isolation but their **ordering** matters in combination — anti-debug before sandbox detection wastes noisy operations if the environment is already automated
- Each evasion module adds code mass that ML classifiers aggregate — the sum exceeds individual thresholds
- Key material scattered across 8 functions needs a combination scheme (MBA XOR) that resists both YARA rules and decompiler simplification
- Module stomping requires a fallback chain (4 DLLs) because any single DLL might not be loadable in the target environment

**What this stage adds:**
1. **Multi-phase kill chain** — 7 sequential phases with silent-exit gates at every step
2. **MBA XOR key derivation** — arithmetic replacement for bitwise XOR that defeats instruction-pattern matching
3. **Hex-encoded ciphertext** — entropy reduction from ~7.3 to ~4.0 to evade entropy-based heuristics
4. **User interaction gate** — mouse clicks + window switches + browser presence (triple anti-sandbox)
5. **Phase ordering discipline** — cheap checks first, irreversible actions last
6. **Evasion module pruning** — deliberate removal of iat_pad, ballast, full_install() to stay below ML thresholds

### Real-World Context (2025-2026)

- **Alpha Hunt: Modular C2 Frameworks** — Modern frameworks (Havoc, Mythic, Sliver) all use multi-phase loaders with configurable gate ordering
- **WindShock: Endpoint Evasion Evolution 2020-2025** — Documents the progression from single-technique to multi-phase evasion chains in the wild
- **Altered Security CETP** ([March 2026](https://www.alteredsecurity.com/evasionlab)) — Multi-phase evasion chain construction as a core certification competency
- **Cobalt Strike 4.11** (May 2025) — Introduced Sleepmask V3 + indirect syscalls, demonstrating that even commercial C2 frameworks now chain multiple evasion layers

---

## Learning Objectives

By the end of this module, you will be able to:

1. Analyze a multi-phase loader that chains 10+ evasion techniques
2. Reconstruct an obfuscated key derivation scheme using MBA encoding
3. Map execution phases to MITRE ATT&CK techniques
4. Identify user interaction triggers and explain their anti-sandbox value
5. Design detection rules for multi-phase execution patterns
6. Evaluate the operational strengths and weaknesses of combined evasion chains

---

## Section 1: Architecture Overview — Why Combine Techniques?

### The Layered Defense Problem

Individual evasion techniques each have known detections:

```
Single-Technique Detection:
┌──────────────────────┬────────────────────────────┐
│ Technique            │ Detection                  │
├──────────────────────┼────────────────────────────┤
│ AES decryption       │ Crypto API patterns         │
│ Anti-debug           │ PEB check hooking           │
│ Sandbox detection    │ Hook sandbox APIs            │
│ AMSI bypass          │ AMSI tamper detection        │
│ Module stomping      │ .text hash comparison        │
│ Registry persistence │ Sysmon Event 13             │
└──────────────────────┴────────────────────────────┘
```

But combining them creates multiplicative complexity for defenders:

```
Combined Chain:
  Analyst must bypass ALL gates to reach the payload.
  Each gate has different detection/bypass requirements.
  Missing even one gate = silent exit, no observable behavior.

  Phase 0 ──▶ Phase 1 ──▶ Phase 1.5 ──▶ Phase 2 ──▶ Phase 3 ──▶ Phase 4 ──▶ Phase 5
  Integrity   Env Check   User Input   ETW/AMSI    Decoy       Decrypt      Stomp
  │           │           │            │           │           │            │
  ▼           ▼           ▼            ▼           ▼           ▼            ▼
  EXIT        EXIT        EXIT         (continue)  (continue)  EXIT         Execute
  on fail     on fail     on fail      on fail     on fail     on fail      payload
```

An analyst who patches the anti-debug but doesn't simulate user interaction will never reach the payload. A sandbox that fast-forwards time but doesn't open a browser will stall at Phase 1.5. This is **defense in depth for offense**.

<details>
<summary>Discussion: Does combining techniques always improve evasion?</summary>

Not always. More code means:
- **Larger binary** — more surface for signature-based detection
- **More API calls** — larger IAT, more behavioral indicators
- **More failure modes** — any bug in any phase kills the entire chain
- **Longer execution time** — more time for real-time EDR to intervene

The art is in balancing thoroughness with minimalism. This combined loader demonstrates a key OPSEC lesson: evasion modules themselves can become detection surface. The `iat_pad`, `ballast`, and `full_install()` persistence modules were deliberately removed because their aggregate code mass pushed ML classifiers over detection thresholds. The current build works because:
1. Each remaining technique serves a distinct purpose (no redundancy)
2. Anti-disassembly between phases impedes static analysis
3. Failure is always silent (return, not crash)
4. ML-harmful modules are excluded to keep the offensive code ratio below classifier thresholds

The overhead is justified when the target environment has multiple security layers (EDR + AMSI + sandbox + SOC analysts).
</details>

---

## Section 2: Phase 0 — Self-Protection

### Integrity Verification

Before any evasion check, the binary verifies its own code hasn't been modified:

```
detect_software_breakpoints(main as *const u8, 64):

  For each byte in main[0..64]:
    if byte == 0xCC:    ← int3 (software breakpoint)
      return true       ← TAMPERED
  return false          ← CLEAN
```

This detects the most common dynamic analysis technique: setting breakpoints on `main()`. If an analyst sets even one int3 breakpoint in the first 64 bytes, the binary silently exits.

### Singleton via Named Mutex

```
acquire_mutex("Global\\WinSecHealthMtx_38f2a"):
  CreateMutexW(name)
  if GetLastError() == ERROR_ALREADY_EXISTS(183):
    return false  ← Another instance running, exit
  return true     ← We're the only instance
```

Prevents multiple instances from interfering and creating detectable noise.

### Persistence Check (Install Disabled)

```
is_installed():
  Check if SystemSoundsService.exe exists at expected install path
  Returns true/false — result is discarded (no action taken)
```

The `full_install()` function (registry Run key, scheduled task, startup folder, COM hijack, WMI event subscription) exists in the common library but is **not called** in this binary. The 5 persistence modules add ~124KB of offensive code patterns — registry manipulation, COM object creation, WMI subscription logic — that push ML classifiers (Google, Varist) over their detection thresholds.

This is a deliberate OPSEC trade-off: persistence increases survivability but also increases detection surface. The install check remains as a conditional placeholder for deployment scenarios where persistence is worth the ML risk.

**Exercise 2.1:** The `full_install()` function exists in the common library but was deliberately excluded from the combined loader. What specific ML detection risks do persistence modules create, and when might an operator accept those risks?

<details>
<summary>Answer</summary>

Persistence modules create multiple ML signals:
1. **Code mass** — 5 persistence methods (registry, schtask, startup, COM, WMI) add ~124KB of code that shifts the benign-to-offensive code ratio
2. **API patterns** — RegSetValueExW, CreateScheduledTask, IWbemServices COM calls are heavily weighted by ML classifiers
3. **String signatures** — Registry paths like `Software\Microsoft\Windows\CurrentVersion\Run` and task XML templates are well-known IOCs
4. **Cumulative effect** — Each method is individually low-signal, but 5 methods together push aggregate ML confidence past thresholds

An operator might accept these risks when:
- The target has active EDR that would terminate the process on reboot without persistence
- Long-term access justifies the increased detection probability
- The binary will be re-obfuscated per-engagement (not a static build)
- The target's AV doesn't use the specific ML classifiers affected
</details>

---

## Section 3: Phase 1 — Three-Layer Environment Validation

### Execution Flow

```
Phase 1 Defense-in-Depth:

  ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
  │  initial_delay() │────▶│ inline sandbox check│────▶│bail_if_debugged()│
  │                 │     │                 │     │                 │
  │ Timing gate:    │     │ 3 inline hardware checks (CPU, RAM, uptime):      │     │ 7 checks:       │
  │ Sleep to evade  │     │ CPU, RAM, Disk,  │     │ PEB, NtGlobalFlag│
  │ sandbox timeout │     │ Uptime, Username,│     │ NtQIP ×3, RDTSC │
  │                 │     │ ComputerName,    │     │ DR0-DR3         │
  │                 │     │ Screen, MAC, VM  │     │                 │
  │                 │     │ registry, VM     │     │                 │
  │                 │     │ files, processes,│     │                 │
  │                 │     │ analysis procs,  │     │                 │
  │                 │     │ sleep accel,     │     │                 │
  │                 │     │ cursor, recent   │     │                 │
  └─────────────────┘     │ Score ≥ 3 → EXIT │     │ Any true → EXIT  │
                          └─────────────────┘     └────────┬────────┘
                                                           │
                                                           ▼
                                                  ┌─────────────────┐
                                                  │check_analysis_  │
                                                  │tools()          │
                                                  │                 │
                                                  │ 27 tool names   │
                                                  │ Process enum    │
                                                  │ Found → EXIT    │
                                                  └─────────────────┘
```

### Noise Between Checks

Between each validation step, the binary inserts:
- `junk_computation()` — meaningless math operations
- `timing_gate()` — RDTSC-based timing check as additional anti-debug
- `antidisasm::opaque_jmp()` — confuses linear disassembly
- `dead_branch_noise()` — unreachable code paths that waste static analysis time

Note: `iat_pad::noise()` (benign Win32 API calls to pad behavioral profile) was deliberately removed — IAT padding modules inflate the binary's offensive code footprint and trigger ML classifiers (Agent.ION signature). The remaining noise techniques achieve time separation and anti-analysis without contributing to detection signatures.

<details>
<summary>Discussion: Why run sandbox checks BEFORE anti-debug checks?</summary>

Ordering matters:
1. **initial_delay()** first — if the sandbox has a time limit (common: 60-120s), the delay might cause it to timeout before reaching any detection-worthy code
2. **Sandbox checks** second — sandbox environments are the most common automated analysis target. Exiting early in a sandbox wastes the least amount of the binary's evasion budget
3. **Anti-debug** third — debuggers are used by analysts who already bypassed sandboxing. These are more targeted, so they run after the broader sandbox gate
4. **Analysis tools** last — checking running processes is the noisiest operation (CreateToolhelp32Snapshot). It should run only after confirming we're not in a sandbox or debugger

Each check is progressively more specific and more detectable, so ordering from least to most intrusive makes operational sense.
</details>

---

## Section 4: Phase 1.5 — The User Interaction Gate

### Why User Interaction Matters

This is the single most effective anti-sandbox technique in the chain:

```
TriggerConfig:
  min_clicks:          3    ← At least 3 mouse button presses
  min_window_switches: 2    ← At least 2 foreground window changes
  require_browser:     true ← A browser process must be running
  poll_interval_ms:    3000 ← Check every 3 seconds
  timeout_ms:          0    ← Wait forever (no timeout)
```

### What This Defeats

```
Analysis Environment          User Trigger Result
────────────────────────────  ──────────────────────
Automated sandbox (ANY.RUN)   ❌ No real clicks
API emulation sandbox         ❌ No window switches
Headless VM analysis          ❌ No browser process
Simple mouse jiggler          ❌ No window switches
AV detonation chamber         ❌ No user interaction
Debugger-only analysis        ❌ No background browser
Manual analyst (with VM)      ✅ Must actively use the VM
Real user machine             ✅ Natural interaction
```

### Polling Architecture

```
wait_for_human(&config):
  loop:
    clicks = count_mouse_clicks()       ← GetAsyncKeyState(VK_LBUTTON)
    switches = count_window_switches()  ← GetForegroundWindow() changes
    browser = is_browser_running()      ← Process scan for chrome/firefox/edge

    if clicks >= 3 AND switches >= 2 AND browser_running:
      return true  ← Human confirmed

    Sleep(3000)  ← Wait 3 seconds between polls
```

**Exercise 4.1:** Design a bypass for this trigger using Windows API calls. Your script needs to generate real mouse click events AND switch foreground windows AND have a browser running.

<details>
<summary>Hint</summary>

```python
import subprocess
import time
import ctypes

# Start a browser
subprocess.Popen(["C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "--headless"])

# Generate mouse clicks via SendInput
user32 = ctypes.windll.user32
for _ in range(5):
    user32.mouse_event(0x02, 0, 0, 0, 0)  # MOUSEEVENTF_LEFTDOWN
    user32.mouse_event(0x04, 0, 0, 0, 0)  # MOUSEEVENTF_LEFTUP
    time.sleep(0.5)

# Switch windows
user32.keybd_event(0x09, 0, 0, 0)     # VK_TAB down
user32.keybd_event(0x12, 0, 0, 0)     # VK_MENU (Alt) down
time.sleep(0.1)
user32.keybd_event(0x09, 0, 2, 0)     # VK_TAB up
user32.keybd_event(0x12, 0, 2, 0)     # VK_MENU up
```

Note: `--headless` Chrome might not satisfy the process name check depending on implementation. A fully visible browser is more reliable.
</details>

---

## Section 5: Key Derivation — Split Keys and MBA Encoding

### Why Not a Simple Key Constant?

A hardcoded 32-byte key in `.rdata` is trivially extractable:
```
strings malware.exe | xxd → key visible
YARA rule: { DE AD BE EF CA FE BA BE ... } → instant match
```

The combined loader uses three layers of obfuscation:

### Layer 1: Key Fragments in Benign Functions

```
8 functions with innocuous names:
  get_locale_info()   → 8 bytes of key material
  get_display_mode()  → 8 bytes of key material
  get_timezone_data() → 8 bytes of key material
  get_font_metrics()  → 8 bytes of key material
  get_dpi_setting()   → 8 bytes of key material (second array)
  get_color_profile() → 8 bytes of key material
  get_sound_level()   → 8 bytes of key material
  get_power_state()   → 8 bytes of key material
```

Each function uses `core::hint::black_box()` to prevent the compiler from inlining or constant-folding the values. In the compiled binary, these appear as 8 separate small functions returning byte arrays — not a single key constant.

### Layer 2: MBA XOR Combination

The two 32-byte arrays are combined using **Mixed Boolean-Arithmetic** XOR:

```
// Standard XOR:
key[i] = a[i] ^ b[i]

// MBA XOR (equivalent result, different instruction pattern):
fn mba_xor(x: u32, y: u32) -> u32 {
    // (x | y) - (x & y)  ← Arithmetic equivalent of XOR
    // Or: (x + y) - 2 * (x & y)
    // Or other arithmetic decompositions
}
```

MBA encoding replaces bitwise operations with arithmetic sequences. A YARA rule looking for XOR instructions won't find them — the XOR is computed using ADD, SUB, AND, OR.

### Layer 3: Hex-Encoded Ciphertext

```
Raw binary ciphertext:   entropy ≈ 7.3 (suspicious — encrypted data)
Hex string ciphertext:   entropy ≈ 4.0 (normal — looks like ASCII text)

"b07dbf8970e22eba5a7f..." → stored as a &str in .rdata
```

Hex encoding doubles the size but halves the entropy, avoiding entropy-based heuristics that flag high-entropy regions as encrypted payloads.

```
Decode Pipeline:
  .rdata hex string → decode_hex() → raw ciphertext → aes::decrypt(key) → shellcode
```

<details>
<summary>Discussion: Can MBA XOR be automatically reversed by decompilers?</summary>

Modern decompilers (Ghidra, IDA Hex-Rays) can sometimes simplify MBA expressions back to their bitwise equivalents through constant propagation and algebraic simplification. However:

1. **Complex MBA expressions** with more terms resist simplification: `(x + y) - 2*(x&y) + ((~x)&y - (~y)&x + x - y) * 0` — the zero-multiplied term confuses some decompilers
2. **Black box hints** prevent compile-time optimization, ensuring the MBA runs at runtime
3. **Multiple MBA variants** per byte operation make pattern matching unreliable

In practice, an analyst can still recover the key by:
- Dynamic analysis: break after `derive_key()`, dump the return value
- Symbolic execution: trace the data flow to collapse the MBA
- Manual analysis: recognize the MBA pattern and compute offline

MBA raises the analysis cost but doesn't prevent key recovery. It's a time-wasting technique, not a cryptographic guarantee.
</details>

---

## Section 6: The Complete Kill Chain

### MITRE ATT&CK Mapping

```
Phase 0:                              Phase 1:
├─ T1480    Execution Guardrails      ├─ T1497.001 System Checks (sandbox)
├─ T1106    Native API (mutex)        ├─ T1622    Debugger Evasion
└─ T1518    Software Discovery        ├─ T1057    Process Discovery
   (install check only)              │
                                     Phase 1.5:
                                     └─ T1497.002 User Activity Check

Phase 2:                              Phase 3:
├─ T1562.001 Disable ETW             └─ T1036    Masquerading (decoy ops)
└─ T1562.001 Disable AMSI

Phase 4:                              Phase 5:
├─ T1140    Deobfuscate/Decode        ├─ T1574.001 DLL Stomping
├─ T1027.013 Encrypted Payload        └─ T1055.001 DLL Injection
└─ T1027.009 Embedded Payloads
```

### Execution Timeline

```
Time ──────────────────────────────────────────────────────────▶
│P0│   │P1│      │P1.5│              │P2│ │P3│ │P4│ │P5│
│In│   │En│      │User│              │ET│ │De│ │De│ │St│
│te│   │v │      │Trig│              │W/│ │co│ │cr│ │om│
│gr│   │Ch│      │    │              │AM│ │y │ │pt│ │p │
│  │   │  │      │Wait│              │SI│ │  │ │  │ │  │
│~1│   │~3│      │∞   │              │~1│ │~2│ │~1│ │~1│
│ms│   │s │      │    │              │ms│ │s │ │ms│ │ms│
└──┘   └──┘      └────┘              └──┘ └──┘ └──┘ └──┘
  ▲      ▲         ▲                  ▲    ▲    ▲    ▲
  │      │         │                  │    │    │    └─ Module stomp
  │      │         │                  │    │    └─ MBA key → AES decrypt
  │      │         │                  │    └─ Fake API activity
  │      │         │                  └─ HW breakpoints on ETW/AMSI
  │      │         └─ Blocks until 3 clicks + 2 switches + browser
  │      └─ Sandbox(15) + Debug(7) + Tools(27)
  └─ Breakpoint scan + mutex + install check
```

---

## Section 7: Detection Engineering for Combined Loaders

### Challenges for Defenders

Combined loaders are hard to detect because:
1. **No single IOC** — each technique generates weak signals
2. **Phase gating** — sandbox analysis sees only Phase 0-1 behavior
3. **Timing separation** — phases spread across time, complicating correlation
4. **Anti-analysis** — breakpoint detection and anti-disassembly impede RE

### Detection Strategy: Behavioral Correlation

Instead of detecting individual techniques, correlate behaviors across time:

```yaml
title: Multi-Phase Loader Behavioral Pattern
id: 9c4d5e6f-0123-4567-89ab-cdef01234567
status: experimental
description: Detects combined loader pattern — mutex + env checks + security bypass + DLL stomp in sequence
logsource:
    category: process_creation
    product: windows
detection:
    phase0_mutex:
        EventID: 1
        CommandLine|contains: 'Global\\'
    phase1_process_enum:
        EventID: 1
        SourceImage|endswith: '.exe'
        CallTrace|contains: 'CreateToolhelp32Snapshot'
    phase2_amsi:
        EventID: 10  # Process access
        TargetImage|endswith: '\amsi.dll'
    phase5_stomp:
        EventID: 7   # Image load
        ImageLoaded|endswith: '\amsi.dll'
    timeframe: 120s
    condition: phase0_mutex and phase1_process_enum and (phase2_amsi or phase5_stomp)
level: critical
tags:
    - attack.execution
    - attack.defense_evasion
```

### YARA Rule: Combined Loader Indicators

```yara
rule Combined_Loader_Multi_Phase
{
    meta:
        description = "Detects multi-phase combined loader with key splitting and module stomping"
        severity = "critical"

    strings:
        // MBA XOR pattern (arithmetic instead of bitwise)
        $mba_or_sub = { 09 ?? 29 }  // OR + SUB sequence

        // Multiple black_box hints (key fragment functions)
        $black_box = { E8 ?? ?? ?? ?? [0-4] 48 89 }  // call + mov pattern ×8

        // Hex decode loop pattern
        $hex_decode = { 30 39 [2-8] 61 66 }  // '0'-'9' range check + 'a'-'f'

        // Module stomp DLL names (obfuscated)
        $amsi = "amsi" ascii nocase
        $dbghelp = "dbghelp" ascii nocase
        $mstscax = "mstscax" ascii nocase

        // Anti-disassembly barriers
        $junk_a = { EB ?? [2-4] E8 ?? ?? ?? ?? }  // JMP over + CALL dead code

        // TriggerConfig-like structure
        $trigger = { 03 00 00 00 [0-8] 02 00 00 00 }  // min_clicks=3, min_switches=2

    condition:
        uint16(0) == 0x5A4D and
        #$black_box >= 4 and
        $hex_decode and
        2 of ($amsi, $dbghelp, $mstscax) and
        $junk_a
}
```

<details>
<summary>Discussion: What is the most reliable single detection for this combined loader?</summary>

The **user interaction trigger** is actually the loader's fingerprint, not its strength:

A process that:
1. Loads amsi.dll (Image Load event)
2. Never calls AmsiInitialize or AmsiScanBuffer
3. Shortly after calls VirtualProtect on amsi.dll's .text section

...is almost certainly a module stomper targeting AMSI. This behavioral pattern is rare in legitimate software and highly specific to this attack chain.

Combined with the process having:
- Created a named mutex with "Global\\" prefix
- Enumerated running processes (CreateToolhelp32Snapshot)
- Loaded amsi.dll without calling exports

...the correlation provides a high-confidence detection with very low false positive rate.
</details>

---

## Section 8: Summary and Kill Chain Assessment

### Technique Inventory

| Phase | Techniques Used | ATT&CK | Purpose |
|---|---|---|---|
| 0 | Breakpoint detection, Mutex, Install check | T1480, T1106 | Self-protection + singleton |
| 1 | 3 inline sandbox checks (CPU, RAM, uptime), 7 debug checks, 27 tool names | T1497, T1622 | Environment validation |
| 1.5 | Mouse clicks, window switches, browser check | T1497.002 | Human presence verification |
| 2 | ETW HW breakpoint, AMSI HW breakpoint | T1562.001 | Security tool neutralization |
| 3 | Decoy API calls | T1036 | Behavioral mimicry |
| 4 | 8-function key split, MBA XOR, hex decode, AES | T1027, T1140 | Payload recovery |
| 5 | Module stomp × 4 DLLs, restore | T1574, T1055 | Stealth execution |
| All | Anti-disassembly, junk code, control flow | T1027.002 | Analysis impediment |

### Key Takeaways

```
┌─────────────────────────────────────────────────────────┐
│ Combined Loader Architecture Principles                  │
├─────────────────────────────────────────────────────────┤
│                                                         │
│ 1. PHASE GATING                                        │
│    Every phase is a gate — failure = silent exit         │
│    No error messages, no crashes, just return            │
│    Analyst must pass ALL gates to see the payload        │
│                                                         │
│ 2. TECHNIQUE ORDERING MATTERS                          │
│    Cheap checks first (mutex, breakpoints)              │
│    Broad checks next (sandbox — defeats automation)     │
│    Specific checks after (anti-debug — defeats analysts)│
│    Irreversible actions last (persistence, execution)   │
│                                                         │
│ 3. NOISE BETWEEN SIGNALS                               │
│    Anti-disassembly between every phase                 │
│    Junk computation to waste analyst time               │
│    Dead branch noise to confuse static analysis         │
│    Decoy operations to mask intent                      │
│                                                         │
│ 4. KEY SECURITY IS LAYERED                             │
│    Not just encrypted — key itself is obfuscated        │
│    8 fragment functions → 2 arrays → MBA XOR → key      │
│    black_box prevents compiler optimization             │
│    MBA prevents XOR instruction pattern matching        │
│                                                         │
│ 5. GRACEFUL DEGRADATION                                │
│    Module stomp: 4-DLL fallback chain                   │
│    Install check without install (ML-safe by default)   │
│    Every critical operation has an alternative path     │
│                                                         │
│ 6. DETECTION REQUIRES CORRELATION                      │
│    No single IOC identifies this loader                 │
│    Behavioral correlation across time is needed         │
│    Mutex + EnvCheck + ProcessEnum + DLL stomp = sig     │
│    Phase 1.5 is the weakest link (must interact)        │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## Section 9: Source Code Deep Dive

### Multi-Phase Execution Architecture

The combined loader chains 6 sequential phases (0 through 5), each acting as a gate. Failure at any phase causes a silent return — no error message, no crash, no observable behavior for defenders. This is the key architectural principle: an analyst must pass ALL gates to observe the payload.

```
Phase 0: Integrity + Singleton
  ├─ detect_software_breakpoints(main as *const u8, 64)
  │    Scan first 64 bytes of main() for 0xCC (int3).
  │    If found → silent return (analyst set a breakpoint)
  │
  ├─ acquire_mutex("Global\\WinSecHealthMtx_38f2a")
  │    CreateMutexW → if ERROR_ALREADY_EXISTS → return
  │    Prevents multiple instances creating detection noise
  │
  └─ is_installed() → check only, result discarded
       full_install() is NOT called — saves ~124KB of offensive code

Phase 1: Environment Validation + Benign Preflight
  ├─ initial_delay()
  │    RDTSC-based sleep → evade sandbox time limits
  │
  ├─ inline sandbox check
  │    3 inline hardware checks (CPU cores < 2, RAM < 4GB, uptime < 30min).
  │    computer name patterns, screen resolution, MAC address,
  │    VM registry keys, VM files, VM processes, analysis processes,
  │    sleep acceleration, cursor movement, recent files
  │    Score >= 3 → ExitProcess via apihash
  │
  ├─ bail_if_debugged()
  │    7 checks: PEB.BeingDebugged, NtGlobalFlag, NtQueryInformationProcess
  │    (ProcessDebugPort, ProcessDebugObjectHandle, ProcessDebugFlags),
  │    RDTSC timing, hardware breakpoints (DR0-DR3)
  │    Any positive → ExitProcess via apihash
  │
  └─ check_analysis_tools()
       CreateToolhelp32Snapshot → Process32FirstW/NextW
       27 tool names: x64dbg, ollydbg, procmon, wireshark, ida, ghidra...
       Any found → ExitProcess via apihash

Phase 1.5: User Interaction Gate
  └─ wait_for_human(TriggerConfig)
       Poll every 3 seconds:
         - GetAsyncKeyState(VK_LBUTTON) → count clicks (need 3+)
         - GetForegroundWindow() → track changes (need 2+ switches)
         - CreateToolhelp32Snapshot → check for browser PIDs
       All three conditions met → proceed
       Timeout = 0 (wait forever) — binary hangs indefinitely in sandbox

Phase 2: Security Tool Neutralization
  ├─ Set hardware breakpoint on EtwEventWrite
  │    DR0 = address of ntdll!EtwEventWrite
  │    SetThreadContext with DR7 enabled
  │    ETW events silently fail (breakpoint causes early return)
  │
  └─ Set hardware breakpoint on AmsiScanBuffer
       DR1 = address of amsi!AmsiScanBuffer
       AMSI scans return S_OK without scanning
       No bytes patched — hardware breakpoints are invisible to integrity checks

Phase 3: Decoy Operations
  └─ Series of benign API calls that mimic legitimate application behavior
       GetComputerNameW, GetUserNameW, GetVersionExW, GetSystemInfo...
       Generates normal-looking behavioral telemetry in EDR logs
       Buys time and adds noise between sensitive phases

Phase 4: Decrypt Payload
  ├─ MBA-encoded key derivation:
  │    8 fragment functions → two 32-byte arrays
  │    mba_xor(a[i], b[i]) → final 32-byte AES key
  │    MBA: (x | y) - (x & y) instead of x ^ y
  │
  ├─ Hex decode ciphertext:
  │    .rdata hex string → raw bytes
  │    Entropy drops from ~7.3 to ~4.0 (defeats heuristics)
  │
  └─ AES decrypt:
       aes::decrypt(ciphertext, derived_key) → plaintext shellcode
       If decryption fails → silent return (wrong key = wrong binary)

Phase 5: Module Stomping Execution
  ├─ Try 4 sacrificial DLLs in order:
  │    1. amsi.dll  (also disables AMSI as side effect)
  │    2. dbghelp.dll
  │    3. mstscax.dll
  │    4. clbcatq.dll
  │    First successful LoadLibraryA wins
  │
  ├─ Inline PE parsing → locate .text + entry point
  ├─ VirtualProtect(RW) → copy shellcode → VirtualProtect(RX)
  ├─ CreateThread at CFG-valid entry point
  ├─ WaitForSingleObject
  │
  └─ Restore original bytes at entry point (cleanup)
       Unlike Stage 12 (which leaves the stomp), the combined loader
       restores the DLL's original code after execution.
```

### Why Removing full_install() Saved 124KB and Killed Google+Varist ML

```
Binary size comparison:
  With full_install():     ~483KB
  Without full_install():  ~359KB
  Difference:              ~124KB of offensive code removed

What full_install() pulled in:
  1. Registry persistence:  RegOpenKeyExW, RegSetValueExW, key path strings
  2. Scheduled task:        COM interfaces (ITaskService, ITaskFolder, IRegistrationInfo)
  3. Startup folder:        SHGetFolderPathW, CopyFileW, startup path strings
  4. COM hijack:            Registry manipulation for InprocServer32 keys
  5. WMI subscription:      IWbemLocator, IWbemServices, WQL query strings

Each module individually scores below ML thresholds. But the aggregate 124KB
of offensive code patterns (registry manipulation + COM + WMI + task scheduling
+ file copying) pushed Google and Varist ML classifiers past their confidence
threshold. The classifiers work on total code mass, not individual techniques.

The fix: remove the full_install() call but keep is_installed() check.
Binary: 483KB → 359KB. Removing persistence killed both ML detections.
```

This is the most important evasion lesson in the entire framework: **subtraction beats addition**. Every offensive module you add contributes to the aggregate ML score. When in doubt, remove code.

### YARA Rule: MBA XOR Key Derivation Pattern

```yara
rule Combined_Loader_MBA_Key_Derivation
{
    meta:
        description = "Detects MBA XOR key derivation with scattered fragment functions"
        author = "Goodboy Course"
        stage = "14"

    strings:
        // 8 black_box'd byte array returns (fragment pattern)
        $bb = { 48 8D 05 ?? ?? ?? ?? 48 89 ?? 24 }  // LEA + MOV to stack
        // MBA XOR: (x | y) - (x & y) pattern
        $mba_or  = { 09 }    // OR instruction
        $mba_and = { 21 }    // AND instruction
        $mba_sub = { 29 }    // SUB instruction
        // AES decrypt call (common library)
        $aes = "aes" ascii
        // Hex decode loop pattern
        $hex_a = { 61 }  // 'a' for hex digit
        $hex_f = { 66 }  // 'f' for hex digit

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        #bb > 6 and
        $mba_or and $mba_and and $mba_sub
}
```

### Python Script: Multi-Phase Loader Analyzer

```python
#!/usr/bin/env python3
"""Analyze a combined loader PE for multi-phase attack chain indicators.
Detects: MBA patterns, hex-encoded payloads, scattered key fragments, module stomp targets."""

import struct, sys, os, re

def read_pe_imports(path):
    with open(path, "rb") as f:
        data = f.read()
    if data[:2] != b"MZ":
        return [], data
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew+4] != b"PE\x00\x00":
        return [], data
    import_rva = struct.unpack_from("<I", data, e_lfanew + 0x90)[0]
    num_sec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    sec_off = e_lfanew + 24 + opt_size
    def rva_to_off(rva):
        for i in range(num_sec):
            s = sec_off + i * 40
            va = struct.unpack_from("<I", data, s + 12)[0]
            vs = struct.unpack_from("<I", data, s + 8)[0]
            raw = struct.unpack_from("<I", data, s + 20)[0]
            if va <= rva < va + vs:
                return rva - va + raw
        return None
    imports = []
    off = rva_to_off(import_rva)
    if off is None:
        return imports, data
    while True:
        ilt_rva = struct.unpack_from("<I", data, off)[0]
        name_rva = struct.unpack_from("<I", data, off + 12)[0]
        if ilt_rva == 0 and name_rva == 0:
            break
        dll_off = rva_to_off(name_rva)
        dll = data[dll_off:data.index(b"\x00", dll_off)].decode("ascii", errors="replace") if dll_off else "?"
        ilt_off = rva_to_off(ilt_rva)
        if ilt_off:
            while True:
                entry = struct.unpack_from("<Q", data, ilt_off)[0]
                if entry == 0: break
                if not (entry >> 63):
                    hint_off = rva_to_off(entry & 0x7FFFFFFF)
                    if hint_off:
                        name = data[hint_off+2:data.index(b"\x00", hint_off+2)].decode("ascii", errors="replace")
                        imports.append((dll.lower(), name))
                ilt_off += 8
        off += 20
    return imports, data

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <combined-loader.exe>")
    sys.exit(1)

imports, data = read_pe_imports(sys.argv[1])
func_names = {name for _, name in imports}

print(f"Multi-Phase Loader Analysis: {os.path.basename(sys.argv[1])}")
print(f"Size: {len(data):,d} bytes | Imports: {len(imports)} functions")
print("=" * 60)

# Phase indicators
phases = {
    "Phase 0 (Integrity)": ["CreateMutexW", "CreateMutexA"],
    "Phase 1 (Sandbox)": ["GetSystemInfo", "GlobalMemoryStatusEx", "GetTickCount64"],
    "Phase 1 (Anti-Debug)": ["NtQueryInformationProcess", "GetThreadContext"],
    "Phase 1.5 (User Trigger)": ["GetForegroundWindow", "GetWindowTextW"],
    "Phase 2 (ETW/AMSI)": ["EtwEventWrite", "AmsiScanBuffer"],
    "Phase 3 (Decoy)": ["GetDesktopWindow", "GetSystemTimeAsFileTime"],
    "Phase 5 (Stomp)": ["LoadLibraryA", "VirtualProtect"],
}

for phase, apis in phases.items():
    found = [a for a in apis if a in func_names]
    indicator = "\033[91m[FOUND]\033[0m" if found else "       "
    print(f"  {indicator} {phase}: {', '.join(found) if found else 'not in IAT (may use apihash)'}")

# Check for hex-encoded payload in .rdata
hex_pattern = re.compile(rb'[0-9a-f]{100,}')
matches = hex_pattern.findall(data)
long_hex = [m for m in matches if len(m) > 200]
if long_hex:
    print(f"\n  \033[91m[HEX PAYLOAD]\033[0m {len(long_hex)} hex-encoded blob(s) found")
    for h in long_hex[:3]:
        decoded_len = len(h) // 2
        print(f"    Length: {len(h)} hex chars = {decoded_len} decoded bytes")
else:
    print(f"\n  No hex-encoded payloads found")

# Check for MBA XOR pattern (scattered black_box arrays)
bb_count = data.count(b"\x48\x8d\x05")  # LEA rax, [rip+disp]
print(f"\n  LEA rip-relative instructions: {bb_count} (>20 suggests scattered data fragments)")

# Module stomp DLL targets
for dll in [b"amsi.dll", b"dbghelp.dll", b"mstscax.dll", b"clbcatq.dll"]:
    if dll in data:
        print(f"  \033[93m[STOMP TARGET]\033[0m {dll.decode()} found in binary")

print(f"\n  Verdict: ", end="")
if long_hex and bb_count > 20:
    print("\033[91mMulti-phase combined loader with MBA key derivation + hex-encoded payload\033[0m")
elif long_hex:
    print("\033[93mHex-encoded payload present — possible staged loader\033[0m")
else:
    print("\033[92mNo strong combined loader indicators\033[0m")
```

### Python Script: MBA XOR Key Extractor (dynamic)

```python
#!/usr/bin/env python3
"""Extract the AES key from a running combined-loader process.
Targets the derive_key() return value by scanning for 32-byte high-entropy regions
on the stack near known fragment function return addresses."""

import ctypes
import ctypes.wintypes as wt
import math, sys, os

kernel32 = ctypes.windll.kernel32

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

def read_memory(handle, address, size):
    buf = (ctypes.c_ubyte * size)()
    read = ctypes.c_size_t()
    ok = kernel32.ReadProcessMemory(handle, address, buf, size, ctypes.byref(read))
    return bytes(buf[:read.value]) if ok else None

def entropy(data):
    if not data: return 0.0
    freq = [0]*256
    for b in data: freq[b] += 1
    return -sum(f/len(data)*math.log2(f/len(data)) for f in freq if f)

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <pid>")
    print(f"  Attach to the combined-loader process after it passes Phase 4")
    print(f"  The 32-byte AES key exists briefly on the stack after derive_key()")
    sys.exit(1)

pid = int(sys.argv[1])
handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
if not handle:
    print(f"Failed to open PID {pid}")
    sys.exit(1)

print(f"Scanning PID {pid} for 32-byte high-entropy regions (potential AES key)...")

# Scan stack region (typically 0x00000000`00100000 - 0x00000000`00800000)
# and heap regions for 32-byte key candidates
candidates = []
for base_addr in range(0x100000, 0x800000, 0x1000):
    data = read_memory(handle, base_addr, 4096)
    if not data or len(data) < 4096:
        continue
    # Scan for 32-byte windows with high entropy
    for off in range(0, len(data) - 32, 8):
        chunk = data[off:off+32]
        ent = entropy(chunk)
        if 6.5 < ent < 8.0:  # Key-like entropy (not random, not plaintext)
            candidates.append((base_addr + off, chunk, ent))

kernel32.CloseHandle(handle)

if candidates:
    print(f"\n{len(candidates)} candidate 32-byte regions found:")
    for addr, chunk, ent in candidates[:10]:
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        print(f"  0x{addr:08X}: entropy={ent:.2f}")
        print(f"    {hex_str}")
    print(f"\n  Try each candidate as AES-256 key against the hex-encoded ciphertext")
else:
    print("  No high-entropy 32-byte regions found (key may have been zeroed)")
```

### Python Script: Hex Payload Decoder

```python
#!/usr/bin/env python3
"""Extract and decode hex-encoded payloads from PE .rdata section.
Detects the Stage 14 pattern: long hex strings storing AES ciphertext."""

import struct, sys, os, re, math

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <combined-loader.exe>")
    sys.exit(1)

with open(sys.argv[1], "rb") as f:
    data = f.read()

# Find .rdata section
e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
num_sec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
sec_off = e_lfanew + 24 + opt_size

rdata = None
rdata_off = 0
for i in range(num_sec):
    s = sec_off + i * 40
    name = data[s:s+8].rstrip(b"\x00")
    if name == b".rdata":
        rdata_off = struct.unpack_from("<I", data, s + 20)[0]
        rdata_sz = struct.unpack_from("<I", data, s + 16)[0]
        rdata = data[rdata_off:rdata_off + rdata_sz]
        break

if rdata is None:
    print("No .rdata section found")
    sys.exit(1)

print(f"Scanning .rdata ({len(rdata):,d} bytes) for hex-encoded payloads...")

# Find long hex strings (>100 chars of [0-9a-f])
hex_pattern = re.compile(rb'([0-9a-f]{100,})')
matches = list(hex_pattern.finditer(rdata))

print(f"Found {len(matches)} hex blob(s)\n")

for i, m in enumerate(matches):
    hex_str = m.group(1)
    offset = rdata_off + m.start()
    decoded = bytes(int(hex_str[j:j+2], 16) for j in range(0, len(hex_str), 2))
    ent = -sum(f/len(decoded)*math.log2(f/len(decoded))
               for f in [decoded.count(bytes([b])) for b in range(256)] if f) if decoded else 0

    print(f"Blob {i+1}:")
    print(f"  File offset: 0x{offset:X}")
    print(f"  Hex length:  {len(hex_str)} chars")
    print(f"  Decoded:     {len(decoded)} bytes")
    print(f"  Entropy:     {ent:.4f}")
    print(f"  First 16:    {' '.join(f'{b:02x}' for b in decoded[:16])}")
    print(f"  Last 16:     {' '.join(f'{b:02x}' for b in decoded[-16:])}")

    if ent > 7.0:
        print(f"  \033[91m[ENCRYPTED]\033[0m High entropy — likely AES/RC4 ciphertext")
    elif ent > 5.0:
        print(f"  \033[93m[ENCODED]\033[0m Medium entropy — possibly compressed or encoded")
    else:
        print(f"  \033[92m[PLAINTEXT]\033[0m Low entropy")

    # Check for AES block alignment (16-byte blocks)
    if len(decoded) % 16 == 0:
        print(f"  \033[93m[AES-ALIGNED]\033[0m Length is multiple of 16 (AES block size)")
    print()
```

### Section 7B: Defense Hardening — Detecting Multi-Phase Loaders

```
Layer 1: Sysmon + ETW Correlation (real-time)
  ☐ Event 1 (Process Create): flag unsigned binaries from non-standard paths
  ☐ Event 7 (Image Load): alert on LoadLibraryA for amsi.dll, dbghelp.dll, clbcatq.dll by non-standard processes
  ☐ ETW: Microsoft-Windows-Threat-Intelligence for AMSI/ETW tampering detection
  ☐ Correlate: CreateMutex → sandbox check APIs → anti-debug → DLL load → VirtualProtect within 10s

Layer 2: AMSI/ETW Tamper Detection (critical)
  ☐ Monitor for hardware breakpoints on AmsiScanBuffer / EtwEventWrite
  ☐ Periodic AMSI integrity check: call AmsiScanBuffer with known-malicious EICAR string
  ☐ ETW consumer validation: verify NtTraceControl returns expected values
  ☐ Alert on: AMSI returning AMSI_RESULT_CLEAN for known-bad content

Layer 3: Memory Forensics (periodic)
  ☐ pe-sieve: scan ALL loaded DLLs for .text section modifications
  ☐ Focus on: amsi.dll, dbghelp.dll, mstscax.dll, clbcatq.dll — common stomp targets
  ☐ Entropy analysis on RW/RX private regions (MBA XOR output has distinctive patterns)
  ☐ Scan interval: every 30 seconds for high-value processes

Layer 4: Behavioral Chain Detection (EDR)
  ☐ Full kill chain rule: CreateMutex → GetSystemInfo+GlobalMemoryStatusEx (sandbox) →
    NtQueryInformationProcess (anti-debug) → GetForegroundWindow (user trigger) →
    LoadLibraryA (stomp) → VirtualProtect (permission change) → CreateThread
  ☐ Alert on: any binary executing this full sequence within 30 seconds
  ☐ ML feature: ratio of evasion APIs to total API calls (high ratio = suspicious)
```

### Exercise 3.1: Identify the MBA XOR Pattern in Ghidra

**Question**: Open combined-loader.exe in Ghidra. Find the `derive_key()` function. You'll see 8 calls to functions named like `get_locale_info`, `get_display_mode`, etc. Each returns an 8-byte array. Then there's a loop that combines two 32-byte arrays using `(x | y) - (x & y)`. What is this arithmetic equivalent to? Why use arithmetic instead of bitwise XOR?

<details>
<summary>Answer</summary>

`(x | y) - (x & y)` is mathematically identical to `x ^ y` (XOR). This is called **Mixed Boolean-Arithmetic (MBA)** obfuscation. The equivalence: `x XOR y = (x OR y) - (x AND y)` holds for all integer values.

**Why arithmetic?** Decompilers like Ghidra and IDA show the arithmetic form (`OR`, `SUB`, `AND`) rather than simplifying to `XOR`. An analyst scanning for XOR-based key derivation will see arithmetic operations and may not recognize the pattern. However, advanced analysts or SMT solvers (like z3) can prove the equivalence automatically.

The MBA obfuscation is **one layer** of key protection. The scattered 8-byte fragments (`get_locale_info`, etc.) are the other layer — the key never exists as a single 32-byte constant in `.rdata`.

</details>

### Exercise 3.2: Recover the AES Key via Dynamic Analysis

**Question**: Instead of reversing the MBA XOR pattern statically, set a breakpoint in x64dbg right after `derive_key()` returns. The 32-byte AES key is in a register or on the stack. What's the fastest way to extract it?

<details>
<summary>Answer</summary>

1. Find `derive_key` in Ghidra — it's `#[inline(never)]` so it's a distinct function
2. Note the return address (the instruction after the `call derive_key`)
3. In x64dbg, set a breakpoint at that return address
4. Run with ScyllaHide (to pass anti-debug gates)
5. When breakpoint hits: the 32-byte key is either in:
   - RAX (pointer to stack array) — dump 32 bytes at the pointed address
   - On the stack directly — examine RSP+offset

This is the **fundamental weakness** of all runtime key derivation: no matter how complex the derivation (MBA, PRNG, scattered fragments), the final key MUST exist in cleartext at the moment of use. A single breakpoint at the right location bypasses all obfuscation layers.

</details>

---

## Section 10: Adversarial Thinking

### Challenge 1: Analyst Patches Out Phase 0

**Scenario**: An analyst NOP-patches the breakpoint detection in Phase 0 (overwrites the `detect_software_breakpoints` call with NOPs). Which later phases still protect the payload?

<details>
<summary>Analysis</summary>

Every subsequent phase operates independently — patching Phase 0 doesn't disable any later gate:

- **Phase 1 (bail_if_sandbox)**: Still runs 3 inline sandbox checks (CPU, RAM, uptime). The analyst's VM must pass CPU, RAM, disk, uptime, screen, and other hardware fingerprints.
- **Phase 1 (bail_if_debugged)**: Still checks PEB.BeingDebugged, NtQueryInformationProcess debug ports, RDTSC timing, and hardware breakpoints. The analyst needs ScyllaHide or equivalent anti-anti-debug.
- **Phase 1 (check_analysis_tools)**: Still enumerates processes for 27 tool names. The analyst must rename or hide their tools.
- **Phase 1.5 (user interaction)**: Still requires 3 clicks + 2 window switches + browser. The analyst must script genuine user interaction. This is the hardest to simulate — most analysts skip it and wonder why the binary "does nothing."
- **Phase 2 (ETW/AMSI)**: Still sets hardware breakpoints on security functions. Proceeds regardless of Phase 0.
- **Phase 4 (key derivation + decryption)**: MBA XOR still obfuscates the key. The analyst must trace through 8 fragment functions + MBA combination to recover the AES key.

The user interaction gate (Phase 1.5) is typically the hardest for analysts to pass because it requires physical interaction with the VM rather than just patching bytes. An analyst who patches Phase 0 and Phase 1 but doesn't script mouse clicks and browser tab switches will stall indefinitely at Phase 1.5.
</details>

### Challenge 2: Defeating MBA Key Derivation with Symbolic Execution

**Scenario**: The MBA expressions use `(x | y) - (x & y)` instead of `x ^ y`. A symbolic execution engine (angr) can simplify these back to XOR. How do you make MBA expressions resistant to symbolic simplification?

<details>
<summary>Hardening approaches</summary>

1. **Add opaque predicates**: Insert conditions that are always true/false but can't be statically determined:
   ```
   let z = if rdtsc() > 0 { mba_xor(a, b) } else { 0xFF };
   ```
   `rdtsc() > 0` is always true at runtime, but a symbolic engine must explore both branches. The false branch introduces a fake key value that wastes solver time.

2. **Use lookup tables**: Replace the arithmetic MBA with a 256-entry lookup table:
   ```
   static MBA_TABLE: [[u8; 256]; 256] = /* precomputed a ^ b for all a,b */;
   key[i] = MBA_TABLE[a[i] as usize][b[i] as usize];
   ```
   The table is functionally a XOR table, but symbolic engines can't simplify a 64KB table lookup into a single XOR without recognizing the pattern. Add a few corrupted entries (with compensating corrections later) to break pattern matching.

3. **Chain multiple MBA layers**: Instead of one MBA operation, compose several:
   ```
   let t1 = (x + y) - 2 * (x & y);           // MBA XOR layer 1
   let t2 = (t1 | z) - (t1 & z);              // MBA XOR layer 2
   let t3 = (!(!t2 | !w) | !(!t2 | w));       // MBA XOR layer 3 (De Morgan)
   ```
   Each layer is individually simplifiable, but the composition creates a deeper expression tree that exponentially increases solver time.

4. **Runtime-dependent terms**: Add terms that evaluate to zero at runtime but are symbolically opaque:
   ```
   let noise = (GetCurrentProcessId() * 0) as u8;  // Always 0
   key[i] = mba_xor(a[i], b[i]) + noise;
   ```
   The symbolic engine must reason about `GetCurrentProcessId()` (potentially any value) and can't simplify the addition away.

In practice, MBA is a time-wasting technique, not a cryptographic guarantee. The goal is to cost the analyst 30-60 minutes of reversing, not infinity. Dynamic analysis (breakpoint after `derive_key()`, dump RAX) always wins against any static obfuscation.
</details>

### Challenge 3: Reducing the Detection Count

**Scenario**: The combined loader triggers more ML classifiers than any other stage due to aggregate code mass. Based on the empirical evasion data, what specific changes would reduce detections?

<details>
<summary>Analysis based on project data</summary>

The persistent detections are:
- ESET Agent.ION (sample-burned — created from repeated VT submissions)
- Bkav AI (ML reclassification)
- DeepInstinct (ML reclassification)
- AVG MalwareX-gen (ML reclassification)
- Avast MalwareX-gen (ML reclassification)

**ESET Agent.ION**: This is a burned signature from March 1-9 VT submissions. The only fix is a new binary hash — which means substantive code changes, not just PE metadata patches. Changing cipher type, hash algorithm, or IAT entries does NOT break it (per MEMORY.md).

**Bkav AI / DeepInstinct / AVG / Avast**: These are ML classifiers that respond to aggregate code mass. Potential reductions:
1. **Eliminate common library dependency entirely** (the nuclear option that worked for c2-agent, Stage 15). Inline only the code actually needed — no shared offensive library.
2. **Remove the 4-DLL fallback chain for module stomping** — a binary that loads amsi.dll + dbghelp.dll + mstscax.dll + clbcatq.dll has four LoadLibraryA strings and the associated DLL selection logic. Use a single DLL.
3. **Remove Phase 1.5 user interaction code** — the polling loop, GetAsyncKeyState, GetForegroundWindow, browser PID enumeration add code mass that ML classifiers weight.

**The hard truth**: Repeated submissions to scanning services train AV ML models against your binary. A production approach would be to never submit the operational binary — test evasion on isolated AV instances instead. This is the price of public ML training through repeated submission.
</details>

---

## Section 11: Dynamic Analysis Walkthrough

### Full 5-Pass Analysis Strategy

**Pass 1: Unmodified — observe bail-out behavior**

Run the binary in a monitored sandbox (Procmon + Sysmon + Wireshark). It will exit silently at Phase 1 (sandbox checks) or Phase 1.5 (no user interaction). Check:
- Procmon: What registry/file/process operations occurred before exit?
- Sysmon Event 1: Process creation with command line
- Sysmon Event 7: Were any DLLs loaded? (No — it exits before Phase 5)
- %TEMP%: Check for breadcrumb files — they show how far execution reached

**Pass 2: Bypass Phase 0 — NOP breakpoint check**

In x64dbg, find the `detect_software_breakpoints` call (search for `0xCC` comparison loop in the first function after main's prologue). NOP the entire call. The binary now survives Phase 0 but still exits at Phase 1 sandbox checks.

**Pass 3: Bypass Phase 1 — ScyllaHide + hardware**

Use ScyllaHide to defeat anti-debug checks. Run on real hardware (or a VM with 4+ cores, 8GB+ RAM, 100GB+ disk). Ensure no analysis tools are visible in the process list. The binary reaches Phase 1.5 and hangs — waiting for user interaction.

**Pass 4: Bypass Phase 1.5 — script interaction**

While the binary is waiting at Phase 1.5, run a script:
```python
# Generate clicks, switch windows, ensure browser is running
import ctypes, subprocess, time
subprocess.Popen(["C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"])
time.sleep(3)
user32 = ctypes.windll.user32
for _ in range(5):
    user32.mouse_event(0x02, 0, 0, 0, 0)
    user32.mouse_event(0x04, 0, 0, 0, 0)
    time.sleep(0.3)
    user32.keybd_event(0x12, 0, 0, 0)  # Alt down
    user32.keybd_event(0x09, 0, 0, 0)  # Tab down
    time.sleep(0.1)
    user32.keybd_event(0x09, 0, 2, 0)  # Tab up
    user32.keybd_event(0x12, 0, 2, 0)  # Alt up
    time.sleep(1)
```

The binary passes Phase 1.5 and proceeds through Phases 2-5.

**Pass 5: Key extraction — breakpoint after derive_key()**

Set a hardware breakpoint (NOT software — Phase 0 checks for 0xCC) after the `derive_key()` function returns. Dump the 32-byte AES key from the return register/stack. With the key, decrypt the hex-encoded ciphertext offline to recover the shellcode without needing to let Phase 5 execute.

### Further Reading

- [Malware Development Lifecycle](https://www.cobaltstrike.com/blog/cobalt-strike-4-0-threat-emulation-for-the-red-team-operator/) — How C2 frameworks evolve
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) — Visualize technique coverage
- [Elastic Security Research](https://www.elastic.co/security-labs) — Multi-technique detection
- [Practical Malware Analysis](https://nostarch.com/malware) — Foundation text for binary analysis

---

## Lab Environment Notes

### Required Setup

- Windows 10/11 VM with:
  - All tools from previous modules
  - ScyllaHide (anti-anti-debug plugin for x64dbg)
  - API Monitor (API call tracing)
  - Process Monitor (file/registry monitoring)
  - Sysmon with SwiftOnSecurity config (event logging)
  - A web browser installed and running

### Analysis Strategy

1. **First pass**: Run in monitored sandbox, observe which phase it exits at
2. **Second pass**: Bypass Phase 0 (NOP breakpoint check), observe Phase 1 behavior
3. **Third pass**: Use ScyllaHide for Phase 1, script mouse/keyboard for Phase 1.5
4. **Fourth pass**: Full bypass — set breakpoint after `derive_key()` to dump key
5. **Final pass**: Extract decrypted shellcode before module stomping

---

### Common Misconceptions

| What People Believe | What's Actually True |
|--------------------|----------------------|
| "More evasion techniques = better evasion" | Each evasion module adds code mass that ML classifiers aggregate. The combined loader's detections dropped significantly only AFTER removing iat_pad, ballast, and full_install() — three evasion/persistence modules whose aggregate ~124KB of offensive code pushed classifiers OVER thresholds. Less can be more |
| "MBA XOR is unbreakable obfuscation" | MBA replaces `x ^ y` with arithmetic equivalents like `(x \| y) - (x & y)`. Ghidra and IDA Hex-Rays can sometimes simplify these back to XOR through algebraic optimization. MBA is a time-wasting technique — it raises the cost of static analysis by 10-30 minutes, not infinity. A dynamic analyst can dump the key after `derive_key()` returns |
| "Module stomping requires zeroing the .text section" | The Goodboy combined loader does NOT zero .text before overwriting. Zeroing creates a detectable anomaly (a DLL with blank .text). Instead, it overwrites directly — the module's original code is replaced, and the PE header's AddressOfEntryPoint provides a CFG-valid entry point for CreateThread |
| "User interaction gates are bypass-proof" | SendInput/mouse_event can generate synthetic clicks. Alt+Tab can be scripted. A browser can be launched headless. The gate raises the cost from "zero effort" (automated sandbox) to "moderate effort" (analyst scripts the interaction). Advanced sandboxes like ANY.RUN already allow human-in-the-loop interaction |
| "Hex encoding is just for transport safety" | Hex encoding serves a dual purpose. Yes, it prevents binary corruption in HTTP text bodies. But critically, it halves entropy from ~7.3 (encrypted data, flagged by heuristics) to ~4.0 (normal ASCII range). Entropy-based heuristics in EDR and AV classify high-entropy regions as encrypted/packed payloads — hex encoding defeats this classification |
| "Phase ordering doesn't matter if all checks pass" | Ordering determines what an analyst or sandbox SEES before the binary exits. Cheap, fast, quiet checks first (breakpoint scan, mutex) mean a sandbox timeout reveals nothing. If you put the noisy CreateToolhelp32Snapshot process enumeration first, the sandbox captures that behavior before it times out — giving defenders IOCs even from failed analysis |

### What Breaks at Stage 15 — The Bridge

The combined loader executes shellcode and exits. Stage 15 transforms this one-shot loader into a **persistent operational implant** — a C2 agent that:

1. **Runs indefinitely** with a beacon loop (not single execution)
2. **Communicates** with a C2 server over encrypted HTTPS
3. **Receives commands** and reports results (shell, upload, download, persist, selfdestruct)
4. **Adapts** via server-controlled sleep interval and jitter

But the biggest evasion lesson from Stage 15 is architectural: the common library dependency itself became the detection vector. The `common` crate's AES implementation, MBA XOR, and 8 hardcoded key fragment functions created a GenKryptik signature (ESET). The fix was the **nuclear option** — eliminating the common library entirely and making the c2-agent fully self-contained.

Stage 15 also introduces the **browser-gate** and **tab-activity gate** — a triple sandbox/NDR bypass that waits for genuine human browser tab switching before initiating any network activity.

### MITRE ATT&CK Mapping

| Technique | ID | How It's Used |
|-----------|----|---------------|
| Execution Guardrails | T1480 | Phase 0: breakpoint scan, mutex, install check — binary gates execution on environment conditions |
| Native API | T1106 | CreateMutexW for singleton, CreateToolhelp32Snapshot for process enum |
| Virtualization/Sandbox Evasion: System Checks | T1497.001 | Phase 1: 3 inline sandbox checks (CPU, RAM, uptime) (CPU, RAM, disk, uptime, screen, username, etc.) |
| Virtualization/Sandbox Evasion: User Activity | T1497.002 | Phase 1.5: mouse clicks, window switches, browser presence |
| Debugger Evasion | T1622 | Phase 1: PEB, NtGlobalFlag, NtQueryInformationProcess, RDTSC, DR0-DR3 |
| Process Discovery | T1057 | Phase 1: 27 analysis tool names via CreateToolhelp32Snapshot |
| Disable or Modify Tools | T1562.001 | Phase 2: ETW and AMSI bypass via hardware breakpoints |
| Masquerading | T1036 | Phase 3: decoy API calls to mimic benign software behavior |
| Deobfuscate/Decode Files or Information | T1140 | Phase 4: hex decode + AES decrypt + MBA XOR key derivation |
| Obfuscated Files or Information: Encrypted/Encoded File | T1027.013 | Phase 4: hex-encoded AES ciphertext in .rdata |
| Obfuscated Files or Information: Embedded Payloads | T1027.009 | Shellcode embedded as hex string constant |
| DLL Side-Loading | T1574.002 | Phase 5: LoadLibraryA sacrificial DLL for module stomping |
| Process Injection: DLL Injection | T1055.001 | Phase 5: shellcode written into loaded DLL .text section |
| Software Packing | T1027.002 | Anti-disassembly barriers, junk computation, dead branch noise between phases |

### Further Reading (2025-2026)

**Multi-phase loader architecture:**
- [Alpha Hunt: Modular C2 Frameworks 2025-2026](https://alphahunt.io/) — Analysis of real-world modular loaders used by APT groups
- [WindShock: Endpoint Evasion Evolution 2020-2025](https://windshock.github.io/en/post/2025-05-28-endpoint-security-evasion-techniques-20202025/) — How multi-phase chains evolved to defeat EDR

**MBA obfuscation:**
- [Quarkslab: MBA Obfuscation](https://blog.quarkslab.com/what-theoretical-tools-are-needed-to-simplify-mba-expressions.html) — Theoretical foundations for Mixed Boolean-Arithmetic
- [Ninon Eyrolles: Obfuscation with MBA (Thesis)](https://tel.archives-ouvertes.fr/tel-01623849/document) — Academic treatment of MBA in software protection

**Module stomping and code injection:**
- [Fortra/Cobalt Strike 4.11 Release Notes](https://www.cobaltstrike.com/blog/) — Indirect syscalls + Sleepmask V3 (May 2025)
- [Altered Security CETP](https://www.alteredsecurity.com/evasionlab) — Module stomping and DLL hollowing as assessment competencies (March 2026)

**Detection engineering:**
- [Elastic Security Labs: Multi-Technique Detection](https://www.elastic.co/security-labs) — Behavioral correlation across time for multi-phase loaders
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) — Visualize technique coverage across kill chain phases
- [CrowdStrike EMBER2024](https://www.crowdstrike.com/en-us/blog/ember-2024-advancing-cybersecurity-ml-training-on-evasive-malware/) — ML training on evasive malware with aggregate code mass analysis
