# Stage 15: C2 Agent — Full Operational Command-and-Control Implant

> **WARNING: This binary is a fully functional, undetectable (0/71 VT) C2 agent.** It executes shell commands, reads/writes files, and enumerates processes. Use ONLY in isolated VMs for authorized security education and research. Unauthorized deployment violates computer fraud laws (CFAA, CMA, StGB 202a-c). The authors assume no liability for misuse.

> Part of the **Goodboy Framework** — a 15-stage progressive Windows malware development & analysis course written in Rust.

## What This Is

The **INSANE** capstone stage — a fully operational C2 agent with encrypted HTTP beaconing via raw TcpStream, 9 commands, and a triple sandbox bypass:

```
Startup:
  4 benign framework modules   Pull in std::net, std::sync, std::thread
  GetTickCount startup delay   5-15 second anti-sandbox window
  wait_for_user_activity()     Blocks until 3 unique browser tab switches observed

Beacon Loop:
  if browser_active:
    XOR encrypt check-in -> hex encode -> HTTP POST /api/v1/telemetry
    Receive encrypted command -> XOR decrypt -> execute -> queue result
  else:
    Silent skip (no failure count)
  Sleep(jittered 42-78s)

Exits when:
  "x" (quit) command received -> exit(0)
  10 consecutive beacon failures (dead-man switch)
```

This binary demonstrates the **ultimate evasion lesson**: eliminating shared offensive code entirely (the "nuclear option") produces cleaner results than adding more evasion modules.

---

## What You'll Learn

| Red Team | Blue Team |
|----------|-----------|
| C2 beacon loop with jitter and dead-man switch | Beacon timing analysis (30% jitter detection) |
| XOR-encrypted comms over raw TcpStream | YARA rules for beacon + browser-gate patterns |
| No Windows HTTP APIs (pure std::net) | Sigma rules for periodic POST + process enumeration |
| Browser-gate triple sandbox bypass | Python mock C2 server + traffic decryptor |
| PRNG key derivation (zero .rdata footprint) | Beacon pattern detector script |
| Why LESS evasion code = BETTER evasion | 4-layer defense hardening guide |

---

## What's New vs Stage 14

| Concept | Stage 14 (Combined Loader) | Stage 15 (C2 Agent) |
|---------|---------------------------|---------------------|
| Architecture | Single execution (load + exit) | **Indefinite beacon loop** |
| Common library | Full dependency (all modules) | **Zero dependency (self-contained)** |
| Crypto | AES + MBA XOR key derivation | **XOR + arithmetic PRNG key** |
| Network | None | **Raw TcpStream HTTP POST (std::net)** |
| Commands | None (execute shellcode) | **9 commands (shell, upload, download, etc.)** |
| Sandbox bypass | User interaction (clicks + switches) | **Browser-gate + tab-activity gate (triple)** |
| Agent identity | None | **Custom hash of COMPUTERNAME + USERNAME** |
| Resilience | None (one-shot) | **Jitter, failure counting, dead-man switch** |

---

## Files

| File | Description |
|------|-------------|
| `LEARNING_PATH.md` | **1,676 lines** — 14 sections + lab notes: protocol deep dive, PE-level evasion, evasion campaign, blue team deep dive (Sysmon rules, memory forensics, Wireshark analysis, Splunk/KQL queries, IR playbook), 2 YARA rules, 3 Python scripts, 4 adversarial challenges, 4 blue team exercises |
| `c2-agent.exe` | The compiled binary (~660 KB, Rust, PE64, self-contained) — requires browser + tab switching to activate |

---

## Technical Details

| Property | Value |
|----------|-------|
| Language | Rust (NO common library — fully self-contained) |
| Binary Size | ~660 KB |
| Crypto | XOR with 32-byte PRNG-derived key |
| Key Derivation | LCG PRNG: seed 0x5A3CF7E1, mul 0x6C7AC8E3, add 0x4B2D9F71 |
| Protocol | HTTP POST via raw TcpStream to /api/v1/telemetry, hex-encoded XOR ciphertext |
| Content-Type | application/json |
| User-Agent | Chrome 131.0.0.0 |
| Agent ID | Custom hash(COMPUTERNAME + USERNAME), format: `{:08X}` |
| C2 Server | 127.0.0.1:8443 (localhost — use mock_c2.py to interact) |
| Beacon Interval | 60s base, +/-30% jitter (42-78s) |
| Dead-Man Switch | 10 consecutive failures -> graceful exit |
| Browser Gate | Requires browser PID + 3 unique foreground window titles |
| Commands | 9 via single-char codes: n(nop), s(shell), d(fetch), u(store), l(list), t(interval), x(quit), i(stub), r(stub) |
| Sandbox Bypass | Triple: browser-gate + tab-activity + startup delay |

---

## Course Progression

This is **Stage 15** of 15 — an **INSANE** stage and the **FINAL** capstone.

```
  EASY              MEDIUM            HARD              INSANE
  ............      ............      ............      ............
  Stage 01          Stage 04          Stage 07          Stage 14
  Stage 02          Stage 05          Stage 08          Stage 15 (this)
  Stage 03          Stage 06          Stage 09
                    Stage 11          Stage 10
                                      Stage 12
                                      Stage 13
```

---

## Safety

> **EDUCATIONAL USE ONLY**

- **C2 server**: 127.0.0.1 (localhost) — without mock_c2.py running, beacons fail and agent exits after ~10 minutes
- **Browser-gate**: Will block indefinitely without a running browser with tab switching activity
- **Persist/Uninstall**: Stub commands — no actual persistence is installed
- **SelfDestruct**: Just `exit(0)` — no file deletion, no cleanup
- **EXECUTE** only in isolated VMs with the mock C2 server

---

## About the Goodboy Framework

15-stage progressive Windows malware development & analysis course.

## License

Educational purposes only. Not for unauthorized access or operational deployment.

## Author

Built with Rust 1.93.1 MSVC | Tested against 76+ AV engines | March 2026
