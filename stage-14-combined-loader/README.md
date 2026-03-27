# Stage 14: Combined Loader — Multi-Phase Attack Chain Orchestration

> Part of the **Goodboy Framework** — a 15-stage progressive Windows malware development & analysis course written in Rust.

## What This Is

The **INSANE** capstone stage — every technique from Stages 01-13 combined into a single operational loader with 7 execution phases:

```
Phase 0: Integrity check → singleton mutex → persistence check
Phase 1: Sandbox bail → anti-debug (7 checks) → analysis tools (27 tools)
Phase 1.5: User interaction trigger (browser + mouse clicks + window switches)
Phase 2: ETW bypass + AMSI bypass (hardware breakpoint method)
Phase 3: Behavioral mimicry (decoy API calls)
Phase 4: MBA XOR key derivation (8 fragments) → AES decrypt → hex decode
Phase 5: Module stomping with 4-DLL fallback (amsi → dbghelp → mstscax → clbcatq)
```

This binary demonstrates the **maximum evasion surface** achievable — and teaches why **aggregate code mass becomes its own detection vector**.

---

## What You'll Learn

| Red Team | Blue Team |
|----------|-----------|
| Multi-phase attack chain orchestration | Full kill chain detection (7-phase behavioral rule) |
| MBA XOR obfuscation: `(x\|y)-(x&y)` = XOR | AMSI/ETW tamper detection strategies |
| User interaction trigger (defeats all sandboxes) | YARA rules for MBA patterns + hex payloads |
| ETW + AMSI bypass via hardware breakpoints | pe-sieve scanning for module stomping |
| Anti-disassembly barriers (6 techniques) | Python multi-phase loader analyzer |
| Why MORE evasion = WORSE detection scores | 4-layer defense hardening guide |

---

## What's New vs Stages 01-13

| Concept | Individual Stages | Stage 14 |
|---------|------------------|----------|
| Execution phases | 1-2 phases per stage | **7 phases in sequence** |
| Key derivation | XOR key as constant | **MBA XOR from 8 scattered fragment functions** |
| Payload encoding | Raw bytes or XOR | **Hex string (entropy ~4.0) + AES encryption** |
| Module stomping | Single DLL target | **4-DLL fallback chain** |
| User trigger | Not used | **Mouse clicks + browser + window switches** |
| Anti-disassembly | Not used | **6 barrier techniques throughout** |
| ETW/AMSI bypass | Not used | **Hardware breakpoint patching** |

---

## Files

| File | Description |
|------|-------------|
| `LEARNING_PATH.md` | **1,319 lines** — 7-phase architecture, MBA XOR deep dive, 2 YARA rules, Sigma rule, 3 Python scripts (multi-phase analyzer, MBA key extractor, hex payload decoder), defense hardening, 4 exercises, adversarial challenges |
| `combined-loader.exe` | The compiled binary (~335 KB, Rust, PE64) — requires browser + user interaction to proceed |

---

## Technical Details

| Property | Value |
|----------|-------|
| Language | Rust (uses full common library — all modules) |
| Phases | 7 sequential execution phases |
| Key Derivation | MBA XOR: 8 fragment functions → arithmetic combine → 32-byte AES key |
| Payload | AES-encrypted, hex-encoded (entropy ~4.0 in .rdata) |
| Injection | Module stomping with 4-DLL fallback (amsi, dbghelp, mstscax, clbcatq) |
| Anti-Debug | 7 checks + 27-tool process scan via common library |
| User Trigger | wait_for_human(): 3 mouse clicks + 2 window switches + browser running |
| ETW Bypass | Hardware breakpoint on EtwEventWrite |
| AMSI Bypass | Hardware breakpoint on AmsiScanBuffer |
| Anti-Disassembly | 6 techniques: junk computation, dead branches, opaque jumps, fake calls, timing gates |
| Binary Size | ~335 KB |

---

## Course Progression

This is **Stage 14** of 15 — an **INSANE** stage.

```
  EASY              MEDIUM            HARD              INSANE
  ............      ............      ............      ............
  Stage 01          Stage 04          Stage 07          Stage 14 (this)
  Stage 02          Stage 05          Stage 08          Stage 15
  Stage 03          Stage 06          Stage 09
                    Stage 11          Stage 10
                                      Stage 12
                                      Stage 13
```

---

## Safety

> **EDUCATIONAL USE ONLY**

- **Payload**: `MessageBox("GoodBoy")` — harmless
- **Requires**: Running browser + mouse activity to pass user trigger gate
- **EXECUTE** only in isolated VMs
- AMSI/ETW bypass is temporary (process-local, reverts on exit)

---

## About the Goodboy Framework

15-stage progressive Windows malware development & analysis course.

## License

Educational purposes only. Not for unauthorized access or operational deployment.

## Author

Built with Rust 1.93.1 MSVC | Tested against 76+ AV engines | March 2026
