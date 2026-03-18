# Safety Rules — Malware Development Workflow

## The Golden Rule
**WRITE code on your host. EXECUTE only in VMs.**

Compilation is safe. `cargo build --release` produces a PE file — the compiler does NOT
execute shellcode during compilation. The danger is ONLY in running the binary.

## Development Workflow

```
HOST (safe)                          VM (dangerous)
───────────────────────────────────  ──────────────────────────────
1. Write / edit Rust code            4. Revert VM to clean snapshot
2. cargo build --release             5. Transfer .exe via host-only net
3. Copy .exe to payloads/            6. Run with Defender + Sysmon ON
                                     7. Analyze detection / logs
                                     8. Revert VM again
```

## VM Setup Checklist

- [ ] Windows 10/11 VM (VMware or VirtualBox)
- [ ] Host-only networking (isolate from internet)
- [ ] Take clean snapshot BEFORE any testing
- [ ] Windows Defender enabled (test real AV)
- [ ] Sysmon installed + logging (observe EDR telemetry)
- [ ] Process Monitor available (API call tracing)
- [ ] x64dbg available (debugging)
- [ ] PE-bear / PE-sieve available (binary analysis)

## What is SAFE on host

- Writing Rust / Python code
- Running `cargo build --release`
- Running `cargo clippy`
- Running Python tools (encrypt, format, hash)
- Running the C2 server (it's just an HTTP listener)
- Analyzing PE files with `strings`, `dumpbin`, PE tools

## What is DANGEROUS (VM ONLY)

- Executing ANY compiled .exe from crates/
- Running shellcode in any form
- Testing against live AV/EDR
- Network beaconing to C2

## Shellcode Safety

All examples ship with **calc.exe shellcode** as the default payload.
This is harmless — it pops a calculator window.

To make operational:
1. Generate shellcode in ATTACKER VM: `msfvenom -p windows/x64/shell_reverse_tcp ...`
2. Encrypt with tools/shellcode_encrypt.py
3. Replace byte array in Rust source
4. Recompile
5. Test in VICTIM VM only

## Emergency

If you accidentally run a binary on your host:
1. Don't panic — default payload is calc.exe
2. Check Task Manager for unexpected processes
3. If using real shellcode: disconnect from network immediately
4. Run full AV scan
5. Consider reimaging if real payload was executed
