# Stage 03: AES Loader + Jigsaw Encoding — Learning Path

## Module Metadata

| Field | Value |
|-------|-------|
| **Module Name** | Payload Fragmentation, Entropy Evasion, and PIC Shellcode |
| **Level** | Intermediate |
| **Estimated Time** | 6-8 hours |
| **Category** | Crypto / Anti-Analysis / Detection Engineering / Shellcode |
| **Platform** | Windows x64 |
| **Binary** | `aes-loader.exe` (~290KB, Rust, PE64) |
| **Prerequisites** | Stage 01 (loader pipeline, API hashing), Stage 02 (XOR crypto, entropy concepts) |
| **MITRE ATT&CK** | T1027, T1140, T1106, T1620 |
| **VT Score** | **0/76 → 5/76 → 3/76** (achieved 0/76 at R14, burned to 5/76 by March 9, currently 3/76 after hash algorithm tweak) |

### VT Detection Journey

```
 ██████████████████████████████████████ 0/76  ← ACHIEVED (R14, early March 2026)
 ███████████████████████████████████░░░ 5/76  ← BURNED   (March 9 — Agent.ION created)
 ████████████████████████████████████░░ 3/76  ← CURRENT  (March 17 — after opt-level fix)
                                               ESET Agent.ION (sample-burned)
                                               AVG MalwareX-gen [Misc] (ML)
                                               Avast MalwareX-gen [Misc] (= AVG)

 This was the FIRST Goodboy binary to demonstrate sample burning. It achieved 0/76,
 then ESET created Agent.ION specifically from the VT submissions between March 1-9.
 The 5→3 drop came from switching common library to opt-level=2 (killed 2 ML engines).

 KEY LESSON: aes-loader was the canary that revealed sample burning exists.
 The pattern then repeated across all 15 binaries. Once you submit, you can't unsubmit.
```

---

## Why This Stage Exists — The Bridge from Stage 02

In Stage 02, you broke XOR encryption three ways: known-plaintext (prologue recovery), IC analysis (key length detection), and entropy classification (cipher identification). All three attacks exploit XOR's fundamental weakness — each key byte operates independently.

**Stage 03 kills all three attacks simultaneously:**

```
Your Stage 02 Attack             Why It Fails on Stage 03
───────────────────────────────  ─────────────────────────────────────────
Known-plaintext (FC 48 → key)    RC4 keystream depends on ENTIRE key via KSA.
                                 Knowing plaintext byte i doesn't reveal key byte i.

IC key-length detection          RC4 output is pseudo-random — no repeating period.
                                 IC is flat regardless of key length.

Entropy classification           Jigsaw fragmentation normalizes entropy to ~6.0.
                                 Encrypted chunks hidden among English text padding.
```

But Stage 03 introduces TWO new attack surfaces:
1. **The permutation map** — a distinctive `[index, 0xFF..FF, index, 0xFF..FF]` pattern in .rdata that YARA can detect
2. **The crypto mislabeling trap** — the module is named "AES" but uses RC4. Analysts who assume AES waste time looking for S-boxes

This is the first stage where **multiple protection layers** work together (jigsaw + crypto). Later stages add more: anti-debug (Stage 09), anti-sandbox (Stage 10), sleep obfuscation (Stage 13). By Stage 14, eight layers are stacked.

### Real-World Context (2025-2026)

- **Qakbot** (2023-2025) — Used AES-encrypted payloads with fragmented delivery across multiple DLLs. Similar multi-layer approach: reassemble fragments → decrypt → execute
- **cocomelonc Cryptography Series** ([43 parts, 2023-2025](https://cocomelonc.github.io/malware/2023/08/13/malware-cryptography-1.html)) — Covers RC4, AES, ChaCha20, and custom cipher implementations in malware. Parts 20-43 cover exactly the kind of custom crypto envelope used here
- **EMBER2024** (KDD 2025) — CrowdStrike's ML training dataset now includes section-level entropy histograms as features. Jigsaw directly targets this: normalizing per-section entropy defeats the EMBER entropy feature
- **Goodboy Evasion Lesson** — The common library's RC4-based "AES" implementation was classified by ESET as `Agent_AGen.LEE` ("malware-grade crypto"). In later stages, this was replaced with simple XOR to kill the detection. Stage 03 is the LAST stage to use the full RC4 envelope — all subsequent stages use inline XOR

### Current VT Score: 0/76 → 5/76 → 3/76

This binary has the richest VT history of any Goodboy crate — it was the **canary** that revealed sample burning.

```
Timeline:
──────────────────────────────────────────────────────────────────────
Early Mar    R14    0/76    All clear. Jigsaw + RC4 + benign code = invisible.

Mar 1-9      ───    (submitted multiple Goodboy binaries to VT during R1-R14)
                    ESET ingests all submissions, identifies shared patterns
                    from common library, creates Agent.ION signature family.

Mar 9        ───    5/76    aes-loader BURNED. Agent.ION appears.
                            5 engines: ESET + 4 others (Fortinet, Google, etc.)
                            This was the first detection that couldn't be explained
                            by code quality — the binary hadn't changed.

Mar 12       R15    0/76    After applying evasion fixes to OTHER crates,
                            aes-loader was retested and achieved 0/76 again
                            (new binary hash from recompilation).

Mar 17       ───    3/76    Rebuilt with common opt-level=2 + tweaked hash.
                            ESET Agent.ION persists (generalized).
                            AVG/Avast MalwareX-gen [Misc] added (cross-sample ML).
──────────────────────────────────────────────────────────────────────
```

**Why this binary was the first to burn**: aes-loader uses the most complex crypto of Stages 01-03 (RC4 with custom envelope, FNV-1a variant integrity hash, nonce derivation). This code mass — 256-byte S-box initialization, KSA loop, PRGA keystream generation — is characteristic of "crypto loaders" and gave ESET's ML classifier strong signal. The simpler XOR-only loaders (Stages 01-02) had less distinctive code patterns and burned later.

**Additional lesson**: In later stages (07+), the RC4 implementation from `common::crypto::aes` was itself classified as `Agent_AGen.LEE` by ESET. The fix was replacing RC4 with simple inline XOR. This is why Stage 03 is the LAST stage to use the full RC4 envelope — it became a detection signal rather than an evasion tool.

```
ESET-NOD32:  Win64/Agent.ION trojan     ← sample-burned (common library + RC4 patterns)
AVG:         MalwareX-gen [Misc]         ← generic ML classifier
Avast:       MalwareX-gen [Misc]         ← same engine as AVG (Avast acquired AVG)
```

**VT URL**: `https://www.virustotal.com/gui/file/0bcdad5d21c7b63eaf322d635a741a037a7c12e583d985e43116f3e87b0f65b5`

---

## Prerequisites

Before starting this module, you should be comfortable with:
- XOR encryption/decryption from Stages 01-02 (multi-byte XOR, known-plaintext attacks)
- Shannon entropy concept from Stage 02 (bits per byte, 0.0-8.0 scale)
- Known-plaintext attacks and why they work against XOR (Stage 02)
- PE `.rdata` section navigation in a disassembler
- Python struct module for binary data parsing
- Basic x86-64 assembly reading (registers, memory operands, calling conventions)

**Software needed**:
- Ghidra 11.x (free) or IDA Free/Pro
- x64dbg + ScyllaHide plugin
- Python 3.10+ (on Windows for exercises)
- PE-bear or CFF Explorer
- CyberChef (entropy visualization plugin)
- Optional: binwalk (`pip install binwalk`)

---

## Learning Objectives

By the end of this module, you will be able to:

1. **Explain** why entropy-based malware detection works and how payload fragmentation defeats it
2. **Identify** permutation map arrays in `.rdata` by their distinctive integer pattern
3. **Implement** a jigsaw reassembly algorithm given a shuffled payload and permutation map
4. **Recognize** non-standard crypto implementations even when named after standard algorithms
5. **Disassemble** position-independent shellcode and annotate each instruction's purpose
6. **Explain** the forwarded export problem and why manual PE export walking can crash on kernel32
7. **Calculate** Shannon entropy before and after fragmentation to quantify the evasion effect
8. **Write** YARA rules that detect jigsaw-like fragmentation patterns
9. **Determine** execution stage reached via dynamic analysis when no filesystem artifacts exist
10. **Articulate** the difference between cryptographic protection and obfuscation layers

---

## Section 1: Theory — The Entropy Problem

### Why AV Engines Care About Entropy

Machine learning classifiers used by modern AV engines (CrowdStrike, Symantec, DeepInstinct) rely heavily on **section entropy** as a feature. The EMBER feature set (the industry-standard ML model for PE classification) includes:

| Feature | What It Measures | Malware Signal |
|---------|-----------------|----------------|
| `.text` entropy | Code section randomness | High = packed/encrypted code |
| `.rdata` entropy | Read-only data randomness | High = encrypted payload blob |
| `.rsrc` entropy | Resource section randomness | High = packed resources |
| Overall entropy | Whole binary randomness | High = likely packed/encrypted |
| Entropy histogram | Distribution across sections | Non-uniform = suspicious |

**The problem for attackers**: Strong encryption (AES, RC4, ChaCha20) produces output that is indistinguishable from random data — Shannon entropy approaches 8.0 bits/byte. A 318-byte encrypted blob in `.rdata` creates an "entropy island" that stands out against the surrounding 4.0-5.0 bits/byte text and structured data.

```
Entropy map of a typical malware binary:

     8.0 ┤
         │                ████                    ← encrypted payload blob
     7.0 ┤               █    █
         │
     6.0 ┤
         │  ████████                    ████████
     5.0 ┤ █        ████████████████████        █ ← normal .rdata content
         │█                                      █
     4.0 ┤                                        ███
         │
     3.0 ┤
         └──────────────────────────────────────────
          .text        .rdata          .data
```

### How Jigsaw Solves It

The jigsaw technique distributes encrypted data among normal-looking padding:

```
Entropy map AFTER jigsaw fragmentation:

     8.0 ┤
         │
     7.0 ┤
         │
     6.0 ┤
         │  ██  ██  ██  ██  ██  ██  ██  ██  ██
     5.0 ┤ █  ██  ██  ██  ██  ██  ██  ██  ██  ██
         │█    ↑    ↑    ↑    ↑    ↑    ↑    ↑   █
     4.0 ┤   pad  enc  pad  enc  pad  enc  pad    ← interleaved
         │
     3.0 ┤
         └──────────────────────────────────────────
                    .rdata (normalized)
```

By interleaving 64-byte encrypted chunks with 64-byte English text chunks, the average entropy per window drops to ~5.0-6.0 bits/byte — well within the "normal software" range. No entropy island, no ML flag.

### The Current Binary's Numbers

The actual aes-loader.exe payload:
- **Encrypted ciphertext**: 318 bytes (5 chunks × 64 bytes, last chunk padded with zeros)
- **Padding chunks**: 5 (English text sentences)
- **Total jigsaw payload**: 640 bytes (10 × 64)
- **Measured entropy**: ~6.4 bits/byte (the jigsaw output)
- **Entropy without jigsaw**: The raw 318-byte ciphertext would be ~7.4 bits/byte

### Discussion

> **Q1**: The jigsaw technique uses English text from a static pool of sentences as padding. What would happen if an AV vendor added these exact sentences to their YARA signatures?

<details>
<summary>Discussion Points</summary>

1. **Direct signature**: An AV rule matching "This application requires a valid license to opera" alongside high-entropy chunks would detect this specific implementation. However:
   - The padding pool is trivially replaceable — swap in different English text, random Wikipedia excerpts, or legitimate error messages from the target environment
   - The technique works with ANY low-entropy padding: null bytes, repeated patterns, structured data (XML, JSON), or even legitimate DLL resources
   - A smart attacker generates padding dynamically from locale-specific system resources

2. **Pattern-level detection**: Instead of matching specific strings, an AV could detect the PATTERN: alternating entropy levels at a fixed chunk size. This is harder to evade but requires more sophisticated analysis

3. **Arms race**: Each specific detection can be bypassed by changing the implementation, but the underlying TECHNIQUE (entropy normalization via padding) is a concept that can be detected structurally

</details>

> **Q2**: Why does the jigsaw technique use a FIXED chunk size (64 bytes) instead of variable-size chunks? What are the trade-offs?

<details>
<summary>Discussion Points</summary>

**Why fixed size**:
- Simplifies the permutation map — each entry maps to a fixed-offset position, no need to store chunk sizes
- Makes reassembly O(1) per chunk (direct index calculation: `position = index * chunk_size`)
- The padding chunks can be pre-generated at a fixed size without knowing the data

**Trade-offs of variable-size chunks**:
- **Advantages**: Harder to detect (no fixed-period pattern), better entropy distribution
- **Disadvantages**: Map must store both index AND size, reassembly requires sequential processing, larger and more distinctive map

**Detection implication**: A fixed chunk size creates a detectable periodic structure. A defender scanning `.rdata` at 64-byte windows and calculating per-window entropy would see alternating high/low values. Variable chunk sizes break this periodicity.

</details>

---

## Section 2: Static Analysis — Dissecting the Jigsaw

### Exercise 1: Entropy Mapping (15 min)

**Goal**: Visually confirm that the jigsaw technique normalizes the binary's entropy profile.

**Instructions**:
1. Open `aes-loader.exe` in Ghidra
2. Navigate to `Window → Entropy` and examine the `.rdata` section
3. Compare with `basic-loader.exe` (Stage 01) — look for entropy islands

**Alternative using Python**:
```python
#!/usr/bin/env python3
"""Calculate sliding-window entropy across a PE section."""
import math
import sys

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    return -sum(
        (c / length) * math.log2(c / length)
        for c in freq if c > 0
    )

def sliding_entropy(data: bytes, window: int = 64) -> list[float]:
    return [
        shannon_entropy(data[i:i+window])
        for i in range(0, len(data) - window, window)
    ]

# Load the .rdata section (extract with PE-bear or objcopy)
with open(sys.argv[1], 'rb') as f:
    rdata = f.read()

entropies = sliding_entropy(rdata, 64)
for i, e in enumerate(entropies):
    bar = '#' * int(e * 8)
    marker = ' [HIGH]' if e > 7.0 else ' [PAD]' if e < 4.5 else ''
    print(f"  Window {i:4d} (0x{i*64:06x}): {e:.2f}  {bar}{marker}")
```

**Expected output for Stage 03 (jigsaw-protected)**:
```
  Window    0 (0x000000): 5.12  ########################################
  Window    1 (0x000040): 7.45  ############################################################
  Window    2 (0x000080): 4.89  #######################################
  Window    3 (0x0000c0): 7.51  ############################################################
  Window    4 (0x000100): 4.23  #################################
  ...
```
Notice the alternating pattern — this IS the fingerprint of jigsaw fragmentation.

> **Q3**: What window size would you use for entropy scanning to maximize detection of this jigsaw implementation? Why?

<details>
<summary>Answer</summary>

**64 bytes** — matching the chunk size. At this window size, each window falls entirely within either an encrypted chunk or a padding chunk, producing the clearest alternating high/low pattern.

- **Larger window** (e.g., 256 bytes): spans multiple chunks, averaging their entropy. The alternating pattern disappears — this is what the attacker WANTS
- **Smaller window** (e.g., 16 bytes): shows micro-variation within each chunk, lower signal-to-noise

**Optimal detection**: Scan at MULTIPLE window sizes. Jigsaw shows high variance at chunk-size windows but low variance at larger windows. This scale-dependent behavior is detectable — legitimate software doesn't behave this way.

</details>

### Exercise 2: Finding the Permutation Map (15 min)

**Goal**: Locate and parse the `JIGSAW_MAP` array in `.rdata`.

**Instructions**:
1. In Ghidra, find the `main` function
2. Trace the second argument passed to `jigsaw_decode()` — this is a pointer to `JIGSAW_MAP`
3. Navigate to that address in `.rdata`

**What you're looking for** — the current map (10 entries):
```
Offset    Bytes                       Value               Meaning
0x0000    00 00 00 00 00 00 00 00    0x0000000000000000   chunk index 0
0x0008    03 00 00 00 00 00 00 00    0x0000000000000003   chunk index 3
0x0010    FF FF FF FF FF FF FF FF    0xFFFFFFFFFFFFFFFF   padding (skip)
0x0018    FF FF FF FF FF FF FF FF    0xFFFFFFFFFFFFFFFF   padding (skip)
0x0020    04 00 00 00 00 00 00 00    0x0000000000000004   chunk index 4
0x0028    FF FF FF FF FF FF FF FF    0xFFFFFFFFFFFFFFFF   padding (skip)
0x0030    FF FF FF FF FF FF FF FF    0xFFFFFFFFFFFFFFFF   padding (skip)
0x0038    01 00 00 00 00 00 00 00    0x0000000000000001   chunk index 1
0x0040    02 00 00 00 00 00 00 00    0x0000000000000002   chunk index 2
0x0048    FF FF FF FF FF FF FF FF    0xFFFFFFFFFFFFFFFF   padding (skip)
```

**The pattern**: Small sequential integers (0, 1, 2, 3, 4) mixed with `0xFFFFFFFFFFFFFFFF` sentinel values. This is unmistakable once you know what to look for — no legitimate data structure has this shape.

> **Q4**: In the map above, how many real data chunks are there? What is the maximum possible original ciphertext size?

<details>
<summary>Answer</summary>

- **Real chunks**: 5 (indices 0, 1, 2, 3, 4)
- **Padding chunks**: 5 (the `0xFF..FF` entries)
- **Maximum ciphertext size**: 5 × 64 = 320 bytes
- **Actual size**: 318 bytes (stored in `JIGSAW_ORIGINAL_LEN`) — the last chunk has 62 bytes of real data + 2 bytes of zero-padding

The ratio is 1:1 (real:padding). The `jigsaw_encode` function creates one padding entry per data entry, so the shuffled payload is always 2× the padded data. This 50% data density is a design choice — more padding = lower entropy but larger binary.

</details>

### Exercise 3: Manual Jigsaw Reassembly (10 min)

**Goal**: Reassemble the ciphertext by hand from the actual binary data.

**Given the current map**: `[0, 3, MAX, MAX, 4, MAX, MAX, 1, 2, MAX]`

```
Slot 0: map[0] = 0   → bytes 0x000-0x03F of payload → place at position 0 (offset 0x00)
Slot 1: map[1] = 3   → bytes 0x040-0x07F of payload → place at position 3 (offset 0xC0)
Slot 2: map[2] = MAX → bytes 0x080-0x0BF of payload → SKIP (padding)
Slot 3: map[3] = MAX → bytes 0x0C0-0x0FF of payload → SKIP (padding)
Slot 4: map[4] = 4   → bytes 0x100-0x13F of payload → place at position 4 (offset 0x100)
Slot 5: map[5] = MAX → bytes 0x140-0x17F of payload → SKIP (padding)
Slot 6: map[6] = MAX → bytes 0x180-0x1BF of payload → SKIP (padding)
Slot 7: map[7] = 1   → bytes 0x1C0-0x1FF of payload → place at position 1 (offset 0x40)
Slot 8: map[8] = 2   → bytes 0x200-0x23F of payload → place at position 2 (offset 0x80)
Slot 9: map[9] = MAX → bytes 0x240-0x27F of payload → SKIP (padding)

Reassembled: [slot 0][slot 7][slot 8][slot 1][slot 4]
Truncate to 318 bytes.
```

**Verify**: The first 12 bytes of the reassembled output are the nonce. These should match `derive_nonce(AES_KEY)` — if they do, your reassembly is correct.

> **Q5**: What happens if two map entries have the same index value (e.g., both map to position 0)?

<details>
<summary>Answer</summary>

In the current implementation, it's NOT possible — `jigsaw_encode` assigns sequential unique indices. If duplicates existed, `jigsaw_decode` would overwrite the earlier chunk with the later one (last-write-wins), causing data corruption.

However, an attacker could INTENTIONALLY introduce duplicate indices as an anti-analysis trick — the last-write-wins behavior means the "correct" chunk depends on slot ordering, adding confusion for reverse engineers who process the map out of order.

</details>

---

## Section 3: The Crypto Layer — Custom is the Enemy of Correct

### Why the Crypto Seeds Matter

Stages 01-02 used simple XOR — trivially breakable. Stage 03 is the first to use a **stream cipher** (RC4 with a custom envelope), making classical cryptanalysis significantly harder. The module is mislabeled "AES" in the source code (`common::crypto::aes`) — but the actual algorithm is RC4 with FNV-1a-derived integrity checking and nonce derivation. This mislabeling is deliberate: an analyst who assumes "this uses AES" and looks for AES S-box tables or round constants will find nothing.

**The crypto constants** (you'll need these to build a solver):

| Component | Value | Purpose |
|-----------|-------|---------|
| Integrity hash seed | `0x27D4EB2F` (custom, NOT standard FNV-1a `0x811c9dc5`) | Starting value for hash computation |
| Integrity extra step | `h ^= h >> 16` after each byte | Improves avalanche, breaks FNV-1a compatibility |
| FNV prime | `0x01000193` | Standard FNV-1a multiply constant |
| Nonce derivation seed | `0x14650FB0739D0383` | 64-bit seed for nonce generation from key |
| RC4 key construction | `key(32) \|\| nonce(12)` = 44 bytes | Concatenated to form RC4 keystream input |
| Envelope format | `nonce(12) \|\| rc4_ciphertext(N) \|\| integrity_hash(4)` | Total = N + 16 bytes |

### Exercise 4: Identify the Constants in Disassembly (15 min)

**Goal**: Find the integrity hash seed and nonce derivation seed in the binary.

**Instructions**:
1. In Ghidra, trace from `main()` → `aes::decrypt()` → `integrity_hash()`
2. Look for the immediate value `0x27D4EB2F` — this is the hash seed
3. Look for the 64-bit immediate `0x14650FB0739D0383` — this is the nonce seed
4. Look for `0x01000193` — this is the FNV multiplier (shared with standard FNV-1a)
5. Look for the `shr` + `xor` pattern after the multiply — this is the extra `h ^= h >> 16`

**What the disassembly looks like for `integrity_hash`**:
```asm
mov  eax, 0x27D4EB2F        ; seed (NOT standard FNV-1a)
; loop:
xor  eax, ecx               ; h ^= byte
imul eax, eax, 0x01000193   ; h *= FNV prime
mov  edx, eax
shr  edx, 16
xor  eax, edx               ; h ^= h >> 16  ← THIS IS THE TRAP
```

> **Q6**: What does the extra `h ^= h >> 16` step accomplish? Why would a malware author add it?

<details>
<summary>Answer</summary>

**Cryptographic purpose**: It improves the **avalanche effect** — small input changes propagate to more output bits. Standard FNV-1a has poor avalanche for the high bits; the `^= h >> 16` mixes high bits into low bits after each byte.

**Anti-analysis purpose**: It breaks compatibility with standard FNV-1a implementations. An analyst who recognizes the `0x01000193` multiplier and assumes "this is FNV-1a" will compute the wrong hash. The integrity check will fail silently — the solver prints "integrity mismatch" instead of working.

**Real-world parallel**: This is common in malware — using SLIGHTLY modified standard algorithms forces analysts to actually reverse the code instead of pattern-matching to known algorithms.

</details>

### Exercise 5: Verify Your Crypto Implementation (10 min)

**Goal**: Confirm your Python crypto functions match the Rust implementation.

**Test vectors**: Use the ACTUAL AES_KEY from the binary:

```python
# The real key from the binary's .rdata section
key = bytes([
    0x80, 0x73, 0xb7, 0x70, 0xa4, 0xc9, 0x92, 0x51,
    0x87, 0x8b, 0x02, 0x23, 0x57, 0xc4, 0x97, 0x30,
    0x1b, 0x54, 0x81, 0x12, 0xfb, 0x04, 0x0e, 0x24,
    0xcc, 0x82, 0x69, 0xc3, 0xec, 0x33, 0x70, 0xca,
])

# Test 1: Nonce derivation
nonce = derive_nonce(key)
print(f"Nonce: {nonce.hex()}")
# Expected: 08134b3bcbe3be3cdce95ae9
# This MUST match the first 12 bytes of the reassembled jigsaw output

# Test 2: Integrity hash of a known input
h = integrity_hash(b"Hello")
print(f"Hash of 'Hello': 0x{h:08x}")
# If your hash function is correct, this value is deterministic

# Test 3: Verify against the binary's stored integrity
# After jigsaw reassembly, the last 4 bytes of the 318-byte blob are the stored hash
# Compute integrity_hash(ciphertext_body) and compare
```

**Validation chain**:
1. Nonce from `derive_nonce(key)` must equal `08134b3bcbe3be3cdce95ae9`
2. First 12 bytes of reassembled jigsaw output must equal that nonce
3. `integrity_hash(reassembled[12:-4])` must equal `u32::from_le_bytes(reassembled[-4:])`
4. If all three match, your crypto implementation is correct

---

## Section 4: Understanding the Multi-Layer Pipeline

### The Processing Order Matters

Stage 03 uses two independent protection layers:

```
BUILD TIME (tools/encrypt_03.py):
  shellcode (302 bytes, MessageBox + ExitProcess)
    → RC4_encrypt(key)
    → ciphertext (318 bytes = 12 nonce + 302 ct_body + 4 integrity)
    → jigsaw_encode()
    → (shuffled_payload 640 bytes, map 10 entries)

RUNTIME (aes-loader.exe):
  JIGSAW_PAYLOAD + JIGSAW_MAP
    → jigsaw_decode()
    → ciphertext (318 bytes)
    → nonce verify + integrity verify
    → RC4_decrypt(key)
    → shellcode (302 bytes)
    → VirtualAlloc(RW) → copy → scrub heap → VirtualProtect(RX) → CreateThread
```

**Critical insight**: The layers must be reversed in the correct order. Attempting RC4 decryption on the shuffled payload produces garbage. Attempting jigsaw reassembly on the decrypted shellcode makes no sense.

### Exercise 6: Cryptographic vs Obfuscation Layers (10 min)

**Goal**: Understand the security contribution of each layer.

Complete the analysis table:

| Property | Jigsaw (Layer 1) | RC4 (Layer 2) |
|----------|-------------------|----------------|
| **Purpose** | ___ | ___ |
| **Security without key** | ___ | ___ |
| **What it hides from** | ___ | ___ |
| **Can be reversed without key?** | ___ | ___ |
| **Key material in binary?** | ___ | ___ |

<details>
<summary>Completed Table</summary>

| Property | Jigsaw (Layer 1) | RC4 (Layer 2) |
|----------|-------------------|----------------|
| **Purpose** | Entropy normalization — defeat ML/statistical scanners | Payload confidentiality — prevent content extraction |
| **Security without key** | None — the map IS in the binary | Moderate — 44-byte key makes brute force impractical |
| **What it hides from** | Automated entropy scanners, EMBER ML features | String scanners, signature matching, known-byte sequences |
| **Can be reversed without key?** | Yes — map is a constant in .rdata | Only if the key is found (it's also in .rdata) |
| **Key material in binary?** | Yes — JIGSAW_MAP + JIGSAW_ORIGINAL_LEN | Yes — AES_KEY (32 bytes) |

**Summary**: Jigsaw is an **obfuscation** layer (transforms data to defeat automation, zero cryptographic security). RC4 is an **encryption** layer (provides confidentiality). Since the key is embedded in the binary, effective security against a human analyst is zero for both layers. They're defense-in-depth against DIFFERENT types of analysis tools.

</details>

---

## Section 4B: RC4 Implementation Deep Dive — Not Standard RC4

### Why This Matters

Stage 03 is the first stage with a **non-trivial cipher**. XOR (Stages 01-02) has no internal state — each byte is independent. This cipher has a 256-byte permutation table that makes the keystream depend on the ENTIRE key. Understanding the internals is essential for both offense (implementing variants) and defense (recognizing non-standard crypto).

### The KSA (Key Scheduling Algorithm)

The `Rc4::new()` function initializes the cipher in two phases:

```
Phase 1: Seed computation (FNV-1a variant)
  seed = 0x14650FB0739D0383          ← NOT standard FNV offset basis
  for each byte b in key:
    seed ^= b
    seed *= 0x100000001b3            ← standard FNV-1a 64-bit prime

Phase 2: S-box permutation (RC4-like KSA)
  table = [0, 1, 2, ..., 255]       ← identity permutation
  acc = seed & 0xFF                  ← accumulator from seed (NOT 0)
  for i in 0..256:
    acc = (acc + table[i] + key[i % key_len]) & 0xFF
    swap(table[i], table[acc])
```

**Key differences from standard RC4:**
- Standard RC4 uses `j = 0` as initial accumulator. This uses `seed & 0xFF` — seeded from the key hash
- Standard RC4 has no seed phase. This pre-hashes the key with FNV to create a seed that influences KSA
- The seed is also stored as `ctr` for the PRGA phase

### The PRGA Variant (Counter-Mode, NOT Standard)

Standard RC4 PRGA:
```
i = (i + 1) % 256
j = (j + S[i]) % 256
swap(S[i], S[j])
K = S[(S[i] + S[j]) % 256]
```

This code's PRGA:
```
ctr += 1
mixed = ctr * 0x9E3779B97F4A7C15     ← SplitMix64 golden ratio mixer
idx1 = (mixed >> 8) & 0xFF
idx2 = (mixed >> 16) & 0xFF
K = table[idx1] ^ table[idx2] ^ (mixed >> 24)
```

**Why the change?**
1. No state mutation — standard RC4 swaps S-box entries during PRGA, making it stateful. This reads the S-box without modifying it
2. Counter-mode — keystream byte N depends only on the counter value N, not on previous bytes. This means you can decrypt byte N independently
3. Uses `0x9E3779B97F4A7C15` — the golden ratio constant from SplitMix64, a well-studied PRNG mixer
4. Triple XOR output — combines two S-box lookups with counter bits for better distribution

### Exercise 4C: Trace the First 4 Keystream Bytes (15 min)

**Goal**: Manually compute the first 4 bytes of RC4 keystream to verify your implementation.

Given a simplified key `[0x41, 0x42, 0x43]` ("ABC"):

```python
def trace_rc4(key):
    # Phase 1: seed
    seed = 0x14650FB0739D0383
    for b in key:
        seed ^= b
        seed = (seed * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
    print(f"Seed: {seed:#018x}")

    # Phase 2: KSA (first 8 entries only for brevity)
    table = list(range(256))
    acc = seed & 0xFF
    for i in range(256):
        acc = (acc + table[i] + key[i % len(key)]) & 0xFF
        table[i], table[acc] = table[acc], table[i]
    print(f"S-box[0:8]: {table[:8]}")

    # Phase 3: PRGA - first 4 bytes
    ctr = seed
    for n in range(4):
        ctr = (ctr + 1) & 0xFFFFFFFFFFFFFFFF
        mixed = (ctr * 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
        idx1 = (mixed >> 8) & 0xFF
        idx2 = (mixed >> 16) & 0xFF
        k = table[idx1] ^ table[idx2] ^ ((mixed >> 24) & 0xFF)
        print(f"  byte[{n}]: ctr={ctr:#018x} mixed={mixed:#018x} "
              f"idx1={idx1} idx2={idx2} K=0x{k:02x}")

trace_rc4(b"ABC")
```

Run this and compare with the Rust implementation. If your values match, your RC4 is correct.

---

## Section 4C: Cryptographic Envelope Format

### The 318-Byte Structure

The binary doesn't just encrypt — it wraps the ciphertext in a **cryptographic envelope**:

```
┌──────────────────────────────────────┐
│ Nonce (12 bytes)                     │  Derived from key via derive_nonce()
│   Purpose: early rejection check     │  Wrong key → wrong nonce → abort
├──────────────────────────────────────┤
│ RC4-Ciphertext (302 bytes)           │  Shellcode XOR'd with RC4 keystream
│   Key used: AES_KEY(32) || nonce(12) │  = 44-byte combined key
├──────────────────────────────────────┤
│ Integrity Hash (4 bytes, LE)         │  FNV variant of ciphertext only
│   Purpose: tamper detection          │  Corrupted payload → abort
└──────────────────────────────────────┘
Total: 12 + 302 + 4 = 318 bytes
```

### Why Three Fields?

**Nonce first** — Before attempting expensive RC4 decryption, the decoder computes `derive_nonce(key)` and compares against the stored nonce. Wrong key = mismatch = early exit. Cost: one nonce derivation (~32 iterations over key bytes) vs. full RC4 setup + 302-byte decrypt.

**Integrity last** — The hash covers ONLY the ciphertext body, not the nonce. Why?
- If nonce were included: nonce corruption would trigger integrity failure instead of nonce mismatch — unclear which failed
- Hash covers ciphertext only: separates "wrong key" (nonce mismatch) from "corrupt data" (integrity mismatch)

**Verification order in code** (`aes_decrypt`, lines 313-336):
1. Check minimum length (16 bytes)
2. Verify nonce matches key → reject wrong key
3. Verify integrity hash → reject corrupted data
4. ONLY THEN perform RC4 decryption

> **Q**: Why not just decrypt and check if the result looks like valid shellcode?

<details>
<summary>Answer</summary>

1. **Timing**: RC4 decryption of 302 bytes takes measurable time. Nonce comparison is instant. A sandbox running the binary thousands of times would notice the time difference between "wrong key" (fast reject) and "correct key" (decrypt + execute).

2. **No oracle**: Checking if decrypted bytes "look like shellcode" requires knowing what shellcode looks like. The binary has no disassembler. The nonce + integrity approach is self-contained.

3. **Defense-in-depth**: Two independent checks mean an attacker who compromises one (e.g., brute-forces a nonce collision) still faces the integrity check.

</details>

---

## Section 4D: Benign Code Gates — What's New in Stage 03

Stage 03 uses the same three environment validation gates introduced in Stages 01-02 (`init_app_config`, `verify_env`, `preflight`). Refer to Stage 02 Section 1B for the detailed gate-by-gate breakdown.

**What's new here is the CONTEXT**: In Stages 01-02, these gates were standalone anti-sandbox measures. In Stage 03, they serve a **dual role** — they also protect the jigsaw + RC4 crypto pipeline. If a gate fails, the binary exits before attempting jigsaw decode, meaning no encrypted payload fragments ever appear in memory. An incident responder who captures a memory dump from a failed gate execution will find zero crypto artifacts — no reassembled ciphertext, no decrypted shellcode, no RC4 state.

**Exercise 4D**: If `verify_env()` fails, what forensic evidence exists in process memory?

<details>
<summary>Answer</summary>

Only the static `.rdata` contents: `JIGSAW_PAYLOAD` (640 bytes of mixed encrypted+padding), `JIGSAW_MAP` (10 usize entries), and `AES_KEY` (32 bytes). No heap allocations for jigsaw decode or RC4. The jigsaw payload looks like a mix of English text and random data — without the map, an analyst might not recognize it as fragmented ciphertext at all.

</details>

---

## Section 4E: Sandbox Check — The Analyst's Perspective

Stage 03 uses the same `sandbox_check()` from Stages 01-02 (CPU, RAM, disk, uptime thresholds — see Stage 01 for details). What's new here is the **analyst challenge**: the sandbox check is now one of SIX gates, and failure at ANY gate produces identical behavior (silent exit, no artifacts).

### Exercise 4E: Triage a Silent Exit (10 min)

Your analysis VM has 1 CPU, 2 GB RAM. The binary exits instantly. You don't know WHICH gate failed.

**Q**: Design a systematic approach to identify the failing gate WITHOUT patching the binary.

<details>
<summary>Answer</summary>

1. **Check env vars first** (gates 1-3): Run `set` in cmd. If SystemRoot, USERPROFILE, APPDATA, TEMP, COMPUTERNAME all exist → gates 1-3 likely pass
2. **Check hardware** (gate 5): `wmic cpu get NumberOfCores`, `wmic memorychip get Capacity`, `wmic diskdrive get Size` → compare against thresholds (2 CPU, 4GB, 60GB)
3. **Check uptime** (gate 5): `net statistics workstation | find "Statistics since"` → if < 30 min, wait
4. **Check debugger** (gate 4): Ensure ScyllaHide is active if running in x64dbg
5. **Fix lowest-cost failures**: Increase CPU/RAM in VM settings, wait for uptime

The key insight: gates 1-3 are environment checks (pass on any properly configured Windows). Gate 4 is debugger detection. Gate 5 is the real sandbox blocker. In practice, gate 5 fails most often in analysis environments.

</details>

---

## Section 4F: The ExitThread → ExitProcess Patch

### Build-Time Shellcode Modification

The 302-byte shellcode was not hand-written — it was generated by a shellcode compiler (Metasploit-style) that uses `ExitThread` for clean thread exit. But `ExitThread` creates a problem: the main thread of the loader process isn't the shellcode thread. Calling `ExitThread` from the shellcode thread leaves the main thread alive but idle — an orphaned process.

### The Patch Pipeline

```
tools/encrypt_03.py:
  1. Read msgbox_raw.bin (302 bytes)
  2. Find ExitThread ROR13 hash at offset 293:
     Bytes: e0 1d 2a 0a → little-endian 0x0A2A1DE0
  3. Replace with ExitProcess ROR13 hash:
     Bytes: f0 b5 a2 56 → little-endian 0x56A2B5F0
  4. Proceed with RC4 encryption + jigsaw
```

### How to Extract ROR13 Hashes from Shellcode

The Metasploit `block_api` uses a ROR13-based hash that combines module name (UTF-16LE bytes, uppercased) and function name (ASCII + null) into a single 32-bit value. The exact algorithm is complex (processes UTF-16 byte-by-byte with uppercasing, continuous accumulator, double-add of module hash) — reimplementing it correctly is notoriously error-prone.

**The practical approach**: Extract hash values directly from the binary by searching for `mov r10d, imm32` instructions (`41 BA xx xx xx xx`):

```python
#!/usr/bin/env python3
"""Extract block_api hash values from shellcode."""

shellcode = open("shellcode_03.bin", "rb").read()

print("block_api hash values (mov r10d, imm32):")
for i in range(len(shellcode) - 5):
    if shellcode[i] == 0x41 and shellcode[i+1] == 0xBA:
        val = int.from_bytes(shellcode[i+2:i+6], 'little')
        print(f"  offset {i} (0x{i:02x}): 0x{val:08X}")

# Known Metasploit block_api hashes (published reference):
KNOWN = {
    0x0726774C: "kernel32.dll!LoadLibraryA",
    0x07568345: "user32.dll!MessageBoxA",
    0x0A2A1DE0: "kernel32.dll!ExitThread",
    0x56A2B5F0: "kernel32.dll!ExitProcess",
    0x006B8029: "kernel32.dll!WinExec",
    0xE553A458: "kernel32.dll!VirtualAlloc",
    0x876F8B31: "kernel32.dll!GetProcAddress",
}
```

### Exercise 4F: Map All Hash Values (5 min)

Run the extraction script on the decrypted shellcode. You should find three hashes:

| Offset | Hash | API |
|--------|------|-----|
| 224 (0xE0) | `0x0726774C` | `kernel32.dll!LoadLibraryA` |
| 273 (0x111) | `0x07568345` | `user32.dll!MessageBoxA` |
| 291 (0x123) | `0x0A2A1DE0` | `kernel32.dll!ExitThread` (patched to `0x56A2B5F0` = `ExitProcess`) |

**Key insight**: You don't need to reimplement the hash function — you can build a lookup table from published Metasploit hash values. The full list is in the Metasploit source (`external/source/shellcode/windows/x64/src/block/block_api_direct.asm`).

---

## Section 5: Forwarded Exports — The Hidden Trap

### Why ExitThread Crashes Shellcode

This section covers a real bug discovered during development of the Stage 03 shellcode. The original shellcode tried to resolve BOTH `WinExec` and `ExitThread` from kernel32.dll's export table. WinExec resolved correctly. ExitThread crashed the process.

### The Problem: Export Forwarding

On modern Windows (10/11), many kernel32.dll exports are **forwarded** to other DLLs:

```
kernel32.dll export table:
  WinExec           → 0x0007A3D0  (real code — RVA points into .text section)
  ExitThread        → "api-ms-win-core-processthreads-l1-1-0.ExitThread"
                      ↑ This is a STRING, not code!
```

When `GetProcAddress` encounters a forwarded export, it transparently follows the forwarding chain — loading the target DLL if needed and resolving the real address. But when shellcode manually walks the PE export table:

1. Read `AddressOfFunctions[ordinal]` → get an RVA
2. Add the DLL base address → get a VA
3. **If the RVA falls WITHIN the export directory's address range**, it's a forwarding string, not executable code
4. Calling that "address" jumps into the ASCII text of the forwarding string → crash

### Exercise 7: Identify Forwarded Exports (15 min)

**Goal**: Write a Python script that enumerates all forwarded exports in kernel32.dll.

```python
#!/usr/bin/env python3
"""Enumerate forwarded exports in kernel32.dll"""
import ctypes
from ctypes import wintypes

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

# Get kernel32 base address
h = ctypes.windll.kernel32.GetModuleHandleW("kernel32.dll")
base = ctypes.cast(h, ctypes.c_void_p).value

# Parse PE headers
e_lfanew = ctypes.c_uint32.from_address(base + 0x3C).value
nt_headers = base + e_lfanew
export_rva = ctypes.c_uint32.from_address(nt_headers + 0x88).value
export_size = ctypes.c_uint32.from_address(nt_headers + 0x8C).value
export_dir = base + export_rva

n_names = ctypes.c_uint32.from_address(export_dir + 0x18).value
names_rva = ctypes.c_uint32.from_address(export_dir + 0x20).value
funcs_rva = ctypes.c_uint32.from_address(export_dir + 0x1C).value
ords_rva = ctypes.c_uint32.from_address(export_dir + 0x24).value

forwarded = []
real = []

for i in range(n_names):
    name_rva = ctypes.c_uint32.from_address(base + names_rva + i * 4).value
    name = ctypes.c_char_p(base + name_rva).value.decode()

    ordinal = ctypes.c_uint16.from_address(base + ords_rva + i * 2).value
    func_rva = ctypes.c_uint32.from_address(base + funcs_rva + ordinal * 4).value

    # Forwarded if RVA falls within the export directory range
    if export_rva <= func_rva < export_rva + export_size:
        fwd_str = ctypes.c_char_p(base + func_rva).value.decode()
        forwarded.append((name, fwd_str))
    else:
        real.append(name)

print(f"Real exports: {len(real)}")
print(f"Forwarded exports: {len(forwarded)}")
print(f"\nForwarded examples:")
for name, target in forwarded[:20]:
    print(f"  {name:40s} → {target}")

# Check specific functions
for check in ["WinExec", "ExitThread", "VirtualAlloc", "CreateThread"]:
    for name, target in forwarded:
        if name == check:
            print(f"\n  ⚠ {check} is FORWARDED → {target}")
            break
    else:
        if check in real:
            print(f"\n  ✓ {check} is a REAL export")
```

**Expected output** (Windows 10/11):
```
Real exports: ~450
Forwarded exports: ~1150

Forwarded examples:
  AcquireSRWLockExclusive              → NTDLL.RtlAcquireSRWLockExclusive
  AcquireSRWLockShared                 → NTDLL.RtlAcquireSRWLockShared
  ...
  ExitThread                           → api-ms-win-core-processthreads-l1-1-0.ExitThread

  ✓ WinExec is a REAL export
  ⚠ ExitThread is FORWARDED → api-ms-win-core-processthreads-l1-1-0.ExitThread
  ⚠ VirtualAlloc is FORWARDED → ...
  ⚠ CreateThread is FORWARDED → ...
```

**Surprise**: On modern Windows, `VirtualAlloc`, `CreateThread`, and most other "kernel32" APIs are ALSO forwarded. The Goodboy loader's `resolve_api()` uses **additive hashing** with raw export table walking — it doesn't follow forwarding chains. It works because these specific APIs happen to be real (non-forwarded) exports on tested Windows versions. If Microsoft forward them in a future update, the loader will break silently.

The Stage 03 shellcode uses the Metasploit block_api which handles forwarded exports by using `GetProcAddress` under the hood. The original shellcode used `ExitThread` (a forwarded export) which was patched to `ExitProcess` (also forwarded, but handled correctly by block_api) to prevent orphaned threads.

> **Q7**: If VirtualAlloc and CreateThread are also forwarded in kernel32, why does the main aes-loader binary resolve them successfully via API hashing?

<details>
<summary>Answer</summary>

The main loader's `resolve_api()` uses inline PEB-walking with additive hashing. It does NOT handle forwarded exports — it directly reads the export table RVA and treats it as a code address. This works because the APIs it resolves (VirtualAlloc, VirtualProtect, CreateThread, WaitForSingleObject, CloseHandle) happen to be real exports in kernel32.dll on the Windows versions tested.

The embedded shellcode uses a completely different resolver — the Metasploit `block_api` subroutine — which uses ROR13 hashing and does handle forwarded exports by calling through the LoadLibrary/GetProcAddress chain.

**Defense implication**: The binary contains TWO independent API resolution mechanisms with different hash algorithms. A detection rule targeting the additive hash (main loader) won't match the ROR13 hash (shellcode), and vice versa. Both must be detected independently.

</details>

---

## Section 6: PIC Shellcode Anatomy

### The 302-Byte Specimen

The decrypted payload from aes-loader.exe is a complete, self-contained, position-independent shellcode. It demonstrates four core techniques in 302 bytes:

1. **PEB Walking** — Finding kernel32.dll without any API calls
2. **PE Export Parsing** — Resolving LoadLibraryA, then MessageBoxA from user32.dll, via Metasploit block_api (ROR13 hashing)
3. **Cross-DLL Resolution** — LoadLibraryA("user32.dll") to access MessageBoxA
4. **Clean Process Exit** — ExitProcess via block_api (not ExitThread, which is a forwarded export)

### Exercise 8: Annotated Disassembly (20 min)

**Goal**: Disassemble the 302-byte shellcode and annotate the major sections.

After decrypting the shellcode (via the CTF or a Python solver), load it in a disassembler or use Python:

```python
#!/usr/bin/env python3
"""Disassemble the 302-byte shellcode with capstone."""
# pip install capstone
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

shellcode = open("shellcode_03.bin", "rb").read()
md = Cs(CS_ARCH_X86, CS_MODE_64)

for inst in md.disasm(shellcode, 0):
    print(f"  0x{inst.address:04x}  {inst.bytes.hex():<24s}  {inst.mnemonic:8s} {inst.op_str}")
```

**Key sections to identify**:

| Offset Range | Purpose | Registers Used |
|-------------|---------|----------------|
| 0x00-0x04 | Jump over block_api subroutine (`jmp +0xBE` → target 0xC3) | — |
| 0x05-0xC2 | block_api: Metasploit ROR13 hash-based API resolver | R10 = target hash |
| 0xC3-0xDF | Prologue + LoadLibraryA("user32.dll") setup | RAX = user32 base |
| 0xE0-0xF0 | Resolve LoadLibraryA via block_api (hash 0x0726774C) | — |
| 0xF0-0x110 | Push "OK" + "GoodBoy" strings to stack | Stack strings |
| 0x111-0x11B | Call MessageBoxA via block_api (hash 0x07568345) | — |
| 0x120-0x12D | ExitProcess(0) via block_api (hash 0x56A2B5F0) | RCX = 0 |

### Exercise 9: Modify the Shellcode (30 min)

**Goal**: Modify the shellcode to call `WinExec("calc", 1)` instead of `MessageBoxA`.

**Challenges you'll face**:
1. `WinExec` is a real (non-forwarded) export in kernel32.dll — simpler than MessageBoxA since no cross-DLL resolution needed
2. `WinExec` has 2 parameters: `(LPCSTR lpCmdLine, UINT uCmdShow)` — smaller stack setup
3. The shellcode will be smaller (~180 bytes) — no need for LoadLibraryA + user32.dll

**Approach**:
1. Reuse the block_api subroutine (ROR13 hash resolver) — it works for any loaded DLL
2. Push "calc\0" to the stack
3. Call WinExec via block_api with hash `0x006B8029`
4. Call ExitProcess via block_api with hash `0x56A2B5F0`

> **Q8**: The block_api resolver uses ROR13 hashing. The main loader uses additive hashing. Why two different hash algorithms?

<details>
<summary>Answer</summary>

**Different origins**: The block_api shellcode comes from the Metasploit Framework, which standardized on ROR13 in the early 2000s. The main loader uses a custom additive hash to avoid matching known Metasploit signatures.

**Different constraints**: Shellcode is size-optimized — ROR13 is compact (~30 bytes for the hash loop). The main loader has no size pressure and uses a more robust hash with better distribution.

**Detection implication**: An analyst who identifies the main loader's additive hash might assume the embedded shellcode uses the same algorithm. It doesn't — the ROR13 hash values in the shellcode won't match an additive hash rainbow table. Each layer must be reversed independently.

</details>

---

## Section 7: Runtime Behavior Analysis

### No Trace Files

Unlike some earlier development versions, the current aes-loader binary writes **no trace files** to disk. The only disk artifact is the `appcfg.tmp` file written by `init_app_config()` — a benign-looking config file containing a single number. This is by design: trace files containing stage names like `asl_jig.txt` or `asl_dec.txt` would be a forensic gift to incident responders.

### Exercise 10: Behavioral Analysis Without Artifacts (15 min)

**Scenario**: You're an incident responder. The binary leaves no filesystem breadcrumbs. How do you determine what stage of execution it reached?

**Approach**: Use dynamic analysis tools:

1. **Sysmon Event ID 1** (Process Create): Confirms the binary launched. Check CommandLine and ParentProcess.
2. **ETW Microsoft-Windows-Kernel-Memory**: Captures VirtualAlloc/VirtualProtect calls. If you see RW→RX transition, the payload was deployed.
3. **Sysmon Event ID 8** (CreateRemoteThread): Won't fire — this is same-process CreateThread. But some EDRs log all thread creation.
4. **Memory dump at breakpoint**: Set `bp NtProtectVirtualMemory` in x64dbg. If it fires, jigsaw decode AND RC4 decrypt both succeeded.

**Key insight**: The absence of trace files is ITSELF a behavioral indicator. Legitimate software typically logs errors to %TEMP% or %APPDATA%. A binary that allocates executable memory but writes no logs is suspicious.

---

## Section 8: Detection Engineering

### YARA Rule: Jigsaw Permutation Map Pattern

```yara
rule Jigsaw_Permutation_Map
{
    meta:
        description = "Detects jigsaw-style permutation maps in .rdata"
        author      = "Goodboy Framework"
        stage       = "03"
        severity    = "medium"
        technique   = "T1027 - Obfuscated Files or Information (jigsaw fragmentation)"

    strings:
        // usize::MAX sentinel (padding marker) — 8 bytes of 0xFF
        $sentinel = { FF FF FF FF FF FF FF FF }

        // Small sequential indices as little-endian uint64
        $idx_0 = { 00 00 00 00 00 00 00 00 }
        $idx_1 = { 01 00 00 00 00 00 00 00 }
        $idx_2 = { 02 00 00 00 00 00 00 00 }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        // At least 2 sentinel values (padding chunks)
        #sentinel >= 2 and
        // Sequential indices present
        ($idx_0 and $idx_1) and
        // Indices and sentinels in the same region (within 256 bytes)
        for any i in (1..#sentinel) : (
            @sentinel[i] - @idx_0 < 256 and
            @sentinel[i] - @idx_0 > -256
        )
}
```

### YARA Rule: Custom Integrity Hash Seed

```yara
rule Custom_FNV_Integrity_Hash
{
    meta:
        description = "Detects custom FNV variant with non-standard seed 0x27D4EB2F"
        author      = "Goodboy Framework"
        stage       = "03"
        severity    = "low"

    strings:
        // mov eax, 0x27D4EB2F (integrity hash seed)
        $seed = { B8 2F EB D4 27 }
        // imul eax, eax, 0x01000193 (FNV prime)
        $prime = { 69 C0 93 01 00 01 }

    condition:
        uint16(0) == 0x5A4D and
        $seed and $prime
}
```

### Sigma Rule: Behavioral Invariant

The Sigma rule from Stage 01 (detecting RW→RX memory transitions via NtProtectVirtualMemory) **still works against Stage 03 unchanged**. This is the key lesson: jigsaw fragmentation and RC4 encryption defeat static analysis (YARA, entropy scanners) but NOT behavioral detection. The VirtualAlloc(RW) → VirtualProtect(RX) sequence is the same across all 15 stages — it's the fundamental loader invariant.

See Stage 01 Section 4.2 for the full Sigma rule. The only Stage 03-specific refinement would be correlating the RW→RX transition with prior file reads of `%TEMP%\appcfg.tmp` (from `init_app_config`).

### Exercise 11: Multi-Scale Entropy Anomaly Detector (20 min)

**Goal**: Write a tool that detects jigsaw-like entropy patterns by scanning at multiple window sizes.

```python
#!/usr/bin/env python3
"""Multi-scale entropy anomaly detector for jigsaw fragmentation."""
import math
import sys

def shannon(data: bytes) -> float:
    if not data: return 0.0
    freq = [0]*256
    for b in data: freq[b] += 1
    n = len(data)
    return -sum((c/n)*math.log2(c/n) for c in freq if c > 0)

def entropy_variance(data: bytes, window: int) -> float:
    """Calculate variance of entropy across windows."""
    vals = [shannon(data[i:i+window]) for i in range(0, len(data)-window, window)]
    if len(vals) < 2: return 0.0
    mean = sum(vals) / len(vals)
    return sum((v - mean)**2 for v in vals) / len(vals)

def detect_jigsaw(rdata: bytes) -> dict:
    """Detect jigsaw fragmentation via multi-scale entropy analysis."""
    results = {}
    for window in [32, 64, 128, 256, 512]:
        var = entropy_variance(rdata, window)
        results[window] = var

    # Jigsaw signature: HIGH variance at chunk-size window (64),
    # LOW variance at larger windows (256, 512)
    var_64 = results.get(64, 0)
    var_256 = results.get(256, 0)

    if var_256 > 0:
        ratio = var_64 / var_256
    else:
        ratio = float('inf') if var_64 > 0 else 0

    results['ratio_64_256'] = ratio
    results['jigsaw_detected'] = ratio > 3.0

    return results

with open(sys.argv[1], 'rb') as f:
    data = f.read()

results = detect_jigsaw(data)
for w, v in sorted((k,v) for k,v in results.items() if isinstance(k, int)):
    flag = " [ANOMALY]" if v > 1.0 else ""
    print(f"  Window {w:4d}: variance = {v:.4f}{flag}")

ratio = results['ratio_64_256']
detected = results['jigsaw_detected']
print(f"\n  Ratio (64/256): {ratio:.2f}")
print(f"  Jigsaw detected: {'YES' if detected else 'no'}")
```

> **Q9**: This detector uses entropy VARIANCE across windows. Why is variance better than average entropy?

<details>
<summary>Answer</summary>

**Average entropy** fails because jigsaw normalizes it. The average of alternating high-entropy (~7.5) and low-entropy (~4.5) windows is ~6.0 — indistinguishable from legitimate `.rdata`.

**Variance** captures the SPREAD. Legitimate binaries have homogeneous entropy (low variance). Jigsaw binaries have sharp alternation (high variance).

The variance ratio across scales (var@64 / var@256) is even more discriminating. Jigsaw shows high variance at chunk size and low variance at larger scales. Legitimate data doesn't show this scale dependence.

</details>

---

## Section 8B: Adversarial Thinking — Breaking the Jigsaw

**Challenge 1: Defeat the Entropy Normalization**

Your entropy scanner detects the alternating high/low pattern at 64-byte windows. The attacker knows this. How do they make jigsaw undetectable by entropy analysis?

<details>
<summary>Approaches</summary>

1. **Variable chunk sizes**: Use 32-128 byte chunks randomly. Breaks the periodic pattern that fixed 64-byte windows detect
2. **Compress before encrypting**: zlib output has ~7.9 entropy. Padding chunks with compressed benign text also have high entropy. No contrast between encrypted and padding chunks
3. **Encrypt the padding too**: Use a different key to encrypt the English text padding. Both encrypted and padding chunks have ~8.0 entropy — indistinguishable
4. **Use steganographic embedding**: Hide encrypted bytes inside legitimate data structures (PE resources, version info, string tables) instead of using a separate payload blob. No entropy anomaly because the data looks like normal PE content

The deeper lesson: entropy analysis catches CONTRAST between sections. Eliminate the contrast and entropy becomes useless.
</details>

**Challenge 2: Defeat the Permutation Map Detection**

Your YARA rule matches the `[index, 0xFF..FF, index, 0xFF..FF]` pattern. How does the attacker hide the map?

<details>
<summary>Approaches</summary>

1. **Encrypt the map**: XOR the map entries with a key derived from the binary's timestamp. The `0xFF..FF` sentinels become random-looking values
2. **Use implicit ordering**: Instead of a map, store chunks in a fixed pattern (every other 64 bytes is real data). No map needed — the decoder just skips even-indexed chunks
3. **Embed the map in code**: Instead of a data array, compile the reassembly order as a series of `memcpy` calls with hardcoded offsets. The "map" exists only as instruction operands, not as a data structure
4. **Use a hash chain**: Each chunk contains a hash of the next chunk's position. The decoder follows the chain. No central map exists — YARA can't match a distributed data structure

Each approach makes the map harder to detect but adds complexity. Trade-off: detection resistance vs implementation simplicity.
</details>

**Challenge 3: The "AES" Module is Actually RC4**

An analyst identifies the crypto as RC4 by finding the 256-byte S-box initialization. How would you hide the S-box pattern?

<details>
<summary>Approaches</summary>

1. **Lazy S-box**: Don't pre-initialize the full 256-byte array. Generate S-box entries on demand as each keystream byte is needed. No contiguous 256-byte allocation = no S-box signature
2. **Replace RC4 entirely**: Use ChaCha20 (completely different structure, no S-box). Or use AES-CTR with a hardware-accelerated implementation (AES-NI instructions look legitimate)
3. **The Goodboy approach**: Replace RC4 with simple XOR. The RC4 implementation was itself classified as "malware-grade crypto" by ESET. Simpler crypto = better evasion. This is exactly what Stages 04+ did

The irony: the "stronger" crypto (RC4) was MORE detectable than the "weaker" crypto (XOR). Cryptographic strength and evasion strength are inversely correlated when the implementation pattern is a signature.
</details>

---

## Section 9: Build Your Own — Custom Fragmentation

### Challenge: Variable-Chunk Jigsaw (30 min)

The fixed 64-byte chunk size is detectable. Design a variant with **variable chunk sizes** to break the periodicity.

**Requirements**:
1. Chunk sizes vary between 16 and 128 bytes
2. Permutation map encodes both position AND size per chunk
3. Total padding still brings average entropy below 6.0 bits/byte
4. Reassembly is deterministic

**Suggested map format**:
```rust
struct MapEntry {
    original_index: u32,    // chunk index (or 0xFFFFFFFF for padding)
    offset: u32,            // byte offset in original ciphertext
    size: u16,              // chunk size in bytes
    _padding: [u8; 6],      // alignment
}
```

> **Q10**: Your variable-chunk implementation defeats periodic entropy analysis. But it introduces a new detection surface — what?

<details>
<summary>Answer</summary>

The **map itself** is more complex and distinctive. It contains structured entries with multiple fields (index, offset, size). This creates:

1. **Size field distribution**: Chunk sizes 16-128 produce distinctive `u16` values
2. **Offset field pattern**: Monotonically increasing sequence — detectable via YARA
3. **Larger footprint**: More bytes per entry = more visible in `.rdata`

Trade-off: Variable chunks defeat entropy periodicity but make the map more detectable. Security engineering is about shifting the detection surface, not eliminating it.

</details>

---

## Section 10: Memory Scrubbing — What's New

Stage 03 uses the same heap scrubbing concept from Stage 02 (see Stage 02 Section 3 for the full analysis). The key difference is the implementation:

```rust
// Stage 02: iterator zeroing (compiler MAY optimize away)
for b in sc.iter_mut() { *b = 0; }

// Stage 03: write_volatile (compiler CANNOT optimize away)
let sc_ptr = shellcode.as_ptr() as *mut u8;
for i in 0..sz {
    core::ptr::write_volatile(sc_ptr.add(i), 0);
}
```

`write_volatile` is a **compiler barrier** — it tells the optimizer "this store has side effects, do not eliminate it." Without `volatile`, the compiler sees "writing zeros to memory we're about to free" and removes it as a dead store optimization. In release builds (`opt-level=2`), this optimization is aggressive.

### Exercise 10: Verify the Optimization (5 min)

**Q**: Build Stage 03 with `opt-level="z"` (size-optimized) and check if the zeroing loop is present in the disassembly. Then build with `opt-level=2` (speed-optimized). Is `write_volatile` still present in both?

<details>
<summary>Answer</summary>

Yes — `write_volatile` is present in both optimization levels because the compiler is forbidden from removing it. If you replaced `write_volatile` with a normal `*ptr = 0` write, `opt-level=2` would eliminate the entire loop (dead store to freed memory), while `opt-level="z"` might keep it. This is why `write_volatile` is essential for security-critical zeroing.

</details>

---

## Section 11: Knowledge Check

**1. A binary has `.rdata` entropy of 5.2 bits/byte. Can you conclude it doesn't contain encrypted payloads?**

<details>
<summary>Answer</summary>

No. An overall entropy of 5.2 is consistent with jigsaw-fragmented encrypted data. The encrypted chunks (~7.9) mixed with text padding (~4.5) average to ~5.0-6.0. You need multi-scale entropy analysis or structural analysis (permutation map) to detect this.

</details>

**2. Your Stage 01 solver prints "Nonce mismatch" when you run it on Stage 03 data. What's wrong?**

<details>
<summary>Answer</summary>

Stage 03 uses a different crypto system entirely. Stages 01-02 use simple XOR (no nonce). Stage 03 uses RC4 with a nonce derived via `derive_nonce()` using FNV seed `0x14650FB0739D0383`. Your Stage 01 XOR solver doesn't implement nonce derivation at all — you need the full RC4 envelope decoder (nonce + integrity + RC4 decrypt).

</details>

**3. Why does the shellcode use ExitProcess instead of ExitThread?**

<details>
<summary>Answer</summary>

The original shellcode template used ExitThread, but this was patched to ExitProcess during the encryption pipeline (`tools/encrypt_03.py` patches the ROR13 hash at offset 293). ExitThread would leave the main process running with no remaining threads, creating an orphaned process. ExitProcess cleanly terminates the entire process. The block_api resolver handles forwarded exports correctly, so both ExitThread and ExitProcess work — but ExitProcess is the safer choice for a CreateThread-based loader.

</details>

**4. You set a breakpoint on NtProtectVirtualMemory and it never fires. What stage did execution reach?**

<details>
<summary>Answer</summary>

The binary exited before reaching VirtualProtect. Possible failure points:
1. **init_app_config()** failed — no env vars, temp dir write failed
2. **verify_env()** failed — sandbox missing 3+ required paths
3. **preflight()** failed — environment checks
4. **PEB.BeingDebugged** — debugger detected (disable with ScyllaHide)
5. **sandbox_check()** — hardware metrics (CPU < 2, RAM < 4GB, disk < 60GB, uptime < 30min)
6. **jigsaw_decode** returned wrong data — unlikely unless binary is corrupted
7. **aes_decrypt** returned None — nonce mismatch (wrong key) or integrity mismatch (corrupted payload)

Use conditional breakpoints on each gate's return to narrow down which one fails.

</details>

**5. If you were designing a detection for jigsaw fragmentation, would you focus on the payload data or the permutation map?**

<details>
<summary>Answer</summary>

The **permutation map** — it has a structurally distinctive pattern (array of usize with sequential values + 0xFFFFFFFFFFFFFFFF sentinels). The payload is deliberately designed to look normal (mixed entropy). The map's structure is rare in legitimate software and cheap to scan for with YARA.

</details>

---

## Section 12: Complete Solver Challenge (45 min)

### Build an End-to-End Decryptor

**Goal**: Write a Python script that takes `aes-loader.exe` as input and outputs the decrypted 302-byte shellcode. This exercises ALL concepts from Stage 03.

**Required steps**:
1. Parse the PE file and locate `.rdata` section
2. Extract `JIGSAW_PAYLOAD` (640 bytes — look for English text interleaved with high-entropy chunks)
3. Extract `JIGSAW_MAP` (10 `usize` entries — look for small integers mixed with `0xFFFFFFFFFFFFFFFF`)
4. Extract `AES_KEY` (32 bytes — harder, must be found by context)
5. Extract `JIGSAW_ORIGINAL_LEN` (318 — stored near the map)
6. Perform `jigsaw_decode(payload, map, 318)` → 318 bytes
7. Verify nonce: `derive_nonce(key)` == first 12 bytes
8. Verify integrity: `integrity_hash(ciphertext)` == last 4 bytes
9. Decrypt: `Rc4::new(key || nonce).apply(ciphertext)` → 302 bytes
10. Disassemble with capstone → confirm MessageBox("GoodBoy") + ExitProcess

**Skeleton**:

```python
#!/usr/bin/env python3
"""Stage 03 complete solver."""
import struct

CHUNK_SIZE = 64

def derive_nonce(key):
    """YOUR IMPLEMENTATION — see Section 4C."""
    pass

def integrity_hash(data):
    """YOUR IMPLEMENTATION — see Section 3, seed 0x27D4EB2F."""
    pass

def rc4_decrypt(key, data):
    """YOUR IMPLEMENTATION — see Section 4B."""
    pass

def jigsaw_decode(shuffled, map_entries, original_len):
    """YOUR IMPLEMENTATION — see Exercise 3."""
    pass

def solve(exe_path):
    with open(exe_path, 'rb') as f:
        pe = f.read()

    # Step 1-5: Extract constants from .rdata
    # Hint: Search for the usize::MAX pattern (FF FF FF FF FF FF FF FF)
    # The JIGSAW_MAP is nearby. The JIGSAW_PAYLOAD follows the map.
    # AES_KEY is 32 bytes of high-entropy data near the other constants.

    # TODO: Your extraction logic here
    aes_key = b''       # 32 bytes
    jigsaw_map = []     # 10 entries
    jigsaw_payload = b'' # 640 bytes
    original_len = 318

    # Step 6: Jigsaw decode
    reassembled = jigsaw_decode(jigsaw_payload, jigsaw_map, original_len)
    assert len(reassembled) == 318

    # Step 7: Verify nonce
    nonce = derive_nonce(aes_key)
    assert reassembled[:12] == nonce, "Nonce mismatch — wrong key?"

    # Step 8: Verify integrity
    ciphertext = reassembled[12:-4]
    stored_hash = struct.unpack('<I', reassembled[-4:])[0]
    assert integrity_hash(ciphertext) == stored_hash, "Integrity check failed"

    # Step 9: Decrypt
    combined_key = aes_key + nonce
    shellcode = rc4_decrypt(combined_key, ciphertext)
    assert len(shellcode) == 302

    # Step 10: Verify
    print(f"Shellcode: {len(shellcode)} bytes")
    print(f"First 16: {shellcode[:16].hex()}")
    # Should start with: e9be000000... (jmp instruction)
    with open("shellcode_03_decrypted.bin", "wb") as f:
        f.write(shellcode)
    print("Written to shellcode_03_decrypted.bin")

if __name__ == "__main__":
    import sys
    solve(sys.argv[1])
```

**Success criteria**: Your script produces a 302-byte file that, when loaded in capstone, disassembles to valid x86-64 with recognizable `mov r10d, 0x56A2B5F0` (ExitProcess hash) near the end.

---

## Module Summary

| Concept | Stage 01 | Stage 02 | Stage 03 |
|---------|----------|----------|----------|
| Encryption | XOR (16-byte key) | XOR (different 16-byte key) | RC4 (mislabeled "AES") with custom seeds |
| Payload storage | Single blob in .rdata | Single blob in .rdata | Fragmented across .rdata (jigsaw) |
| Entropy profile | High island (~7.1) | Moderate island (~6.5) | Normalized (~6.4 average) |
| Obfuscation layers | 1 (crypto) | 1 (crypto) | 2 (jigsaw + crypto) |
| API resolution | Additive hash (PEB walk) | Additive hash (PEB walk) | Additive hash (PEB walk) |
| Shellcode type | 302-byte MessageBox (block_api) | 302-byte MessageBox (block_api) | 302-byte MessageBox + ExitProcess (block_api) |
| Anti-forensics | Memory scrub | Memory scrub | Memory scrub (no trace files) |
| New red team concept | Loader pipeline basics | Key rotation | Entropy normalization, crypto mislabeling |
| New blue team concept | Algorithm identification | Cryptanalysis | Multi-scale entropy analysis, permutation map detection |
| Static detection | Find blob + key | Known-plaintext attack | Find map + reassemble + correct crypto seeds |
| Dynamic shortcut | bp VirtualProtect | bp VirtualProtect | bp VirtualProtect |

### Common Misconceptions

| What People Believe | What's Actually True |
|--------------------|-----------------------|
| "The binary uses AES-256 encryption" | It uses RC4 with a custom envelope (nonce + integrity hash). The module name `common::crypto::aes` is a deliberate mislabel. There are no AES S-boxes, no round keys, no block structure in the binary |
| "Jigsaw is encryption" | Jigsaw is obfuscation — it shuffles data to defeat entropy analysis but provides ZERO confidentiality. The permutation map is in the binary. Anyone who finds the map can reassemble the data without any key |
| "Stronger crypto = better evasion" | The RC4 implementation in this binary was classified by ESET as Agent_AGen.LEE ("malware-grade crypto") in later testing. Simple XOR achieved 0/76 where RC4 achieved 5/76. The crypto implementation IS a signature |
| "Entropy normalization is invisible" | The alternating high/low entropy at the chunk size creates a detectable periodic pattern. Multi-scale variance analysis catches it. The permutation map's `0xFF..FF` sentinels are even easier to signature |
| "Memory scrubbing with write_volatile is secure" | write_volatile prevents compiler optimization but doesn't prevent: (1) the allocator keeping freed memory, (2) page file writes, (3) kernel-level memory capture. It's a speed bump, not a wall |
| "Forwarded exports are a Windows bug" | Export forwarding is by design — it's how Microsoft refactored kernel32.dll across Windows versions. Over 70% of kernel32 exports are forwarded on Windows 11. The block_api shellcode handles this; simple PEB walkers (like the main loader's resolve_api) may not |

### What Breaks at Stage 04 — The Bridge

Stages 01-03 all use the **same API resolution mechanism** (PEB-walking with additive hash-based export lookup), but the learning paths haven't deeply examined it. Stage 04 is a dedicated deep dive into this mechanism:

1. **Hash algorithm details** — The additive hash function uses seed `0x1F2E3D4C`, `wrapping_mul(0x1003F)`, and `xor(h >> 11)`. Stage 04 teaches you to identify and reverse this custom hash by finding the seed and multiplier constants in disassembly
2. **Rainbow table construction** — Pre-computing hashes for all kernel32.dll exports lets you instantly identify which APIs any Goodboy binary resolves
3. **Detection rules targeting the invariant** — The PEB walk pattern (`gs:[0x60]` → Ldr → module list) is the same across ALL 15 stages. A single detection rule catches them all

### MITRE ATT&CK Mapping

| Technique | ID | How It's Used |
|-----------|----|---------------|
| Obfuscated Files or Information | T1027 | Jigsaw fragmentation (payload split + shuffled + padded) + XOR-encrypted shellcode |
| Deobfuscate/Decode Files | T1140 | Runtime jigsaw reassembly + RC4 decryption |
| Dynamic API Resolution | T1106 | PEB-walking hash-based API resolution |
| Reflective Code Loading | T1620 | VirtualAlloc + VirtualProtect + CreateThread in own process |
| Indicator Removal | T1070 | write_volatile heap scrubbing (remove decrypted shellcode from memory) |
| Masquerading | T1036 | Crypto module mislabeled "AES" (actually RC4) |

### Further Reading (2025-2026)

**Entropy evasion and payload fragmentation:**
- [CrowdStrike: EMBER2024 Dataset](https://www.crowdstrike.com/en-us/blog/ember-2024-advancing-cybersecurity-ml-training-on-evasive-malware/) — The ML dataset that jigsaw targets: section-level entropy histograms
- [cocomelonc: Malware Cryptography 1-43](https://cocomelonc.github.io/malware/2023/08/13/malware-cryptography-1.html) — RC4, AES, custom ciphers in malware (C implementations)
- [MDPI: Adversarial Attacks Against ML PE Detection](https://www.mdpi.com/1999-5903/16/5/168) — GanGenetic achieves >96% ML bypass (2025)

**RC4 and stream cipher analysis:**
- [cocomelonc: AV Evasion 11-18](https://cocomelonc.github.io/malware/2023/02/12/malware-av-evasion-11.html) — Evasion techniques including crypto-based approaches
- [RedOps.at: Direct Syscalls](https://redops.at/en/blog/direct-syscalls-a-journey-from-high-to-low) — Context for API resolution mechanisms

**Shellcode and PIC code:**
- cocomelonc: [Windows Shellcoding 1-3](https://cocomelonc.github.io/tutorial/2021/10/27/windows-shellcoding-1.html) — Building PIC shellcode from scratch
- cocomelonc: [Linux Shellcoding 1-2](https://cocomelonc.github.io/tutorial/2021/10/09/linux-shellcoding-1.html) — Cross-platform comparison

**Blue team perspective:**
- [Microsoft RIFT](https://www.microsoft.com/en-us/security/blog/2025/06/27/unveiling-rift-enhancing-rust-malware-analysis-through-pattern-matching/) — Rust binary analysis tool (identifies common library code)
- [Oblivion: Detecting Syscalls](https://oblivion-malware.xyz/posts/detecting-syscalls/) — Detection of PEB-walking patterns

## What's Next

- **Stage 04 (API Hashing)**: Deep dive into the PEB-walking and hash-based API resolution mechanism that ALL stages use. Build rainbow tables, reverse the custom hash algorithm, write detection rules targeting the invariant
- **Stage 05 (Process Injection)**: The loader breaks out of its own process for the first time — injecting shellcode into a remote process via `WriteProcessMemory` + `CreateRemoteThread`
