# Cobalt Strike passive config format notes (WS-4 B-4.1)

Status: format facts only. The provided references do not specify enough of the setting-block encoding to implement a parser without guessing. Unknown details are explicitly marked `UNVERIFIED`.

## Setting block

The facts document describes approximately 80 indexed TLV settings, each with a type and value, and identifies the type families as short, int, pointer, and string. [F1, lines 19–25]

- Entry layout (index/type/length/value): **UNVERIFIED** beyond the general TLV description.
- Byte order: **UNVERIFIED**.
- Numeric type codes and type-specific lengths: **UNVERIFIED**.
- End marker and its value: **UNVERIFIED**.

These fields are required to parse values safely. No synthetic wire encoding is chosen in the absence of a citation.

## Anchor, patch sizes, and XOR keys

The default single-byte XOR keys are `0x69`, `0x2e`, and `0x00`; if defaults miss, the reference uses a fallback over remaining single-byte keys ranked by byte frequency. The precise ranking algorithm is **UNVERIFIED**. [F1, line 17; F2, lines 5, 9]

The anchor is the DER `rsaEncryption` OID `06 09 2A 86 48 86 F7 0D 01 01 01` inside the public-key setting. Search is described as XOR-searching the OID with rotated key phases, locating the covering TLV, and extracting a fixed patch block. [F1, lines 18–19; F2, lines 6, 8]

Patch size is `0x1000` through CS 4.8 and `0x1800` from CS 4.9. [F1, line 22; F2, line 7]

## xorencoded wrapper

The documented wrapper byte layout is `| nonce (4 bytes) | encoded_size (4 bytes) | encoded MZ+payload |`. The wrapper is described as rolling 4-byte XOR. The exact state update, byte order of `encoded_size`, and relationship between nonce and successive payload bytes are **UNVERIFIED** in the provided fact notes. Therefore G-4.3 is `BLOCKED_MISSING_SOURCE`; no decoder or synthetic encoding is supplied. [F2, line 11; F3, lines 23–24]

## Version map and reused indices

The map is many-to-one and should be expressed as an approximate range, not an exact version. The cited rows available in the facts document are:

| Maximum setting index | Approximate version range |
|---:|---|
| 20 | 3.4 |
| 31 | 3.6 |
| 35 | 3.7 |
| 36 | 3.8 |
| 37 | 3.9 |
| 38, 39 | 3.11 |
| 48 | 3.12 |
| 49 | 3.13 |
| 53 | 3.14 |
| 55 | 4.0 |
| 58 | 4.1 |
| 59 | 4.2 |
| 70 | 4.3 |
| 73 | 4.5 |
| 74 | 4.7 |
| 76 | 4.9 |
| 78 | 4.10 |
| 80, 85, 87 | 4.11 |
| 89 | 4.12 |
| 91 | 4.13 |

Annotate as `max setting index N (≈ CS x.y per dissect.cobaltstrike v1.3.0 map)`; absent entries are `unknown`. [F2, line 13; F3, lines 31–33]

Setting indices are reused across versions: 16 is `KILLDATE_YEAR` through 4.6 and `BOF_ALLOCATOR` from 4.7; 17 is `KILLDATE_MONTH` then `SYSCALL_METHOD` in 4.8; 36 is `INJECT_OPTIONS` then `WATERMARKHASH` from 4.5; index 48 is also reused, but the new meaning is **UNVERIFIED**. [F1, line 61]

## Citation key

- **F1:** `references/dissect-cobaltstrike-ttp-port.md` (copied input), line numbers refer to that file.
- **F2:** local research fact sheet `R-01-dissect-cobaltstrike-facts.md`, line numbers refer to the original fact sheet.
- **F3:** `references/v11b-technical-readiness-review-F2-F4.md` (copied input), line numbers refer to that file.

This is a facts-only clean-room note. No reference implementation code has been copied or translated.
