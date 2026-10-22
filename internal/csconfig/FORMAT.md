# Cobalt Strike passive config format notes (WS-4 B-4.1)

This document is the implementation source of truth for the standalone passive carver. Reference facts are separated from local implementation decisions. Reference source code is never copied or translated.

## Reference identity

The local reference is the two identical Downloads archives named `dissect.cobaltstrike-main.zip` and `dissect.cobaltstrike-main (1).zip`, SHA-256 `0aa5896e5dbb05b6805b11b38d4b5ae7dabf6d143f80ccf01ccc0bc2dec4f366`. They contain no Git metadata. `pyproject.toml` declares a VCS-derived dynamic version (`:7, :122-125`); `CHANGELOG.md` has an `[Unreleased]` heading and release `1.3.0` dated 2026-10-01 (`:8-10`). The reference source identity is therefore recorded as archive SHA plus changelog release 1.3.0; it is not asserted to be an exact Git tag tree. R-01b identifies the facts it extracted as tag v1.3.0, commit prefix `a1c35dd`.

## Setting block — reference facts

A setting is a six-byte header followed by its value: three big-endian uint16 fields in order `index`, `type`, `length`, then exactly `length` value bytes. Type codes are `TYPE_NONE=0`, `TYPE_SHORT=1`, `TYPE_INT=2`, and `TYPE_PTR=3`. Index zero terminates the settings walk (the first two bytes are `00 00`). [Reference: `beacon.py:234-246`, `:326`; R-01b: `struct Setting`, `SettingsType`, `walk_settings`, `iter_settings`]

The whole candidate config block, headers included, is XORed before the settings are parsed. The default one-byte keys, in order, are `0x69`, `0x2e`, `0x00`; key `0x00` leaves bytes unchanged. [Reference: `beacon.py:447-448`, `:586-616`; `utils.py:20-30`; R-01b: `XOR scope`, `DEFAULT_XOR_KEYS`]

The anchor is DER rsaEncryption OID `06 09 2A 86 48 86 F7 0D 01 01 01` inside the public-key setting. The reference also recognizes DER sequence prefixes `30 81` and `30 82`. Its search accounts for rotated key phases. [Reference: `beacon.py:450-454`, `:586-616`; R-01b: `ASN1_RSA_ENCRYPTION`, `_DER_SEQ_PREFIXES`]

Config patch sizes are `0x1000` through Cobalt Strike 4.8 and `0x1800` from 4.9; the reference maximum patch size is `0x1800`. [Reference: `beacon.py:491-496`; R-01b: `BeaconPatchSize`]

The settings walk treats indices and types as opaque for discovery, advances by six header bytes plus the declared length, and stops on index zero. Discovery requires at least three walked entries and payload evidence around the candidate. [Reference: `beacon.py:502-506`, `:518-548`, `:618-625`; R-01b: `walk_settings`]

## XOR-encoded stage wrapper — reference facts

- Scan candidate nonce offsets from 0 through 1023; the first valid candidate is selected. [Reference: `xordecode.py:35-72`, `:89-107`]
- The header is a four-byte nonce followed by a four-byte encoded size; payload starts eight bytes after the nonce offset. Decode size as little-endian uint32 of `(nonce XOR size_field)`. [Reference: `xordecode.py:35-65`, `:110-117`; `utils.py:120-143`; R-01b: `Header`, `Size decode`]
- The decoded size must be at least `0x200`; payload must fit, with zero to 256 trailing bytes allowed. [Reference: `xordecode.py:26-27`, `:63-72`; R-01b: `Header validation`]
- Payload decoding XORs each encoded byte with the ciphertext byte four positions earlier; the first four bytes use the nonce. The nonce remains fixed. [Reference: `xordecode.py:78-83`, `:128-137`; R-01b: `Rolling XOR`]
- The decode path does not require an MZ check. [R-01b: `MZ check`]

## Setting identifiers and reused-index rules

The relevant index names are declared in `beacon.py:61-232` (BeaconSetting enum). Reused meanings and reference disambiguation are:

| Index | Meaning and resolution | Reference citation |
|---:|---|---|
| 16 | `KILLDATE_YEAR` when maximum setting index is below 74; `BOF_ALLOCATOR` otherwise | `beacon.py:80-81`, `:777-780`; R-01b: `BeaconSetting`, index 16 row |
| 17 | `KILLDATE_MONTH` for SHORT; `SYSCALL_METHOD` for INT | `beacon.py:83-84`, `:774-776`; R-01b: index 17 row |
| 36 | `INJECT_OPTIONS` for SHORT; `WATERMARKHASH` otherwise | `beacon.py:112-113`, `:771-773`; R-01b: index 36 row |
| 48 | `PROCINJ_ALLOWED` for SHORT when maximum setting index is below 74; `PROCINJ_BOF_REUSE_MEM` otherwise | `beacon.py:134-135`, `:781-784`; R-01b: index 48 row |

The maximum-index map is many-to-one; annotations must use approximate wording and unlisted indices are `unknown`. [Reference: `version.py:22-45`; R-01b: `Version map`]

| Maximum index | Approximate version |
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

Required annotation: `max setting index N (≈ CS x.y per dissect.cobaltstrike v1.3.0)`. [Reference: `version.py:22-45`; R-01b: `Annotation wording`]

## Design decisions — c2parser rules, not reference facts

1. Decode SHORT and INT values as big-endian unsigned integers only when the declared length is exactly 2 or 4 bytes. For every other length, preserve raw bytes and set `unexpected_length`. PTR and other values remain raw. This is the R-01b value-width rule; it is deliberately tolerant rather than strict type/width validation. [R-01b: `Value width`]
2. Try the three default XOR keys first. If none yields a valid anchored settings walk, try other byte keys in descending frequency of that byte in the current candidate window, ties by ascending key value. Candidate acceptance requires the OID within a setting value and a structurally valid terminated walk. This deterministic order is an implementation choice, not a statement of reference behavior. The reference fallback instead ranks repeated four-byte equal-byte groups (`beacon.py:674-691`). This is an intentional, recorded divergence from the reference fallback order.
3. At `Result()`, validate xorencoded candidates against the total number of bytes fed, using the retained bounded window for candidate bytes. This selects the R-01b streaming option that defers end-of-stream trailer validation until `Result()`. Never require MZ. [R-01b: `Streaming note`, `MZ check`]
4. Do not implement 4.11 obfuscated wrappers, guardrails, or multi-byte XOR keys; report `NOT_CARVED` with a reason. [R-01b: `Still UNVERIFIED`; readiness review F3, Q-04]
5. Retained state for decode windows is bounded to two rolling windows of `3 × 0x1800` bytes each: one for input and one for the derived xorencoded stream. `Feed` processes arbitrary input in chunks no larger than `0x1800`, bounding transient derived bytes too. Header candidates are limited to offsets 0–1023 and stored as offset/decoded-size pairs; pending anchors are capped at 128 per scanner. The independent concurrency limiter admits at most 32 carvers. These caps are local resource decisions. [Owner order: Q-06 bounds; S1F §2]
6. For the derived stream, preserve absolute byte positions with four prefix bytes, then compute `d[j] = c[j] XOR c[j-4]`. The first four payload bytes are nonce-dependent; config acceptance requires its entire patch block to fit within a size-valid header candidate's `[offset+12, offset+8+size)` interval. Defer end/trailer validation until `Result()`. [S1F §2; R-01b: `Rolling XOR`, `Streaming note`]
7. Evaluate each anchor no more than once, after `anchor + 0x1800` bytes are available or when `Result()` finalizes. Decode only the local slice `[anchor-0x1800, anchor+0x1800)`, clamped to retained input. One carver shares an allowance of 32 anchor evaluations across raw and derived scanners. Each evaluation tries no more than `0x1800` settings-walk starts, so aggregate walk work is bounded by `32 × 0x1800` starts. This permits at least 16 false anchors plus a later valid config while bounding dense-anchor inputs; the cap also prevents unbounded repeated walks. When another anchor is pending after the allowance is consumed, stop and report `work_budget_exhausted`. Derived-stream processing runs before raw scanning so a raw false candidate cannot consume the entire allowance first. [S1F2 §3]
8. Exact reasons are assigned only for a final `NOT_CARVED` result: no detected OID anchor is `no_anchor`; an OID exists but no valid config walk is `anchor_without_valid_config`; exhausted anchor evaluations is `work_budget_exhausted`; a size-valid xorencoded header whose derived config fails containment/end/trailer checks is `invalid_xorencoded_wrapper`; concurrency refusal is `resource_limit`. A successful config always has an empty reason. This slice cannot positively identify any out-of-scope wrapper form, so it does not emit `out_of_scope_wrapper`. [S1F2 §3]
9. A candidate PUBKEY setting is accepted only when its setting type is TYPE_PTR. `Feed` continues bounded scanning/accounting after an early config so total byte and wrapper-boundary bookkeeping remains consistent. `Close()` releases an admitted limiter slot even when `Result()` was not called. [S1F §3]

## Citations and unresolved facts

- **R-01b:** `R-01b-dissect-cobaltstrike-wire-facts.md`, symbols named above; its facts are checked against the local archive where file/line citations are given.
- **Archive source files:** `dissect/cobaltstrike/beacon.py`, `xordecode.py`, `utils.py`, `version.py` in the archive identified above.
- **Other scope facts:** `dissect-cobaltstrike-ttp-port.md` and `v11b-technical-readiness-review-F2-F4.md` supplied in the order inputs.

No remaining wire-layout or wrapper fact required by this slice is marked UNVERIFIED. Ranking of the exact reference fallback is intentionally not replicated; its observed behavior is cited above and the deterministic c2parser order is a design decision. No reference code or real beacon material is included in this document.
