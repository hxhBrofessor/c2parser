# C2Parser v11.2 — Release Notes

The framework-profile and Sigma signals remain heuristic: **a profile or rule match is not confirmed framework attribution.** v11.2 makes **no vendor-agnostic claim**; the G-VA evaluation is pending.

## What changed

### WS-5 — built-in Sigma rules

- The built-in Sigma set was reduced to one rule (`e1f2bf20`, id unchanged). The legacy prefix rule (`50995159`) was retired; three Mythic/Apollo examples moved out of the built-in set into optional documentation examples (`docs/sigma-examples/`, not compiled in).
- **Rule metadata corrected.** The example rule's references and descriptive text were corrected without changing its identifier.

### WS-4 — passive configuration carver and HTTP tap

- The standalone `internal/csconfig` carver handles plain and xorencoded stages, single-byte keys, patch lengths `0x1000` and `0x1800`, and approximate version annotations. These version annotations are estimates, not attribution.
- **B-4.4 engine tap (released, S2a).** The HTTP-response tap has three admission paths (MZ at offset 0; `application/octet-stream` ≥ 64 KiB; a validated xorencoded header) and a per-response 4 MiB feed cap. It emits `cs_config:beacon_config` at weight 0.60 only after structural validation and evidence sufficiency (at least two recognized non-PUBKEY settings, including SLEEPTIME or JITTER). A lone sufficient config contributes a medium finding and never reaches critical. It is BLIND-suppressed under VA-0.
- Current reviewed B-4.4 limitations: no decompression; xorencoded admission requires a `Content-Length`; 4.11 obfuscation, guardrails and multi-byte keys are `NOT_CARVED`.

### VA-0 — framework-blind evaluation

- A framework-blind mode is available through the test and evaluation harness only. It is not a product feature or CLI option. It suppresses registered attribution evidence for evaluation; no vendor-agnostic claim is made, and G-VA remains pending.

### Documentation

- The v11.1 wording is corrected to say it **adds no new detectors**. Its request-token handling can still surface additional carrier detections.
- The diagnostic `-timing v2` `smb_pipe` key grammar is documented as `pipe|<client addr:port>|<server addr:port>|<pipe>|<first frame>`.

## Accepted-change register (v11.1 → v11.2) — OA-1

Only these output deltas are intended; anything else is a regression.

1. **AC-1 (Sigma set):** no corpus change; on the Gate A lab, exactly the 6 Havoc C2 findings (cap0/cap1/cap3 × v1/v2) differ in text only (the rule title in the signal detail; the renamed rule file in the evidence). Score, severity, signal names and weights are identical.
2. **AC-2 (B-4.4 tap):** no corpus or lab change (no CS config present); new detections appear only on inputs that carry a sufficient carved CS configuration.
3. **AC-3 (VA-0):** test/eval harness only; zero FULL output change.
4. **AC-4 (version/docs):** the binary differs from the v11.1 build only by the version string, plus docs/CHANGELOG/release-notes.

## Known limitations and open work

- **Sigma rule packs affect scores.** By default C2Parser refreshes community SigmaHQ rules (at most once a day) and loads them alongside its single built-in rule. A matching community rule can raise a finding's score (one user-agent rule contributed up to 0.68 in a synthetic test), so results can differ with the state of the rule cache. For reproducible results use `-offline -no-sigma-update` (optionally with `-sigma-cache <dir>`). A Sigma match is not confirmed framework attribution.
- **Synthetic benign control (FP_OB).** A synthetic benign HTTP series scores high only when a community Sigma user-agent rule is loaded. Its score is driven by that rule and by a browser-header anomaly in the test fixture, not by the random cookie values or by timing. With the built-in rules only, it scores medium (v1) or low (v2). This is a synthetic observation, not a measured false-positive rate.
- **VA-0 OPEN-1:** mixed signals are suppressed wholesale in BLIND; sanitizing a mixed signal's detail while proving neutral behavior remains open.
- **VA-0 OPEN-5:** surviving generic evidence may contain framework fingerprint bytes even when framework names are removed. Content-level sanitization remains open.
- Framework-profile and behavior signals remain heuristic. No vendor-agnostic performance claim is made; G-VA is pending.
