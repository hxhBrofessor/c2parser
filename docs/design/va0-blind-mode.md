# VA-0: framework-blind evidence policy, registry and harness

Status: VA-0 slice 1 (architecture + registry + policy + harness + FULL-vs-BLIND measurement preview).
Test/eval harness only — **no CLI flag, no env var, no product default**. FULL output is byte-identical to the baseline.
Authority: G-VA VA-0..VA-8 (ratified, R0-3), ChatGPT B-3, owner W5-5, owner VA-0 S1 authorization. No thresholds; VA-1/VA-2 unratified.

## 1. Modes and entry point

`EvidenceMode` is exactly `FULL` or `FRAMEWORK_BLIND`; any other value is `INVALID_MODE`.

- FULL is the production path. It is the identity: the scorer runs with `pol == nil` and no BLIND branch executes. `Engine.score()` is unchanged in behaviour.
- BLIND is reachable only through `Engine.EvaluateBlind()` (test/eval only; never called from `Finish`/CLI). It runs the **same** detector pipeline (`scoreCore`) with a non-nil policy, then a blind-safe output projection, and returns FULL findings, BLIND findings and the audit ledger.

`scoreCore(sc)` holds the shared pipeline; `score()` calls it with `sc.pol == nil`. Every BLIND branch is guarded by `sc.pol != nil && sc.pol.Blind`, so the FULL instruction stream is untouched (proven by R6).

## 2. Registry (R1) — closed, data-not-code

Seeded from the R0 `SIGNAL_CLASSIFICATION_MATRIX.csv`, embedded as `internal/engine/va0_registry.json` (`go:embed`). Each signal name resolves by **exact name first**, then by a **registered dynamic family prefix with a closed suffix allow-list**; anything else is `UNKNOWN`.

Classes and BLIND action:
- `framework_specific` → **suppress** (drop the signal before it is stored; record in the ledger).
- `sigma_attribution` → **suppress**; decided by the rule's pinned exact short-id in the registry (today only `sigma:e1f2bf20`), **never** by string-matching the title.
- `generic` → **retain**.
- `derived_correlation` → **rederive** (retain; see §4, R3 bullet). Justified delta from the CSV (which lists the correlation row as MIXED "suppress or rederive"): we rederive, because `correlate`/`scoreRecon` run over the already-blind accumulators, so these signals are naturally recomputed from blind findings only.
- `mixed` → **suppress** for slice 1 (the signal is dropped; its generic siblings in the same finding are kept independently). Sanitising-and-proving-neutral is deferred (OPEN-1).
- `UNKNOWN` → **block = fail closed**: treated as `framework_specific`, suppressed **and** recorded as `unclassified` (R2).

Dynamic families and their closed suffix allow-lists (from R0): `default_profile:` (covenant, merlin, poshc2, cobaltstrike → framework_specific; any other suffix → UNKNOWN/block), `sigma:` (pinned exact id set → class per id; anything else → UNKNOWN/block), `uri_shape:` (checksum8-x86, checksum8-x64 → mixed; word-dot-ext, fixed-uri → generic; else block), `hdr:` (closed anomaly-name set → generic; ua_c2_default, server_c2_default → suppress; else block), `ioc:` (domain/ip/cert/ja3/ja4/ja3s → mixed/suppress), `rpc:` (closed operation allow-list → generic; else block), `sig:` (pe/elf/zip/7z/rar → generic; havoc-demon-header, mythic-agent-message → framework_specific; else block), `encoded_payload_in_` (query/path/cookie/header/resp → generic; else block). No broad string filtering.

### R0 classification deltas (each justified)
| Registry entry | R0 CSV | VA-0 slice 1 | Why |
|---|---|---|---|
| `recon_from_c2_host`, `pivot_from_c2_host`, `same_channel_as_c2` | MIXED (suppress or rederive) | `derived_correlation` → rederive | R3 mandates recomputation from blind findings; `correlate`/`scoreRecon` already read the blind accs, so suppressing at `acc.add` would double-handle and wrongly delete a legitimately rederived join. |
| `pivot_frame_header` | FRAMEWORK_SPECIFIC | **generic** (retained) — S1a/V0-4 | Its detector (`internal/engine/frameprefix.go:191` `pivotFrameSignal`; design note lines 13–18) fires on **any** repeated constant 4-byte prefix (≥90% of ≥8 messages), labelled "unknown constant frame header… No attribution". It is explicitly the non-vendor counterpart of the magic-table `c2_framing_in_pipe` (which stays framework_specific). Per the review rule "detects any repeated constant prefix ⇒ generic". |
| `sigma:50995159/1cc74d57/96cd9d1f/0b00ae2f` | framework_specific (5 bundled) | retained as pinned ids but **not embedded** post-WS-5 S2a (only `sigma:e1f2bf20` ships) | they still get a pinned classification in case loaded via `-sigma`. |

## 3. Fail-closed completeness (R2)

A completeness test enumerates every signal name produced by the corpus (45 scenarios × v1/v2) and the existing unit tests, and fails on any name the registry cannot classify. A mutation case injects a fake name and asserts the test fails. Unregistered dynamic suffixes resolve to UNKNOWN → block, never generic.

## 4. Policy stage placement (R3) and the acc.add bypass checklist

BLIND is applied to the per-finding signal set **before scoring and before correlation**, by suppressing at `acc.add` (the signal-insertion choke point). Because every downstream consumer reads `a.sigs`, this is sufficient for scoring, caps and correlation; the remaining bypasses are handled explicitly. Each R0 bypass:

1. **Finding creation / metadata before signals (`sc.get`).** Existence is decided by the final `score >= 0.05` gate: a finding whose only signals were suppressed has an empty blind set → NoisyOR 0 → dropped. A mixed finding keeps its generic signals and survives with a recomputed (≤ FULL) score. Category/title are projected (§5).
2. **Evidence and frames (`acc.evidence`, `acc.frames`).** Not stored signals; handled by the output projection (§5), which replaces framework names in evidence/detail text. Suppressed-sigma evidence is additionally never emitted (bypass 4).
3. **Detector create decisions inspecting framework signals (`scoreBehavior`).** The create decision may still run, but with the framework signal suppressed the acc carries only its generic signals (or none → dropped by the 0.05 gate). No FULL-path change.
4. **`scoreSigma` host-pair index / folding.** Explicit BLIND guard: a `sigma_attribution` signal that the registry suppresses is never folded and no standalone Sigma finding, evidence or frame is emitted for it (recorded in the ledger).
5. **`correlate` / `scoreRecon` derive from prior findings.** They read `a.score()` over the blind `a.sigs` and `a.capped(...)`, so joins (`pivot_from_c2_host`, `same_channel_as_c2`, `recon_from_c2_host`) fire only when the blind-surviving finding still clears the threshold — i.e. rederived from blind findings only. No separate suppression needed.
6. **Caps inspect signal sets (timing / URI / DNS / recon).** The final loop rebuilds `a.f.Signals` from the blind `a.sigs` before the cap logic, so caps act on the blind set automatically.
7. **`Result.Hosts` / report JSON / summaries.** `hostRisk` is recomputed from the blind findings. Summary strings are passed through the output projection (§5) so no framework name survives in `http_channels`/`smb_files`/`dns_domains` notes.

## 5. Blind-safe output projection (R4, revised by S1a/V0-1)

The primary mechanism is **dropping**, not projecting: an evidence line or frame set is linked to its originating signal (`acc.evidenceFrom` / `acc.framesFrom`), and in BLIND a suppressed signal's evidence and frames are dropped and recorded in the ledger (`evidence_dropped` / `frames_dropped`) — they never appear projected. Wired framework frame sites so far: `c2_framing_in_pipe` magic frames (`findings.go`) and `default_profile:*` frames (`httpdefaults.go`); B-4.4 `cs_config:*` evidence must use the same link so it disappears in BLIND rather than showing up projected.

A closed framework-name list in the registry (Cobalt Strike, Brute Ratel, Havoc, Demon, Mythic, Apollo, Poseidon, Sliver, Covenant, Merlin, PoshC2, Empire; generic words such as "beacon", "pipe", "agent", "profile", "payload", "channel" are **excluded** and documented) drives a residual safety-net projection: any framework name still present in a surviving (generic) finding's title/detail/evidence/summary is **removed with neutral wording** — **no `[framework]` token** (S1a/V0-1: the token itself reveals recognition). With the drop mechanism in place this should rarely fire. Category labels (C2 channel, DNS tunnelling, SMB named-pipe, Sigma match, lateral movement, recon) are semantic, not framework names, and are kept (see §5a).

### 5a. Category derivation (R3 / S1a-V0-3)

Categories are generic semantic labels assigned by the detector at `sc.get`, not framework names, so they are retained in BLIND. The one category that is *framework-origin* is the standalone `Sigma match` finding (`CatSigma`), created only from a Sigma rule hit: when that rule is a suppressed `sigma_attribution` signal, the standalone finding has an empty blind signal set and is dropped by the `score ≥ 0.05` gate, so no framework-origin category survives. A finding that keeps a semantic category (e.g. `C2 channel`) on surviving generic signals keeps that category; the existing title demotion (`HTTP C2 …` → `HTTP channel …` below 0.2) already reflects the blind score. No per-detector category is derived from a framework name. OPEN-4: a finding whose category was chosen by a detector *because* a framework signal fired (not reflected in the signal set) is not separately re-derived in slice 1; none is known among current detectors, tracked as OPEN.

## 5b. Evidence/frame link audit (S1b / V1a-1)

Every `a.evidence` / `a.frames` call that lives in a function which also adds a **suppressed-class** signal (framework_specific / sigma_attribution / mixed / unknown — derived_correlation and generic do not count, they are retained) was audited. An AST guard test (`internal/engine/va0_evlink_test.go`, `TestVA0EvidenceLinkDiscipline`) enforces this going forward: in such a function a plain `evidence`/`frames` call fails the test unless it is converted to `evidenceFrom`/`framesFrom` or carries a justification on the test's allow-list.

**CONVERTED** (tied to a suppressed signal, dropped in BLIND): the two framework *frame* sites, done in S1a —
- `findings.go` `scoreSMB` `c2_framing_in_pipe` magic frames → `framesFrom("c2_framing_in_pipe", …)`;
- `httpdefaults.go` `scoreFrameworkDefaults` `default_profile:*` frames → `framesFrom(profSig, …)`.

**GENERIC** (observed-data companion lines, retained; none names a framework — framework attribution lives only in the suppressed signal's `Detail`, which dies with the signal):

| Function (file) | call | content | why generic |
|---|---|---|---|
| `scoreBehavior` (behavior.go:215,217,330,334 ev; 218,336 fr) | evidence/frames | SNI, connection counts, JA3/JA4, first frame | observed TLS/channel facts; the framework signal is `c2_default_certificate`/`ioc:domain` (suppressed) |
| `scoreCarriers` (findings.go:1022 ev; 1047 fr) | evidence/frames | WebSocket message counts, frame | observed volume; framework signal is `sig:*` (suppressed) |
| `scoreDNS` (findings.go:824,851 ev; 826 fr) | evidence/frames | longest/example DNS names, first frame | observed query names (data, not a framework label); framework signal is `ioc:domain`/`cs_dns_defaults` (suppressed) |
| `scoreHTTP` (findings.go:424,426,429 ev; 394,435 fr) | evidence/frames | request/response counts, User-Agent string, methods/URIs, first frame | observed HTTP facts; framework signal is `sig:*`/`hdr:*` (suppressed). See OPEN-5. |
| `scoreRawStreams` (findings.go:1074 ev; 1075 fr) | evidence/frames | connection counts, frames | observed volume; framework signal is `sig:*` (suppressed) |
| `scoreSMB` (findings.go:602,640 ev; 604,642 fr) | evidence/frames | SMB authenticated user, pipe open/first frames | observed SMB session facts; framework signals (`c2_default_pipe_name`, `mythic_message_in_pipe`, `c2_framing_in_pipe`) are suppressed and their magic frames are the converted site above |

`scoreSigma` (sigmaemit.go) builds its signal name in a local variable (`sigName := "sigma:"+shortID(r)`), so the AST guard does not statically see a non-generic `a.add`; it is nonetheless safe because the function's explicit BLIND guard `continue`s past its `evidence`/`frames` for any suppressed `sigma_attribution` rule (§4 bypass 4). Documented limitation of the static guard.

**OPEN-5 (content-level sanitization):** a GENERIC evidence line can still echo framework *fingerprint* bytes that are not a framework *name* — e.g. `scoreHTTP`'s `User-Agent: <default-profile UA>`. VA-4 (no framework names) holds, but a VA-3 reviewer could re-derive attribution from such content. Slice 1b keeps these lines (dropping them would also remove benign observed data) and tracks content-level sanitization of known default strings with OPEN-1 (mixed-signal handling). Not a blocker for INTEG-2 / B-4.4.

## 6. Audit ledger (R5)

Per finding: the suppressed signal names, their classes (incl. `unclassified` for fail-closed), and the FULL→BLIND score/severity delta (computed by the harness by matching FULL and BLIND findings on their key). Ledger is harness/test-only and never carries raw payload bytes. It is the raw material for VA-3/VA-5.

## 7. FULL identity (R6) and severity (R7)

R6 proof: v1+v2 JSON byte-identical to baseline on all 45 scenarios; empty-register behavior_diff 143/143 changed 0; lab counts identical. R7: all FULL/BLIND comparisons use production `stats.Severity(round2(score))`; boundary tests at raw 0.394/0.395/0.400 take expected values from production rounding.

## 8. WS-4 coupling (R8) and OPEN items

- R8: a registry slot is reserved for `cs_config:` → `framework_specific` (Codex B-4.4 later). `internal/csconfig` is untouched by this slice.
- OPEN-1: `mixed` signals (uri_shape:checksum8-*, cert anomalies with framework detail, ioc:*, hdr:ua_c2_default) are suppressed wholesale in slice 1; the "sanitize detail and independently prove neutral behavior" path (R0) is deferred.
- OPEN-2: summary projection is a text scrub; a structural blind summary builder is deferred.
- OPEN-3: VA-1/VA-2/VA-6 need WS-9 datasets and ratified thresholds.
