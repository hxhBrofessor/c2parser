# c2parser v11a review — neutral C2 catch-all layer

_2026-10-17 (historical review; v11a was later published 2026-10-19). Documents the v11a engineering review based on v10.0. The `v11a` tag points to `425897e8c36005e001e6f6254ede16117194f9d2`; release assets are identified by `SHA256SUMS`. v11.0 is planned after v11b. Each item lists spec → observed behavior → resolution → evidence. Results are from local Darwin/arm64 runs with Go 1.27.2. Lab-dependent claims are under "Not verified here" and are **not** claimed as passed._

> **D01 correction (2026-10-18):** This is a historical engineering review,
> not current release acceptance. The original N1 decoder-precedence account
> and corpus tally below were superseded: current N1 preserves v10-compatible
> primary outputs and adds opt-in, unconfirmed Base32/Base58 candidates; the
> current corpus is 45 scenarios (39 baseline + 6 added, with one existing
> scenario modified), evaluated by the corpus test under two engines. The
> local Sliver/Mythic ZIP snapshots have unverified commit identities. Current
> source, evidence and release-gate status are summarized in
> [`docs/reference.md`](reference.md) and the D01 remediation artifacts.

## Baseline

- Before any change: `go vet ./...` clean; `go test ./...` green (lab subtests skip: `C2PARSER_TESTDATA` unset); `git diff --check` clean.
- The working tree already held partial v11a work (WIP decoders, unwired response tokens, family mapping, a baak test rewrite, a first Sliver model). It was kept and finished. Where it was wrong it was corrected, as noted per item.
- Comparison harness (outside the repo): a v10.0 build from `git archive HEAD`, the v10 and v11a corpus generated with each tree's `synthgen` (byte-identical pcaps), every finding compared field by field at `-min-score 0` in both engines.

## Baak fix and Sliver DNS falsification study

| Spec | Finding | Resolution |
|---|---|---|
| Downgrade `dnsfeat.go:12` comment | WIP already generic; pointed at the wrong file | Comment generic, points at `sliverdns_test.go` |
| Rewrite the self-confirming behavior test | WIP `TestDNSConstantFramingPrefix` draws the prefix from the seed and has a no-prefix case | Kept; passes |
| Independent Sliver-DNS model; vary session, type, nonce, ciphertext, length, fragments; benign confusers; never force baak | WIP model used the RFC 4648 alphabet while calling it "custom32", had no protobuf framing, and "no prefix" held only because two sessions split 50/50 against the profiler's 90 % rule; its ciphertext came from `crypto/rand` (non-deterministic) | Model rewritten (`internal/synth/sliverdns.go`) as a parameter sweep: 2 alphabets × {protobuf, fixed} envelope × {1, 3} sessions, seeded. The test asserts that the reported prefix equals the leading columns computed from the generated data, that detection does not depend on a prefix, and that confusers stay < 0.4. Results and the stable/unstable split are in `docs/eval/v11-synthetic.md` |

Findings from the study: one session's header produces a 7–12-char constant prefix; across sessions at most a 1–2-char tag remains. **Profiler limit:** a multi-session protobuf envelope drives `positional_randomness` to 0 (varint widths shift the constant tags). Detection stays critical on other signals. Recorded for v11b, not tuned.

Not changed: `rules/sigma/dns_sliver_beacon_name_shape.yml` still matches `^baak`. It is a separate legacy Sigma rule and remains an unresolved specificity/attribution limitation; the synthetic study does not establish this prefix as universal. D01 did not change this rule's behavior.

## N1 — carrier decoder (current contract)

| Contract | Current implementation and evidence |
|---|---|
| Preserve primary decoding | The v10-compatible primary decoder retains its label, bytes, carrier/location evidence and ordering. The differential regression is in `internal/engine/decodecompat_test.go`. |
| Add alternate interpretations | Base32/Base58 candidates are separate, bounded, explicitly unconfirmed records. They are opt-in via `engine.AnalyzeFileWithCandidates` or CLI `-candidate-json`; they do not affect scores/findings. Sidecar schema version 2. |
| Candidate completeness and publication | Response-body candidates are limited to the retained 512-byte sample; incomplete bodies are omitted and counted. The CLI protects destination aliases and publishes the sidecar atomically. See `.local/v11a-remediation/n1/sidecar-hardening/` and its independent retest. |
| Current corpus | 45 distinct scenarios: 39 original + six added; one existing scenario is modified. The permanent corpus test runs both engines (90 scenario-engine evaluations). |

The detailed historical WIP decoder account from the 2026-10-17 report is
preserved in `.local/v11a-remediation/d01/D01-claim-inventory.md`; it must not
be read as the current N1 contract. Current decoder and sidecar details are in
`docs/reference.md`.

**Pre-existing v10 defect (not fixed, pinned):** every *request* token is `url.QueryUnescape`d, which turns a standard-base64 `+` into a space, so such tokens decode as `raw` (≈ 93 % of a 172-char Cobalt Strike metadata cookie contains a `+`). Query values are even unescaped twice. Fixing it changes existing request findings, which v11a forbids. `TestDecodeTokenV10PlusIsSpace` pins it. Follow-up.

**Resolved by F03:** word runs in response bodies can now produce
`encoded_payload_in_resp` through bounded streamed analysis. The earlier
512-byte-prefix limitation applied to the incomplete implementation and is no
longer current behavior. `TestCarrierWordRunBody`,
`TestCarrierWordRunBodyChunked` and `TestCarrierWordRunBodyGuards` cover
ordinary/chunked responses and variability controls; the corpus scenario also
expects the response signal. This is distinct from N1 candidate generation,
which still omits incomplete response tokens rather than decoding a prefix.

**Unverified:** the Sliver source snapshot's archive identity is not pinned. The local snapshot now permits static inspection of its English encoder and dictionary, but this does not establish historical-version equivalence or universal behavior. The synthetic study remains a model, not framework execution.

## N2 — URI-shape families

| Spec | Resolution |
|---|---|
| Preserve the CS stager emit byte for byte | `httpdefaults.go` untouched; `TestURIShapeStagerFixtures` checks the feature string and 0.35 |
| Family table `checksum8-x86/x64`, `word-dot-ext`, `fixed-uri`; `uri_shape:<family>` ~0.3, `http_client_quirks` | `internal/engine/urishape.go`, weight 0.3. checksum8: 0.5 for a bare hit (contribution 0.15, below "low"), 1.0 when the response was a ≥ 64 KB non-text download. `word-dot-ext`: `/<word>.<php,asp,aspx,jsp,gif,png,jpg,ico,js,css,rss,xml,htm,html>`, scored only when ≥ 80 % of ≥ 5 requests hit it over ≤ 3 distinct URIs (polling, not browsing) |
| `fixed-uri` cap-safe: timing family + `timingPlusFixedURI` guard | `fixed-uri` → `timing` (`stats.FixedURITimingFamily`), **and** a `timingPlusURIShape` guard (mirrors `timingPlusRecon`) applies the timing-only caps to timing + any `uri_shape:*`, because `word-dot-ext`/`checksum8` can ride a beacon too. `acc.capped()` uses the same rule |
| x86 rule decision | **Kept the stricter 4-char rule for x86.** dissect applies none for x86; with no length rule 1 in 256 of all benign paths would match. No lab or corpus case needs the looser rule |

**Decision — `fixed-uri` is a `-timing v2` signal.** Measured with it scored in both engines: the benign Prometheus scrape in `benign-models` rose 0.75 → 0.83 under v1 (0.02 short of critical), and a 10-request apt poll with no real timing signal appeared at 0.30. v1 combines all signals by plain noisy-OR with no families, so a timing-derived signal double-counts the timing. v2 folds it into the timing family. It is emitted only when a timing signal contributes ≥ 0.05. Result: v1 byte-identical; v2 moves the Prometheus finding 0.75 → 0.77 (high → high).

Evidence: `urishape_test.go`. The fleet-gate mutation matrix: each protection alone keeps the series ≤ 0.39, removing both lifts it, and the `word-dot-ext` fleet lifts without the guard. `/api/v4/users` and static-file browsing fire nothing. Two corpus gates: `gate-fleet3-http-{fixed-uri,word-dot-ext}`.

## N3 — pivot frame header

| Spec | Resolution |
|---|---|
| `containsFramePrefix(b, prefixes) (hits, which)`; magic table | `signatures.go`: `knownFrameMagics` (0xDEADBEEF), `containsFramePrefix`; `containsC2Magic` wraps it. Differential fuzz vs the v10 function: identical counts (30 s, 5.7 M execs) |
| Known magic → `c2_framing_in_pipe` unchanged; unknown constant → `pivot_frame_header` ~0.45 | `frameprefix.go`: per pipe and direction, a ≤ 16-entry counter of the 4 bytes at offset 0 and at offset 4 (after a length field). Fires when one value starts ≥ 90 % of ≥ 8 messages. Excluded: DCE/RPC messages (`05 00`), length-encoding values, all-zero/all-0xFF, standard Windows pipes, and pipes that already have a known magic or Mythic hit (no double count). Score `frac·clamp((n−4)/8)`, weight 0.45 |

Evidence: `frameprefix_test.go`. Positives: invented prefix at offset 0 and after an LE32 length. Boundary: 7 messages/direction → none, 8 → fires. Negatives: random data, length-prefixed random data, DCE/RPC on an unknown pipe, the same header on `srvsvc`. A Havoc pipe keeps `c2_framing_in_pipe` and gets no `pivot_frame_header`. Mutation (literal magics only) loses `shape-smb-pipe-framed`.

## M2 — decoded-length residue

| Spec | Resolution |
|---|---|
| `internal/engine/payloadshape.go`, math in `internal/stats` | `stats.LengthResidue` (mod 16, then mod 8; class at ≥ 90 % share); engine trackers per direction for HTTP bodies and SMB pipe messages |
| Guard: ≥ 8 distinct lengths, CV ≥ 0.05 | plus ≥ 8 messages |
| AEAD/CBC framing only, never QUIC | measured only when the aggregate decoded bytes look encrypted (Assess ≥ 0.8 over ≥ 512 B); DCE/RPC excluded; QUIC has no tracker |
| `length_residue`, never critical alone | weight 0.35 (`FuzzPayloadShape` checks contribution < 0.85) |

Decoded length is exact or the message is skipped: raw bodies count as themselves, and encoded bodies only when wholly retained and decoding as one run with no wrapper. Memory: ≤ 2048 lengths and one 256-bin histogram per direction, allocated from that direction's second message (one-shot connections never allocate).

Evidence: `residue_test.go` (classes ≡0/≡4/≡12 mod 16, ≡4 mod 8, uniform, guard boundaries; fuzz 30 s), `payloadshape_test.go`. Corpus: ≡12 (mod 16) on `shape-residue-http-12`, ≡4 on `shape-smb-pipe-framed`. Negatives: uniform, aligned JSON, fixed-size heartbeat, opaque images, QUIC, benign browsing, XOR-8 artifacts. Mutation: dropping the randomness gate measures aligned JSON as ≡0.

## Scoring integration (families)

**Decision: the preferred option, a `payload_shape` family** for `encoded_payload_in_*`, `sig:mythic-agent-message`, `mythic_message_in_pipe`, `pivot_frame_header` and `length_residue`. `payload_randomness` stays for entropy signals. Reason: these say *how* data is carried and framed, a different fact from *how random* it looks. Keeping them apart avoids damping a channel that shows both, and folding the previously unmapped signals into one family can only lower their combined lift (`TestV11aFamilyMappings`). `uri_shape:*` → `http_client_quirks`; `fixed-uri` → `timing`.

- Families only affect `-timing v2` and `family_scores`. v1 scoring has no families, so the mapping cannot move a v1 score.
- The latent bug is fixed: the formerly unmapped signals are mapped. `TestV11aSignalsMapped` checks that every v11a signal emitted on the new scenarios has a family.
- Severity boundaries vs v10.0: the fresh full 45-scenario × two-engine comparison found four crossings, not only the two SMB crossings. `shape-smb-pipe-framed` is the existing-v10-scenario pair (v1 0.74 High → 0.91 Critical; v2 0.62 Medium → 0.81 High). Two additional crossings occur in v11a-added scenarios: `shape-carrier-words` v2 0.84 High → 0.94 Critical and `shape-residue-http-12` v1 0.64 Medium → 0.82 High. The latter two are v10 counterfactuals run on the same S0-generated captures; they were not part of the original v10 corpus. On 2026-10-19, the human owner approved J-E1 as a scoped interpretation for those two v11a-added scenarios and J-E2 as explicit exceptions for the two existing SMB crossings. Gate J is RESOLVED_WITH_OWNER_APPROVED_SCOPED_DISPOSITIONS for exactly these four rows; this is not an unqualified regression PASS, and no other severity crossing is approved. See [the four-crossing comparison](eval/v11-synthetic.md) for the maintained table and rounded-score details.

## Human-owner decisions (2026-10-19)

- **J-E1 APPROVED — scoped interpretation only:** `shape-carrier-words` v2, 0.84 High → 0.94 Critical, and `shape-residue-http-12` v1, 0.64 Medium → 0.82 High. These two v11a-added scenarios are excluded from the v10-only comparison set; this does not authorize other crossings.
- **J-E2 APPROVED — scoped exceptions only:** `shape-smb-pipe-framed` v1, 0.74 High → 0.91 Critical, and v2, 0.62 Medium → 0.81 High. No other existing-scenario crossing is approved.
- **Gate B NOT_APPLICABLE:** the owner states that no NetSupport sample will be provided. This is not a test pass and no substitute sample is used.
- **Gate A WAIVED / UNVERIFIED — HUMAN OWNER (v11a only; 2026-10-19):** the human owner explicitly waived this milestone's lab requirement. The named inputs were `http_c2_enum`, `http_c2_enum…part2`, `smb2-data` and `smb2-wks`; exact filenames and provenance are unavailable. The 16 core capture/engine/Sigma combinations, related recon/RPC/transform checks, and v10 Critical-preservation comparison are NOT RUN / UNVERIFIED, not PASS. The waiver does not extend to v11b or formal v11.0 planning.
- **Gate G CANDIDATE VERIFIED:** candidate CLI version `11a` and the four reproducible target builds are verified; this is candidate readiness only.
- **Publication HOLD:** a local candidate package may be staged for owner review; no Git tag, GitHub Release, upload, deployment or formal publication authorization is included here.

## Historical verification gates (pre-remediation review evidence; not current release acceptance)

| Gate | Result |
|---|---|
| `go vet ./...` | clean |
| `go test ./...` | green |
| `go test -race ./...` (CGO on) | green |
| fuzz 30 s: `FuzzDecodeToken`, `FuzzContainsFramePrefix`, `FuzzPayloadShape`, `FuzzLengthResidue` | pass |
| 4-target builds (darwin arm64/amd64, linux amd64, windows amd64; `CGO_ENABLED=0`) | built (outside the repo) |
| corpus: 45 distinct scenarios, `TestCorpusScenarios` | Current registry count is 45; each case is evaluated under v1 and v2 (90 scenario-engine evaluations). See the D01 claim inventory and current validation log. |
| v1 byte-identity vs v10.0 on the 39 v10 scenarios | identical except the target scenario |
| stress gate `TestStressGateVsBest` (141 cells) | green (stats layer; unaffected) |
| flow-heavy scale, 200k conns, v10.0 vs v11a, same machine, 3 runs each | wall time +1–10 %; peak RSS 1.36–1.44 GB vs 1.39–1.46 GB; findings identical. A first cut was +25 % RSS (per-one-shot residue tracker and response carrier locations); fixed before acceptance |
| `TestScaleFlowHeavy` (darwin) | **fails on darwin for v10.0 and v11a alike**: `Maxrss << 10` assumes Linux KB, macOS reports bytes. Like-for-like: 52.2k vs 54.5k conns/s, RSS/conn lower in v11a. The Linux gate was not run here |
| no lab-derived data in the repo | none added |

## Not verified here

- **Gate A residual risk:** the four prescribed authentic inputs (`http_c2_enum`, `http_c2_enum…part2`, `smb2-data`, `smb2-wks`) were unavailable; exact filenames and provenance were not established. `TestCapture*` 16/16, `TestLabTransforms`, related recon/RPC/transform checks, and unchanged v10 lab Critical findings are NOT RUN / UNVERIFIED. The human-owner waiver applies only to v11a; these checks were not passed. Residual risk is undetected regressions or false positives on those traffic sets and their transforms. Highest-risk lab paths: response carriers on WinRM/WSUS HTTP, `length_residue` on Havoc HTTP/pipe, `uri_shape:*` on any 4-char or `/<word>.<ext>` polling, and the Havoc `gainz` pipe (a synthetic Havoc pipe stands in).
- **Supplemental public traffic:** the campaign covered six PCAPs and 36 runs, including the user-supplied QakBot-labeled case. QakBot used `-min-score 0.2`; supported-protocol relevance remains UNKNOWN. These observations do not replace Gate A, establish family attribution, or provide precision/recall.
- **NetSupport:** NOT_APPLICABLE by human-owner decision because no sample will be supplied; this is not a test PASS.
- Sliver source provenance: a local snapshot is now available under `_reference-sources/sliver/`, but its ZIP commit identity is unverified. The snapshot supports only narrowly cited static facts; synthetic model assumptions and cross-version equivalence remain unverified.
- The Linux `TestScaleFlowHeavy` RSS gate.
- Public v11a release archive, release binaries and tag were published 2026-10-19 (`v11a` → `425897e8c36005e001e6f6254ede16117194f9d2`; assets per `SHA256SUMS`). The four locally preserved candidate binaries and candidate review evidence ZIP are engineering artifacts, not substitutes for the published assets.

## Follow-ups

1. Request-token `+`→space decoding (v10 defect; changes existing findings, so it needs its own change and lab check).
2. `dns_sliver_beacon_name_shape.yml` `^baak` rule (v11b).
3. The positional profiler on multi-session protobuf framing (v11b; the study shows the limit).
4. **Resolved by F03:** bounded streamed response-body word-run analysis; see `TestCarrierWordRunBody`, `TestCarrierWordRunBodyChunked` and `TestCarrierWordRunBodyGuards` above.
5. `TestScaleFlowHeavy` RSS units on darwin.
6. `pivot_frame_header` on raw-TCP pivots (`shape-tcp-pivot-be12` carries constant bytes at offset 4); v11a covers SMB pipes only.
