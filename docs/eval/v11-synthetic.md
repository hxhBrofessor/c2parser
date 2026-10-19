# v11 synthetic corpus evaluation

> **Regression and robustness evidence only — synthetic data cannot set thresholds or measure real-world accuracy.**

_Historical study dated 2026-10-17; it describes the then-current v11a tree, not a release acceptance result. The current registry contains 45 distinct YAML scenarios: the v10 baseline's 39, six added scenarios, and one existing scenario modified in place. The corpus tests exercise each scenario under both `-timing v1` and `-timing v2`, for 90 scenario-engine evaluations. The scenario generators model C2 and benign traffic shapes; these tests do not estimate real-world prevalence or accuracy._

Reproduce:

```sh
go run ./tools/synthgen -out corpus-out corpus/scenarios
go test ./internal/engine -run 'TestCorpusScenarios|TestCapGateSeedSweep|TestURIShapeCapMutations|TestPivotFrameHeader|TestLengthResidue|TestCarrier|TestGenericDNSWireSweep|TestSliverDNSFalsification' -v
```

## Movement vs v10.0 on the 39 v10 scenarios

Every finding on these 39 shared scenarios was compared field by field (title, score, severity, signals with detail, evidence, families) between an authentic v10.0 build and v11a, at `-min-score 0`, for both engines: 78 scenario-engine outputs. A separate fresh full-corpus comparison also ran all six v11a-added captures against v10 as counterfactuals (45 scenarios × two versions × two engines, 180 CLI runs). Across all 45 scenarios that comparison found four severity crossings; the two added-scenario crossings are shown below and are not part of the 39-scenario historical subset.

| Scenario | Engine | v10.0 | v11a | Why |
|---|---|---|---|---|
| all 39 except `shape-smb-pipe-framed` | **v1 (default)** | — | **byte-identical** | |
| shape-smb-pipe-framed | v1 | 0.74 High | 0.91 Critical | N3 `pivot_frame_header` + M2 `length_residue` (≡ 4 mod 16), combined with existing evidence; J-E2 owner-approved scoped exception |
| shape-smb-pipe-framed | v2 | 0.62 Medium | 0.81 High | same; J-E2 owner-approved scoped exception |
| benign-models (Prometheus `/metrics` scrape) | v2 | 0.75 high | 0.77 high | N2 `uri_shape:fixed-uri` joins the timing family; no boundary crossed |
| gate-poller-scrape, gate-scheduler-{jamf,gpo,wsus,chrony} | v2 | 0.39 | 0.39 | `uri_shape:fixed-uri` added; the cap holds |
| shape-artifacts-http | v2 | 0.97 | 0.97 | `uri_shape:fixed-uri` added; score unchanged |

No other finding changed. In particular, no v10 scenario carries `encoded_payload_in_*` or a Mythic signal, so mapping those to `payload_shape` moves nothing here.

## v11a scenario changes (six added, one existing scenario modified)

| Scenario | Label | What it tests | v10 v1 / v2 (same S0 capture) | v11a v1 / v2 | Gate |
|---|---|---|---|---|---|
| shape-carrier-base32 | c2 | N1: Base32-shaped fresh token per GET (`?d=`) and response body; primary v10-compatible decoder path | 0.93 / 0.93 | 0.93 / 0.93 | `encoded_payload_in_query` and `encoded_payload_in_resp`; primary carrier details remain `base64`; no crossing |
| shape-carrier-base58 | c2 | N1: same, base58 | 0.97 / 0.97 | 0.99 / 0.97 | same; no crossing |
| shape-carrier-words | c2 | N1: same, English word runs (one word per byte); F03 response-body support | 0.85 / 0.84 | 0.97 / 0.94 | v2 High → Critical (0.84 → 0.94); J-E1 owner-approved scoped disposition |
| gate-fleet3-http-fixed-uri | benign | N2: 3-host fleet polling one plain-HTTP URI | 0.39 ×3 / 0.39 ×3 | 0.39 ×3 / 0.39 ×3 | fleet cap holds with `uri_shape:fixed-uri` (v2) |
| gate-fleet3-http-word-dot-ext | benign | N2: 3-host fleet polling `/updates.rss` | 0.39 ×3 / 0.39 ×3 | 0.39 ×3 / 0.39 ×3 | fleet cap holds with `uri_shape:word-dot-ext` |
| shape-residue-http-12 | c2 | M2: base64 POST bodies, decoded lengths ≡ 12 mod 16 | 0.64 / 0.89 | 0.82 / 0.93 | v1 Medium → High (0.64 → 0.82); J-E1 owner-approved scoped disposition |
| shape-smb-pipe-framed | c2 | N3 + M2 on the existing framed pipe | 0.74 / 0.62 | 0.91 / 0.81 | J-E2 owner-approved scoped exception; two crossings (`pivot_frame_header`, `length_residue`) |

The Base32 scenario remains Base32-shaped synthetic input; its reported 0.93
finding does **not** mean the primary decoder identifies Base32. Its carrier
details remain labeled `base64` under the v10-compatible primary path (2 of 40
query tokens and 1 of 40 response bodies pass the random-after-decoding
carrier gate). Optional N1 Base32 candidates are separate, explicitly
unconfirmed interpretations and do not contribute to these scores. The v10
numbers for the six added scenarios are counterfactual runs on the exact S0
captures; they do not mean those scenarios or captures existed in the v10
registry. Only the two SMB rows in the 39-scenario table are shared-corpus
crossings; the full 45-scenario comparison adds the two J-E1 crossings above.

### Mutation checks (each gate tests its rule)

| Rule removed | Effect | Test |
|---|---|---|
| response carriers (`carrierResponses`) | response-side `encoded_payload_in_resp` disappears | `TestCarrierResponseEncodings` |
| CDN / trace-id response-header exclusion | a benign fresh `X-Amz-Cf-Id` fires | `TestCarrierRespIDExclusionMutation` |
| `fixed-uri` → timing family **and** the timing+URI-shape guard | fleet-capped series lifts above 0.39 | `TestURIShapeCapMutations` |
| either one of the two alone | still capped (each protection suffices) | same |
| timing+URI-shape guard (`word-dot-ext` fleet) | lifts above 0.39 in v1 and v2 | same |
| generic frame header (literal 0xDEADBEEF only, v10) | `shape-smb-pipe-framed` loses `pivot_frame_header` | `TestPivotFrameHeaderCorpusMutation` |
| "encrypted-looking" gate on residues | aligned plaintext JSON reports ≡ 0 (mod 16) | `TestLengthResidueRandomGateMutation` |

## Generic DNS wire-shape sweep (synthetic, non-protocol model)

`TestGenericDNSWireSweep` in `internal/engine/sliverdns_test.go` runs the
parameter sweep over `DNSWireModel` in `internal/synth/sliverdns.go`: two
alphabets × two envelope choices × one or three modeled sessions. This is a
generic positional experiment, not the source-grounded Sliver falsification
study. Its generated envelope, payload, alphabet, label length and session
count are fixture parameters, not a Sliver wire contract. The table below is
the generic model's recorded output, not live protocol validation:

| Alphabet | Envelope | Sessions | Reported prefix (len) | Col-0 symbols | Constant / varying cols | Positional score | Remainder alphabet / randomness | `positional_randomness` | `framing_prefix` | Finding |
|---|---|---|---|---|---|---|---|---|---|---|
| RFC 4648 lower | protobuf | 1 | 12 | 1 | 15 / 45 | 0.14 | base32 / 1.00 | yes | yes | 0.97 critical |
| RFC 4648 lower | protobuf | 3 | 2 | 1 | 2 / 58 | 0.00 | base32 / 0.96 | **no** | no | 0.97 critical |
| RFC 4648 lower | fixed | 1 | 7 | 1 | 7 / 53 | 1.00 | base32 / 1.00 | yes | yes | 0.99 critical |
| RFC 4648 lower | fixed | 3 | 0 | 3 | 0 / 60 | 0.42 | base32 / 1.00 | yes | no | 0.97 critical |
| custom32 | protobuf | 1 | 12 | 1 | 15 / 45 | 0.15 | custom32 / 1.00 | yes | yes | 0.97 critical |
| custom32 | protobuf | 3 | 1 | 1 | 1 / 59 | 0.00 | custom32 / 0.96 | **no** | no | 0.97 critical |
| custom32 | fixed | 1 | 7 | 1 | 7 / 53 | 1.00 | custom32 / 1.00 | yes | yes | 0.99 critical |
| custom32 | fixed | 3 | 0 | 2 | 0 / 60 | 0.43 | custom32 / 1.00 | yes | no | 0.97 critical |

In every run the reported prefix equals the leading columns computed from the generated labels themselves (exact = ≥ 90 % columns), and benign confusers stay below 0.4. The literal `baak` never appears.

**Model-only observations:** the fixture's selected alphabet and label-fill
policy are recoverable from the generated cases; its modeled logical/raw
cardinality is 1.00 because the generator creates unique names without
retries. The observed findings and prefixes are properties of those fixtures,
not confirmed Sliver defaults or framework attribution.

**Not a protocol conclusion:** prefixes vary across these fixture parameters.
The study cannot establish whether a prefix in a real capture is a Sliver
literal or protocol field.

The multi-session protobuf case also records a limitation of the positional
feature for that synthetic input. It is not evidence that Sliver uses that
envelope in every profile or release.

## Source-grounded Sliver DNS falsification and matched-control study

`TestSliverDNSFalsification` in `internal/engine/sliverdns_test.go` is a
separate deterministic study. It models poll, mixed and no-prefix traffic from
the narrowly inspected Sliver snapshot properties and compares suspicious
fixtures with matched cached-benign and novel-benign DNS controls. These are
synthetic packets informed by static source inspection; no Sliver software or
live C2 was run, and the archive's commit identity remains unverified.

The current test run reports the following detector scores under both
engines. Values are synthetic outcomes, not prevalence estimates or confirmed
framework attribution:

| Mode | Sessions | Suspicious score v1 / v2 | Cached-benign control v1 / v2 | Novel-benign control v1 / v2 |
|---|---:|---:|---:|---:|
| poll | 1 | 0.97 / 0.97 | 0.19 / 0.19 | 0.96 / 0.96 |
| poll | 3 | 0.91 / 0.92 | 0.27 / 0.28 | 0.96 / 0.96 |
| mixed | 1 | 0.96 / 0.97 | 0.39 / 0.39 | 0.98 / 0.98 |
| mixed | 3 | 0.96 / 0.97 | 0.39 / 0.39 | 0.98 / 0.98 |
| no-prefix | 1 | 0.85 / 0.87 | 0.23 / 0.25 | 0.94 / 0.95 |
| no-prefix | 3 | 0.86 / 0.88 | 0.26 / 0.28 | 0.94 / 0.95 |

The test also models retries (480 of 720 poll queries; 600 of 900 mixed
queries) and single-/multisession cases. These reported values should be
reproduced with `go test -count=1 -v ./internal/engine -run
'^(TestGenericDNSWireSweep|TestSliverDNSFalsification)$'`; the separate
generic sweep must be named explicitly when reproducing the preceding table.

### Source and scoring follow-up

The maintained F07 tests include snapshot-grounded source notes and synthetic
single-/multi-session positives with matched cached benign controls. The
separate R-01 change applies its DNS shape cap only when name reuse is measured
from logical query and distinct-name counts (distinct/logical < 0.4 and the
unique-name set is not saturated). Retries are folded into logical queries.
Missing novelty evidence below 20 logical queries is not treated as measured
reuse; high-novelty channels at 19, 20 and 21 queries remain uncapped. The
independent R-01 review reproduced the boundary tests under both engines.

Residual risks remain: aggregating by zone can dilute novelty across mixed
traffic; short low-novelty channels may be capped when the shape-only rule is
met; novel-hash benign DNS controls can still score highly. A DNS score is
behavioral evidence, not confirmed Sliver attribution. See
`.local/codex-reviews/v11a-r01-independent-closure.md` for the independent
test evidence and limitations.

## Known limits and resolved F03 behavior (v11a)

- **Resolved by F03:** word runs in a response body can produce
  `encoded_payload_in_resp`. The earlier concern that the retained 512-byte
  prefix alone was too short was addressed with bounded streamed body-word
  analysis. `TestCarrierWordRunBody`, `TestCarrierWordRunBodyChunked` and
  `TestCarrierWordRunBodyGuards` cover ordinary and chunked bodies, variability
  guards and the prose negative control. This does not remove the separate
  candidate-decoder completeness limits documented in `docs/reference.md`.
- `uri_shape:fixed-uri` is a `-timing v2` signal only (see `docs/review-v11a.md`, N2).
- `length_residue` measures only exact decoded lengths. HTTP bodies longer than the retained prefix count only when raw binary, and pipe messages only when they are not DCE/RPC. QUIC is never measured.
