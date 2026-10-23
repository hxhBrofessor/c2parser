# WS-4 B-4.4 design: HTTP tap for passive CS configuration

Status: design only; no engine or production code changed. Baseline: v11.2
`v11.2/ws4-csconfig` at `2e5ba0eae38422a04cbd13eea99c35244f5a7daf`.
The v11.1 source citations below are pinned to the `v11.1` tag in this
repository. The CLI identity target is
`81819a22e574f6f031a00e8b3f0531f8e86abec568dde6ca62724dbdc0a4fa90`.

## Scope and outcome vocabulary

Only the carver's existing success and failure outcomes are used. A
`STRUCTURALLY_VALID_CONFIG` means the existing `Result()` success contract:
a terminated settings walk, at least three settings, a TYPE_PTR PUBKEY value
containing the anchor OID, and the complete patch. That contract is implemented
in `internal/csconfig/carve.go` and `settings.go`; the engine tap must not
weaken it. `NOT_CARVED` uses the existing reasons `no_anchor`,
`anchor_without_valid_config`, `invalid_xorencoded_wrapper`,
`work_budget_exhausted`, and `resource_limit` (`carve.go:33-44, 450-500`).
`PARTIAL_FACTS` and `UNSUPPORTED_FORMAT` are not API outcomes. There is no
need for either in this design; compressed HTTP bodies are filtered before
carver creation (D1/D10). If S2 later needs either state, that API change is
an owner decision, not a parallel outcome invented in the engine.

Structural validity alone is not enough to publish a framework-named finding.
I recommend an additional evidence-sufficiency gate: require the structurally
valid config plus at least two recognized, non-PUBKEY passive settings, one of
which is SLEEPTIME or JITTER. Only then may the `cs_config:*` signal or any
framework-named title/evidence be emitted. For a structurally valid but thin
config, keep the carver success outcome and suppress only the engine signal;
record an `evidence_insufficient` filter count separately, not as a new
carver reason. The owner must ratify this extra gate (OD-B44-3).

## D1 — Admission

**Recommendation.** Consider completed or in-progress HTTP **responses** only.
Do not tap requests, text media types (`text/*`), or bodies with a non-identity
`Content-Encoding`. Admit a response through one of these narrowly scoped
prefixes:

1. `MZ` at body offset 0. Start a provisional carver after the two-byte
   signature; a complete result is signal-eligible only when the body has at
   least `0x1400` bytes. `0x1400` is the minimum complete `0x1000` patch
   preceded by the `0x400` container prefix used by the synthetic layout; the
   carver still verifies the actual complete patch. Newer `0x1800` patches
   that do not fit fail structural validation.
2. `Content-Type: application/octet-stream`. Start a bounded provisional
   carver when the header is known; a result is signal-eligible only when the
   response has at least 64 KiB. If a valid Content-Length is already below
   64 KiB, skip carver creation. This retains readiness F2's conservative
   generic-binary threshold without buffering 64 KiB outside the carver.
3. A valid xorencoded size header at an allowed prefix offset (0–1023), with a
   decoded size of at least `0x1000`. This is the wrapper's minimum useful
   complete patch length. Probe at most 1032 body bytes; once the header
   validates, create the carver and feed the retained prefix exactly once,
   followed by the stream. The wrapper header is only a prefilter; the carver
   validates its decoded stream, containment, and end/trailer at `Result()`.

Reject known text media and non-identity `Content-Encoding` on every path.
Parse the media type and reject `text/*` plus known text application types such
as `application/json`, `application/xml`, `application/javascript`, and
`application/x-www-form-urlencoded`. For an absent/unknown media type, do not
admit generically: only a body-start MZ signature or a valid xorencoded header
may reach the carver.
For wrapper prefiltering, cap concurrent temporary prefix probes at 32
process-wide; refuse and count `resource_limit` when that small probe pool is
full. Transfer a successful probe's prefix into the carver once, then discard
the probe. MZ and typed octet-stream candidates go directly to a provisional
carver and count against the existing 32-carver limiter. Do not buffer a full
body. The carver itself retains bounded windows
(`internal/csconfig/carve.go:12-24, 107-129`).

The 64 KiB octet-stream threshold is carried forward from readiness F2 to
avoid producing findings for moderate binary downloads. The 0x1400 MZ floor
derives from the minimum patch plus container prefix; the xorencoded floor
derives from the minimum complete patch and its validated size header. MZ or
a valid wrapper header are narrow byte discriminators; generic typed binary
remains the explicit 64 KiB fallback. Temporary wrapper-probe memory is capped
at `32 × 1032` bytes, while provisional carver windows remain under the
existing 32-carver cap.

No corpus or lab captures were inspected or measured in this docs-only slice.
Baseline admissions on v11.1 are **0** because the tap does not exist.
Post-S2 candidate counts are **NOT MEASURED**: the allowed inputs contain no
per-response corpus/lab inventory, and source inspection cannot derive one.
S2 must report, by the frozen 45-scenario corpus and by lab set: responses
seen; each admission branch; carver-created; structurally valid; evidence
sufficient; and counts for each existing `NOT_CARVED` reason. Never infer a
rate from a scenario count. Approval to defer those counts to S2 is OD-B44-2.

**Alternatives.** Keep the old 64 KiB threshold for every branch: simpler, but
misses small plain MZ and xorencoded responses. Admit every non-text body over
64 KiB: simpler, but admits unrelated binary transfers and has no narrow
xorencoded discriminator. Buffer 64 KiB for every undecided response: avoids
provisional carver slots but needs a second capped buffer pool and adds copying.
Admit by content type alone without a size threshold: too broad and can
consume all 32 slots on routine octet-stream responses.

**Source facts.** `headSample` is 512 bytes; `addBody` retains that prefix and
updates a histogram, but not the full body (`v11.1:internal/engine/http.go:37-75`).
`onHTTPMessage` runs only after message completion (`http.go:436-443, 539-562`).
F2 records the earlier 64 KiB, non-text MZ/octet-stream proposal and the
streaming/bounded-memory requirement (`v11b-technical-readiness-review-F2-F4.md:5-16`).
S1F2 currently bounds each decode window and each carver to 32 concurrent
instances (`internal/csconfig/carve.go:12-24, 107-156`).

## D2 — Lifecycle and body delivery

**Recommendation.** Keep the tap state on `httpMsg`, because that object
represents one response body and `addBody` is the only current incremental
body callback. Add a small `stagerTap` helper in `internal/engine/stager.go`
that owns the carver, prefix replay, counters, and one idempotent close path.
`addBody` feeds body bytes after the admission prefilter is satisfied. Since
`head` is only 512 bytes, S2 must add a separate bounded admission-prefix buffer
and replay it once; calling a whole-buffer carve from `onHTTPMessage` cannot
work (`v11.1:internal/engine/http.go:62-95, 539-562`).

`finish()` is the normal ownership boundary: detach `h.msg`, invoke
`onHTTPMessage`, call `Result()` once for a complete admitted response, then
`Close()` in a defer. If the message is truncated, call `Close()` and discard
without emitting a signal. This makes normal end-of-message, bodyless statuses,
chunk terminator, and read-until-close completion converge on one finalizer.
Fixed-length bodies finish at their declared length; chunked bodies finish
after the zero chunk and trailers; bodyless responses finish in `parseHead`
(`v11.1:internal/engine/http.go:210-282, 327-433`).

Every current exceptional path also reaches cleanup:

| Exit | Current source behavior | S2 tap action |
|---|---|---|
| Normal response end | `finish()` calls `onHTTPMessage` (`http.go:436-443`) | `Result()`, then deferred `Close()` |
| TCP gap / malformed chunk / invalid framing | `gap()` marks `truncated` then calls `finish()` (`http.go:144-151, 243-258`) | discard partial result; close |
| Connection close / 4-tuple reuse | `finishConn()` closes both protocol halves once (`engine.go:586-589, 649-660`) | `httpHalf.close()` finalizes; truncated bodies are discarded |
| Closed reassembly stream / compaction | `ReassemblyComplete()` closes halves before compacting (`engine.go:889-925`) | idempotent finalize/close; no retained carver in compacted flow |
| Capture end | `Finish()` flushes assembly and calls `finishConn` for all TCP connections (`engine.go:340-347`) | same `finishConn` path |
| Ingest error | `analyzeFile` returns before `Finish()` and currently only defers reader close and lean-GC release (`engine.go:196-210`) | S2 must add a deferred engine/tap finalizer so all active taps close on this return path |
| Admission refused | `New` returns a non-admitted carver with `resource_limit` (`carve.go:131-156`) | count refusal; no `Feed`; no slot was acquired |

`tcpStream.ReassemblyComplete` and `finishConn` are not interchangeable: both
must be covered because they can close HTTP halves at different lifecycle
points. `sweepConns` only deletes already compacted entries; it does not itself
finish a live HTTP message (`v11.1:internal/engine/engine.go:566-579,
889-925`). S2 should make `stagerTap.Close` idempotent and put a final sweep in
engine teardown as a defensive backstop. The carver's `Close` releases an
admitted limiter slot even without `Result()` (`internal/csconfig/carve.go:515-525`).

**Alternatives.** Keep the tap on the TCP connection: risks mixing multiple
HTTP messages and keeping a limiter slot after one response. Wait until
`onHTTPMessage` to create the carver: impossible because the body has already
been reduced to a 512-byte head and histogram.

## D3 — Limits and refusal

**Recommendation.** Use the process-wide default limiter of 32, shared across
engines and their active response carvers. Keep S1F2's 32 anchor evaluations,
128 pending anchors, and bounded rolling windows unchanged
(`internal/csconfig/carve.go:12-24, 131-156`). On refusal, skip that response,
record exactly one internal `resource_limit` counter, and do not retry or
queue it. A refusal is not an engine finding. `New` does not acquire a slot
when the cap is reached (`carve.go:60-67, 131-156`). v11.1 has no carver
limiter yet; response bytes enter through TCP reassembly, with periodic
assembler flush (`v11.1:internal/engine/engine.go:313-327`).

**Alternatives.** Queue until a slot opens: adds unbounded or separately
bounded pending-body state and makes response completion ordering harder.
Raise the cap adaptively: weakens the memory bound and makes G-4.9 less
predictable.

## D4 — Signal, finding, evidence, and watermark

**Recommendation.** Use one stable signal name: `cs_config:beacon_config`.
Map the `cs_config:` prefix to the existing `default_profile` scoring family
in `internal/stats/families.go`. This follows B-4.4's current family mapping
intent while using the `cs_config:*` namespace reserved for VA-0. Assign
weight `0.35`, score `1.0` only after structural and evidence sufficiency
checks; one signal then contributes at most 0.35, below the medium severity
threshold of 0.40. It can support a combined finding, but cannot make a finding
critical by itself. Profiles never gate independently.

Add the signal to the existing HTTP C2 finding for the client/server/port;
use category `C2 channel`. Keep the ordinary HTTP channel title when an
existing channel finding is present. If no HTTP C2 finding exists because the
request side was not captured or had no other score, create a deterministic
config-specific C2 finding keyed by endpoint; do so only for an evidence-
sufficient result. Title it `HTTP response contains a passive beacon
configuration`; include `Cobalt Strike` only after the sufficiency gate.
There is no new finding if the response was not structurally valid and
evidence sufficient. Existing finding JSON fields are sufficient
(`v11.1:internal/engine/findings.go:36-51`).
The current family mapper's named profile cases are at
`v11.1:internal/stats/families.go:44-80`.

Emit a fixed, deterministic evidence order, only for present fields:

1. `Sleep: <SLEEPTIME>` and `Jitter: <JITTER>` (numeric, no raw bytes).
2. The config's `SUBMITURI`, `USERAGENT`, `HOST_HEADER`, and `PIPENAME`
   settings when present. These are parsed config values, not the observed
   HTTP request URI, User-Agent, or Host header.
3. `Version: <version annotation>` and `Xorencoded: yes|no`.

Cap each attacker-controlled rendered string to 128 UTF-8 bytes, escape
control characters and invalid UTF-8, and omit empty or unknown settings. Do
not render the XOR key, PUBKEY bytes, other raw settings, watermark, or any
unrecognized setting. Watermark is explicitly left out: it is not required
for passive characterization and would add a second attribution mechanism.
Use the annotation as an approximate map result, never an exact version.

**Alternatives.** Use backlog's `cobalt_strike_beacon_config`: this has the
closest legacy register name, but does not satisfy the reserved `cs_config:`
family slot. Give each recovered setting a separate signal: increases output
surface and creates multiple scoring contributions from one config. Use a
weight ≥ 0.40: one config could reach medium without corroboration.

**Conflict to resolve.** The backlog G-4.7 table names a
`cobalt_strike_beacon_config` finding, while the later S1F2 review reserves
`cs_config:*` as the VA-0 registry family. I recommend retaining
`cs_config:beacon_config` and updating the additions-register expected signal
to that exact identifier (OD-B44-1). Do not publish both names as aliases.

## D5 — VA-0 registry and BLIND behavior

**Recommendation.** After VA-0's registry lands, add exactly this family row
using its finalized schema:

| Match kind | Pattern | Class | Reason |
|---|---|---|---|
| `family_prefix` | `cs_config:` | `framework_specific` | Every signal in the reserved WS-4 namespace names or describes a parsed framework configuration. |

Add `Cobalt Strike` to the registry's closed framework-name list. Do not
classify by title text. In FULL mode, the evidence-sufficient finding may name
the framework. In BLIND mode, the signal is suppressed before scoring and
correlation; if it was the only signal, the finding vanishes; if generic
signals remain, rebuild the title/category/evidence from the remaining blind
signals. No BLIND title, detail, evidence, or summary may contain `Cobalt
Strike`. These behaviors follow VA-0 R1/R3/R4 and the S1F2 reserved-family
note; final row serialization must match VA-0's actual schema.

**Alternatives.** Register only the exact signal name: easy to omit a later
`cs_config:*` signal. Suppress with a broad title substring: not fail-closed
and cannot rebuild the finding safely.

## D6 — Output stability and telemetry

**Recommendation.** Do not add fields to `engine.Result`, `Counters`, finding
JSON, or normal text output for the tap. Existing JSON serializes the fixed
result/finding structs (`v11.1:internal/engine/findings.go:17-34;
internal/report/report.go:21-40`). If no evidence-sufficient config is
carved, existing v1/v2 output must remain byte-identical. If a config is
carved, the only default-output delta is the registered finding/signal and
its bounded evidence.

Maintain in-memory counts for admission filter branches and each final
`NOT_CARVED` reason, including `work_budget_exhausted` and `resource_limit`.
Expose them only through the existing opt-in `report.Options.Verbose` text
path, or an eval stats sidecar, both absent from default JSON and normal text
(`v11.1:internal/report/report.go:15-19`). `resource_limit` is counted at refusal; the other
reasons are counted once when `Result()` returns false. A successful result
has no failure reason (`carve.go:450-500`). Do not add a new JSON field just to
report telemetry.

**Alternatives.** Add default result counters: violates no-collateral JSON
identity. Log payload or config data: disallowed and unnecessary. Silently
discard reasons: loses the required capacity/false-carve diagnostics.

## D7 — Synthetic fixtures and additions register

**Recommendation.** Use only synthetic data assembled from the documented
wire facts. Put a small test-local pcap builder and two fixtures in an isolated
`ws4-synthetic` additions lane: one plain `MZ` response and one xorencoded
response. Keep the frozen 45-scenario lane and its expected count unchanged.
Create exactly these expected additions rows, each for v1 and v2:

| Lane | Fixture | Engine | Expected addition |
|---|---|---|---|
| `ws4-synthetic` | `csconfig-plain` | v1 | one `cs_config:beacon_config` signal after evidence sufficiency |
| `ws4-synthetic` | `csconfig-plain` | v2 | one `cs_config:beacon_config` signal after evidence sufficiency |
| `ws4-synthetic` | `csconfig-xorencoded` | v1 | one `cs_config:beacon_config` signal after evidence sufficiency |
| `ws4-synthetic` | `csconfig-xorencoded` | v2 | one `cs_config:beacon_config` signal after evidence sufficiency |

The additions-register tool must see only this additive lane; no rows are
expected for the frozen corpus or lab. Q-09 permits adding corpus scenarios
as a separate C1 test change, but does not require changing the frozen 45
count (`v11.1:internal/engine/corpus_test.go:42-45`;
`v11b-open-questions-for-chatgpt.md:15`; backlog B-4.3 lines 140-143).
No real beacon material, vendor samples, or captured production payloads are
allowed.

**Alternatives.** Put the synthetic case into one of the frozen 45: changes
the frozen lane and its no-collateral baseline. Test only the carver package:
does not exercise HTTP admission, chunk handling, lifecycle, or finding output.

## D8 — RSS, throughput, and 33-response stress

**Recommendation.** Run the G-1.3 paired procedure with `tools/rss_pair.py`
on the same flow-heavy synthetic/approved capture set, five ABBA pairs, on
the same Mac. Compare the exact v11.1 baseline tag with the B-4.4 branch;
pass at median peak RSS ratio ≤ 1.20 and throughput ratio ≥ 0.80. This follows
the corrected baseline, not the older v11a label in the R0 gate table
(`v11b-acceptance-and-gates.md:64`; B-4.4 backlog lines 145-150; C-2 in the
order). The named `tools/rss_pair.py` is not present in the `v11.1` tag's
`tools/` tree (which contains only `perturb` and `synthgen`), and it was not
found in this workspace. S2 therefore needs the reviewed harness path or
owner approval to add it before G-4.9 can run (OD-B44-9). The analysis path
to measure is v11.1 packet ingestion through `Engine.Finish()`
(`v11.1:internal/engine/engine.go:273-327, 340-347`).

Add an engine-level worst-case fixture with at least 33 simultaneous eligible
responses across distinct live HTTP flows. Prove exactly 32 can hold slots,
the 33rd reports one `resource_limit`, and a replacement response is admitted
after each release case: normal end, truncated/gap, connection close/reuse,
chunk framing error, and engine `Finish()`. Include all responses carrying
near-max carver streams to measure peak RSS and throughput, plus a repeated
cycle to expose leaked slots. The separate carver-level 33rd refusal test
does not replace this engine-level stress test (C-3).

**Alternatives.** Measure only one active response: misses cap behavior and
slot leaks. Use one unpaired run: throughput/RSS noise can hide the cost.

## D9 — Determinism in v1, v2, and repeated runs

**Recommendation.** Preserve the carver's settings sequence; if evidence
renders fields from an index map, sort by setting index then by stable field
name. Render the fixed evidence order from D4. Emit at most one
`cs_config:beacon_config` signal per HTTP channel, choosing a deterministic
representative (highest contribution, then lexicographically smallest
canonical evidence tuple) if more than one response qualifies. Do not depend
on map iteration order. v1 and v2 receive the same signal and evidence; only
their established score/family computation differs. Repeat the same synthetic
pcap within each engine mode and compare canonical JSON byte-for-byte; compare
the new signal and evidence across v1/v2 without requiring whole-result
equality because v2 has its established additional output. Existing
finding serialization sorts signals by contribution and name
(`v11.1:internal/stats/combine.go:63-73`) and v2 assigns family scores in
`findings.go:194-212`.

**Alternatives.** Emit one signal per HTTP response: can make evidence
selection depend on message order. Iterate settings or evidence maps directly:
can reorder serialized output. Force v1/v2 to share scoring implementation:
would change established behavior beyond this slice.

## D10 — Risks and stop conditions

**Recommendation.** Stop implementation if any of these occur:

- a no-carve corpus or lab JSON/text output changes;
- a response is admitted without a reproducible, bounded prefix reason;
- the engine cannot close a tap on every completion, gap, teardown, reuse, or
  error path;
- any 33-response run leaks a slot or exceeds the 32-carver cap;
- evidence lacks the owner-approved sufficiency threshold, includes raw bytes,
  or can name the framework in VA-0 BLIND mode;
- G-4.6 changes outside the additions register, G-4.7 contains unregistered
  rows, or G-4.9 misses either bound;
- claiming support for compressed-body decoding would require new decoder
  behavior that the owner has not approved.

These remain open for the owner: the admission thresholds and expected counts;
the minimum passive-setting sufficiency rule; whether compressed stages are
permanently excluded; signal identifier versus the older G-4.7 name; telemetry
presentation; and the exact additive fixture-lane shape. No captures were
examined in this design. These no-collateral requirements are grounded in the
fixed `Result`/`Finding` serialization (`v11.1:internal/engine/findings.go:17-51`)
and report JSON projection (`v11.1:internal/report/report.go:21-40`).

## HTTP compression and chunking (C-4)

In v11.1, `parseHead` records `Content-Encoding` as a header but does not
decompress it. `benignOpaque` treats any non-identity `Content-Encoding` as
opaque for entropy scoring; it does not transform the body
(`v11.1:internal/engine/http.go:327-375, 520-536, 558-562`). Chunked transfer
framing is decoded by the HTTP parser: chunk-size lines, CRLF boundaries, and
trailers are consumed, and only each chunk's payload is passed to `addBody`
(`http.go:210-277, 368-375`). Therefore S2 can receive dechunked body bytes,
but compressed bytes remain compressed. The recommendation is to reject
non-identity content-encoding at admission and not add decompression here. If
the owner wants compressed-stage support, it requires a separate decoder
design and bounded decompression policy (OD-B44-4).

## Implementation outline for B-4.4 S2

**Files.** Add `internal/engine/stager.go` for response eligibility, bounded
prefix replay, per-response lifecycle, reason counters, evidence sanitization,
and signal construction. Extend `httpMsg`/`addBody` and message finalization in
`internal/engine/http.go`. Add the `cs_config:` family mapping in
`internal/stats/families.go`. Touch `findings.go` only if the existing HTTP
channel scorer cannot accept the signal without changing the FULL no-carve
path. Keep telemetry out of `Result` and JSON structs.

**Test-first list.** Before production changes, add synthetic tests for:

1. every D1 branch and rejected text/random inputs; split prefixes at every TCP
   and chunk boundary; no duplicate replay of the retained prefix;
2. plain and xorencoded fixtures, both patch sizes, no MZ requirement for the
   xorencoded case, unsupported `Content-Encoding`, dechunked body handling;
3. all D2 exit paths, truncation suppression, `Close` idempotence, and
   process-wide 32-slot release;
4. 33 concurrent eligible engine responses and release/re-admission after
   each exit path in D8;
5. evidence sufficiency, numeric/string caps, escaping, no raw values,
   watermark exclusion, fixed setting/evidence ordering;
6. v1/v2 and repeat-run canonical JSON identity; FULL no-carve equality; G-4.7
   additions-only rows; VA-0 BLIND suppression/rebuild and framework-name
   scan over titles, details, evidence, and summaries.

**Gates.** G-4.6: compare the frozen 45 corpus and lab outputs against v11.1,
empty register outside synthetic additions, and byte-identical v1/v2 JSON
when no config is carved. G-4.7: register exactly the four synthetic rows in
D7 and no existing scenario. G-4.9: five ABBA RSS/throughput pairs plus the
33-response engine stress. VA-0 BLIND check: framework-specific signal is
removed before score/correlation; finding is absent if nothing generic
remains; rebuilt output contains no registered framework names. This design
does not claim those gates pass; they belong to S2.

## OWNER DECISIONS REQUIRED

1. **OD-B44-1 — Signal/register ID:** approve `cs_config:beacon_config` and
   update G-4.7's legacy expected identifier to it (recommended).
2. **OD-B44-2 — Admission counts:** approve the three admission branches and
   defer post-change corpus/lab counts to S2, with no counts inferred here
   (recommended).
3. **OD-B44-3 — Evidence sufficiency:** approve at least two recognized
   non-PUBKEY settings, including SLEEPTIME or JITTER, before naming the
   framework (recommended).
4. **OD-B44-4 — Compression:** keep non-identity `Content-Encoding` out of
   scope and reject it at admission (recommended).
5. **OD-B44-5 — Telemetry:** keep reason/admission counts in opt-in verbose
   text only, never default JSON or normal output (recommended).
6. **OD-B44-6 — Fixture lane:** approve an additive synthetic-only lane beside
   the frozen 45 scenarios, with the four D7 register rows (recommended).
7. **OD-B44-7 — Watermark:** omit it from evidence (recommended).
8. **OD-B44-8 — Amendments source:** the order states AM-1..AM-8 were adopted,
   but its amendments section does not enumerate their text. Confirm the
   explicit D1-D10 and C-1..C-4 provisions in this document exhaust the
   intended amendments, or provide the missing AM text (recommended: confirm
   this scope before S2).
9. **OD-B44-9 — G-4.9 harness:** provide the reviewed `tools/rss_pair.py` path
   or approve adding/reviewing the harness before S2 (recommended: provide the
   designated tool and preserve the exact five-pair procedure).

## References

- `v11.1` tag source paths cited inline above.
- `v11b-acceptance-and-gates.md`, G-4.6/G-4.7/G-4.9; `v11b-engineering-backlog.md`, B-4.3–B-4.5; `v11b-technical-readiness-review-F2-F4.md`, F2.
- `v11-2-ws4-s1f-review.md`, §4: reserve `cs_config:*` as `framework_specific` for VA-0; `v11-2-va0-s1-order.md`, R1/R3/R4.
- `v11-2-ws4-b44-design-order.md`, D1-D10 and corrections C-1..C-4.

---

# B-4.4 S2 implementation addendum (binding corrections B-1..B-7)

Added for S2 per `v11-2-ws4-b44-design-review.md` (B-1..B-7, AM-1..AM-8) and `OWNER_V11_2_B44_DECISIONS_20261022.md` (OD-B44-1..11; weight **0.60**, feed cap **4 MiB**).

## A. AM-4 lifecycle state machine (B-1)

One owner: `stagerTap` on `httpMsg` (`tap *stagerTap`), created lazily on the first response body fragment. States:

```
UNCLASSIFIED ──first response body──▶ INSPECTING_PREFIX
INSPECTING_PREFIX ──reject (text/*, non-identity CE, CL<64KiB octet, no discriminator)──▶ REJECTED (terminal; no slot held)
INSPECTING_PREFIX ──admit (MZ@0 | octet-stream | validated xorencoded header)──▶ ADMITTED (csconfig.New acquires 1 slot)
   New refused ──▶ REJECTED + count resource_limit (no slot held)
ADMITTED ──Feed each fragment──▶ FEEDING
FEEDING ──fed > 4 MiB without result──▶ FINALIZED (feed_cap_reached; Result/Close release the slot exactly once)
FEEDING ──finish()/truncation/teardown/reuse/ReassemblyComplete/Finish()/ingest-error defer──▶ FINALIZED (release exactly once)
```

Pseudocode:

```
addBody(b):                       # response only
  if state==REJECTED or FINALIZED: return
  if state==UNCLASSIFIED: state=INSPECTING_PREFIX; probe=acquireProbe()  # ≤32 probes
  if state==INSPECTING_PREFIX:
      append b into prefix (cap 1032); decide():
         reject -> state=REJECTED; releaseProbe(); return
         admit  -> carver=csconfig.New(limiter); releaseProbe()
                   if !carver.admitted: count resource_limit; state=REJECTED; return
                   state=ADMITTED; carver.Feed(prefixSoFar); fed=len(prefixSoFar)  # replay once
         undecided (need more bytes, <1032 and not final) -> return
  if state==ADMITTED/FEEDING:
      state=FEEDING; fed+=len(b)
      if fed>4MiB: reason=feed_cap_reached; finalize(emit=false); return
      carver.Feed(b)

finalize(emit):                   # idempotent; from finish()/close()/gap()/defer
  if state in {FINALIZED, REJECTED, UNCLASSIFIED}: carver?.Close(); state=FINALIZED; return
  if truncated or !emit: carver.Close(); state=FINALIZED; return
  cfg,ok = carver.Result()        # releases slot
  if ok and eligible(bodyLen) and sufficient(cfg): store cfg for scoreStager
  else: count the carver Reason() / evidence_insufficient
  carver.Close()                  # idempotent; state=FINALIZED
```

`stagerTap.Close()` is idempotent (guards on `state==FINALIZED`); `Result()` and `Close()` on the carver each release at most once (carver `releaseLocked` guard). No use-after-close: all paths route through `finalize`. Engine backstop: `analyzeFile` adds a deferred `e.finishStagers()` on the ingest-error return, and `Finish()` sweeps any still-open tap.

## B. AM-2 HTTP body decision table (B-2)

Bytes: **wire** (TCP) → **transfer-decoded** (de-chunked; v11.1 `addBody` already receives de-chunked payload, `http.go` chunk path) → **content-decoded** (v11.1 never produces this). The tap feeds **transfer-decoded** bytes only.

| Case | Tap behavior |
|---|---|
| Correct Content-Length | feed body to declared length; finalize at `finish()` |
| Incorrect Content-Length (short/long) | feed what the parser delivers; truncation → discard (no emit) |
| Missing Content-Length (read-until-close) | feed streamed bytes; finalize on close; truncated unless `stUntilClose` |
| Chunked | feed de-chunked payload only (chunk sizes/CRLF/trailers consumed by parser) |
| Compressed (`Content-Encoding` ≠ identity/absent) | **reject at admission**; no carver; no decompression |
| Truncated / gap / malformed chunk | `truncated=true` → finalize(emit=false); Close; no signal |
| Teardown before completion (conn close / 4-tuple reuse) | `httpHalf.close()`/`finishConn` → finalize(emit=false) |
| Oversized (> 4 MiB fed) | stop feeding; `feed_cap_reached`; release slot |
| Misleading stage-like prefix (benign) | carver returns NOT_CARVED (`no_anchor`/`anchor_without_valid_config`); counted; no signal |

No existing HTTP parser contract is changed; the tap only observes `addBody`/`finish`.

## C. B-4 — MZ floor removed

The synthetic `0x1400` floor was circular (derived from the fixture's `0x400` container prefix). **Removed.** MZ@0 admits immediately; the carver validates a complete patch (`0x1000`/`0x1800`) at `Result()`. The octet-stream branch keeps the format-independent **64 KiB** eligibility (signal gated on `bodyLen ≥ 64 KiB` at finalize); the xorencoded branch keeps the decoded-size ≥ `0x1000` header check.

## D. B-3 — per-response feed cap (OD-B44-11)

`stagerFeedCap = 4 MiB`. When cumulative fed bytes exceed it without a result, finalize NOT_CARVED `feed_cap_reached`, release the slot. Not a retained-memory budget — the carver's bounded windows (`3×0x1800`) still govern memory; the cap bounds work/slot-holding so benign large downloads cannot starve the 32-slot pool.

## E. B-7 — tap telemetry counters (verbose only)

Tap-level counters (not carver reasons), in-memory, surfaced only via opt-in verbose text / eval sidecar — never default JSON or normal text: admission branch counts (`mz`, `octet_stream`, `xorencoded`), `resource_limit`, `feed_cap_reached`, `evidence_insufficient`, and the carver `NOT_CARVED` reasons observed at finalize.

## F. B-6 — VA-0 evidence→signal link

The `cs_config:beacon_config` signal, and **every** evidence line and frame for it, go through `acc.evidenceFrom(...)` / `acc.framesFrom(...)` with signal name `cs_config:beacon_config`. In BLIND the signal is `framework_specific` (registry `cs_config:` row), suppressed before scoring/correlation; its evidence/frames are dropped and recorded in the ledger (never projected); a config-only finding disappears; a corroborated finding rebuilds from the surviving generic signals with no `Cobalt Strike` anywhere.

## G. Evidence (D4, OD-B44-7) and signal weight (OD-B44-10)

Weight **0.60**, score 1.0, only after structural validity **and** evidence sufficiency (≥2 recognized non-PUBKEY settings incl. SLEEPTIME or JITTER). Lone config: NoisyOR 0.60 → **medium**, never critical. Evidence order: `Sleep`, `Jitter`, then `SUBMITURI`, `USERAGENT`, `HOST_HEADER`, `PIPENAME` (config values), then `Version:` annotation and `Xorencoded: yes|no`. Each attacker-controlled string capped at 128 UTF-8 bytes; control chars / invalid UTF-8 escaped; no watermark, XOR key, PUBKEY or raw bytes.

## H. S2a corrections (review S2-1..S2-3)

- **S2-1 (probe-slot release, FIXED).** A `stagerTap` is registered in the
  engine's active set as soon as it acquires a pre-admission probe (INSPECTING),
  not only at admission, and `finalize` deregisters on every terminal branch. So
  `closeStagers()` — the `analyzeFile` ingest-error defer and the `Finish()`
  backstop — finalizes INSPECTING taps and releases their probe exactly once.
  Without this, 32 abandoned inspecting responses (common with truncated/corrupt
  pcaps) permanently exhausted the process-global 32-probe pool and silently
  disabled the tap.
- **S2-2 (xorencoded requires Content-Length, accepted limitation).** The
  xorencoded prefilter ties the decoded size to the declared Content-Length
  (within the carver's 256-byte slack). A chunked xorencoded stage that is not
  typed `application/octet-stream` and carries no Content-Length is therefore not
  admitted via the xor branch (MZ@0 and octet-stream still apply). This keeps
  false admissions ~0; it is counted as `xor_unadmitted_no_clen` (tap telemetry,
  verbose/sidecar only) when a valid-size header is seen without a length.
- **S2-3 (worst-case memory bound).** Concurrent tap memory is bounded by
  construction: at most 32 carvers × (2 bounded decode windows of 3×0x1800 B
  each + metadata) + at most 32 pre-admission probes × 1032 B ≈ **1.3 MiB**
  process-wide, independent of body sizes (the 4 MiB feed cap bounds work, not
  retention). The 33-response test proves the cap functionally; G-4.9 need not
  rerun for S2a since only probe bookkeeping and a counter changed (no change to
  the retained-memory model).
