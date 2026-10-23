# C2Parser v11.1 — Release Notes

v11.1 is a focused reliability and parsing release over v11.0. It improves determinism and HTTP
request-token handling; it adds no new detectors and is **not** claimed
vendor-agnostic (the G-VA vendor-agnostic evaluation is pending).

Framework-profile and behavioral signals remain heuristic: a high or critical score, or a
framework-profile match, is **not** confirmed framework attribution.

## What changed since v11.0

- **D1 / D1b — DNS/DGA determinism.** Deterministic tie handling (lowest client address wins ties)
  in both timing engines.
- **D2 / D2R (+ key grammar) — SMB pipe timing key.** `smb_pipe` timing_series key grammar is now
  `pipe|<client addr:port>|<server addr:port>|<pipe>|<first frame>`, one per TCP connection instance
  (diagnostic `-timing v2` output only).
- **FIX-REUSE — reused TCP 4-tuples.** Connections that reuse a 4-tuple without FIN/RST are now
  parsed (each reuse gets its own reassembly state); previously the second connection's application
  data was dropped.
- **PM-4 — deterministic output.** Deterministic tie handling for TLS certificate/SNI details,
  JA3/JA4 IOC details, UDP end-of-capture flush, scheduler cadence, summary row ordering, and
  request query-parameter carrier token order.
- **Q-07 (CAND2) — per-location request-token decoding.** Query values are not unescaped a second
  time (url.ParseQuery already decoded them, so a base64 `+` is no longer turned into a space);
  path, cookie and custom-header values use url.PathUnescape (decode `%XX`, keep a literal `+`).
  This recovers percent-encoded base64 carried in paths, cookies and headers and stops
  `+`-corruption of request carrier tokens; new carrier detections may appear. Response-side
  decoding is unchanged.

## Accepted-change register (v11.0 → v11.1) — OA-1

The only intended output deltas versus v11.0 are:

1. DNS/DGA tie client and order (D1/D1b);
2. the `smb_pipe` timing key grammar (D2/D2R, R1-03);
3. a second FIN-less reused connection is now parsed (FIX-REUSE);
4. tie-detail and summary ordering is deterministic (PM-4);
5. request-token decoding (Q-07: new carrier detections possible).

Any other output delta is a regression, not an accepted change.

## Known limitations

- A literal `+` in a query **value** is mapped to a space by `url.ParseQuery` (HTTP form semantics)
  before c2parser sees it, so such a token is not recovered.
- One synthetic benign carrier-only series scores high and is tracked as an **FP_OB candidate** (a
  false-positive observation candidate, not a measured real-world false-positive rate).
- v11.1 makes **no vendor-agnostic performance claim**; the G-VA evaluation is pending.
