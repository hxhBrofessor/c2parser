# Changelog

Default output is the `-timing v1` engine. Entries marked **[default]**
change what a plain `c2parser capture.pcap` run reports; everything else
only affects `-timing v2` or adds new output.

## v11.2

v11.2 adds passive Cobalt Strike beacon-configuration detection and reworks the
built-in Sigma set. Framework-profile and Sigma signals remain heuristic; a
profile or rule match is not confirmed framework attribution.

- **[default] WS-5 / Q-05 — built-in Sigma rules.** The built-in set is one rule
  (`e1f2bf20`, id unchanged; folds into the matching C2 finding as before). The
  legacy `^baak` rule (`50995159`) was retired (measured corpus/lab delta zero;
  Sliver-like DNS is covered by the shape and positional-randomness analysis).
  Three Mythic/Apollo example rules moved to `docs/sigma-examples/` as optional,
  non-authoritative examples — not compiled in; load with `-sigma`/`C2PARSER_SIGMA`.
  The kept rule's metadata was corrected (no unit or person strings; references
  repointed) without changing its id.
- **WS-4 / S1F2 — passive configuration carver.** The standalone
  `internal/csconfig` carver supports plain and xorencoded stages, single-byte
  keys, patch lengths `0x1000` and `0x1800`, and approximate version annotations
  (estimates, not attribution).
- **[default] WS-4 / B-4.4 — HTTP response tap.** A passive tap
  with three admission paths (MZ at offset 0; `application/octet-stream` >= 64 KiB;
  a validated xorencoded header) and a per-response 4 MiB feed cap. It emits
  `cs_config:beacon_config` (weight 0.60) only after structural validation and
  evidence sufficiency (>= 2 recognized non-PUBKEY settings, including SLEEPTIME
  or JITTER). A lone sufficient config is medium, never critical.
- **VA-0 — framework-blind evaluation.** Available from the test/evaluation
  harness only; not a product feature or CLI option. G-VA is pending; no
  vendor-agnostic claim is made.
- **Documentation.** The v11.1 description now says "adds no new detectors";
  request-token parsing may still surface additional carrier detections. The
  diagnostic `-timing v2` `smb_pipe` key grammar remains documented.

### Accepted-change register (v11.1 -> v11.2)

The only intended output deltas versus v11.1 are:

1. **AC-1 (Sigma set):** no change on the synthetic corpus (no built-in rule
   fires); on the project's private lab captures, findings that match the built-in
   rule change in text only — the rule title in the signal detail and the renamed
   rule file in the evidence; score, severity, signal names and weights are
   identical.
2. **AC-2 (B-4.4 tap):** no corpus or lab change (no CS config present); a new
   `cs_config:beacon_config` signal/finding appears only on inputs that carry a
   sufficient carved CS configuration.
3. **AC-3 (VA-0):** test/eval harness only; zero FULL output change.
4. **AC-4 (version/docs):** version string 11.2 and documentation; no other code
   change beyond AC-1 to AC-3.

Any other output delta is a regression.

### Known limitations

- **Sigma rule packs affect scores.** By default C2Parser refreshes community
  SigmaHQ rules (at most once a day) and loads them alongside its single built-in
  rule. A matching community rule can raise a finding's score (one user-agent rule
  contributed up to 0.68 in a synthetic test), so results can differ with the
  state of the rule cache. For reproducible results use `-offline -no-sigma-update`
  (optionally with `-sigma-cache <dir>`). A Sigma match is not confirmed framework
  attribution.
- **Synthetic benign control (FP_OB).** A synthetic benign HTTP series scores high
  only when a community Sigma user-agent rule is loaded; its score is driven by
  that rule and a browser-header anomaly in the fixture, not by the random cookie
  values or by timing. With the built-in rules only it scores medium (v1) or low
  (v2). A synthetic observation, not a measured false-positive rate.
- **B-4.4:** no decompression; xorencoded admission requires a `Content-Length`;
  4.11 obfuscation, guardrails and multi-byte keys are `NOT_CARVED`.
- **Framework-blind evaluation (mixed signals):** mixed signals are suppressed
  wholesale; sanitizing a mixed signal while proving neutral behavior remains open.
- **Framework-blind evaluation (generic evidence):** surviving generic evidence
  may retain framework fingerprint bytes; content-level sanitization remains open.
- No vendor-agnostic performance claim; G-VA is pending.

A profile or rule match is not confirmed framework attribution.

## v11.1

v11.1 is a focused reliability and parsing release. It improves determinism and HTTP
request-token handling over v11.0; it adds no new detectors and is **not**
claimed vendor-agnostic (the G-VA vendor-agnostic evaluation is pending). Framework-profile and
behavioral signals remain heuristic: a high or critical score, or a profile match, is not
confirmed framework attribution.

**Summary of changes since v11.0**

- **D1 / D1b** — deterministic DNS/DGA tie handling (lowest client address wins ties) in both timing
  engines.
- **D2 / D2R (+ key grammar)** — `smb_pipe` timing_series key grammar is now
  `pipe|<client addr:port>|<server addr:port>|<pipe>|<first frame>`, one per TCP connection instance
  (diagnostic `-timing v2` output only).
- **FIX-REUSE** — TCP connections that reuse a 4-tuple without FIN/RST are now parsed (each reuse
  gets its own reassembly state); previously the second connection's application data was dropped.
- **PM-4** — deterministic tie handling for TLS certificate/SNI details, JA3/JA4 IOC details, UDP
  end-of-capture flush, scheduler cadence, summary row ordering, and request query-parameter carrier
  token order.
- **Q-07 (CAND2)** — request carrier tokens are unescaped per location: query values are not
  unescaped a second time (url.ParseQuery already decoded them), and path/cookie/custom-header values
  use url.PathUnescape (decode `%XX`, keep a literal `+`). Response-side decoding is unchanged.

**Accepted-change register (v11.0 → v11.1, OA-1).** The only intended output deltas versus v11.0 are:
(1) DNS/DGA tie client and order (D1/D1b); (2) the `smb_pipe` timing key grammar (D2/D2R, R1-03);
(3) a second FIN-less reused connection is now parsed (FIX-REUSE); (4) tie-detail and summary
ordering is deterministic (PM-4); (5) request-token decoding (Q-07, which may surface new carrier
detections). Any other output delta is a regression, not an accepted change.

**Known limitations.** A literal `+` in a query *value* is mapped to a space by `url.ParseQuery`
before c2parser sees it (HTTP form semantics), so such a token is not recovered. One synthetic
benign carrier-only series scores high and is tracked as an FP_OB candidate (a false-positive
observation candidate, not a measured real-world false-positive rate). v11.1 makes no
vendor-agnostic performance claim; G-VA remains pending.

### Change log (v11.1)
- **[default]** Request carrier tokens are now unescaped per location (Q-07): query values are not
  unescaped a second time (url.ParseQuery already decoded them, so a base64 `+` is no longer turned
  into a space), and path, cookie and custom-header values use url.PathUnescape (decode `%XX`, keep
  a literal `+`). This recovers percent-encoded base64 carried in paths, cookies and headers and
  stops `+`-corruption of request carrier tokens; new carrier detections may appear. Response-side
  decoding is unchanged.
- Deterministic tie handling for TLS certificate/SNI details, JA3/JA4 IOC details, UDP end-of-capture flush,
  scheduler cadence, and summary row ordering (PM-4).
- Deterministic request query-parameter carrier token order (url.ParseQuery keys iterated sorted; value order
  kept), so findings no longer depend on Go map iteration order (PM-4).
- Deterministic DNS/DGA tie order in both timing engines (lowest client address wins ties).
- smb_pipe timing_series[].key grammar is now
  `pipe|<client addr:port>|<server addr:port>|<pipe>|<first frame>`, one per TCP connection instance;
  diagnostic -timing v2 output only.
- TCP connections that reuse a 4-tuple without FIN/RST are now parsed (each reuse gets its own reassembly state);
  previously the second connection's application data was dropped.

## v11.0 — release (v11a + v11b)
CLI version `11.0` is reported as `c2parser 11.0`. v11.0 contains the v11a
changes below plus the v11b work summarized here. Behavior-oriented C2
heuristics and compatibility signals remain heuristic: a high or critical
score, or a framework profile match, is not confirmed framework attribution.

**Gate A: PASS** for v11.0 (owner disposition
`1bb3aedd403d29f90460440db84b626edddb49035d57ade06579865527fe3158`,
2026-10-21). This replaces the v11a Gate A waiver for v11.0; that waiver
applied to v11a only and does not carry forward. On the four authentic lab
captures, G-A1 (capture fingerprint contract), G-A2 (33/33 required lab tests,
including all 16 capture/engine/Sigma cells, with zero skips) and G-A3 (lab CLI
diff: v10.0 Critical findings preserved; v11a → v11b empty register; v10.0 →
v11b changes owner-registered) passed with no waivers. The only v10.0 → v11b
lab finding changes are the v11a signals `length_residue` and
`uri_shape:fixed-uri` (`-timing v2`) added to an HTTP C2 finding; its score
and severity are unchanged.

- **Framework profile registry (WS-3).** An embedded, strictly validated
  `data/framework-fingerprints.yaml` with per-field-group evidence and source
  records. The Covenant, Merlin, PoshC2 and Cobalt Strike HTTP defaults and
  six static certificate identities moved from code tables into the
  registry. Each migration was frozen against the v11a behavior first, and
  detection output is unchanged.
- **Profile and evidence contract hardening (B-3.4).** The loader rejects
  YAML aliases, anchors, custom tags, duplicate and unknown keys, and matcher
  items outside the registered grammars. It enforces evidence and source
  rules, certificate registry ownership and HTTP weight validation. The PoshC2
  D-07 JSON evidence terminators are repaired.
- **Stress and scale harness.** The stress gate compares against a stored
  v10.0 baseline, and the scale gate compares against v10.0. Darwin peak-RSS
  units are corrected (macOS reports bytes, not KB).
- **Tests.** `FuzzParseProfiles` fuzzes the profile loader (test-only).
- **Known issues (fixed in v11.1).**
  - **GA3-D1:** with `-timing v2`, the order of `timing_series` entries is
    not reproducible between runs, because DNS series are emitted in Go map
    order. Findings are unaffected in all lab runs. Present since v10.0 or
    earlier.
  - **GA3-D2:** with `-timing v2`, `smb_pipe` timing entries can repeat with
    the same (site, key) when one named pipe appears on several connections.
    The copies are identical, and findings are unaffected. Present in all
    versions.
- WS-4 (Cobalt Strike configuration carving) is not part of v11.0.

## v11a — released 2026-10-19
Candidate CLI version `11a` is reported as `c2parser 11a`. Behavior-oriented C2 heuristics and compatibility signals remain heuristic: a high or critical score is not confirmed framework attribution. On the 39 v10 corpus scenarios, `-timing v1` output is byte-identical to v10.0 except `shape-smb-pipe-framed` (J-E2 owner-approved scoped exception). The full 45-scenario, two-engine comparison has four owner-approved scoped dispositions (J-E1 for two v11a-added scenarios and J-E2 for the two SMB comparisons); this is not an unqualified regression PASS. See `docs/eval/v11-synthetic.md` for the four-row register.
Separately, all 39 shared synthetic PCAPs were byte-identical when generated
by v10 and S0. The human owner waived Gate A for v11a only on 2026-10-19.
The required lab executions and v10 Critical-preservation comparison remain
NOT RUN / UNVERIFIED, not PASS; the six public PCAPs are supplemental and do
not replace prescribed lab evidence (`docs/review-v11a.md`).

- **Carriers: additive Base32/Base58 candidates (N1).** The v10-compatible
  primary decoder keeps its labels and bytes. The opt-in API and
  `-candidate-json` sidecar expose bounded, syntactically valid alternate
  Base32/Base58 interpretations as explicitly unconfirmed candidates. A
  successful decode does not identify the intended encoding; candidates do
  not affect scoring or findings. The historical word-run carrier detector
  is separate from these alternate candidates.
- **[default] Carriers: responses (N1).** Non-standard response headers
  and the retained response-body prefix feed the same path as
  `encoded_payload_in_resp`; CDN / trace-id headers, ID values, opaque
  content types and tokens that don't decode are skipped.
- **[default] Carrier evidence names a constant wrapper (N1):**
  `…, constant prefix "SESSIONID="`. Detail text only.
- **[default] URI shapes (N2).** `uri_shape:checksum8-x86`/`-x64` (0.5 for
  a bare 4-char stager path, 1.0 when followed by a ≥ 64 KB download) and
  `uri_shape:word-dot-ext` (a polled `/<word>.<ext>`), weight 0.3,
  family `http_client_quirks`. The Cobalt Strike default-profile stager
  feature is unchanged. Timing plus URI shapes takes the timing-only caps.
- **`uri_shape:fixed-uri` (N2, `-timing v2` only).** One URI on a beacon
  cadence, in the `timing` family; capped like timing.
- **[default] `pivot_frame_header` (N3).** An unknown constant 4-byte
  header (offset 0, or after a length field) on ≥ 90 % of ≥ 8 messages of
  a non-standard named pipe, weight 0.45. Known magics keep
  `c2_framing_in_pipe`; `containsFramePrefix` generalises the
  0xDEADBEEF scan with identical counts.
- **[default] `length_residue` (M2).** Decoded message lengths in one
  residue class mod 16 / mod 8 on an encrypted-looking HTTP or pipe
  channel (≥ 8 messages, ≥ 8 distinct lengths, CV ≥ 0.05), weight 0.35.
  Never on QUIC, plaintext or DCE/RPC.
- **`payload_shape` family.** `encoded_payload_in_*`,
  `sig:mythic-agent-message`, `mythic_message_in_pipe`,
  `pivot_frame_header` and `length_residue` are no longer `unmapped`
  (`-timing v2` and `family_scores` only).
- **Sliver DNS shape analysis:** the positional profiler does not assume a
  literal `baak` prefix, and the seeded test-only study varies model alphabet,
  envelope and sessions (`docs/eval/v11-synthetic.md`). A separate built-in
  Sigma rule still matches the legacy `^baak` pattern; it remains an
  unresolved attribution limitation and is not evidence that the broader DNS
  detector identifies Sliver.
- synthgen: `base58` and `words` encodings and a `wrap` (prepend/append)
  content option; six scenarios were added and one existing scenario was
  modified. The current corpus has 45 distinct scenarios (39 original plus
  six additions), exercised under both engines.

### Additional verified default-output behavior

The v10.0 comparison used the original 39 scenarios under both engines. At
the scenario-by-engine comparison level, nine original runs differ: one v1
run and eight v2 runs. The v1 difference is the intended
`shape-smb-pipe-framed` target (0.74 high → 0.91 critical). In v2, the same
target moves 0.62 medium → 0.81 high; `benign-models` Prometheus moves 0.75 →
0.77 and remains high; the four `gate-poller-scrape` findings and the
`gate-scheduler-chrony`, `gate-scheduler-gpo`, `gate-scheduler-jamf` and
`gate-scheduler-wsus` findings remain at 0.39 while gaining
`uri_shape:fixed-uri`; `shape-artifacts-http` remains at 0.97 while gaining
that signal. These are nine scenario-engine comparisons, not nine new corpus
scenarios. They do not establish lab or release acceptance.

The following entries describe verified behavior in the unreleased v11a
working tree. Some are new v11a capabilities relative to v10; the remediation
notes identify fixes to the uncommitted v11a implementation, not claims about
a prior tagged release.

- **[default] F03 — response-body word-run evidence (v11a capability; F03
  resolved a draft limitation).** Bounded streamed analysis recognizes fresh,
  random-after-decoding English word runs in HTTP response bodies and can emit
  `encoded_payload_in_resp`, including across chunk boundaries. Ordinary prose
  and variability controls remain guarded. The N1 alternate-candidate path
  retains its separate incomplete-body omission rules.
- **[default] F05 — merged frame-header evidence (v11a capability; merge
  correction within the uncommitted tree).** Bounded per-direction candidate
  counts are merged deterministically by descending count and then byte value,
  so a dominant unknown 4-byte pipe header survives record consolidation.
  Existing known frame-magic behavior is preserved.
- **[default] F06 — first eligible residue sample (v11a capability; sample
  accounting correction within the uncommitted tree).** The first eligible
  decoded message length contributes to `length_residue` after later samples
  allocate the tracker; a one-shot connection still allocates no tracker.
  First-sample payload bytes are not included in the randomness histogram.
- **[default] F09 — qualified Mythic-style detail text (v11a heuristic
  wording).** UUID-prefix and related Mythic-style operator details now say
  that attribution is unconfirmed and describe the observed framing/token
  structure. Signal identifiers, scores and classifications are unchanged.

### Corrections to the uncommitted v11a implementation

These entries record remediation behavior and must not be read as new v10
release history:

- **[default] F01 — composed score caps.** Timing, reconnaissance and URI-shape
  evidence now use the applicable combined cap; independent payload evidence
  can still lift it. The `/updates.rss` regression remains 0.84 high instead
  of receiving the draft's erroneous critical elevation.
- **[default] F02 — structured-response suppression.** Random-looking values
  in structured response fields do not count as independent encoded-payload
  evidence unless request-side encoded payload corroborates the exchange;
  bare carrier and corroborated positives remain available.
- **[default] F07/R-01 — measured DNS-name-reuse cap.** The shape-only cap now
  requires actually measured name reuse and an unsaturated unique-name set.
  Missing novelty evidence is not treated as reuse, and high-novelty traffic
  below 20 logical queries is not capped on that basis. This corrects the
  draft guard's suspicious high-novelty false negative while retaining
  matched cached-benign controls. DNS scores remain behavioral evidence, not
  Sliver attribution.
- **[default] F03, F05, F06 and F09** are the response-body, deterministic
  merge, first-sample and wording corrections described above; these changes
  repair behavior in the uncommitted v11a tree and do not revise v10 release
  claims.

### D01 evidence and readiness note

The v11a corpus count is 45 distinct scenarios, not 46: 39 are present at the
v10 baseline, six YAML scenarios were added, and the existing
`shape-smb-pipe-framed` scenario was edited. `TestCorpusScenarios` exercises
each scenario under v1 and v2 (90 scenario-engine evaluations). This count is
separate from the parameterized Sliver DNS study cases and Go unit tests.

v11a release acceptance remains **HOLD**. Local Go and synthetic regression
results do not substitute for the unavailable lab captures/transform gates,
NetSupport capture threshold, Linux runtime/scale comparison, a current stress
baseline, live Sigma validation, or real-data manifests. See
[`docs/reference.md`](docs/reference.md#v11a-acceptance-evidence) for the
evidence table and platform limits. Mythic profile defaults named by current
compatibility rules are not established by the locally preserved Mythic core
snapshot; those labels remain an unresolved provenance limitation.

## v10.0 — 2026-10-15 (release)
Closes the v10 cycle: v10a (data readiness, raw-TCP DCE/RPC + DC guard,
AD recon, QUIC Initial → JA4 `q`), v10a.1 (lab fixes) and the commit-1
fixes below. Lab-validated on the four GOAD/Havoc captures: 16/16 capture
subtests plus the RPC/recon/QUIC gates; findings ≥ 0.4 identical to v9.0.
Payload shape, Sliver/h2c/defaults, CS-1/CS-2 and data-driven calibration
move to v11. `-timing v1` stays the default.

- **Startup banner.** A multi-colour `C2PARSER` banner leads every run (any flags, `eval` too). It goes to stderr and only on an interactive terminal, so stdout, pipes and CI logs are unchanged. `NO_COLOR` prints it plain; `-no-banner` or `C2PARSER_NO_BANNER=1` turns it off.

### Commit 1 (from the v10a.1 lab review)
- **[default] Group Policy refresh is not ACL collection.** SD_FLAGS reads
  of GPO security descriptors under `CN=Policies,CN=System` (the Windows
  Group Policy client, every refresh) no longer raise
  `ldap_acl_collection`. Before this, every domain workstation could get a
  medium standalone "AD reconnaissance" finding (0.45).
- **[default] Capped C2 findings don't correlate.** A beacon capped as
  fleet/poller/scheduler traffic (0.39) no longer lends
  `pivot_from_c2_host` to the host's pipes or `same_channel_as_c2` to its
  uploads.
- synthgen: `content.sasl: ntlm|krb` for `ldap` streams; the `logon`
  preset includes the gpsvc GPO security read; `benign-domain-logon` runs
  Kerberos-signed (RRC 12).

## v10a.1 — 2026-10-15
- **[default] Windows-signed LDAP is read.** Kerberos wrap tokens with a
  rotated checksum (RRC = 12, the Windows default for signed, unsealed LDAP)
  are unrotated, so recon detection now sees ADSI / .NET / PowerView
  traffic. In v10a it was counted as sealed volume.
- **[default] `ldap_acl_sweep`** (recon, 0.5): security descriptors read one
  object at a time (base scope + SD_FLAGS) on ≥ 10 distinct account objects
  within 10 minutes. `ldap_bulk_enum` also fires for a bare user/person
  subtree search that completed and returned every account, so small
  domains count.
- **[default] Recon joins only uncapped findings.** A fleet/poller/scheduler-
  capped series no longer takes `recon_from_c2_host` (in v10a it could, and
  lost its 0.39 cap). Timing plus recon alone is capped at 0.84 (never
  critical).
- `-timing v2` `family_scores`: signals with no named family are reported
  together as `unmapped` (scores unchanged).
- `c2parser eval`: `-calibrate` refuses below 1000 benign series;
  `report.json` adds `default_flip_gate`.
- Corpus: 39 scenarios (+ `benign-aduc-browsing`, `shape-ldap-acl-sweep`);
  synthgen LDAP presets `acl-sweep`, `aduc`.

## v10a — 2026-10-15
- **[default] Raw-TCP DCE/RPC.** DCE/RPC is found by its PDU header on any
  TCP port, not just SMB pipes, and fragments are reassembled. `rpc_calls`
  gains rows with `transport: tcp`, and new fields `ports`, `learned`
  (`ept_map`/`oxid`, when the interface came from an endpoint-mapper or DCOM
  answer instead of a BIND) and `auth_level`. WMI `ExecMethod` and DCOM
  activation over tcp are scored like their pipe forms ("Remote execution
  over DCE/RPC tcp/N"). A BIND_ACK rejection drops the context.
- **[default] DC guard.** `DRSGetNCChanges` from a domain controller (seen
  serving Kerberos/LDAP or drsuapi, or named with the new `-dc` flag) is an
  info "DC replication" finding; from any other host it raises
  `dcsync_from_non_dc` (0.8: high, not critical alone). The old generic
  DCSync row is gone from the risk table.
- **[default] MS-TSTS interfaces named** in `rpc_calls` (TermSrvSession,
  TermSrvEnumeration, RCMPublic …; opnums unnamed). lsarpc opnum 77 shows as
  `LsarLookupNames4`; fuller drsuapi/samr/netlogon/EPM opnum tables.
- **[default] AD reconnaissance.** LDAP searches (also inside NTLM/Kerberos
  SASL wraps; sealed sessions count volume only) and samr / MS-TSTS
  enumeration. From a host with a C2 or pivot finding ≥ 0.6 the recon joins
  that finding (`recon_from_c2_host` + "AD recon: <filter>" evidence) and
  can raise its score. Elsewhere it is a new "AD reconnaissance" finding
  capped at medium. rootDSE, GPO reads, single-account lookups and DC↔DC
  traffic are never scored.
- **[default] QUIC SNI and JA4.** Client Initials are decrypted (RFC 9001 /
  9369 keys from the DCID). QUIC channels in `top_talkers` carry `sni` and a
  `q…` JA4. New counters `quic_initial_flows`, `quic_client_hellos`,
  `quic_initial_errors`. Under `-timing v2` QUIC series join the K1 name
  key, so a QUIC beacon over several IPs is one finding.
- `c2parser eval`: manifest schema v2 (strict; globs; rotated segments;
  roles c2/benign/mixed; labels by Zeek conn.log UID join, per capture or by
  time window; internal override; expected host-hours) and `-check`, `-j N`,
  `-calibrate`. Report v2: `report.md` + `report.json` with confidence
  intervals, FP per benign host-hour by severity, top 20 benign findings,
  destination prevalence, jitter-cell TPR and `detection_vs_jitter.csv`. A
  synthetic-only report with < 1000 benign series refuses operating points.
  v8/v9 manifests still load.
- Calibration harness (`internal/eval/calibrate.go`): L2 logistic regression
  over family scores, nested leave-one-framework-out, Platt scaling. It
  writes proposed weights only.
- `synthgen`: transports `quic`, `ldap`, `dcerpc-tcp`; `-zeek` writes a Zeek
  conn.log and a UID label file per capture. Corpus: 37 scenarios.
- `TestScaleFlowHeavy` reports kpkt/s and connections/s and gates against
  the stored v9.0 baseline (> 20 % regression fails).
- Go 1.24 (stdlib `crypto/hkdf`).

## v9.0 (v9c) — 2026-10-14
- **[default] Fleet threshold is relative.** The fleet reason for capping a
  timing-only finding at 0.39 now needs ≥ max(3, 25 % of active internal
  clients) on one destination with the same cadence (v9b: 2). A beacon on a
  handful of hosts is no longer explained away. Capped findings say
  "fleet-wide periodic destination (N of M hosts)" and stay in JSON and in
  text at the default `-min-score`.
- **[default] Internal poller reason.** One internal client reaching ≥ 3
  internal servers on the same cadence (monitoring scrapes, backup and
  inventory agents) is capped at 0.39 as "internal poller (N targets)".
- **[default] More scheduler shapes:** the MDM check-in ladder (3 min ×5,
  15 min ×8, then ~8 h with push syncs) and the browser updater (5 h +
  U(0, 60 s), sometimes 6 h).
- **[default] WireGuard rule, port-aware.** UDP with the WireGuard keep-alive
  shape (32 B both ways, ~25 s) is capped as a benign keep-alive, except
  on UDP 53. On 53 with non-DNS payloads it raises the new
  `wireguard_shape_on_dns_port` signal (0.4, family `transport_anomaly`),
  because UDP 53 is a C2 WireGuard-transport default.
- **[default] TLS inside HTTP CONNECT.** After a 2xx to `CONNECT host:port`,
  the tunnel's TLS handshake is parsed. Inner SNI, JA3/JA4 and certificate
  land on the proxy channel. A new "Beaconing client → host:port via proxy
  … (HTTP CONNECT)" finding scores the tunnel's timing under the CONNECT
  target. Non-TLS tunnels are unchanged.
- **[default] WebSocket push mode.** An upgrade with `Accept-Type: Push` is
  classified `push_or_saas`. Under `-timing v2` its timing is refused; both
  engines add a low-weight `websocket_push_mode` annotation (+0.08 on the
  synthetic push channel).
- **[default] Output determinism.** Signals with equal contributions are
  ordered by name. They used to come out in random order between runs.
  `dns_domains` ties are ordered by name.
- **[default] Summary tables capped** at 5000 rows each (`http_channels`,
  `dns_domains`; `-max-summary-rows`). Dropped rows are counted in
  `counters.summary_rows_dropped`; findings are unaffected. Per-series event
  arrays share one cap (`-max-series-events`, default 200000, as before for
  channel bursts, now also for HTTP requests, DNS queries, pipe operations
  and WebSocket messages); drops are counted in
  `counters.series_events_dropped`.
- `-timing v2`: a beacon spread over redirector IPs behind one SNI/Host is
  **one** finding keyed by (client, name), with the K1 series as its timing
  and the per-IP channels listed as evidence. Per-IP findings are merged
  into it. v1 is unchanged (it has no K1 series).
- **`-j N`** analyses several capture files concurrently. Output stays in
  argument order and is identical to `-j 1`. Memory ≈ N × per-file peak.
- **Memory:** closed connections release their parsers and buffers, and
  per-channel tallies keep one key inline. Lookups that were quadratic per
  host (JA4/User-Agent destinations) are now constant. Above 512 MB of
  live heap the GC runs leaner (`-lean-gc-mb`). Flow-heavy scale scenario
  at 200k connections: 11.2 → 5.3–5.5 KB of peak RSS per connection;
  throughput up 18 %.
- `-version`.
- Tools: `synthgen -scale N`; scenario `expect` rows can require an
  evidence substring.

## v9b — 2026-10-14
- **[default] Timing-only findings, scoped.** A finding whose only evidence
  is timing (plus session duration) is capped at 0.39 only when it looks like
  a benign scheduler: ≥ 2 internal clients reach the same destination on the
  same cadence (period within ±20 %), or the series matches a scheduler
  shape (GPO, Jamf, WSUS, chrony, anchored grid). Any other timing-only
  finding keeps its score but is capped at 0.84, so timing alone never
  reaches critical. Signals contributing < 0.05 no longer lift the cap.
  This undoes v9a's recall loss: a single-host HTTPS beacon with no other
  tell scores 0.62–0.69 again (v9a: 0.39).
- **[default] `rpc_calls` aggregated**: one row per (client, server,
  endpoint, op, transport) with summed counts, the pipes seen, and
  first/last frame.
- `-timing v2`: keep-alive-shaped sessions use the normal timing weight at
  every period (v9a used 0.45); the keep-alive interval match is an
  annotation.
- **[default] Tunnelled traffic is analysed by its inner addresses.** GRE,
  ERSPAN II, VXLAN and IP-in-IP (SPAN/ERSPAN feeds, cloud traffic
  mirroring) used to be attributed to the tunnel endpoints (GRE/ERSPAN) or
  ignored (VXLAN). Findings on such captures now name the real hosts; a new
  `decapsulated` counter reports how many packets were unwrapped.
  802.1Q/QinQ were already handled.
- Malformed YAML (scenario files, eval manifests, Sigma rules) is reported
  as an error instead of crashing (a go-yaml decoder panic, found by fuzzing).
- Synthetic corpus generator (`internal/synth`, `tools/synthgen`) and
  capture transforms (`tools/perturb`). See `docs/corpus.md`.

## v9a — 2026-10-14
- **[default] Sigma hits fold into the existing finding** for their
  (client, server) pair — the C2 channel on the hit's port when there is one
  — instead of a separate "Sigma rule match" finding. Standalone Sigma
  findings remain only for host pairs with no other finding. Users upgrading
  from v6 will see fewer findings; the `sigma:<id>` signals now sit on the
  C2 finding.
- **[default] HTTP after packet loss.** After a TCP gap the parser resyncs on
  the next complete request/status line at any offset (it used to require a
  line boundary, so one lost segment could drop many messages on a
  keep-alive connection). Lab `http_c2_enum` at 1 % loss: 782 → 1042 of 1060
  messages. HTTP-derived counts and signals can change on damaged captures.
- **[default] Titles**: HTTP channels scoring below 0.2 are titled "HTTP
  channel …" instead of "HTTP C2 …".
- **[default] `rpc_calls`** in JSON (DCE/RPC calls over SMB pipes).
- **[default] Timing-only cap at 0.39** for every timing-only finding —
  superseded by the scoped cap in v9b.
- `-timing v2`: idle-poll size look, cadence-cliff removal, stress gate vs
  max(v1, last release).

## v8b — 2026-10-14
- **[default] SMB per-pipe consolidation.** Lost CREATE/READ requests no
  longer split one pipe into extra "opened before capture fid=…" findings;
  opens of one pipe merge into one finding keyed (client, server, pipe); the
  unattributable zero-FileId bucket is never scored alone. smb2-wks: two
  duplicate `gainz` findings removed.
- `-timing v2`: keep-alive classifier fix, harmonic folding, gamma(4)
  provisional null, `http_client_quirks` family.

## v8a — 2026-10-14
- `-timing v2` (opt-in): event models, name-keyed series, generated null
  tables, refusal ladder, signal families; `c2parser eval`.

## v6 — 2026-10-14
- **[default]** Known C2 certificates and certificate anomalies, Cobalt
  Strike DNS defaults, framework default HTTP profiles (Covenant, Merlin,
  PoshC2, Cobalt Strike no-profile).
- **[default] Bug fix:** self-signed leaf certificates (CA:FALSE or no
  basicConstraints) are now recognised as self-signed.
