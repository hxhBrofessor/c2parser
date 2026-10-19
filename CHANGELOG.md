# Changelog

Default output is the `-timing v1` engine. Entries marked **[default]**
change what a plain `c2parser capture.pcap` run reports; everything else
only affects `-timing v2` or adds new output.

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
