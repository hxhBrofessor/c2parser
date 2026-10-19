# c2parser — reference

Hunts for command-and-control and data exfiltration in packet captures.
Every score comes with the signals that produced it.

| Engine | What it looks at |
|---|---|
| **HTTP C2** | Full TCP reassembly → HTTP/1.x (Content-Length, chunked, keep-alive, pipelining, CONNECT, retransmissions). Body randomness, C2 framing signatures, request beaconing, header anomalies, file uploads. |
| **TLS / QUIC** | ClientHello → SNI, ALPN, **JA3, JA4** (validated byte-for-byte against Wireshark 4.2 on 462 handshakes); ServerHello → JA3S; certificate (TLS ≤ 1.2) → self-signed, fresh/expired, name mismatch; **known C2 certs** by SHA-256 / serial / DN (Cobalt Strike `0x8BB00EE`, PoshC2 `CN=P18055077`, Covenant `CN=Covenant`, Brute Ratel C4 Unit 42 cluster, Sliver operator CA); **framework-agnostic cert anomalies**: empty issuer/subject DN (Sliver CA, Merlin), self-signed `O=Microsoft`, generator validity spans (730/1095/3650 days) on self-issued certs. **QUIC Initial decryption** (RFC 9001 v1 / RFC 9369 v2 keys from the DCID, stdlib crypto only) → ClientHello → SNI, ALPN, JA4 `q…`; QUIC SNI keys the v2 K1 series, so QUIC beacons over several IPs roll up. |
| **Framework default HTTP profiles** | Per-channel conjunction (noisy-OR, threshold 0.65) of request and response literals: **Covenant** (`SESSIONID=1552332971750`, `i=a19ea…&data=` template, Chrome/41 UA, `/en-us/*.html`, IIS/7.5 + Hello World), **Merlin** (`application/octet-stream; charset=utf-8`, `Bearer eyJ…`, Chrome/40 UA, `POST /`), **PoshC2** (`Server: Apache ` with trailing space, HTTP/1.0 + `Content-type`, `SessionID=` cookie, 404/200 page literals), **Cobalt Strike no-profile** (21 default GET URIs + bare base64 Cookie, `POST /submit.php?id=`, checksum8 stager URIs, empty text/plain 404). Single common fields never fire alone. |
| **Generic beaconing** | Client→server bursts on any TCP/UDP channel scored for timer-like regularity. |
| **Encrypted DNS** | DoT (TCP/853), DoQ (QUIC on UDP/853 or 8853), DoH to public resolvers (hostname/IP lists), ALPN `dot`/`doq`. Custom DoH is caught by behaviour: long-lived no-SNI sessions and beaconing. |
| **SMB2 named pipes** | Tree connect / create / READ / WRITE / pipe-transceive tracked per FileId → pipe name, volume, timing, embedded C2 framing, NTLM user. Catches Havoc / Cobalt Strike SMB pivots. Default pipe names for Cobalt Strike (`msagent_##`, `postex_####`, `TSVCPIPE-…`, `Winsock2\CatalogChangeListener-###-0`, `cubeb-pipe-…`), Covenant (`gruntsvc`) and PoshC2 (`jaccdpqnvbrrxlaf`). |
| **Lateral movement (DCE/RPC)** | BIND/REQUEST parsing over SMB pipes **and raw TCP** (found by PDU header, not port; fragments reassembled) → interface + opnum: PsExec/smbexec service creation, atexec/schtasks, PetitPotam, PrinterBug, PrintNightmare, **WMI `ExecMethod` (wmiexec)** and **DCOM `RemoteCreateInstance` (dcomexec)**. Responses teach dynamic ports: `ept_map` towers and DCOM OXID bindings label streams whose BIND predates the capture. Auth level is recorded; sealed/signed stubs are volume only. **DC guard:** `DRSGetNCChanges` from a domain controller (seen serving Kerberos/LDAP or drsuapi, or named with `-dc`) is an info "DC replication" finding; from any other host it is `dcsync_from_non_dc`. Every call is listed in JSON `rpc_calls`. |
| **AD reconnaissance** | LDAP SearchRequests (BER, also inside SASL NTLM-signed / Kerberos wraps incl. the Windows rotated-checksum form; sealed binds give volume only): UAC delegation and AS-REP bit tests, `servicePrincipalName=*`, delegation and LAPS attributes, `adminCount=1`, `nTSecurityDescriptor` with SD_FLAGS (subtree, or per-object sweeps of ≥ 10 accounts in 10 min), bulk subtree dumps (≥ 50 entries / ≥ 2 pages, or a completed dump of every user); samr account/group enumeration; MS-TSTS session enumeration (low weight). From a host with a C2 finding ≥ 0.6 the recon joins that finding (`recon_from_c2_host`, filters as evidence); elsewhere it is a standalone finding capped at medium. rootDSE, GPO (`gPLink`) reads, single-account lookups and DC↔DC traffic are never scored. |
| **DNS** | Per registrable domain: name cardinality ratio, unique subdomains, length, label length, alphabet-aware randomness, encoded bytes, TXT/NULL use, answers never contacted, query beaconing. Per client: NXDOMAIN spread (DGA). UDP and TCP. **Cobalt Strike DNS beacon defaults** as a conjunction: stager marker (`.stage.123456.`, `aaa.stage.`), `cdn.`/`www6.`/`api.`/`www.`/`post.` + hex names, idle answer `0.0.0.0`, TTL 1. |
| **Exfiltration** | Per channel *and* per connection: upload volume × producer/consumer ratio, encrypted uploads, fixed-size chunks, HTTP file uploads, SMB share writes, DNS-encoded volume. |
| **Host risk** | Cumulative risk per internal host across all findings. |

Tunnelled traffic (GRE, ERSPAN II, VXLAN, IP-in-IP, 802.1Q/QinQ) is analysed
by its inner addresses, so SPAN/ERSPAN feeds and cloud traffic mirroring work
as-is. See `CHANGELOG.md` for default-output changes since v6.

No libpcap/cgo: pcap and pcapng are read natively, so it cross-compiles anywhere
(`GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build`).

```bash
go build -o c2parser .
./c2parser capture.pcapng                  # text report
./c2parser -v capture.pcapng               # + HTTP / SMB / DNS / top-talker tables (with JA4, SNI)
./c2parser -json *.pcapng > results.json   # machine-readable, includes host_risk
./c2parser -ioc iocs.txt capture.pcapng    # match IPs, domains/SNI, JA3, JA3S, JA4, cert sha256
./c2parser -fail-on high capture.pcapng    # exit 2 if anything ≥ high (CI / pipelines)
./c2parser -add-internal 100.64.0.0/10 …   # treat Tailscale/CGNAT as internal
```

IOC file: one per line, `kind:value # label` or bare values (kind is inferred):
```
ip:100.113.27.34          # lab Havoc teamserver
domain:evil.example       # matches SNI, Host, DNS (suffix match)
t13d1516h2_8daaf6152771_02713d6af862
ja3:72a589da586844d7f0818ce684948eea
```

## Sigma rules (auto-updated, like `nuclei -ut`)

c2parser renders what it parses into Sigma's logsources (`proxy`, `webserver`,
`dns`, Zeek `http`/`dns`/`smb_files`/`dce_rpc`/`x509`/`rdp`/`conn`, `firewall`) and
runs the rules on every record. Hits become findings and corroborate the
behavioural finding on the same channel.

| Command | What happens |
|---|---|
| `c2parser cap.pcapng` | At most once per 24 h, asks GitHub for the latest SigmaHQ commit; downloads only if it changed (only the network/web/emerging-threats folders); then loads cache + 5 built-in rules |
| `c2parser -update-sigma` | Check now and exit (with captures: check now, then analyse) |
| `c2parser -offline …` | Never touch the network; cached + built-in rules |
| `c2parser -no-sigma-update …` | Same as offline for Sigma only |
| `c2parser -sigma-ref r2026-08-01 …` | Pin a tag/branch/commit (reproducible runs, CI) |
| `c2parser -sigma-repo you/sigma-fork …` | Pull from your fork |
| `c2parser -sigma ./my-rules …` | Add your own rule directories on top |
| `c2parser -sigma-report …` | Show which rules were skipped and why |
| `c2parser -no-sigma …` | Disable Sigma |

Transport: GitHub API + tarball over HTTPS (honours `HTTPS_PROXY`, uses
`GITHUB_TOKEN` if set), falling back to `git ls-remote` + sparse shallow clone.
Downloads are filtered to `.yml` under the rule folders, size-capped and guarded
against path traversal. Cache: `<user cache dir>/c2parser/sigma/` with a
`state.json` recording repo, ref, SHA and check time. Network failures never
stop an analysis.

Built-in rules (`rules/sigma/`, compiled into the binary): Havoc default profile,
Mythic `http` and `websocket` defaults, Mythic `smb` UUID pipe names, Sliver DNS
name shape. To write your own, copy one and change the detection. Escape
literal `*`/`?` as `\*`/`\?`; e.g. Havoc's `Content-Type: */*` is `'\*/\*'`.

The evaluator supports the modifiers and conditions the network corpus uses
(`contains`, `startswith`, `endswith`, `all`, `re`, `cidr`, `base64`,
`base64offset`, `windash`, `exists`, `cased`, `gt/gte/lt/lte`; `and/or/not`,
parentheses, `1 of`/`all of`, `them`, keyword lists). Aggregations and
correlation rules are reported as unsupported. On the 2026-10 corpus: 178 of
573 rule files apply to packet data, with 0 parse errors.

## Detection math

### 1. Randomness instead of raw entropy
The original tool flagged bodies with Shannon entropy > 7.5 (tuned to 7.80 in the
presentation). That can't work on its own:

* **Size**: n bytes can hold at most log₂(min(n,256)) bits/byte, and random data
  only *expects* ≈ 8 − 184/n. A 20-byte Havoc check-in can never exceed ~4.2;
  a 300-byte encrypted blob averages ~7.4.
* **Encoding**: base64 ciphertext tops out at 6.0 bits, hex at 4.0, base32 at 5.0.
* **Context**: compressed/certificate content is supposed to be high-entropy.

`stats.Assess` detects the alphabet (hex, letters, base32, alnum, base64, text,
binary), folds case and padding, and compares H to a **null model**: the mean and
standard deviation of H for uniformly random data of the *same length and
alphabet*. Small n uses a deterministic Monte-Carlo table; n ≥ 16k uses the
asymptotic result 2n·ln2·(log₂k − H) ~ χ²ₖ₋₁. Score = max(z-test within ~3σ,
ratio ≥ 98% of E[H]) × sample-size confidence. Benign opaque content types are
excluded. Raw Shannon ≥ 7.80 is still reported as `legacy_entropy_threshold`.

### 2. Beaconing (jitter- and noise-tolerant)
`stats.ScoreBeacon` on event times (HTTP requests, client bursts, DNS queries,
SMB pipe I/O):

* **timing** = 0.2·(1 − |Bowley skew|) + 0.35·(1 − 2·MAD/median) + 0.2·coverage + 0.25·on-period share
* **size** = mean(1 − |Bowley skew|, 1 − 2·MAD/median, mode share)
* **score** = (0.65·timing + 0.35·size) × confidence(n)

*On-period share* is the share of gaps within ±30% of the median. That covers
sleep timers up to ~50% jitter; Netskope's Cobalt Strike example is 60 s ± 15%,
i.e. 51–69 s. Gaps at 2× and 3× the period (missed check-ins) get half credit.
The 2·MAD/median term separates a jittered timer (≈0.2) from Poisson/human
traffic (≈1.4 → 0).

Robust statistics are deliberate. On the part2 Havoc channel the classic
mean ± SD is 2.42 ± 2.72 s (CV 1.12, which looks random) because operator
tasking skews it, while the median and MAD show a 2.08 s timer with 8% jitter
and 82% of gaps on-period. Mean, SD and CV are still printed for comparison
with hunt.io-style analysis.

### 3. Exfiltration
`exfilShape = out/(out + H) × clamp(PCR/0.5)`, with PCR = (out − in)/(out + in).
It is computed per connection as well as per channel, because exfil is often one
upload connection inside a channel that also downloads tasking. Extra signals:
encrypted uploads, fixed-size chunks (e.g. 14 × 512 KB), HTTP file uploads
(multipart filename / PUT), SMB share writes, and DNS qname-encoded bytes
(chars × log₂ alphabet / 8).

### 4. DNS tunnelling, DNS beacons & DGA
Per registrable domain:
* **Name cardinality ratio** (Luise 2024): distinct names / queries. Tunnels
  and DNS beacons make a new name almost every query. Sliver's DNS C2 keeps
  per-name entropy normal on purpose, so this signal is *not* gated on
  randomness. Scored from 0.4 (Luise's production threshold) to 0.8, with
  volume ≥ 20.
* Unique subdomains, mean length, longest label, alphabet-aware randomness
  (modulates, never gates), TXT/NULL share, encoded volume, query beaconing.
* **Resolved but never contacted**: answer IPs the client never connects to
  (answers carry data, not destinations).

Per client: distinct NXDOMAIN registrable domains × randomness of those labels
(a 26-letter alphabet separates DGA strings from English-like names).

### 5. When content is hidden (encrypted DNS / TLS C2)
From Active Countermeasures' encrypted-DNS comparison: encryption moves
detection from content to behaviour.
* DoT: port 853 + SNI; DoQ: QUIC on 853/8853; ALPN `dot`/`doq`.
* DoH to public resolvers: hostname/IP lists (policy: bypasses DNS logging).
* Custom DoH: **long_connection** (one session held ≥ 30 min, full at 4 h),
  **tls_no_sni** (server addressed by IP), beaconing, asymmetry.
* Infrastructure evidence: self-signed / Cobalt Strike default certificates,
  fresh or expired certificates, SNI/certificate mismatch, IOC matches.
* Per-host baselines (Netskope): a JA4 or User-Agent used by this host only
  toward this one server. Weak; it only amplifies a channel that already has
  evidence, as does `direct_ip_no_dns`.

### 6. Combining evidence
Each finding is a set of named signals with strength `s` and weight `w`:

```
P = 1 − Π (1 − wᵢ·sᵢ)        (noisy-OR)
```

Severity: critical ≥ 0.85, high ≥ 0.65, medium ≥ 0.4, low ≥ 0.2. Cross-protocol
correlation adds `pivot_from_c2_host` (C2 host opening a non-standard pipe) and
`same_channel_as_c2` (an amplifier for exfil on a C2 channel). **Host risk**
combines all of a host's findings the same way, so weak signals across protocols
accumulate (Netskope's cumulative-risk model) instead of firing binary alerts.

## Results on the lab captures

| Capture | Original tool | This version |
|---|---|---|
| `http_c2_enum` | 11 per-packet hits, all server responses; **0 of 31** encrypted uploads | C2 **1.00** (Havoc framing in 530 bodies, default UA, 1.86 s beacon); exfil **0.95** (8.05 MB single-connection upload, 14 × 512 KB chunks) |
| `http_c2_enum_part2` | 9 hits, 2 false positives | C2 **1.00** (beacon 0.88, 82% on-period); updog upload of `beacon4a.txt` (355 KB) **0.59**; nothing else ≥ 0.4 |
| `smb2-wks` | 13 hits, 5 false positives (Edge CRX, certs); SMB not analysed | C2 **1.00**; `\\pipe\gainz` pivot **1.00** (49 Havoc frames, correlated to the HTTP C2 host, NTLM `sevenkingdoms.local\vagrant`) |
| `smb2-data` | 0 | `gainz` pipe **0.99** (tree connect predates capture; identified by name shape + framing) |

The 121 MB / 152k-packet part2 capture processes in ≈0.5 s.

## Timing v2 and evaluation (`-timing v2`, `c2parser eval`) — experimental

`-timing v1` (default) behaves exactly as before. `-timing v2` switches on the
v8 statistics engine:

* **Event models.** Each series is `per_request` (HTTP, DNS, WebSocket, and
  any TCP/TLS channel carrying application-sized turns — including kept-alive
  HTTPS beacons), `persistent_heartbeat` (only on positive transport evidence:
  QUIC, or tiny near-constant keep-alive bursts in both directions on a UDP
  flow or long-held session; known keep-alive cadences are a low-weight note)
  or `p2p` (SMB pipe legs: timing refused).
* **Name-keyed series.** HTTP Host / TLS SNI across server IPs and ports (K1)
  and server IP across ports (K2), so round-robin redirectors don't split one
  beacon into k slow ones.
* **Refusal ladder.** < 10 idle gaps: refused (with `capture_needed_hours`);
  10–19: dispersion only; ≥ 20: + harmonic concentration, Fano, ρ₁; ≥ 30:
  + absolute phase, edges, polarity; ≥ 50: true percentiles.
* **Idle-poll size.** If ≥ 80 % of idle-poll sizes sit within ±max(8 B, 2 %)
  of their median, timing needs one decade less significance (q1e-2 instead
  of q1e-3). Findings judged on < 60 events with high spread say how many
  events full power needs.
* **Missed check-ins.** Gaps in [1.5P, 3.5P] are folded to g/round(g/P) and
  counted as `missed_beats`, so packet loss or a sleeping host doesn't read
  as irregularity.
* **Evidence vs. annotation.** Only dispersion scores: idle-gap CV, folded
  and unfolded, each against its own generated null at the series' gap
  count, Bonferroni-corrected for the two looks. Harmonic
  concentration, spread (1 − p2/p98, *not* the jitter setting), polarity,
  integer-second lattice and the anchored-scheduler shape are annotations
  (finding text describes edge shape, e.g. "upper edge sharp"; the jitter
  estimate is in JSON only);
  the anchored shape multiplies timing evidence by 0.7 (never zero).
* **Null tables** are generated (`go generate ./internal/stats`) from the same
  pipeline: 200k replicates per gap count, Poisson and gamma k = 0.5/2/4.
  Until a benign corpus is measured, thresholds come from the gamma(k=4) null
  (CV ≈ 0.5, the most regular plausible benign renewal traffic).
* **Signal families.** Correlated signals combine as max + 0.3 × second
  within a family (UA oddities capped at 0.35), families by noisy-OR.
  Findings carry `family_scores`; the result carries `timing_series`.

Both engines: Sigma hits fold into the existing finding for their host pair,
and timing-only findings are capped as described under "Timing-only findings"
below. Keep-alive-shaped sessions use the normal timing weight at every
period; a match to a transport keep-alive interval is noted, not scored
differently. A WebSocket upgraded with `Accept-Type: Push` is `push_or_saas`:
its timing is refused (`refused: "event_model:push_or_saas"`). Under v2 a
beacon behind several redirector IPs with one SNI/Host is one finding, keyed
by (client, name), with the K1 series as its timing.

`c2parser eval -manifest m.yaml -out dir [-j N] [-calibrate]` runs v2 over
labelled captures (manifest schema v2: globs, rotated segments, roles
`c2`/`benign`/`mixed`, labels from a Zeek conn.log UID join, per capture or
by time window; strict — unknown keys and missing files are errors; `-check`
validates without running). It writes `report.md` and `report.json`
(per-series v1/v2/RITA-like/"n ≥ 20" scores; benign quantiles at 1 − 10⁻²,
10⁻³, 10⁻⁴ with distribution-free intervals; Neyman–Pearson operating points
at the benign 1 − 10⁻⁴ quantile — positives never set thresholds; TPR per cell
and per jitter cell with Wilson intervals; worst held-out framework; FP per
benign host-hour per scorer and per severity with Poisson intervals; top 20
benign findings; destination prevalence), plus `series.csv`,
`detection_vs_jitter.csv` and `prevalence.csv`. A report built only from
synthetic captures carries the synthetic banner and emits no operating points
with fewer than 1,000 benign series. `-calibrate` fits L2 logistic regression
over family scores with nested leave-one-framework-out and Platt scaling and
writes `proposed-weights.json` + `calibration.md`; it never changes product
weights. See `docs/eval-manifest.example.yaml` and `docs/datasets/`.

## Tests

```bash
go test ./...                                      # unit + synthetic captures
C2PARSER_TESTDATA=/path/to/captures go test ./...  # + lab-pcap regression, JA3/JA4 vs tshark
go test ./internal/engine -run '^$' -fuzz FuzzReviewFile -fuzztime 60s
```

Synthetic captures cover:
* a dnscat-style TXT tunnel, benign lookups and a DGA burst
* a Sliver-style low-entropy DNS beacon
* HTTP C2 with header/body split across segments, retransmissions and chunked responses
* SMB2 Havoc pipe I/O, including async reads, and lost CREATE/READ requests (one finding per pipe); `rpc_calls` JSON
* stress gate: 141 cells (null FP budgets; detection vs max(v1, last release) − 0.03, trade-offs in `docs/stress-tradeoffs.md`)
* HTTP recovery under 0.1–5 % packet loss (≥ 95 % of intact messages, monotonic)
* finding-level scheduler gate (Jamf/GPO/WSUS/chrony alone < 0.4), Sigma folding, cadence-cliff gate
* metamorphic invariants: time shift, gap scaling, IP renumbering
* WMI `ExecMethod` and DCOM `RemoteCreateInstance` over an SMB pipe (lateral finding), and a benign `srvsvc` share enum (no finding)
* Cobalt Strike / Covenant / PoshC2 default pipe names, with near-miss negatives
* known C2 certificates and cert anomalies (generated in-test with crypto/x509), plus a PoshC2 cert over a TLS 1.2 handshake
* Cobalt Strike DNS beacons (tasked, idle-only, stager marker) vs. benign `www.`/`api.`/`cdn.` and low-TTL CDN lookups
* Covenant, Merlin, PoshC2 and Cobalt Strike no-profile HTTP vs. benign channels carrying one lookalike field each
* DoT beaconing (5 s ± 2 s), a 2.5 h no-SNI DoH session and DoQ
* a Cobalt Strike 60 s ± 15% beacon with tasking noise and missed check-ins
* corpus scenarios with score gates (Phase 0.1 cap: single host ≥ 0.6 in v2 over 30 seeds, fleet and schedulers ≤ 0.39, fleet-check mutation)
* transform gates: 0 % damage is a no-op, re-addressing is a metamorphic no-op, re-timing to the original schedule reproduces findings, wrapping is transparent, splicing never lowers a C2 score

### Synthetic corpus and capture transforms

`corpus/scenarios/*.yaml` are declarative traffic scenarios: transport,
timing model, schedule artifacts, content shape and topology (fleets, NAT,
redirectors, CONNECT proxy). `tools/synthgen` turns them into pcap/pcapng
plus a `c2parser eval` manifest. The same (scenario, seed) always gives the
same bytes. `tools/perturb` rewrites real captures: damage, conflicting
retransmissions, one-direction capture, VLAN/QinQ/GRE/ERSPAN/VXLAN
wrapping, re-addressing, cloning a client into a fleet, redirectors,
re-timing one channel's transactions to a timing model while keeping its
bytes, and splicing into background.

```bash
go run ./tools/synthgen -out corpus-out corpus/scenarios
./c2parser eval -manifest corpus-out/manifest.yaml -out eval-out
go run ./tools/perturb -in lab.pcap -out x.pcap -t wrap:kind=vxlan -t drop:p=0.01
go run ./tools/perturb -in lab.pcap -out y.pcap \
    -t retime:client=10.0.0.5,server=203.0.113.9,port=80,model=lengthening,sleep=45,jitter=0.3
go run ./tools/synthgen -scale 500000 -out scale-out      # flow-heavy scale capture (v9c)
```

Synthetic scenarios carry shape labels, never framework names. They test
c2parser against our own model of C2 and cannot set thresholds. See
`docs/corpus.md` for the scenario catalogue, the transform gates and the
scores c2parser gives each scenario.

### Timing-only findings
A finding whose only evidence is timing keeps its score up to 0.84 (high,
never critical). It is capped at 0.39 when it looks like a benign scheduler,
and the cap reason is in the finding's evidence:

| Reason | When |
|---|---|
| `fleet-wide periodic destination (N of M hosts)` | ≥ max(3, 25 % of the M internal clients active in the capture) reach the destination (SNI/Host name merged over IPs, or server IP) on the same cadence (±20 %) |
| `internal poller (N targets)` | one internal client reaches ≥ 3 internal servers on the same cadence (monitoring scrapes, backup/inventory agents) |
| `cadence matches …` | the series matches a scheduler shape: GPO, Jamf, WSUS, NTP/chrony, anchored grid, MDM check-in ladder, browser updater, or WireGuard keep-alive (32 B, ~25 s) **off UDP 53** |

WireGuard-shaped non-DNS traffic **on** UDP 53 raises
`wireguard_shape_on_dns_port` instead. Capped findings stay in JSON and show
in text at the default `-min-score` (0.2).

### Flags added in v9
| Flag | Default | |
|---|---|---|
| `-timing v1\|v2` | v1 | scoring engine (v2 experimental; see above) |
| `-j N` | 1 | analyse N capture files concurrently; output in argument order, identical to `-j 1`; memory ≈ N × per-file peak |
| `-max-series-events` | 200000 | cap on stored events per timing series |
| `-max-summary-rows` | 5000 | cap on rows per summary table (findings unaffected) |
| `-lean-gc-mb` | 512 | above this live heap, collect garbage more often (cuts peak memory on flow-heavy captures; 0 = off). With RAM to spare, `-lean-gc-mb 0` is faster on flow-heavy captures (500k connections: about −25 % wall time, about +35 % peak RSS) |
| `-version` | | print the version |

### Flags added in v10a
| Flag | Default | |
|---|---|---|
| `-dc a,b` | | domain controller IPs, added to those inferred (Kerberos/LDAP service, drsuapi server): their replication is not DCSync and their LDAP/samr is not recon |
| `eval -j N` | 1 | evaluate N captures (or rotated sets) concurrently |
| `eval -calibrate` | off | fit the calibration harness (proposed weights only) |
| `eval -check` | off | validate the manifest and that every file exists |

### JSON fields added in v10a
* `rpc_calls[]`: `transport` is `smb-pipe` or `tcp`; new `ports` (tcp),
  `learned` (`ept_map` / `oxid` when the interface came from a response, not a
  BIND), `auth_level` (`none` … `privacy`). MS-TSTS endpoints are named
  (`TermSrvSession`, `TermSrvEnumeration`, `RCMPublic` …).
* `counters.quic_initial_flows`, `quic_client_hellos`, `quic_initial_errors`.
* `top_talkers[]` QUIC channels (`quic: true`) carry `sni` and `ja4` (`q…`).
* New finding categories: `AD reconnaissance`, `Directory replication (info)`.
* `family_scores` (v2): signals with no named family are grouped as `unmapped`.
* `eval` `report.json`: `default_flip_gate`.
* New signals: `ldap_*` (incl. `ldap_acl_sweep`, v10a.1), `samr_enumeration`, `tsts_session_enum` (family
  `recon`), `recon_from_c2_host`, `dcsync_from_non_dc` (family
  `credential_access`), `dc_replication` (info).

### JSON fields added in v9
* `counters.decapsulated`: packets analysed inside GRE / ERSPAN / VXLAN / IP-in-IP.
* `counters.series_events_dropped`, `counters.summary_rows_dropped`: what
  the caps above dropped (omitted when zero).
* `rpc_calls`: one row per (client, server, endpoint, op, transport) with
  `count`, `pipes`, `bound`, `first_frame`, `last_frame`.
* `timing_series[].refused`: why a series wasn't scored (`event_model:p2p`,
  `event_model:push_or_saas`, too few events …), under `-timing v2`.
* Finding `evidence` carries the timing-only cap reason (table above);
  `family_scores` (v2) includes `transport_anomaly`.

Fuzz targets cover SMB, HTTP, DNS, TLS, whole-file parsing, scenario YAML
and the capture transforms. One fuzz crash
in gopacket's DNS decoder is contained and kept as a regression seed.

## Limits / next steps

* Raw-TCP DCE/RPC whose BIND and endpoint-mapper answer both predate the
  capture stays `unbound` (opnum only; never scored). MS-TSTS opnums are not
  named (the IDL wasn't available; no guessing).
* Framework default HTTP literals are matched on HTTP/1.x only. Merlin's default
  transport is HTTP/2 (TLS or h2c); h2c needs preface + HPACK decoding, not done yet.
  PoshC2's 32 `urls.txt` beacon stubs and BRc4 HTTP check-ins aren't in the table.
* Backdated `NotBefore` (Sliver 0–364 d, Merlin 0–359 d) isn't scored: on its own
  it can't be told apart from an ordinary older certificate.
* Licensing if this ships commercially: JA4 (client) is BSD-3; JA4S/JA4H/JA4X are
  FoxIO License 1.1 and need an OEM agreement to sell. c2parser emits JA3S and
  JA4 only.
* `-timing v2` is unvalidated on real captures: thresholds are provisional
  (gamma null) until `c2parser eval` runs on TQH-C2 and a benign capture
  (the plumbing is ready: `docs/datasets/`); the default stays v1.
* QUIC: only client Initials are decrypted (that is all the RFC keys open);
  a ClientHello whose first Initial isn't in the capture can't be read.
* TLS 1.3 encrypts certificates; SMB3-encrypted sessions are counted, not inspected.
* Known corpus gaps (`docs/eval/v10-synthetic.md`): length-framed raw-TCP
  pivots aren't scored; push-mode WebSocket is refused for timing and needs
  content indicators; single-target benign pollers (a Prometheus scrape of
  one host) still score like beacons (0.75) — fleets, multi-target pollers
  and the listed scheduler shapes are capped, a prevalence store is the
  general fix.
* IP fragments aren't reassembled. eTLD+1 uses a built-in suffix list.
* Weights are hand-set from these captures and published research. With labelled
  benign traffic they should be fitted (logistic regression on the same signals).
  The Netskope paper's point about multi-scope baselines (device / role / org)
  needs more than one capture's worth of history.
