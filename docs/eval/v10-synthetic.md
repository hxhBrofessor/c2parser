# v10 synthetic corpus evaluation

> **Regression and robustness evidence only — synthetic data cannot set thresholds or measure real-world accuracy.**

_2026-10-15, c2parser v10a. 39 scenarios in `corpus/scenarios/` (v9.0's 33, plus 4 for the v10a parsers and 2 for v10a.1), generated with `tools/synthgen` at their committed seeds, run with `-no-sigma` under `-timing v1` (default) and `-timing v2`. The scenarios are our own model of C2 and benign traffic shapes. They check that each detector does what it was built to do, and keeps doing it. They say nothing about how often real implants or real fleets look like this. Thresholds and accuracy wait for TQH-C2 and Bryan's benign capture; the eval plumbing for both is ready (`docs/datasets/`)._

Reproduce:

```sh
go run ./tools/synthgen -zeek -out corpus-out corpus/scenarios
c2parser eval -manifest corpus-out/manifest.yaml -out eval-out -j 4 -calibrate
go test ./internal/engine -run 'TestCorpusScenarios|TestCapGateSeedSweep' -v
```

## Per-scenario scores

"C2" is the best finding on the scenario's labelled C2 endpoint. "Other" is the best finding anywhere else. In benign scenarios everything is "other". `—` means no finding ≥ 0.05.

| Scenario | Label | What it tests | C2 v1 | C2 v2 | Other v1 | Other v2 |
|---|---|---|---|---|---|---|
| gate-single-https-keepalive-30s / -60s | c2 | single-host timing-only HTTPS beacon, keep-alive (Phase 0.1) | 0.53 / 0.60 | 0.65 / 0.65 | — | — |
| gate-single-https-new-conn-30s / -60s | c2 | same, new connection per check-in | 0.61 / 0.63 | 0.65 / 0.65 | — | — |
| gate-tiny-bursts-30s / -45s / -120s | c2 | ≤ 100 B keep-alive bursts, no cadence cliff | 0.65 / 0.65 / 0.69 | 0.65 / 0.65 / 0.69 | — | — |
| gate-fleet3-https-60s | benign | 3 of 3 hosts on one cadence → fleet cap | — | — | 0.39 | 0.39 |
| gate-fleet20 | c2 + benign | D3: 2- and 3-host beacons stay uncapped in a 20-host capture; a 15-host schedule is capped "fleet-wide periodic destination (15 of 20 hosts)" | 0.65 | 0.65 | 0.39 | 0.39 |
| gate-poller-scrape | benign | D2a: one client scraping 4 internal servers every 15 s → "internal poller (4 targets)" | — | — | 0.39 | 0.39 |
| gate-scheduler-jamf / gpo / wsus / chrony | benign | scheduler shapes (v9a) | — | — | 0.39 | 0.39 |
| gate-scheduler-mdm | benign | D2b: MDM check-in ladder (3 min ×5, 15 min ×8, ~8 h + push syncs) | — | — | 0.39 | 0.39 |
| gate-scheduler-browser-updater | benign | D2b: 5 h + U(0, 60 s), sometimes 6 h | — | — | 0.39 | 0.39 |
| gate-wireguard-51820 | benign | D2c: WireGuard keep-alive shape off UDP 53 → capped | — | — | 0.39 | 0.39 |
| gate-wireguard-dns-port | c2 | D2c: same shape on UDP 53, non-DNS → `wireguard_shape_on_dns_port` | 0.79 | 0.79 | — | — |
| shape-https-redirectors-round-robin-3 | c2 | 2.1: K1 roll-up, 3 IPs round-robin | 0.57 (per IP) | 0.76 (one finding) | — | — |
| shape-https-redirectors-random-3 | c2 | 2.1: K1 roll-up, 3 IPs random | — | 0.76 (one finding) | — | — |
| shape-https-redirectors-cdn | c2 | K1 roll-up, 4 IPs random | — | 0.70 (one finding) | — | — |
| shape-https-proxy-connect | c2 | 2.3: TLS 1.2 inside HTTP CONNECT → inner SNI, K1 series by CONNECT target | 0.60 | 0.65 | — | — |
| shape-websocket-push | c2 | 2.2: `Accept-Type: Push` → `push_or_saas`, timing refused | 0.28 | 0.28 | — | — |
| shape-websocket-poll | c2 | WebSocket poll mode (unchanged) | 0.84 | 0.88 | — | — |
| shape-artifacts-http | c2 | every schedule artifact, base64 POST, residue 4, XOR-8 | 0.88 | 0.97 | — | — |
| shape-dns-txt-base32 | c2 | DNS TXT tunnel via resolver | 0.95 | 0.96 | — | — |
| shape-smb-pipe-framed | c2 | SMB named pipe, fixed header, residue 4 | 0.74 | 0.62 | — | — |
| shape-anchored-lattice-backoff | c2 | anchored grid (capped as scheduler by design), 1 s lattice, 2× back-off | 0.65 (lattice) | 0.65 | — | — |
| shape-pcapng-snaplen | c2 | pcapng ns resolution, 96 B snaplen | 0.65 | 0.65 | — | — |
| shape-nat-fleet | benign | 3 clients behind one NAT address | — | — | — | — |
| shape-tcp-pivot-le32 / -be12 | c2 | length-framed raw-TCP pivot | — | — | — | — |
| benign-models | benign | WireGuard, Prometheus (1 target), browsing, gamma(0.5), Poisson, apt, MDM ladder, browser updater | — | — | 0.75 | 0.75 |
| **v10a** shape-dcerpc-tcp | c2 + benign | 2.1: WMI `ExecMethod` on dynamic tcp/49712 (BIND seen) → "Remote execution over DCE/RPC tcp/49712"; drsuapi on a port learned from `ept_map` (no BIND) → `learned: ept_map`, `DRSCrackNames` not scored | — (lateral 0.70) | — (lateral 0.70) | — | — |
| **v10a** shape-recon-from-c2-host | c2 | 2.2: HTTPS beacon host also sends delegation / AS-REP bit tests, an SPN hunt and a paged SD_FLAGS ACL dump to the DC → `recon_from_c2_host` + "AD recon: <filter>" evidence on the beacon finding; no standalone recon finding (with `reconC2` off: beacon 0.65, standalone recon 0.64) | 0.82 | 0.82 | — | — |
| **v10a** benign-domain-logon | benign | 2.2 synthetic gate: 12 workstations × 6 logons (rootDSE, own computer object, gPLink, GPO containers, partitions) → nothing | — | — | — | — |
| **v10a.1** shape-ldap-acl-sweep | c2 | user dump + per-object SD_FLAGS reads on 15 accounts from a non-C2 host → standalone recon with `ldap_acl_sweep` + `ldap_bulk_enum`, capped | — (recon 0.64) | — (recon 0.55) | — | — |
| **v10a.1** benign-aduc-browsing | benign | ADUC: OU listings + 4 Security tabs per session, 6 sessions → nothing | — | — | — | — |
| **v10a** shape-quic-redirectors-3 | c2 | 2.3: QUIC v1 check-ins over 3 IPs, one SNI; Initials decrypted → SNI keys the K1 series → one v2 finding "3 server IPs" | — | 0.70 (one finding) | — | — |

All 33 v9.0 scenarios give the same top findings and scores as v9.0 under both engines.

**Seed sweep** (`TestCapGateSeedSweep`, 30 seeds): v2 single-host beacons score ≥ 0.6 at every seed. v1 ranges 0.51–0.64 with median ≥ 0.6 (trade-off D1 in `docs/stress-tradeoffs.md`). The fleet of 3 is capped at every seed.

**Mutation checks** (`TestV9cRuleMutations`, `TestFleetGateMutation`): with each rule removed, its gate scenario flips.
- Poller removed: the scrape scores ≥ 0.4.
- Gap shapes removed: MDM and the updater score ≥ 0.4.
- WireGuard port test removed: the UDP 53 case drops below 0.4.
- v9b's absolute fleet threshold of 2: the 2-host beacon is capped.
- Fleet check removed: the 3-host fleet scores ≥ 0.4.

## `c2parser eval` over the corpus (v2, report v2)

110 timing series: 37 captures, 32 C2, 28 benign. The report opens with the banner above and then refuses, in its own words:

> No operating points: this report is built only from synthetic data and has 28 benign series, fewer than the 1000 required. Thresholds, TPR and FP-per-host-hour at an operating point are not computed. Score distributions and the detection-vs-jitter curve (mean and median scores) are still reported.

v9.0's report computed an operating point anyway (the sample maximum, 1.0), which put TPR at 0 in every cell. v10a's refusal rule makes that explicit instead of printing a meaningless table. What remains is still useful as regression evidence:

| Jitter cell | n | v1 mean / median | v2 mean / median | RITA-like mean / median |
|---|---|---|---|---|
| 10 % | 20 | 0.745 / 0.905 | 0.850 / 1.000 | 0.726 / 0.884 |
| 20 % | 6 | 0.620 / 0.530 | 0.783 / 1.000 | 0.668 / 0.665 |
| 25 % | 3 | 0.547 / 0.820 | 0.667 / 1.000 | 0.576 / 0.864 |

(15 %, 30 % and unknown have one series each.) These are series-level scores, not finding scores.

- **Benign findings per host-hour** (finding level, 1770 benign host-hours, mostly the long scheduler scenarios): critical 0, high 1 (the single-target Prometheus scrape, 0.75), medium 0, low 16 (the capped fleet/poller/scheduler findings at 0.39), each with a Poisson interval in the report.
- **Benign quantiles** carry distribution-free intervals. With 28 series, every upper bound at 1 − 10⁻² and beyond is "?" (unbounded), which is the honest answer.
- **Prevalence**: the fleet-of-3 destination (3 clients, 10 s–1 min bucket) tops the table; everything else is single-client.
- **Calibration** (`-calibrate`): since v10a.1 it refuses below 1000 benign series, so the corpus run prints "not fitted". In v10a it ran end to end on 46 rows over 22 synthetic "frameworks" (shape labels) and writes `proposed-weights.json` + `calibration.md`, both carrying the banner. The fitted weights mean nothing here: synthetic rows, a handful per fold. The harness itself is gated in `TestCalibrationRecoversWeights` (known weights recovered within 0.05).
- **Zeek UID join** (`synthgen -zeek`): 1285/1285 connections join (100 %), and 100 % after `drop 0.01` + `jitter 0.5` on the pcaps (`TestZeekJoinGate`).

## Open gaps (v10b/c)

- **Length-framed raw-TCP pivots** (`shape-tcp-pivot-le32/-be12`): no finding in either engine. This needs payload-shape / P2P framing (old v9 Phase 3.5).
- **WebSocket push**: now classified and refused, as intended, so it scores only on non-timing evidence (0.28 here). Real push-mode detection needs content indicators (Q4).
- **Single-target benign keep-alives**: a single-target Prometheus scrape (0.75) and other one-off pollers still score like beacons. Only fleets, pollers with ≥ 3 targets and the listed scheduler shapes are capped. v10a measures the problem (the eval prevalence table) but does not feed it back; a cross-run prevalence store is the general fix.
- **QUIC under v1**: v1 has no K1 series, so a QUIC beacon spread over redirector IPs gives no v1 finding (v2: 0.70).
- **Anchored-shape false cap**: the anchored-scheduler test (ρ₁ ≤ −0.35) fires by chance on about 2 % of genuine single-host beacons with ~30 events (0 % at 60 events; 100-seed probe). Those are capped at 0.39. It needs a rung-dependent ρ₁ bound once real data exists.
- **v1 redirectors**: v1 has no K1 series and reports per-IP findings (unchanged by design).
