# Synthetic and permuted capture corpus

_v9 rev 2 Phase 1. Generator: `internal/synth` + `tools/synthgen`. Transforms: `internal/perturb` + `tools/perturb`._

## Rules

- **Shapes, not frameworks.** Synthetic traffic tests c2parser against *our own model* of C2. It catches regressions and robustness problems. It **cannot set thresholds or claim real-world accuracy**; thresholds come from TQH-C2 and benign fleet data (Phase 5).
- Scenario names and `shape:` labels describe shapes (`polarity=shortening`, `residue=4`, `framing=be12`). The parser rejects framework names (`TestScenarioValidation`). The only exception is a small unit fixture for a parser of a documented format, built with fake values.
- **Nothing large is committed.** `corpus/` holds scenario YAML only, each < 200 KB (`TestCorpusRules`). Captures are generated in CI or locally.
- **Lab-derived captures stay outside the repo.** That covers re-timed, spliced, damaged or re-addressed captures. Tests build them at run time from `C2PARSER_TESTDATA` (`TestLabTransforms`) and write only to temp dirs.
- The benign models below are approximations for regression tests. They are not measurements of the real products.

## Regenerating

```sh
go run ./tools/synthgen -out corpus-out corpus/scenarios        # pcaps + manifest.yaml
c2parser eval -manifest corpus-out/manifest.yaml -out eval-out   # per-cell tables
go run ./tools/synthgen -seed 7 -out alt corpus/scenarios        # same scenarios, another seed
```

Every capture is a function of (scenario, seed). `TestDeterminism` checks that two runs are byte-identical and that changing the seed changes the bytes. `manifest.yaml` uses the `c2parser eval` format:
- `framework: synth:<scenario>` is a shape cell, never a framework;
- `c2:` labels list client + server IP, or the name for DNS, redirector and proxy scenarios;
- `jitter` is in percent;
- provenance fields: `scenario`, `seed`, `shapes`, `sha256`.

## Scenario format

```yaml
name: shape-artifacts-http      # file name stem; no framework names
seed: 210
start: 2024-03-25T07:00:00Z     # default 2024-03-25T12:00:00Z
format: pcap                    # or pcapng (tsresol: 6|9), snaplen: N keeps orig_len
streams:
  - label: c2                   # c2 | benign
    shape: polarity=shortening,encoding=base64,residue=4
    transport: http-keepalive   # see below
    server: 198.51.100.74       # server IP (dns: resolver)
    port: 80                    # default per transport
    name: news.example          # SNI / Host / DNS zone / pipe name
    topology:
      clients: [10.5.0.29]
      fleet: {base: 10.50.0.11, n: 3}     # N consecutive clients
      nat: 10.0.0.1                       # all clients behind one address
      redirectors: {mode: round-robin|random|cdn, ips: [...]}
      proxy: "10.0.0.8:3128"              # HTTPS via CONNECT
      stagger: 7                          # client start step (s)
    timing: {model: shortening, sleep: 60, jitter: 0.2, events: 150}
    artifacts:
      missed: 0.05                                        # skipped beats
      tasking: {every: 25, burst: 4, gap: 2, resp_bytes: 4000}
      stalls: [{after: 40, seconds: 900}]
      sleep_change: {after: 80, sleep: 120, jitter: 0.2}
      working_hours: {start: 8, end: 18}                  # UTC
      second_implant: {model: symmetric, sleep: 300, jitter: 0.1, events: 20}
    content:
      method: POST              # GET puts the poll body in ?d=
      uri: /api/v1/update
      headers: ["User-Agent: …"]
      encoding: base64          # raw | text | base64 | base64url | base32 | hex | netbios
      header: "c0ffee01"        # fixed leading bytes (hex)
      xor_key: 8                # ASCII plaintext XOR a repeating key of this length
      pad: [0, 32]              # random padding range
      residue: "4"              # decoded length ≡ 0 | 4 | 12 (mod 16) | uniform
      poll: {dist: uniform, min: 40, max: 80}     # fixed | uniform | normal (mean, sd, min, max)
      resp: {dist: normal, mean: 120, sd: 30, min: 16}
      alpn: [h2]; tls: "1.2"    # https hello
      qtype: TXT                # dns: A | TXT | AAAA
      framing: le32             # tcp-pivot: le32 | be32 | be12
      preset: recon             # ldap: recon | acl-sweep | aduc | logon; dcerpc-tcp: wmi-exec | epm-drsuapi
      sasl: krb                 # ldap: "" plain | ntlm | krb (Kerberos-signed, Windows RRC 12)
expect:                         # optional score gates (TestCorpusScenarios)
  - {engine: v1, server: 198.51.100.74, client: 10.5.0.29, min: 0.6, max: 0.84}
  - {engine: v2, category: recon, server: 10.82.0.10, max: 0.01}   # category: "" (C2 channel) | recon | lateral | any
```

Unknown keys are errors (strict YAML).

**Transports:**
- `http-new-conn`, `http-keepalive`;
- `https-new-conn`, `https-keepalive` (TLS 1.3 or 1.2 ClientHello; the server handshake and application data are opaque records);
- `dns` (via the resolver; query labels carry the encoded poll);
- `websocket-poll`, `websocket-push` (HTTP Upgrade, then binary frames, client frames masked);
- `smb-pipe` (TREE_CONNECT IPC$ + CREATE, then WRITE/READ);
- `tcp-pivot` (length-framed);
- `udp`;
- `quic` (v10a: one QUIC v1 connection per check-in — client Initial(s) with the ClientHello for `name` as SNI, protected with the RFC 9001 keys, then short-header packets);
- `ldap` (v10a: one LDAP session to the DC per event; `preset: recon` sends delegation/AS-REP bit tests, an SPN hunt and a paged SD_FLAGS ACL dump; `preset: logon` sends rootDSE, own-object, gPLink and GPO-container reads);
- `dcerpc-tcp` (v10a: `preset: wmi-exec` binds IWbemServices on `port` and calls ExecMethod; `preset: epm-drsuapi` asks the endpoint mapper on 135 for drsuapi, then calls DRSCrackNames on the learned `port` with no BIND).

`synthgen -zeek` also writes `<name>.conn.log` (Zeek TSV derived from the packets, independent of the engine) and `<name>.labels.jsonl` (UID → `c2`/`benign` plus the cell) for the eval Zeek-UID join. `h2c` arrives with v10b.

**Timing models.** Polarity names, never framework names.

| Model | Gap |
|---|---|
| `fixed` | S |
| `shortening` | S·(1 − J·u) |
| `lengthening` | S·(1 + J·u) |
| `symmetric` | S·(1 + J·(2u − 1)) |
| `anchored` | event k at k·S + U[0, J·S] |
| `lattice` | symmetric, rounded to whole seconds |
| `backoff` | S·factorᵏ up to `max`, then repeats |

**Benign models:**

| Model | Gap |
|---|---|
| `poisson` | Exp(mean S) |
| `gamma` | gamma(shape, S/shape) |
| `browsing` | Poisson sessions of 5–30 requests 0.1–3 s apart |
| `jamf` | 900 ± 300 s |
| `gpo` | 5400 + U[0, 1800] s |
| `wsus` | 79200 × U[0.8, 1] s |
| `apt` | 12 h grid + U[0, 12 h] |
| `chrony` | S (default 1024) × U[1, 1.02] |
| `prometheus` | 15 s ± 5 ms |
| `wireguard` | 25 s ± 2 ms |
| `intune` | 8 h × U[0.95, 1.05] |
| `chrome` | 5 h × U[0.9, 1.1] |

`TestTimingModels` and `TestArtifacts` check the bounds and artifacts.

## Scenario catalogue (`corpus/scenarios/`) and what c2parser reports

The current scores for all scenarios, and what each one tests, are in [`docs/eval/v10-synthetic.md`](eval/v10-synthetic.md). The table below is the v9b snapshot of the original 25.

v9c added these scenarios:
- `gate-fleet20` (relative fleet threshold);
- `gate-poller-scrape`;
- `gate-scheduler-mdm` and `gate-scheduler-browser-updater`;
- `gate-wireguard-51820` and `gate-wireguard-dns-port`;
- `shape-https-redirectors-round-robin-3` and `-random-3` (K1 roll-up).

Each has `expect` rows, several with an `evidence:` substring the finding must carry.

v9c also changed three existing scenarios:
- `shape-https-proxy-connect` gained `expect` rows for the inner SNI;
- `shape-websocket-push` now sends `Accept-Type: Push`;
- the `intune` and `chrome` benign models now produce the MDM ladder and the updater shape.

Scores at the committed seeds (`go test ./internal/engine -run TestCorpusScenarios -v`):

| Scenario | Shape | v1 | v2 | Note |
|---|---|---|---|---|
| gate-single-https-keepalive-30s | single host, 10 % shortening, 350–389 B / 200–599 B | 0.53 | 0.65 | Phase 0.1 gate; v1 varies by seed, see below |
| gate-single-https-keepalive-60s | ″ | 0.60 | 0.65 | |
| gate-single-https-new-conn-30s / -60s | ″, new TLS connection per check-in | 0.61 / 0.63 | 0.65 / 0.65 | |
| gate-tiny-bursts-30s / -45s / -120s | 35 B / 85 B bursts, keep-alive | 0.65 / 0.65 / 0.69 | 0.65 / 0.65 / 0.69 | no cadence cliff |
| gate-fleet3-https-60s | 3 clients, same cadence, one destination | 0.39 ×3 | 0.39 ×3 | fleet cap |
| gate-scheduler-jamf / gpo / wsus / chrony | single client, scheduler model | 0.39 | 0.39 | shape cap |
| shape-artifacts-http | every artifact, base64 POST, residue 4, XOR-8 | 0.88 | 0.97 | |
| shape-dns-txt-base32 | DNS TXT via resolver, base32 labels | 0.95 | 0.96 | |
| shape-smb-pipe-framed | SMB pipe, 4-byte header, residue 4 | 0.74 | 0.62 | |
| shape-websocket-poll | WS poll, base64 | 0.84 | 0.88 | |
| shape-websocket-push | WS server push only | 0.20 | 0.20 | **gap**: push channels; v9 Q4 `push_or_saas` |
| shape-tcp-pivot-le32 / -be12 | length-framed raw TCP pivot, 5 s / 10 s | — | — | **gap**: Phase 3.5 P2P framing |
| shape-https-proxy-connect | HTTPS via CONNECT proxy | 0.20 | 0.20 | **gap**: TLS inside CONNECT tunnels is not parsed |
| shape-https-redirectors-cdn | one SNI over 4 IPs, new conn | — | 0.70 ×4 | v1 sees 4 short series; v2 finds each IP, not one K1 finding |
| shape-anchored-lattice-backoff | anchored / 1 s lattice / 2× back-off | 0.39 / 0.65 / — | 0.39 / 0.65 / — | anchored grid takes the scheduler cap by design |
| shape-pcapng-snaplen | pcapng ns, 96 B snaplen | 0.65 | 0.65 | |
| shape-nat-fleet | 3 clients behind one NAT IP | — | — | |
| benign-models | WireGuard, Prometheus, browsing, gamma(0.5), Poisson, apt, Intune, Chrome | Prometheus 0.75, WireGuard 0.65, Chrome 0.65, Intune 0.64 | same | **single-host benign keep-alives score like beacons** |

**Phase 0.1 cap gates over 30 seeds** (`TestCapGateSeedSweep`):

| Scenario | v1 min / median / max | v2 |
|---|---|---|
| keep-alive 30 s | 0.52 / 0.60 / 0.64 | 0.65 at every seed |
| keep-alive 60 s | 0.53 / 0.61 / 0.64 | 0.65 |
| new-conn 30 s | 0.51 / 0.60 / 0.64 | 0.65 |
| new-conn 60 s | 0.51 / 0.60 / 0.64 | 0.65 |
| tiny bursts | 0.65–0.69 at every seed | 0.65–0.69 |
| fleet of 3 | 0.39 at every seed | 0.39 |

v2 meets ≥ 0.6 at every seed. v1 meets it at about 60 % of seeds. Its raw beacon score depends on how spread the drawn response sizes are, and the cap is not involved: the sweep asserts that no single-host series is ever capped. This is v1 scoring as it has been since v6. The v6 numbers (0.62–0.63) were single seeds.

`TestFleetGateMutation` disables the fleet check and requires the 3-client scenario to rise to ≥ 0.4, which it does.

## Scale scenario (v9c 3.2)

`synth.WriteScale` / `go run ./tools/synthgen -scale N -out dir` streams a flow-heavy capture, writing in time order with flat memory. It contains:
- N one-shot TCP connections from 2,000 internal clients to 50,000 external servers: 40 % TLS, the rest plain HTTP with browser headers;
- 0.4·N DNS lookups through an internal resolver;
- one periodic TLS series (`10.9.9.9 → rare-sync.example`, 60 s, 10 % shortening) as the needle.

The nightly / report path runs it:

```sh
C2PARSER_STRESS_REPORT=1 go test ./internal/engine -run TestScaleFlowHeavy -v -timeout 30m   # 500k connections
C2PARSER_STRESS_REPORT=1 C2PARSER_SCALE_CONNS=200000 go test ./internal/engine -run TestScaleFlowHeavy -v
```

It reports throughput, peak RSS, RSS per TCP connection, the needle's rank, and any dropped series events or summary rows. It fails if the needle ranks below 5th. Baselines are in `internal/engine/testdata/scale_baseline.json`.

## Transforms (`tools/perturb`)

| Transform | Spec | Gate |
|---|---|---|
| `drop` `dup` `reorder` `snap` `skip` `jitter` | p / n / fraction / seconds, seeded | 0 % is a byte-level no-op (`TestDamageZeroIsNoop`) |
| `conflict` | retransmission of the same seq range with different bytes, before or after the original | top finding survives 2 % conflicts in both orders |
| `oneway` | keep the initiator's (`c2s`) or responder's (`s2c`) packets | logged. c2s only: HTTP C2 0.86/0.96. s2c only: 0.35 "suspicious session" |
| `wrap` | VLAN, QinQ, GRE (TEB), ERSPAN II, VXLAN | findings identical to the unwrapped capture (`TestWrapTransparent`). **This found a bug**: GRE/ERSPAN were attributed to the tunnel endpoints and VXLAN was dropped. Fixed in v9b, see CHANGELOG |
| `readdress` | consistent IPv4 and port maps, RFC 1624 incremental checksums (valid on truncated packets) | scores identical after remapping every address; mapping back is byte-identical (`TestReaddressMetamorphic`, `TestChecksums`) |
| `clone` | copy a client's packets onto N new clients, offset k·Δ | a single-host beacon cloned to 3 clients takes the fleet cap (`TestCloneMakesFleet`) |
| `redirect` | spread a server's flows over k IPs (round-robin / random) | flows keep one address; checksums valid |
| `retime` | split a channel into request→response transactions; move each to a timing-model schedule, keeping intra-transaction offsets, seq/ack and every byte. Transactions on one keep-alive connection never overlap (pushed 1 ms past the previous one) | re-timing to the original schedule reproduces the findings exactly; per-transaction request/response bytes and the packet-byte multiset are unchanged; the new median gap is in the model's range (`TestRetime`) |
| `splice` | merge a capture into background at an offset | adding background never lowers the C2 score (`TestSpliceNeverLowersC2`) |

Every transform emits a manifest row; `-manifest file.jsonl` appends them.

**Lab gates** (`TestLabTransforms`, `C2PARSER_TESTDATA`):
- re-time the strongest C2 channel in `http_c2_enum` (the Havoc session) to its own schedule: findings identical;
- re-time it to three models: bytes preserved, scores logged;
- re-address: scores unchanged;
- drop 0 %: no-op;
- splice into `http_c2_enum_part2`: the C2 score is not lowered.

These need Bryan's machine.
