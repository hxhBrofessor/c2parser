# TQH-C2 v1.2.2 — dataset notes (v8 spec Q0.1; loader v10a 1.2)

**Status: not acquired.** Zenodo is blocked from the build sandbox (proxy 403 on
2026-10-13). Per the v8 operating constraints the fetch was not retried by
another route. Upload the files below, or fetch them on a workstation, and
fill in this page.

| Item | Value |
|---|---|
| Record | Zenodo 22732327, DOI 10.5281/zenodo.22732327 |
| Licence | CC BY 4.0 — attribution + change note required for derived subsets. Strip JA4S/JA4H columns (FoxIO License 1.1) from anything committed or shipped; never use them as model or threshold inputs |
| Size | 39.9 GB, 48 cells (30/300/1800/3600 s × 0/30/70 % jitter × Sliver TLS, Merlin QUIC + h2, Mythic HTTP) |

## First tranche (≤ 5 GB; verify every SHA-256 against `SHA256SUMS_v122.txt`)
1. `README_v122.md`, `SHA256SUMS_v122.txt`, `TQH-C2_scripts.zip` (check its own LICENSE)
2. `TQH-C2_labels_v110.zip`, `TQH-C2_labels_D.zip` (record the hash — size changed 791.5 kB → 2.2 MB with "records unchanged"), `TQH-C2_features_v110.zip`, `TQH-C2_features_D.zip`
3. `TQH-C2_pcap_C_mythic_http.zip` (379.2 MB) — plaintext HTTP
4. `TQH-C2_pcap_D_merlin_h2.zip` (1.8 GB)
5. Selected Sliver cells from `TQH-C2_pcap_A_sliver_tls.zip` (33.4 GB) via HTTP Range extraction

## To record once the README is read
- per-cell duration and event counts; framework versions/commits
- which Mythic agent and profile; Sliver HTTPS vs mTLS
- whether operator tasking runs in each cell; benign background generator
- `labeled.jsonl` schema (likely Zeek conn UIDs) and Parquet column list
- whether 1800/3600 s cells are long enough to score (the refusal ladder
  needs ≥ 10 idle gaps: 5 h at 1800 s, 10 h at 3600 s; ≥ 20 for T1)

## Attribution (for NOTICE when any derived subset ships)
"TQH-C2 v1.2.2, Zenodo record 22732327, licensed CC BY 4.0. Changes: subset
of cells; JA4S/JA4H fields removed."

## Loader (v10a) — ready, waiting for the data

`c2parser eval` joins TQH labels to c2parser's connections by Zeek UID:
each `conn.log` row (TSV or JSON, plain or `.gz`) → (ts, 5-tuple), matched
to a c2parser connection with the exact 5-tuple in either direction and a
start within ±1 s. The report lists matched / unmatched-zeek /
unmatched-c2parser / ambiguous per capture. A run fails below `min_join`.
**No column name is assumed**: every field is mapped in the manifest
(`labels.columns`), and the defaults are Zeek's standard names.

Synthetic gate (`TestZeekJoinGate`): conn.logs written beside the 37 corpus
scenarios join 100 % (1285 connections), and 100 % after `drop 0.01` +
`jitter 0.5` on the pcaps.

### Manifest skeleton (`~/data/tqh/manifest.yaml`, not in the repo)

```yaml
version: 2
name: TQH-C2 v1.2.2 first tranche
captures:
  - path: C_mythic_http/*/*.pcap          # adjust to the unzipped layout
    role: mixed                           # or c2 if the background isn't verified benign
    licence: ccby
    framework: mythic                     # or leave blank: filled from the label file's majority value
    transport: http
    labels:
      source: zeek-uid
      conn_log: C_mythic_http/*/conn.log*
      label_file: labels/labeled.jsonl    # confirm name and schema in README_v122.md
      positive: [c2]                      # confirm the label values
      min_join: 0.95
      columns:                            # confirm every name against README_v122.md
        uid: uid
        label: label
        # framework: …  transport: …  sleep: …  jitter: …   (per-row cell metadata, if present)
```

One entry per cell if the cell's sleep/jitter isn't in the label file. A
directory glob covers several pcaps per cell; use `rotated: true` only if a
cell's pcaps are time-sequential segments of one capture.

### Run

```sh
c2parser eval -manifest ~/data/tqh/manifest.yaml -check
C2PARSER_TQH=~/data/tqh c2parser eval -manifest ~/data/tqh/manifest.yaml -out ~/data/tqh/eval-out -j 4
C2PARSER_TQH=~/data/tqh go test ./internal/eval -run TestTQHManifest -v
```

### Still to fill in from the data (nothing here is guessed)

| Item | Value |
|---|---|
| Unzipped directory layout per cell | _pending_ |
| `labeled.jsonl` field names (uid, label, cell columns) and label values | _pending_ |
| conn.log format (TSV/JSON), `ts` format | _pending_ |
| Join rate per cell (from the report's Units table) | _pending_ |
| Per-cell duration and event counts; framework versions | _pending_ |
| Whether the background traffic is usable as benign (`role: mixed`) or must stay `role: c2` | _pending_ |
