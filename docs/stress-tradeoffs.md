# Stress-gate trade-offs

Cells where `-timing v2` scores below max(v1, last release) − 0.03 on the stress grid, accepted with a reason (v9 Phase 0.3).
`internal/stats/stressgate_test.go` fails for any such cell **not** listed here, and fails if this list and the test's `stressTradeoffs` map disagree.

Measured 2026-10-14, fixed seeds, 300 reps per cell, 60 s sleep. The gate's last release is now **v9.0**; its recorded grid is identical to v9a in all 141 cells (the stats engine did not change in v9b/v9c), so the v9a column stands for both. Detection = v2 dispersion evidence ≥ 0.75; v1 = ScoreBeacon ≥ 0.55.

| Cell | v1 | v8b | v9a | Reason |
|---|---|---|---|---|
| `beacon/shorten/70/n15/clean` | 0.23 | 0.03 | 0.13 | A |
| `beacon/symmetric/50/n15/clean` | 0.34 | 0.04 | 0.21 | A |
| `beacon/symmetric/70/n15/clean` | 0.06 | 0.00 | 0.02 | A |
| `beacon/symmetric/70/n30/clean` | 0.12 | 0.01 | 0.06 | A |
| `beacon/symmetric/70/n60/clean` | 0.21 | 0.04 | 0.13 | A |
| `beacon/anchored/50/n15/clean` | 0.79 | 0.34 | 0.74 | A |
| `beacon/anchored/70/n15/clean` | 0.39 | 0.04 | 0.24 | A |
| `beacon/anchored/90/n15/clean` | 0.16 | 0.01 | 0.05 | A |
| `beacon/anchored/90/n30/clean` | 0.38 | 0.05 | 0.21 | A |
| `beacon/anchored/90/n60/clean` | 0.73 | 0.30 | 0.64 | A |
| `artifact/shorten/70/n60/miss20%` | 0.55 | 0.01 | 0.02 | B |
| `artifact/shorten/70/n60/stall5%` | 0.72 | 0.34 | 0.60 | C |
| `artifact/symmetric/70/n60/miss20%` | 0.18 | 0.00 | 0.00 | B |
| `artifact/symmetric/70/n60/stall5%` | 0.15 | 0.00 | 0.03 | C |
| `artifact/symmetric/70/n60/quant1s` | 0.16 | 0.01 | 0.10 | C |

**Reasons**

- **A** — High jitter at few events: CV can't separate 50–90 % jitter from gamma(4) benign at this n. v1's higher rate comes without benign-FPR control (v1 FP on gamma(4) fixed-size benign: 9 % at 30 events, 92 % at 200; v2 ≤ 2 %). Findings print an 'events needed' note.
- **B** — Missed beats at 70 % jitter: single gaps span 0.3–1.7P and doubled gaps 0.6–3.4P, so folding can't tell a missed check-in from jitter; v1 scores these partly on size regularity without FPR control.
- **C** — Stalls / 1 s quantisation on 70 % jitter: a few injected long gaps push an already borderline CV (≈ 0.3–0.4) above the gamma(4) tail.

These are inherent to timing-only evidence at a bounded benign false-positive rate. They are re-measured on TQH-C2 and the benign corpus in Phase 5, where v1 and v2 are compared at a matched benign operating point.

## Engine-level trade-offs (default `-timing v1`, not in the stats grid)

These come from the corpus seed sweep (`TestCapGateSeedSweep`, 30 seeds per scenario), not from the stats grid above. `internal/engine/corpus_test.go` checks that every scenario named here exists and is swept.

| Scenario (corpus) | v1 min / median / max | v2 | Reason |
|---|---|---|---|
| gate-single-https-keepalive-30s | 0.52 / 0.60 / 0.64 | 0.65 at every seed | D1 |
| gate-single-https-keepalive-60s | 0.53 / 0.61 / 0.64 | 0.65 | D1 |
| gate-single-https-new-conn-30s | 0.51 / 0.60 / 0.64 | 0.65 | D1 |
| gate-single-https-new-conn-60s | 0.51 / 0.60 / 0.64 | 0.65 | D1 |

- **D1** (v9b review decision, accepted 2026-10-14): v1 scores a timing-only single-host HTTPS beacon below 0.6 on about 40 % of seeds. Its beacon score includes a size-regularity term, which falls when response sizes vary (200–599 B here). This has been v1 behaviour since v6, and the timing-only cap is not involved: the sweep asserts no single-host series is ever capped. v1 is not retuned. v2 reaches ≥ 0.6 at every seed, which is one more input to the default flip once TQH-C2 and benign data exist. Gate: v2 ≥ 0.6 at every seed; v1 never capped, median ≥ 0.6.
