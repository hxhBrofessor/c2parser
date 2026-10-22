# WS-5 Sigma rule findings register (v11.2 / Q-05)

Per-rule disposition, owner decision id, and external reference status. Reference
statuses and pinned citations are from the WS-5 S1 review §6 (ChatGPT external
verification, 2026-10-22, Claude-reviewed). Citations are pinned to a full commit
SHA with full paths (S2a / S2-1); tracking parameters (`utm_*`) are stripped.

Reference-status vocabulary: **VERIFIED** (confirmed in a pinned upstream source);
**LAB_OBSERVED** (reproducible on internal Gate A captures; mechanism not located
upstream); **NOT SUPPORTED** (upstream source does not support the claim);
**UNVERIFIED** (no confirmation either way).

| Signal | Rule | Disposition | Owner decision | Status in v11.2 |
|---|---|---|---|---|
| `sigma:50995159` | Sliver DNS `^baak` | **RETIRED** (deleted from the embedded set) | W5-1 | removed; Sliver-like DNS detected by shape / positional-randomness analysis |
| `sigma:e1f2bf20` | Havoc HTTP (shipped example profile) | **KEPT**, id unchanged; de-identified; references repointed | W5-2 + §6 C1/C2/C3 | built-in; folds into the matching C2 finding |
| `sigma:1cc74d57` | Mythic http | **MOVED** to `docs/sigma-examples/` (not embedded) | W5-3 = M-B | optional example; not loaded by default |
| `sigma:96cd9d1f` | Mythic websocket | **MOVED** to `docs/sigma-examples/` (not embedded) | W5-3 = M-B | optional example; not loaded by default |
| `sigma:0b00ae2f` | Apollo SMB (UUID pipe) | **MOVED** to `docs/sigma-examples/` (not embedded) | W5-3 = M-B | optional example; not loaded by default |

## Reference status detail

### `sigma:50995159` — Sliver DNS `^baak` — **NOT SUPPORTED → RETIRED**
The cited source describes encoded subdomains and volume-based detection, not a
fixed `baak` prefix; it does not support a literal-prefix rule. Together with the
measured corpus/lab delta of 0/0 (WS-5 S1), this supports retirement. The rule also
failed VA-4 ("a framework name only with framework-specific evidence"), an
independent reason to retire.
- Citation: `immersivelabs.com/resources/c7-blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide`

### `sigma:e1f2bf20` — Havoc HTTP — split status (UA / POST / `*/*`)
The rule is kept with its id unchanged. "Default" was an overclaim (Havoc ships
example profiles and the operator selects one); the title now says "shipped example
profile". The three matched facts carry separate statuses:

| Fact | Status | Basis |
|---|---|---|
| User-Agent (Chrome 96 / Win 7) | **VERIFIED** | appears in a shipped example profile |
| `POST` method | **VERIFIED (example)** | appears in the wiki example |
| `Content-Type: */*` | **LAB_OBSERVED** | matched on the wire in Gate A cap0, cap1, cap3 (WS-5 S1 lab register); **not found upstream**; mechanism UNKNOWN (not asserted whether the agent or the HTTP stack adds it) |

- Citations (pinned; in the rule's `references:`): `https://github.com/HavocFramework/Havoc/blob/c84f7755a8b1c0f737576bdd3a0e982a296012f1/profiles/http_smb.yaotl#L34`; `https://github.com/HavocFramework/Havoc/blob/c84f7755a8b1c0f737576bdd3a0e982a296012f1/WIKI.MD`
- Public rule text says only "observed in lab traffic" — no unit, lab, or person names.

### `sigma:1cc74d57` — Mythic http — **documented as example, not default (UNVERIFIED default)**
`/index?q=` is an example and the default User-Agent is not established upstream; the
rule is an optional example, not an embedded default.
- Citation: `https://github.com/MythicC2Profiles/http/blob/b1e7ed17719ed123ddc1a99d9802b3b9d85849f8/documentation-c2/http/_index.md#L100-L104`

### `sigma:96cd9d1f` — Mythic websocket — **VERIFIED**
The default `websocketuri` is `socket`.
- Citations: `https://github.com/MythicC2Profiles/websocket/blob/326fc8cd1e90a6c902a8ee2df0e8a83e9ae8aec3/C2_Profiles/websocket/websocket/c2_code/config.json#L8`; `https://github.com/MythicC2Profiles/websocket/blob/326fc8cd1e90a6c902a8ee2df0e8a83e9ae8aec3/C2_Profiles/websocket/websocket/mythic/websocket.py#L59-L61`

### `sigma:0b00ae2f` — Apollo SMB — **VERIFIED (not Mythic-exclusive)**
The default pipe name is a random GUID; the UUID-pipe shape is not Mythic-exclusive
(it overlaps the native `uuid_pipe_name` signal, `internal/engine/findings.go:471`).
Labelled Apollo (a Mythic agent), not "Mythic smb profile".
- Citation: `https://github.com/MythicAgents/Apollo/blob/ae4c56df97f6f98b3d380ae7994c3ce1d6e6ffd4/README.md`

## Carried forward (not in this slice)
- **W5-5 / VA-0:** all framework-naming Sigma signals are evidence class
  `sigma_attribution`, suppressed in blind mode — handled in the VA-0 order.
- Confirmation of the Havoc `*/*` mechanism and of the Mythic http default UA
  remain open for owner/ChatGPT follow-up.
