# WS-5 Sigma rule findings register (v11.2 / Q-05)

Per-rule disposition, owner decision id, and external reference status. Reference
statuses and pinned citations are from the WS-5 S1 review §6 (ChatGPT external
verification, 2026-10-22, Claude-reviewed). Citations are pinned to a commit where
the source is GitHub; tracking parameters (`utm_*`) are stripped. Where the source
review elided a path segment with `…`, it is preserved as given, not reconstructed.

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

- Citations (pinned; in the rule's `references:`): `HavocFramework/Havoc@c84f7755…/profiles/http_smb.yaotl#L34`; `HavocFramework/Havoc@c84f7755…/WIKI.MD`
- Public rule text says only "observed in lab traffic" — no unit, lab, or person names.

### `sigma:1cc74d57` — Mythic http — **documented as example, not default (UNVERIFIED default)**
`/index?q=` is an example and the default User-Agent is not established upstream; the
rule is an optional example, not an embedded default.
- Citation: `MythicC2Profiles/http@b1e7ed17…/documentation-c2/http/_index.md#L100-L104`

### `sigma:96cd9d1f` — Mythic websocket — **VERIFIED**
The default `websocketuri` is `socket`.
- Citations: `MythicC2Profiles/websocket@326fc8cd…/…/c2_code/config.json#L8`; `MythicC2Profiles/websocket@326fc8cd…/…/mythic/websocket.py#L59-L61` (path segments elided as in the source review)

### `sigma:0b00ae2f` — Apollo SMB — **VERIFIED (not Mythic-exclusive)**
The default pipe name is a random GUID; the UUID-pipe shape is not Mythic-exclusive
(it overlaps the native `uuid_pipe_name` signal, `internal/engine/findings.go:471`).
Labelled Apollo (a Mythic agent), not "Mythic smb profile".
- Citation: `MythicAgents/Apollo@ae4c56df…/README.md`

## Carried forward (not in this slice)
- **W5-5 / VA-0:** all framework-naming Sigma signals are evidence class
  `sigma_attribution`, suppressed in blind mode — handled in the VA-0 order.
- Confirmation of the Havoc `*/*` mechanism and of the Mythic http default UA
  remain open for owner/ChatGPT follow-up.
