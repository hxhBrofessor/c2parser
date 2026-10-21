# B-3.4 ratified contract hardening

This addendum records the owner-ratified B34-D1 through B34-D6 decisions (including Claude's amendments) for this implementation slice. It does not authorize non-HTTP migration or release publication.

- **D1 — pending groups (Option C):** `verify: true` is declared-but-unpopulated. The generic YAML parser requires the `items` key to be a sequence and rejects any nonempty sequence with `PENDING_GROUP_ITEMS_NOT_EMPTY`. Pending groups do not enter the production HTTP registry. No requiredness flag, suppression, fallback or diagnostic path is added. A populated group requires a separately approved slice.
  Pending groups are fixture-only; the production asset may not declare a group until that group's separately reviewed slice extends the closed registry.
- **D2 — item fields:** fields are consumed by fixed typed algorithms or exact-bound by validation. In Covenant, URI/header/body kinds consume `message`, `method` where applicable, `header`, `value`/`values`, `feature` and `weight`. Merlin's method/path and header kinds consume their corresponding fields. PoshC2's cookie, raw-server, protocol/raw-header-name and body kinds consume their corresponding fields. Cobalt's default-URI kind consumes `method`, `header`, the URI set and feature/weight; submit-ID consumes method/path/query and content type value/elevated weight; checksum8 consumes method/checksums and substituted feature fields; empty-404 consumes status/content type and the fixed empty-body/content-length checks. Cobalt `header: content-type` on both `post_submit_id` and `response_empty_404` is an exact-bound invariant because runtime receives the normalized content-type value. CS-1's configured Cookie header remains dynamically consumed by the matcher. Identity and provenance fields (`id`, `debt_id`, `code_locator`, `reason`) are validated by parser/registry and do not configure predicate logic.
- **D3 — locators:** each item retains one immutable v11a locator. Supplemental source ranges remain in the versioned source map. The existing Cobalt CS-1 `match_lines: 135-138` entry closes the supplemental-pointer question; no YAML or source-map rewrite was made.
- **D4 — production boundary:** the generic parser retains its fixture compatibility for `field_groups: {}` and semver source revisions. The engine production registry rejects empty group maps and non-immutable source revisions (full lowercase 40- or 64-hex IDs) before admitting the four approved HTTP profiles. D-07 IDs, values and counts remain frozen; Cobalt's 21 URI values are a membership set while runtime/evaluation order remains fixed.
- **D5 — evidence JSON:** the Go suite recursively discovers tracked `evidence/**/*.json`, rejects non-UTF-8, non-object/multiple/trailing documents and duplicate object keys at any depth, accepts a final LF, and checks one-to-one PoshC2 and Cobalt D-07 profile/debt/source-map bindings. No CI/ruleset or dependency change is included.
- **D6 — scope:** DNS/DGA/tunnel, TLS/transport/QUIC/WireGuard, certificate anomaly heuristics and stateful URI shapes remain trusted Go algorithms. Certificate static identities are the next possible bounded data slice; framework frame magics are optional only after a finite inventory is established; `version_map` is deferred. The six field-group names remain in the schema and no non-HTTP group is populated here.

## Frozen runtime field ownership matrix

| Framework/kind | Runtime-consumed fields | Exact-bound or identity/provenance fields |
|---|---|---|
| Covenant `uri_exact` | message, value, feature, weight | method/header/values absent by closed grammar; id/debt/locator/reason are validation metadata |
| Covenant `header_exact` / `header_contains` | message, header, value, feature, weight | method/values absent by closed grammar; identity/provenance metadata as above |
| Covenant `body_prefix` / `body_contains_any` | message, value or values, feature, weight | method/header absent by closed grammar; identity/provenance metadata |
| Merlin `request_method_uri_exact` | message, method, value, feature, weight | header/values absent by closed grammar; identity/provenance metadata |
| Merlin `header_trim_equal_fold`, `header_prefix`, `header_exact` | message, header, value, feature, weight | method/values absent by closed grammar; identity/provenance metadata |
| PoshC2 `cookie_prefix`, `response_server_raw_exact`, `response_proto_and_raw_header_name`, `body_contains` | message, header/value as appropriate, feature, weight | method/values absent by closed grammar; identity/provenance metadata |
| Cobalt `get_default_uri_b64_cookie` | message, method, header, values-set membership, feature, weight | other Cobalt-only fields absent; id/debt/locator/reason are registry/provenance metadata |
| Cobalt `post_submit_id` | message, method, path, query predicate, value, elevated weight, feature, weight | header exact-bound to `content-type`; id/debt/locator/reason metadata |
| Cobalt `get_checksum8_stager` | message, method, checksums, feature substitutions, weight | other Cobalt-only fields absent; identity/provenance metadata |
| Cobalt `response_empty_404` | message, status, value, fixed body/content-length predicate, feature, weight | header exact-bound to `content-type`; identity/provenance metadata |

The four existing frozen framework tables and the B-3.1 golden oracle remain independent value authorities; no expected-value table is derived from YAML.
