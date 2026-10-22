# Third-party notices

c2parser is MIT-licensed (see [LICENSE](LICENSE)). Components it depends on keep their own licenses:

| Component | License |
|---|---|
| `github.com/google/gopacket` | BSD-3-Clause |
| `github.com/goccy/go-yaml` | MIT |
| `golang.org/x/sys` | BSD-3-Clause |
| JA4 TLS client fingerprint (method by FoxIO) | BSD-3-Clause |

SigmaHQ rules are downloaded at runtime under the Detection Rule License (DRL) 1.1 and are not distributed with this software.

c2parser does not implement JA4S, JA4H or JA4X; those are under the FoxIO License 1.1. Don't add them, or any data derived from them, without checking that license first.

Format reference: dissect.cobaltstrike (MIT), facts only, no code.
