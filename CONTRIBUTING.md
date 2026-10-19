# Contributing

Thanks for helping out. Bug reports, detection ideas and pull requests are all welcome.

## Setup

You need Go 1.24 or newer.

```sh
git clone https://github.com/hxhBrofessor/c2parser.git
cd c2parser
make build      # ./c2parser
make test       # go vet + go test ./...
```

Lab-capture tests skip unless `C2PARSER_TESTDATA` points at a directory of captures; that's expected. The synthetic test corpus lives in `corpus/scenarios/` (see [`docs/corpus.md`](docs/corpus.md)).

## Making a change

1. Open an issue first for anything bigger than a small fix, so we can agree on the approach.
2. Branch from `main`, one topic per branch.
3. Keep `make test` green and run `gofmt -w` on changed files.
4. Add or update tests for behaviour you change. New detections need a scenario in `corpus/scenarios/`, including a benign lookalike that must *not* fire.
5. Note user-visible changes under an "Unreleased" heading in `CHANGELOG.md`.
6. Open a pull request against `main` describing what changed and why.

## Ground rules

- **No packet captures in the repo.** No `.pcap`, `.pcapng` or `.cap` files, real or redacted. Use the synthetic corpus or describe the traffic.
- **No real secrets or customer data**, including in tests and fixtures. Use `example` domains and documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
- **Licensing:** contributions are accepted under the MIT License. Don't add JA4S/JA4H/JA4X or other code with incompatible licenses (see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)).
- Prefer the standard library; new dependencies need a reason in the PR.

## Releases

Maintainers cut releases by tagging `main` (`vX.Y`) and running `make release`, which builds static binaries for macOS, Linux and Windows plus `SHA256SUMS`.
