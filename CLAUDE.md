# CLAUDE.md — working in this repository

ArtiGate is a single Go binary (`cmd/artigate`) that mirrors package ecosystems
across a one-way data diode: a `low` side fetches and signs bundles, a `high`
side verifies and serves them. It sticks to the standard library plus a few
vetted dependencies (see `go.mod`).

## Required validation before every push

Run **all** of these from the repo root and make sure each passes before
committing/pushing Go changes. CI (`.github/workflows/go.yml`) gates on them, so
skipping any just moves the failure to the PR.

```bash
go build ./...
go vet ./...
go test -race ./...
golangci-lint run          # REQUIRED — do not skip; CI runs this and fails the PR on any issue
```

### golangci-lint is mandatory

You must **always validate with golangci-lint** — never push Go changes without
running it and getting `0 issues`. It is not optional and `go vet` is not a
substitute: the CI lint job (`golangci-lint-action`, **pinned to v2.12.2**, config
in `.golangci.yml`) enables a strict linter set — including complexity limits
(`gocognit`/`cyclop`/`funlen`/`nestif`), `revive`, `gocritic`, `errorlint`,
`gochecknoglobals`, `gochecknoinits`, and the `gofmt`/`gofumpt`/`goimports`
formatters — and fails the build on a single finding.

Watch out for the complexity linters in particular: adding one more `if`/`||`/
loop to an already-borderline function (many hover near the limit) will trip
`gocognit`/`cyclop`. When that happens, extract a helper rather than loosening
the config.

Install and run the **same version CI uses** (the toolchain must match `go.mod`,
currently Go 1.26.x — the module requires a newer Go than a typical system
default, so set `GOTOOLCHAIN` explicitly):

```bash
GOTOOLCHAIN=go1.26.5 go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2
GOTOOLCHAIN=go1.26.5 "$(go env GOPATH)/bin/golangci-lint" run
```

(CI itself sets `GOTOOLCHAIN=local` only because its runner pre-installs the
`go.mod` toolchain; locally, pass `GOTOOLCHAIN=go1.26.5` so the right compiler is
used.)

## Architecture notes worth keeping in mind

- **The high side trusts nothing transferred.** It verifies the Ed25519 manifest
  signature, per-stream sequencing, and every file's SHA-256, and regenerates all
  repository indexes from the artifacts actually present. When you touch the
  import path, preserve that: validate untrusted input (paths, names) at least as
  strictly as the low side does at collect time, and contain filesystem writes
  with `safeJoin`/`validateRelPath`.
- **Each ecosystem is an independently sequenced stream** so one stalled bundle
  never blocks the others. Bundle production is serialized per stream by
  `streamLock`.
- **The low side holds the signing key** and is the privileged control plane;
  the high side serves only already-verified public content and is unauthenticated.
- Background goroutines (the watch scheduler, diode workers) must not let a panic
  escape — recover it into an error, or a single bad upstream response crashes the
  whole server. See `recoverCollectPanic` in `watch.go`.

## Tests

Tests live beside the code as `*_test.go` (many `cov*_test.go` files exist purely
to hold coverage cases — extend the nearest relevant one rather than creating a
new file for a single case). Keep coverage high; the suite runs fast (`~20s`,
`~50s` with `-race`).

An opt-in end-to-end suite lives under `e2e/` behind the `e2e` build tag
(`make e2e`); it needs network access plus the real client toolchains and runs
in CI via `.github/workflows/e2e.yml`. The default `go build/vet/test ./...`
and `golangci-lint run` never compile it (only the untagged `e2e/doc.go` is in
the default build), so when touching `e2e/` also run `go vet -tags e2e ./e2e`
and keep the files gofumpt-formatted yourself — CI lint won't catch them.
