# Go modules

ArtiGate mirrors Go modules end to end: the [low side](../low-side.md) fetches them from the internet with the real `go` toolchain and packs the resulting module-cache files into signed bundles, and the [high side](../high-side.md) serves them back over HTTP as a read-only [GOPROXY](https://go.dev/ref/mod#goproxy-protocol) for air-gapped clients.

Go work travels on the `go` stream. Like every ecosystem, that stream has its own sequence counter, export lock, and export-dedup index, so a Go collect never blocks or interleaves with Python, Maven, npm, APT, RPM, container, or AI model work.

## What it mirrors

For every module version ArtiGate transfers exactly three files — the ones a GOPROXY must serve:

| File | Purpose |
|---|---|
| `<version>.info` | JSON `{Version, Time}` metadata |
| `<version>.mod` | the module's `go.mod` |
| `<version>.zip` | the module source archive |

The `.ziphash` and `.lock` files that `go` writes into its cache are **deliberately not** transferred — they are local artefacts, not part of the trust chain across the diode. See [Limitations](#limitations) for what that implies for clients.

## Low-side inputs

Drive a collect with `POST /admin/go/collect`. The request body (max 8 MiB, to leave room for an embedded `go.sum`) is:

```json
{
  "modules": ["rsc.io/quote@v1.5.2", "golang.org/x/text"],
  "resolve_deps": false,
  "go_mod": "",
  "go_sum": "",
  "force": false
}
```

`force: true` bypasses the export-dedup index for this collect, producing a full self-contained bundle (see [Dedup](#internals) below).

There are four ways to describe what to fetch. They are dispatched by **precedence — `go_mod` wins**: when it is set, `modules` and `resolve_deps` are ignored.

### 1. Explicit module list

Set `modules` to concrete specs. Each entry is parsed on the **last** `@`:

```json
{ "modules": ["rsc.io/quote@v1.5.2", "golang.org/x/text@v0.14.0"] }
```

Only concrete versions are downloaded; a spec must resolve to a real version before the module ZIP is fetched.

### 2. Bare module / `@latest`

A spec with no version, or the literal `@latest`, is resolved to a concrete version first (ArtiGate runs `go list -m -json <module>@latest`) and then downloaded:

```json
{ "modules": ["rsc.io/quote", "golang.org/x/text@latest"] }
```

### 3. Module list plus full dependency graph

Set `modules` **and** `resolve_deps: true`. ArtiGate writes a synthetic `go.mod` that requires the listed roots and then downloads the **entire** module graph — every transitive dependency, not just the roots:

```json
{ "modules": ["rsc.io/quote"], "resolve_deps": true }
```

The synthetic module pins a deliberately low `go 1.16` directive so the toolchain never rejects it:

```go
module artigate-collect

go 1.16

require rsc.io/quote v1.5.2
```

### 4. Project `go.mod` (and optional `go.sum`) upload

Send the project's own `go.mod` as `go_mod` and, optionally, its `go.sum` as `go_sum`. This is the most faithful "what this project actually builds" mode: ArtiGate writes both files into a temporary module directory and downloads the whole graph, honouring the project's real `go` directive and `require` list.

```json
{
  "go_mod": "module example.com/app\n\ngo 1.22\n\nrequire rsc.io/quote v1.5.2\n",
  "go_sum": "rsc.io/quote v1.5.2 h1:...\nrsc.io/quote v1.5.2/go.mod h1:...\n"
}
```

!!! note "The full dependency graph is always fetched in graph modes"
    Both mode 3 and mode 4 run `go mod download -json all` in the temp directory. `-json all` enumerates the graph **and** populates the module cache that the bundle is built from — so ArtiGate mirrors everything the project can reach, not only its direct requires.

!!! warning "`go_mod` silently overrides the list"
    If `go_mod` is non-empty, `modules` and `resolve_deps` are ignored. Sending both is not an error — the list is simply dropped. With `go_mod` empty **and** `modules` empty, the collect fails with `no go modules provided`.

## Fetch configuration

Every `go` invocation runs with a fresh environment. Some values are fixed; the rest come from `low` flags (see the [configuration reference](../configuration.md) for the full list).

Fixed, hard-coded values:

| Env var | Value | Why |
|---|---|---|
| `GO111MODULE` | `on` | modules always on |
| `GOPATH` | `<root>/gopath` | server-managed |
| `GOMODCACHE` | `$GOPATH/pkg/mod` | server-managed |
| `GOCACHE` | `<root>/gobuildcache` | build cache |
| `GIT_TERMINAL_PROMPT` | `0` | never block on an interactive git/SSH password in daemon mode |

Configurable flags:

| Flag | Default | Env var | Notes |
|---|---|---|---|
| `--upstream-goproxy` | `https://proxy.golang.org,direct` | `GOPROXY` | `direct` falls through to VCS for uncovered paths |
| `--gosumdb` | `sum.golang.org` | `GOSUMDB` | checksum DB consulted at collect time |
| `--goprivate` | *(empty)* | `GOPRIVATE` | set only when non-empty |
| `--gonosumdb` | *(empty)* | `GONOSUMDB` | set only when non-empty |
| `--gonoproxy` | *(empty)* | `GONOPROXY` | set only when non-empty |
| `--govcs` | `*:git` | `GOVCS` | governs `direct`/VCS fetches |
| `--gotoolchain` | `auto` | `GOTOOLCHAIN` | set only when non-empty |
| `--go` | `go` | *(binary path)* | which `go` to run |

!!! tip "Checksum verification happens here"
    `GOSUMDB` **defaults on** (`sum.golang.org`) on the low side. This is the security boundary: modules are verified against the public checksum database *before* they enter the trusted zone. The high side never re-checks against a sumdb — the signed bundle is the substitute trust anchor (see [Client setup](#client-setup)).

### Toolchain selection

`GOTOOLCHAIN` defaults to `auto`, which lets `go` download a newer toolchain when a module's `go` directive exceeds the installed one. The official `golang` container images pin `GOTOOLCHAIN=local`, which would instead abort with `requires go >= X`; ArtiGate overrides that so large graphs resolve cleanly. Pin it back with `--gotoolchain local` if you want strict, offline-friendly behaviour.

### Private modules

`GOPRIVATE`, `GONOPROXY`, and `GONOSUMDB` are injected only when non-empty, so private-module handling is strictly opt-in. A typical private setup keeps `direct` in the proxy list so private paths fall through to a VCS (git) fetch governed by `GOVCS=*:git`:

```bash
artigate low \
  --private-key /etc/artigate/low.ed25519 \
  --upstream-goproxy https://proxy.golang.org,direct \
  --goprivate 'github.com/your-org/*' \
  --gonosumdb 'github.com/your-org/*'
```

!!! warning
    Private modules require preconfigured git/SSH credentials in the low-side container. Because `GIT_TERMINAL_PROMPT=0` is forced, an unauthenticated private fetch fails immediately rather than hanging on a password prompt.

## Internals

**Staging.** Fetches land in the standard on-disk GOPROXY layout under `$GOPATH/pkg/mod/cache/download` (`<module>/@v/<version>.{info,mod,zip,ziphash,lock}`). A single-version collect runs `go mod download -json <module>@<version>` and requires the `info`, `mod`, and `zip` outputs to all be present, or it reports that version as failed. The bundle manifest captures exactly those three files per module version.

**Resilient batches.** A module version that fails to fetch is recorded (module, version, error) and **skipped**, not fatal — one bad version never blocks the rest of the batch. Failed modules surface in the collect result as `SkippedModules`. If *nothing* fetches, the collect errors with `no modules could be fetched` and **no sequence is burned** — an all-failed collect must never leave a permanent gap the high side would wait on forever.

**Dedup.** After fetching, ArtiGate checks every file against the per-stream export index. If all content was already exported, it writes no bundle and burns no sequence (the result is marked skipped, "no new content since the last export"). If only some files are new, it writes a **delta bundle**: the archive carries the new files, the rest ride in the manifest as `prior` references (counted in the result's `prior_files`), and the high side verifies them against its accumulated repository. `"force": true` bypasses the index for a full, self-contained bundle. Dedup fails safe: an empty file set or any store error means *not* skipped. Go has no pre-download hash from upstream, so files are always fetched (the module cache makes re-fetches cheap) and deduped after hashing.

**Flag-injection safety.** Caller-supplied module paths and versions become `go` command-line arguments, so both are validated before any `go` call:

- Module paths reject empty path elements, any element starting with `-` (which would smuggle a flag like `-modfile` or `-C`), and any control/space byte (`<= 0x20` or `0x7f`).
- Versions reject an empty string, a leading `-`, and the same control/space bytes. Only concrete versions download — `""` and `latest` are explicitly refused by the fetch step.

Each `go` invocation is capped at a **10-minute timeout**, and stdout and stderr are kept separate so `go: downloading …` progress and toolchain notices on stderr never corrupt the JSON that ArtiGate parses from stdout.

## High-side GOPROXY serving

On the high side, imported Go modules live under `<root>/cache/download/go/` in GOPROXY layout. Each file is SHA-256-verified on import; an existing immutable file whose content differs triggers an `immutable file conflict` rather than a silent overwrite, and a matching re-import is a no-op. A version becomes servable only once a `<version>.complete` marker sits beside its `.info`, `.mod`, and `.zip`.

The `/go` prefix (and everything under it) is served as a GOPROXY. Only `GET` and `HEAD` are accepted; anything else is `405`.

### Routes

All routes are relative to the `GOPROXY` base plus `/go`, with `<module>` and `<version>` **bang-escaped** (each uppercase letter becomes `!` + its lowercase form, e.g. `github.com/Sirupsen` → `github.com/!sirupsen`):

| Route | Response |
|---|---|
| `/go/<module>/@v/list` | `text/plain`, one version per line |
| `/go/<module>/@latest` | `application/json` `{Version, Time}` |
| `/go/<module>/@v/<version>.info` | `application/json` |
| `/go/<module>/@v/<version>.mod` | `text/plain` |
| `/go/<module>/@v/<version>.zip` | `application/zip` |
| `/go/<module>/@v/<version>.ziphash` | `text/plain` *(route exists; see below)* |

Behavioural notes:

- **`/@v/list`** enumerates only *complete* versions and keeps only valid, non-pseudo semver — **pseudo-versions never appear in `list`**, even when present in the cache.
- **`/@latest`** prefers the highest release, then the highest prerelease, then the newest pseudo-version by `.info` time; it is `404` (`no complete versions`) when the module has none.
- Version-file requests `404` unless the version is complete, and the ZIP/mod/info are served straight from disk.

## Client setup

Point air-gapped clients at the high side and turn the checksum database off:

```bash
export GOPROXY=https://high-proxy:8080/go,off
export GOSUMDB=off
```

Or per-invocation:

```bash
GOPROXY=https://high-proxy:8080/go,off GOSUMDB=off go build ./...
```

- **`GOPROXY=<base>/go,off`** — `/go` is where ArtiGate's proxy lives, and the trailing `,off` forbids any fallback to a direct/VCS fetch. The client can only ever obtain modules ArtiGate has already mirrored.
- **`GOSUMDB=off`** — the client must not consult a checksum database.

### Why there is no sumdb mirroring

ArtiGate mirrors **no** checksum database — there is no `sumdb/` route on the high side, and nothing from `sum.golang.org` is ever stored or transferred. That is deliberate:

- Checksums were already verified **on the low side at collect time** (`GOSUMDB=sum.golang.org`), before the module entered the trusted zone.
- Integrity across the diode is guaranteed instead by the **Ed25519-signed manifest** plus per-file **SHA-256** verification on import, and by immutable-file conflict detection. The high side re-derives everything it serves from verified bytes and never trusts transferred metadata.
- A `GOSUMDB` left on would make the client try to reach the public sumdb over the network — unreachable in an air-gapped environment, and blocked by `,off` anyway. Hence `GOSUMDB=off` is required; the signed-bundle chain is the trust anchor.

## Limitations

- **`.ziphash` is never transferred.** The route exists and passes the completeness check, but the file itself was never bundled, so a `.ziphash` request `404`s. This is inert in practice: clients configured with `GOSUMDB=off` do not request `.ziphash`.
- **Pseudo-versions are hidden from `/@v/list`.** They are still fetchable by exact version, and `/@latest` falls back to the newest pseudo-version only when a module has no tagged release.
- **`go_mod` mode ignores `modules`/`resolve_deps`.** See the precedence warning above.
- **The synthetic collect module pins `go 1.16`.** Project (`go_mod`) mode instead honours the real `go` directive from the uploaded file.
- **Each `go` call is capped at 10 minutes.** A very large graph download that exceeds it fails the whole collect; split it into smaller collects.
- **Empty or all-failed collects produce no bundle and no sequence** — by design, to avoid creating a gap the high side would wait on indefinitely.

## Related pages

- [Low side](../low-side.md) — operating the exporter
- [High side](../high-side.md) — operating the read-only proxy
- [HTTP API reference](../api.md) — the exact request/response contracts
- [Configuration reference](../configuration.md) — every flag and environment variable
