# Low side

The low side is ArtiGate's internet-facing **exporter**. Operators drive it to fetch artifacts with the native package toolchains, pack each fetch into a signed three-file bundle, and write those bundles to the export directory for the data diode to carry across to the [high side](high-side.md).

The low side is deliberately *not* a proxy. It never serves modules to clients — `ServeHTTP` accepts only `/admin/*` routes, the dashboard UI, and `/healthz`; everything else returns `404`. Pulling is a separate concern that lives entirely on the high side.

## Running it

The low side is the `low` subcommand of the single `artigate` binary. It requires a base64 Ed25519 **private key** (created with `artigate keygen`); it is fatal to start without one.

```bash
artigate low \
  --listen :8080 \
  --root /var/lib/artigate-low \
  --export-dir /var/spool/diode-out \
  --private-key /etc/artigate/low.ed25519
```

On startup the server creates `<root>`, `<export-dir>`, and the Go module cache (`<root>/gopath/pkg/mod/cache/download`), opens two SQLite databases (`<root>/watches.db` for scheduled pulls and `<root>/exported.db` for the export-dedup index), and loads or creates `<root>/low-state.json` (the per-stream sequence counters).

### Common flags

| Flag | Default | Purpose |
|---|---|---|
| `--listen` | `:8080` | HTTP listen address |
| `--root` | `/var/lib/artigate-low` | Low-side working directory |
| `--export-dir` | `/var/spool/diode-out` | Where signed bundles are written (the diode outbound spool) |
| `--private-key` | *(required)* | Base64 Ed25519 private key path |
| `--upstream-goproxy` | `https://proxy.golang.org,direct` | GOPROXY for the Go fetcher; use `direct` to fetch from VCS |
| `--gotoolchain` | `auto` | `auto` lets `go` download a newer toolchain when a module needs it; `local` pins the installed one |
| `--python` | `python3` | Interpreter used for `pip download` |
| `--maven` | `mvn` | Maven command |
| `--npm` | `npm` | npm command |
| `--container-registry` | *(empty)* | Comma-separated `host=baseURL` registry overrides, e.g. `docker.io=https://mirror.example.com` |
| `--watch-interval` | `60s` | How often the scheduler checks for due watches; `0` disables scheduled pulls |

!!! note
    `--watch-interval` is a Go duration, so `30s`, `5m`, `2h` all work. The full set of flags — including the Go private-module knobs (`--goprivate`, `--gonoproxy`, `--gonosumdb`, `--govcs`, `--gosumdb`), `--go`, and `--npm-registry` — is in the [configuration reference](configuration.md).

!!! warning "Unauthenticated by default"
    When `ARTIGATE_LOW_AUTH` is unset, the dashboard **and** every mutating `/admin/*` endpoint are open. Bind the low side to localhost or a trusted network, or set `ARTIGATE_LOW_AUTH` to require a form login. See [Security &amp; trust](security.md); for HTTPS see [TLS / HTTPS](tls.md).

## The dashboard

Point a browser at the listen address (`/`, `/ui`, or `/ui/`) for a single self-contained HTML dashboard — no external assets. The navigation has three kinds of view:

| View | What it shows |
|---|---|
| **Overview** | Every scheduled pull (watch) across all ecosystems: stream, last run, status, next run, and per-watch actions |
| One page per ecosystem | A collect form for that ecosystem, a live progress modal, an inline result box, and a "schedule the above" row |
| **Status** | The bundle ledger: next sequence per stream and every exported sequence with its archive/outbound state |

There is one ecosystem page per stream: **Go**, **Python**, **Maven**, **npm**, **APT**, **RPM**, and **Containers**. Each page's collect form maps directly to the matching `/admin/<stream>/collect` endpoint. See [Ecosystems](ecosystems/index.md) for the payload each one accepts.

If `ARTIGATE_LOW_AUTH` is configured, a **Log out** button appears (it POSTs to `/logout`), and any `401` from an expired session redirects the whole UI to `/login`.

## Collect &amp; export

A collect resolves a set of artifacts, fetches them with the host toolchain, and — if there is anything new to send — writes one signed bundle. Every ecosystem follows the same shape:

1. **Lock the stream.** Each stream has its own mutex, so two exports on the same stream can never claim the same sequence number, while different streams (say a long APT mirror and a Python collect) run concurrently.
2. **Resolve** the request into concrete artifacts.
3. **Fetch** with the native tool *before* allocating a sequence. A single artifact that fails to download is recorded and skipped — one bad version never aborts the batch. If *nothing* could be fetched, the collect errors out rather than emit an empty bundle (which would leave the high side waiting forever).
4. **Dedup check.** If every fetched file's SHA-256 was already exported on this stream, the collect is skipped — **no sequence is consumed and no bundle is written**.
5. **Allocate → write → sign → commit.** Otherwise the next sequence is taken, the bundle is built, the manifest is signed, the sequence counter advances, and the file hashes are recorded in the dedup index (only *after* the commit succeeds).

You can drive a collect from the dashboard, or directly over HTTP:

```bash
curl -X POST http://localhost:8080/admin/go/collect \
  -H 'Content-Type: application/json' \
  -d '{"modules":["rsc.io/quote@v1.5.2"],"resolve_deps":true}'
```

A buffered (non-streaming) collect responds with a JSON `ExportResult`:

```json
{
  "stream": "go",
  "sequence": 1,
  "exported_modules": 3,
  "bundle_id": "go-bundle-000001",
  "skipped_modules": [
    {"module": "example.com/broken", "version": "v0.1.0", "error": "..."}
  ]
}
```

A dedup skip instead returns `{"stream":"go","skipped":true,"message":"no new content since the last export"}`.

### What lands in the export dir

Bundle IDs are `<stream>-bundle-<seq>` zero-padded to six digits — for example `go-bundle-000001`, `python-bundle-000007`, `apt-bundle-000042`. Each bundle is exactly **three files** that share that ID:

| File | Contents |
|---|---|
| `<id>.tar.gz` | The artifact archive (built deterministically) |
| `<id>.manifest.json` | The manifest — the exact bytes that are signed |
| `<id>.manifest.json.sig` | Detached base64 Ed25519 signature of the manifest bytes |

All three are written atomically into `--export-dir` and then copied into the persistent archive at `<root>/bundles`. The diode transfer moves the copies *out of* the export dir; the archive copy is what makes a later re-export possible.

!!! note
    The manifest's `type` field is always the legacy string `"go-module-bundle"` for **every** ecosystem — the real ecosystem is carried by the `stream` field and the populated sub-manifest (`python`, `apt`, `npm`, …). The signature is over the exact on-disk manifest bytes, so any tool that rewrites that JSON breaks verification.

## Live progress (NDJSON streaming)

The dashboard always POSTs collects with `?stream=1`, which switches the response from a single buffered JSON object to a live **NDJSON** stream (`Content-Type: application/x-ndjson`, `Cache-Control: no-store`). One JSON object is emitted per line:

```text
{"type":"log","message":"Resolving the Go module graph…"}
{"type":"log","message":"Resolved 3 module(s); fetching…"}
{"type":"log","message":"→ [1/3] rsc.io/quote@v1.5.2"}
{"type":"log","message":"Packing 9 file(s) into a signed bundle…"}
{"type":"done","result":{"stream":"go","sequence":1,"exported_modules":3,"bundle_id":"go-bundle-000001"}}
```

There are three event types: `log` (a human-readable progress line), a terminal `done` carrying the full `ExportResult`, and a terminal `error` carrying the error string. You can consume the same stream from the command line:

```bash
curl -N -X POST 'http://localhost:8080/admin/python/collect?stream=1' \
  -H 'Content-Type: application/json' \
  -d '{"requirements":"requests"}'
```

In the browser this drives a shared **progress modal**: a spinner, a live-tailing log, and a result box. Close is disabled while a collect runs, and Esc / backdrop dismissal is blocked until it finishes. A dedup skip renders uniformly as "No new content since the last export — nothing to send across the diode." The modal always refreshes the Status page afterward.

!!! tip
    Without `?stream=1` the collect runs buffered and emits no progress lines — the progress sink is a no-op, which is exactly how scheduled watches run. Streaming is purely a UI/observability aid; the export result is identical either way.

## Export deduplication

ArtiGate keeps a per-stream index of the SHA-256 of every file it has ever exported (SQLite, `<root>/exported.db`). Before writing a bundle, a collect checks whether **every** resolved file is already in that index; if so it skips, consuming no sequence and producing no diode traffic. This is what makes a scheduled re-pull of an unchanged upstream cheap.

The index is an optimization, never correctness state: an empty file set or any store error fails safe (it exports rather than wrongly skips), and it records hashes only *after* the sequence commit succeeds. Re-export bypasses the index entirely. The full rationale is in the [architecture](architecture.md) page.

## Status page &amp; re-transmitting bundles

The **Status** page (backed by `GET /admin/bundles` / `GET /ui/api/status`) shows the next sequence per stream and one row per exported sequence, with columns **Stream · Sequence · Bundle · Size · Archive · Outbound**:

- **Archive** — `✓ kept` when the retained copy still exists in `<root>/bundles` (required for re-export), or `✗ not kept` once it has been pruned.
- **Outbound** — `staged` (still in the export dir, awaiting the diode) or `sent` (forwarded — the files were moved out; this is normal, not an error).

### Re-export a bundle number or range

If a bundle is lost in transit or a high side is rebuilt, replay the exact archived bytes with `POST /admin/reexport`. This is a **byte-exact replay of the archived bundle** — not a re-collect and not a re-sign — so it works for every ecosystem and never touches the dedup index.

The sequence spec accepts single numbers and inclusive ranges, comma-separated (`42,45-47`), capped at 10000 sequences per request. The target stream can come from the query string, a JSON body, or a raw body, and **defaults to `go`** when unspecified.

```bash
# query form
curl -X POST 'http://localhost:8080/admin/reexport?stream=python&sequences=7,10-12'

# JSON body form
curl -X POST http://localhost:8080/admin/reexport \
  -H 'Content-Type: application/json' \
  -d '{"stream":"go","sequences":"42,45-47"}'
```

Re-export takes the same per-stream lock as a fresh export (so it cannot collide with one in flight) and reports which sequences were replayed and which failed:

```json
{
  "stream": "python",
  "requested_ranges": ["7", "10-12"],
  "sequences": [7, 10, 11, 12],
  "reexported": [{"stream":"python","sequence":7,"bundle_id":"python-bundle-000007","message":"re-exported from archive"}],
  "failed": ["11: no archived bundle for python-bundle-000011"]
}
```

!!! warning
    Re-export only works while the archive copy exists. A bundle showing `✗ not kept` on the Status page has been pruned and can no longer be replayed.

## Scheduling

Any collect form can be turned into a recurring **watch** with the "Schedule the above" row — pick an interval in hours or days and the stored spec re-runs on the scheduler tick. A watch replays exactly the collect body its page would POST, so moving references (a container tag, `@latest`, `resolve_deps`) re-resolve on every run, while dedup ensures unchanged upstreams produce no new bundles. See [Scheduling (watches)](scheduling.md) for the full model, the API, and the run-now / enable / disable controls.

## Fetching uses host tools and credentials

The low side deliberately **delegates fetching to the tools already installed on the host** and runs them with the host's credentials and network access. Make sure the relevant binaries are present and configured:

| Ecosystem | Host tooling used |
|---|---|
| Go | `go` (and `git` for VCS fetches) |
| Python | `python3` / `pip download` |
| Maven | `mvn` |
| npm | `npm` |
| APT | `gpgv` (to verify the upstream `Release` against a supplied keyring) |
| RPM | `gpgv` (optional, for repo signature verification) |

Because fetching runs as native tooling, upstream credentials and proxy settings come from the host environment. In particular:

- **Private Go modules** need Git and SSH configured on the low-side host (working `~/.ssh`, `~/.gitconfig`, credential helpers), plus the matching `--goprivate` / `--gonoproxy` / `--gonosumdb` flags so `go` fetches them directly from the VCS instead of the public proxy and sum database.
- ArtiGate always forces `GIT_TERMINAL_PROMPT=0`, so Git never blocks on an interactive password prompt — configure non-interactive auth (SSH keys or a credential helper) or the fetch fails fast.

The Go `GO*` environment knobs are only applied when their flags are non-empty. Per-ecosystem fetching details live on the [ecosystems](ecosystems/index.md) pages.
