# Low side

The low side is ArtiGate's internet-facing **exporter**. Operators drive it to fetch artifacts with the native package toolchains, pack each fetch into a signed three-file bundle, and write those bundles to the export directory for the data diode to carry across to the [high side](high-side.md).

The low side is deliberately *not* a proxy. It never serves modules to clients — `ServeHTTP` accepts only `/admin/*` routes, the dashboard UI, and the monitoring endpoints (`/healthz`, `/readyz`, `/metrics`); everything else returns `404`. Pulling is a separate concern that lives entirely on the high side.

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
| `--hf-endpoint` | *(empty)* | Alternative Hugging Face endpoint (private mirror); empty means `https://huggingface.co` |
| `--watch-interval` | `60s` | How often the scheduler checks for due watches; `0` disables scheduled pulls |

!!! note
    `--watch-interval` is a Go duration, so `30s`, `5m`, `2h` all work. The full set of flags — including the Go private-module knobs (`--goprivate`, `--gonoproxy`, `--gonosumdb`, `--govcs`, `--gosumdb`), `--go`, `--npm-registry`, and the upstream overrides `--crates-index`, `--terraform-registry`, `--nuget-source` (plus `--git` for Terraform `git::` module sources) — is in the [configuration reference](configuration.md).

!!! warning "Unauthenticated by default"
    When `ARTIGATE_LOW_AUTH` is unset, the dashboard **and** every mutating `/admin/*` endpoint are open. Bind the low side to localhost or a trusted network, or set `ARTIGATE_LOW_AUTH` to require a form login. See [Security &amp; trust](security.md); for HTTPS see [TLS / HTTPS](tls.md).

## The dashboard

Point a browser at the listen address (`/`, `/ui`, or `/ui/`) for a single self-contained HTML dashboard — no external assets. The navigation has three kinds of view:

| View | What it shows |
|---|---|
| **Overview** | Every scheduled pull (watch) across all ecosystems: stream, last run, status, next run, and per-watch actions |
| One page per ecosystem | A collect form for that ecosystem, a live progress modal, an inline result box, and a "schedule the above" row |
| **Status** | The bundle ledger: next sequence per stream and every exported sequence with its archive/outbound state |

There is one ecosystem page per stream: **Go**, **Python**, **Maven**, **npm**, **APT**, **RPM**, **Containers**, **AI Models**, **Crates**, **Terraform**, **Helm**, **NuGet**, and **Alpine**. Each page's collect form maps directly to the matching `/admin/<stream>/collect` endpoint. See [Ecosystems](ecosystems/index.md) for the payload each one accepts.

If `ARTIGATE_LOW_AUTH` is configured, a **Log out** button appears (it POSTs to `/logout`), and any `401` from an expired session redirects the whole UI to `/login`.

## Collect &amp; export

A collect resolves a set of artifacts, fetches them with the host toolchain, and — if there is anything new to send — writes one signed bundle. Every ecosystem follows the same shape:

1. **Lock the stream.** Each stream has its own mutex, so two exports on the same stream can never claim the same sequence number, while different streams (say a long APT mirror and a Python collect) run concurrently.
2. **Resolve** the request into concrete artifacts.
3. **Fetch** with the native tool *before* allocating a sequence. A single artifact that fails to download is recorded and skipped — one bad version never aborts the batch. If *nothing* could be fetched, the collect errors out rather than emit an empty bundle (which would leave the high side waiting forever). Collectors whose upstream declares each file's SHA-256 up front (APT, RPM, containers, Hugging Face LFS) don't even download files the dedup index says were already forwarded.
4. **Mark prior content.** Every resolved file whose `(path, sha256)` was already exported on this stream is flagged as *prior*. If **everything** is prior, the collect is skipped — **no sequence is consumed and no bundle is written**.
5. **Allocate → write → sign → commit.** Otherwise the next sequence is taken and the bundle is built — the archive carries only the *new* files, while prior files ride in the manifest as references (a **delta bundle**). The manifest is signed, the sequence counter advances, and only then are the file hashes recorded in the dedup index.

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

A dedup skip instead returns `{"stream":"go","exported_modules":0,"skipped":true,"message":"no new content since the last export"}`, and a delta bundle carries a `"prior_files"` count of the manifest entries that reference already-forwarded content. Every collect body also accepts `"force": true` to bypass the dedup index entirely and produce a full, self-contained bundle.

### What lands in the export dir

Bundle IDs are `<stream>-bundle-<seq>` zero-padded to six digits — for example `go-bundle-000001`, `python-bundle-000007`, `apt-bundle-000042`. Each bundle is exactly **three files** that share that ID:

| File | Contents |
|---|---|
| `<id>.tar.gz` | The artifact archive (built deterministically; delta bundles carry only the new files) |
| `<id>.manifest.json` | The manifest — the exact bytes that are signed |
| `<id>.manifest.json.sig` | Detached base64 Ed25519 signature of the manifest bytes |

All three are written atomically into `--export-dir` and then copied into the persistent archive at `<root>/bundles`. The diode transfer moves the copies *out of* the export dir — with the [HTTP diode transport](deployment.md) configured (`ARTIGATE_DIODE_URL`), ArtiGate uploads them itself right after export and clears them on success; the archive copy is what makes a later re-export possible either way.

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

There are four event types: `log` (a human-readable progress line), `dl` (a throttled byte-progress sample for the file currently downloading, packing, or uploading — name, bytes done/total, transfer rate), a terminal `done` carrying the full `ExportResult`, and a terminal `error` carrying the error string. You can consume the same stream from the command line:

```bash
curl -N -X POST 'http://localhost:8080/admin/python/collect?stream=1' \
  -H 'Content-Type: application/json' \
  -d '{"requirements":["requests"]}'
```

In the browser this drives a shared **progress modal**: a spinner, a live-tailing log, a **per-file progress bar** (percentage, bytes, transfer rate, ETA — shown for direct HTTP downloads, bundle packing, and diode uploads once a transfer outlasts half a second), and a result box. A **Stop** button aborts the running collect server-side — downloads, spawned tools, and packing all cancel, nothing is exported, and no sequence number is burned; only a stop landing in the final signing moment still exports, which the stopped message calls out. Close is disabled while a collect runs, and Esc / backdrop dismissal is blocked until it finishes. A dedup skip renders uniformly as "No new content since the last export — nothing to send across the diode." The modal always refreshes the Status page afterward.

With an [HTTP diode endpoint](deployment.md) configured, each successful collect ends by uploading the bundle; a failed upload turns the result into a warning — the bundle is committed, archived, and still staged, ready to re-transmit from the Status page.

!!! tip
    Without `?stream=1` the collect runs buffered and emits no progress lines — the progress sink is a no-op, which is exactly how scheduled watches run. Streaming is purely a UI/observability aid; the export result is identical either way.

## Export deduplication and delta bundles

ArtiGate keeps a per-stream index of every file it has ever exported — `(stream, sha256, path)` rows in SQLite at `<root>/exported.db`. It buys three things:

- **Whole-collect skip.** When every resolved file is already in the index, the collect is skipped: no sequence consumed, no bundle written, no diode traffic. This is what makes a scheduled re-pull of an unchanged upstream free.
- **Delta bundles.** When only some files are new, the bundle's archive carries just those; the rest are listed in the manifest as `prior` references that the high side verifies against its accumulated repository. A daily schedule over a slowly-changing mirror sends only the churn.
- **Download skip.** Collectors whose upstream declares each file's SHA-256 before the bytes are fetched — APT `Packages` indexes, RPM `primary.xml`, container image digests, Hugging Face LFS files — consult the index first and skip the download entirely. The pip/mvn/npm/go-driven fetches have no usable pre-download hash, so they download as before and dedup after hashing.

`"force": true` on any collect bypasses the index for that run and produces a full, self-contained bundle — use it when a high side is rebuilt from scratch or its earlier bundles were pruned, because **a delta bundle imports only on a high side that already holds this stream's earlier content** (the import error names the missing prior file and this exact remedy).

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
  "reexported": [{"stream":"python","sequence":7,"exported_modules":1,"bundle_id":"python-bundle-000007","message":"re-exported from archive"}],
  "failed": ["11: no archived bundle for python-bundle-000011"]
}
```

!!! warning
    Re-export only works while the archive copy exists. A bundle showing `✗ not kept` on the Status page has been pruned and can no longer be replayed. And because a *re-collect* after pruning would produce delta bundles referencing content the rebuilt high side lacks, recovery from a from-scratch high side is a **forced** collect (`"force": true`), not a normal one.

## Scheduling

Any collect form can be turned into a recurring **watch** with the "Schedule the above" row — pick an interval in hours or days and the stored spec re-runs on the scheduler tick. A watch replays exactly the collect body its page would POST, so moving references (a container tag, `@latest`, `resolve_deps`) re-resolve on every run, while dedup ensures unchanged upstreams produce no new bundles. See [Scheduling (watches)](scheduling.md) for the full model, the API, and the run-now / edit / enable / disable controls.

## Fetching uses host tools and credentials

The low side deliberately **delegates fetching to the tools already installed on the host** and runs them with the host's credentials and network access. Make sure the relevant binaries are present and configured:

| Ecosystem | Host tooling used |
|---|---|
| Go | `go` (and `git` for VCS fetches) |
| Python | `python3` / `pip download` |
| Maven | `mvn` |
| npm | `npm` |
| APT | `gpgv` (to verify the upstream `Release` against a supplied keyring) |
| RPM | `gpgv` (optional, for repo signature verification), `xz` (for `.xz`-compressed indexes) |
| Terraform | `git` (only for modules with `git::` sources; `--git` selects the binary) |
| Containers, AI models, crates, Helm, NuGet, Alpine | none — fetched over HTTP with the Go standard library |

Because fetching runs as native tooling, upstream credentials and proxy settings come from the host environment. In particular:

- **Private Go modules** need Git and SSH configured on the low-side host (working `~/.ssh`, `~/.gitconfig`, credential helpers), plus the matching `--goprivate` / `--gonoproxy` / `--gonosumdb` flags so `go` fetches them directly from the VCS instead of the public proxy and sum database.
- ArtiGate always forces `GIT_TERMINAL_PROMPT=0`, so Git never blocks on an interactive password prompt — configure non-interactive auth (SSH keys or a credential helper) or the fetch fails fast.
- **Gated Hugging Face models** need `ARTIGATE_HF_TOKEN` set in the low side's environment.
- **Private container registries** take a one-shot login on the pull (the `auth` field / the Containers page form) or standing `ARTIGATE_CONTAINER_AUTH` entries (`host=user:password`, comma-separated) in the low side's environment; scheduled pulls use only the latter.
- **Private git, APT, RPM, and Alpine upstreams** work the same way with `ARTIGATE_UPSTREAM_AUTH` (keyed by the mirror URL's exact host, `host:port` included) or the one-shot `auth` field on those collects; URLs embedding `user:pass@` are rejected.
- **Private Go module hosts** use the same `ARTIGATE_UPSTREAM_AUTH` / `auth`-field login, injected into the `go`/`git` subprocesses (per-collect netrc + git credential helper) and added to `GOPRIVATE` for that collect; SSH-key auth via a preconfigured `~/.ssh` still works too.

The Go `GO*` environment knobs are only applied when their flags are non-empty. Per-ecosystem fetching details live on the [ecosystems](ecosystems/index.md) pages.
