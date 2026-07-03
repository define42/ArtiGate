# ArtiGate

[![codecov](https://codecov.io/gh/define42/ArtiGate/graph/badge.svg?token=RBKT8U26R8)](https://codecov.io/gh/define42/ArtiGate)

`ArtiGate` is a Go dependency mirror for one-way data-diode environments.

It contains two modes in one binary:

- `low`: internet-side GOPROXY pull-through server that can fetch from `proxy.golang.org`, `direct` VCS/GitHub, or private GitHub repos using normal `go`/`git` credentials. It records concrete `module@version` requests and exports signed bundle files.
- `high`: air-gapped, read-only GOPROXY server. It imports signed bundles in sequence, verifies all hashes, quarantines out-of-order future bundles until gaps are filled, and serves only complete module versions.

The implementation intentionally uses only the Go standard library. The low side invokes the installed `go` command to produce canonical `.info`, `.mod`, and `.zip` files in the normal Go module cache layout.

## Build

```bash
go build -o artigate ./cmd/artigate
```

## Quick start with Docker Compose

Bring up a full low-side + high-side stack, wired together by a shared `diode`
volume that stands in for the one-way data diode:

```bash
make run          # docker compose up --build (foreground)
# or: make run-detach   to run in the background
# then: make stop       stop but KEEP state (bundle sequence continues on restart)
# or:   make reset       stop and WIPE all volumes (fresh start, sequence back to 1)
```

State (the bundle sequence counter, signing keys, and the mirror) lives in Docker
volumes, so `make stop` followed by `make run` resumes where you left off. Use
`make reset` only when you want a clean slate.

Then:

- Low-side exporter dashboard: <http://localhost:8080/>
- High-side repository dashboard (package tree): <http://localhost:8081/>

Mirror something on the low side and watch it flow through to the high side:

```bash
# Go module plus its dependency graph
curl -XPOST localhost:8080/admin/go/collect \
  -d '{"modules":["rsc.io/quote@latest"],"resolve_deps":true}'

# Python wheels
curl -XPOST localhost:8080/admin/python/collect \
  -d '{"requirements":["requests"]}'
```

A one-time `keygen` service generates the signing key pair into a shared volume,
so the low side signs and the high side verifies without any manual key setup.

## Create signing keys

```bash
./artigate keygen \
  --private ./low.ed25519 \
  --public ./high.ed25519.pub
```

Keep the private key only on the low side. Install the public key on the high side.

## Low side

```bash
./artigate low \
  --listen :8080 \
  --root /var/lib/artigate-low \
  --export-dir /var/spool/diode-out \
  --private-key /etc/artigate/low.ed25519 \
  --upstream-goproxy https://proxy.golang.org,direct \
  --goprivate github.com/your-org/* \
  --gonosumdb github.com/your-org/* \
  --export-interval 60s
```

Low-side Go clients:

```bash
go env -w GOPROXY=http://low-proxy:8080,off
```

### Newer Go toolchains

Some modules declare a `go` directive newer than the toolchain installed on the
low side (e.g. a module requiring `go 1.25` while the fetcher runs `go 1.22`). By
default the low side sets `GOTOOLCHAIN=auto`, so `go` transparently downloads the
required toolchain to fetch such modules. Override with `--gotoolchain` — for
example `--gotoolchain local` to pin the installed toolchain (fetching a module
that needs a newer one then fails with `requires go >= X`), or a specific version
like `--gotoolchain go1.25.0`.

For private GitHub modules, configure the service user's `git`/SSH credentials before starting the proxy, for example:

```bash
git config --global url."ssh://git@github.com/".insteadOf "https://github.com/"
ssh-keyscan github.com >> ~/.ssh/known_hosts
```

The low side writes these files for every export batch:

```text
go-bundle-000001.tar.gz
go-bundle-000001.manifest.json
go-bundle-000001.manifest.json.sig
```

The implementation uses `.tar.gz` because it is in the Go standard library. If you want `.tar.zst`, replace the gzip writer/reader with a zstd package such as `klauspost/compress/zstd`.

You can force an export immediately:

```bash
curl -XPOST http://127.0.0.1:8080/admin/export
```

### Collecting an explicit module list

Besides the demand-driven pull-through cache (where a `go` client hitting the
proxy is what triggers a fetch), the low side can fetch an explicit list of
modules on demand and export them in one bundle — useful when you already know
what an air-gapped project needs. Each entry is `module@version`, or `module` /
`module@latest` to resolve the latest version:

```bash
curl -XPOST http://127.0.0.1:8080/admin/go/collect \
  -H 'Content-Type: application/json' \
  -d '{
        "modules": [
          "golang.org/x/text@v0.14.0",
          "rsc.io/quote@latest",
          "github.com/your-org/internal-lib"
        ]
      }'
```

Each requested `module@version` is fetched with the low-side toolchain and
written into a signed bundle on the shared sequence stream, exactly like the
Python collector (`/admin/python/collect`). This is the Go equivalent of a
`requirements.txt`-style manifest.

By default only the listed modules are fetched. Set `resolve_deps` to also
capture their full transitive module graph (the Go analogue of pip resolving a
dependency tree):

```bash
curl -XPOST http://127.0.0.1:8080/admin/go/collect \
  -H 'Content-Type: application/json' \
  -d '{"modules": ["rsc.io/quote@latest"], "resolve_deps": true}'
```

With `resolve_deps`, ArtiGate writes a synthetic module that requires the listed
modules and asks the toolchain to download the whole module graph (`go mod
download all`), so indirect dependencies such as `golang.org/x/text` are bundled
too. `@latest` entries are still resolved to concrete versions first, so the
bundle is fully pinned.

#### Mirror exactly what a project needs

For the most faithful result, send the project's own `go.mod` (and optionally
`go.sum`) instead of a module list. ArtiGate then mirrors exactly the module
graph that project resolves, honoring its own `go` directive and requirements:

```bash
curl -XPOST http://127.0.0.1:8080/admin/go/collect \
  -H 'Content-Type: application/json' \
  -d "$(jq -Rs --argjson empty '{}' \
        '{go_mod: ., go_sum: ""}' < go.mod)"
```

or more simply from a script:

```bash
jq -n --rawfile mod go.mod --rawfile sum go.sum '{go_mod:$mod, go_sum:$sum}' \
  | curl -XPOST http://127.0.0.1:8080/admin/go/collect \
      -H 'Content-Type: application/json' -d @-
```

When `go_mod` is provided, `modules` and `resolve_deps` are ignored — the go.mod
is the source of truth. This is the closest equivalent to "download everything
needed to build this project offline".

You can list previously exported bundle sequences:

```bash
curl http://127.0.0.1:8080/admin/bundles
```

If the high side reports missing bundles, enter the missing number or range on the low side to regenerate those exact sequence numbers:

```bash
curl -XPOST 'http://127.0.0.1:8080/admin/reexport?sequences=42,45-47'
```

The same endpoint also accepts a raw body or JSON body:

```bash
curl -XPOST http://127.0.0.1:8080/admin/reexport \
  -H 'Content-Type: application/json' \
  -d '{"sequences":"42,45-47"}'
```

Every produced bundle (Go pull-through, `/admin/go/collect`, or `/admin/python/collect`) is retained in a persistent archive under `<root>/bundles/`. Re-export replays the exact archived signed files back into the export directory, so it works uniformly for **both Go and Python** bundles — no re-signing and no dependency on the original recorded requests. (Bundles produced before archiving existed fall back to reconstructing the Go bundle from recorded module requests.)

### Web dashboard

The low side serves a self-contained web UI at its root:

```text
http://low-proxy:8080/
```

It provides a form to **re-transmit a bundle number or range** the high side is
missing (e.g. `42`, `45-47`, or `42,45-47`) — the same operation as
`/admin/reexport`, but point-and-click — and shows the current export status:
the next sequence, pending modules, and a table of exported bundles indicating
whether each bundle's files are still present in the export directory. The
status is also available as JSON at `/ui/api/status`.

Protect the admin endpoints (and the UI) with firewall rules, a local-only listener, or a reverse proxy with authentication.

## Data diode

Transfer the three files together:

```text
go-bundle-NNNNNN.tar.gz
go-bundle-NNNNNN.manifest.json
go-bundle-NNNNNN.manifest.json.sig
```

The high side imports bundles strictly in sequence, but future bundles are **not rejected**. If bundle `000043` arrives while `000042` is missing, bundle `000043` is moved to the high-side quarantine directory. It stays there until `000042` arrives and is imported. The importer then automatically drains any consecutive quarantined bundles.

Duplicates and old replays are moved aside and are not imported.

## High side

```bash
./artigate high \
  --listen :8080 \
  --root /var/lib/artigate-high \
  --landing /var/spool/diode-in \
  --public-key /etc/artigate/high.ed25519.pub \
  --import-interval 10s
```

High-side Go clients:

```bash
go env -w GOPROXY=http://high-proxy:8080,off
go env -w GOSUMDB=off
```

For CI:

```bash
go build -mod=readonly ./...
go test -mod=readonly ./...
```

You can force an import immediately:

```bash
curl -XPOST http://127.0.0.1:8080/admin/import
```

You can ask the high side which bundle numbers/ranges are missing:

```bash
curl http://127.0.0.1:8080/admin/missing
```

The same status is available from:

```bash
curl http://127.0.0.1:8080/admin/status
```

Example response when bundle `42` is missing but `43`, `44`, and `47` are already quarantined:

```json
{
  "last_imported_sequence": 41,
  "next_expected_sequence": 42,
  "highest_seen_sequence": 47,
  "blocking_missing_sequence": 42,
  "missing_ranges": ["42", "45-46"],
  "landing_sequences": [],
  "quarantined_sequences": [43, 44, 47],
  "ready_to_import": false
}
```

After bundle `42` is received, `/admin/import` imports `42` and then automatically processes quarantined `43` and `44`. It will stop again at `45` until `45-46` are received.

### Web dashboard

The high side serves a self-contained web UI at its root (no external assets, so
it works fully air-gapped):

```text
http://high-proxy:8080/
```

The front page shows the import status — prominently flagging **missing bundles**
(the ranges the repository is blocked on) alongside the last-imported, next-expected,
highest-seen, and quarantined sequences. A top menu switches between **Go modules**
and **Python packages**.

Below that is a **lazily loaded tree**. Go modules are grouped hierarchically by
their import path — everything under `github.com` sits beneath a single
`github.com` node, then the org, then the module, then its versions — so large
mirrors stay navigable. Each level is fetched from `/ui/api/tree` only when you
expand its parent, so the initial page transfers just the top-level nodes rather
than the whole catalog. Python projects expand to their wheels the same way.

The front-end is TypeScript ([cmd/artigate/ui/app.ts](cmd/artigate/ui/app.ts)); its
compiled output (`app.js`) is embedded into the binary via `go:embed`, so the UI
stays self-contained and air-gapped. After editing the TypeScript, recompile with
`make ui` (uses `tsc` via `npx`).

The same data is available as JSON for scripting:

```bash
curl http://127.0.0.1:8080/ui/api/overview
```

## High-side latest/list behavior

The high side never trusts a transferred `list` or `latest` file as truth. It calculates them dynamically from completed module versions in its local repository.

A module version is visible only if these exist and a `.complete` marker has been written:

```text
<module>/@v/<version>.info
<module>/@v/<version>.mod
<module>/@v/<version>.zip
<module>/@v/<version>.complete
```

`@v/list` returns complete non-pseudo versions only.

`@latest` means "latest imported and approved in this mirror", selected as:

1. highest release version
2. else highest pre-release version
3. else newest pseudo-version by `.info` time

## Python (PyPI) support

ArtiGate mirrors Python wheels through the same numbered, signed bundle
pipeline. Go modules and Python packages share one global sequence stream, so a
bundle may carry Go only, Python only, or both.

The low side collects wheels with `pip download` (resolution without install)
and packs them into a signed bundle. The high side imports the wheels and serves
them through the [PyPI Simple Repository API](https://peps.python.org/pep-0503/).

### Low side: collect wheels

Trigger a collection from the low side. Requirements and an optional cross-target
are sent as JSON:

```bash
curl -XPOST http://127.0.0.1:8080/admin/python/collect \
  -H 'Content-Type: application/json' \
  -d '{
        "requirements": ["requests==2.32.4", "urllib3"],
        "target": {
          "python_version": "3.12",
          "implementation": "cp",
          "abi": "cp312",
          "platforms": ["manylinux_2_28_x86_64", "manylinux_2_34_x86_64"]
        }
      }'
```

When a `target` is given, ArtiGate passes `--only-binary=:all:` plus the matching
`--python-version`, `--implementation`, `--abi`, and `--platform` flags so pip
downloads wheels for the high-side interpreter rather than the low-side host.
Without a `target`, wheels are downloaded for the current platform. Set the
interpreter with `--python` (default `python3`).

The result is a normal signed bundle (`go-bundle-NNNNNN.*`) transferred through
the diode exactly like a Go bundle.

### High side: serve /simple/

After import, the high side serves:

```text
/simple/                      # index of all mirrored projects
/simple/<normalized-project>/ # one hashed anchor per wheel
/packages/<filename>          # the wheel bytes
```

Project names are normalized per PEP 503 (lowercase; runs of `.`, `_`, and `-`
collapse to a single `-`), so `/simple/Requests/` and `/simple/requests/` resolve
to the same project. Each file link includes a `#sha256=...` fragment.

High-side pip clients should use **only** ArtiGate — avoid `--extra-index-url`,
which is vulnerable to dependency confusion:

```ini
# /etc/pip.conf
[global]
index-url = https://artigate-high.local/simple/
disable-pip-version-check = true
```

```bash
pip install --only-binary=:all: -r requirements.txt
```

Wheels-only is the recommended mode for air-gapped builds: the high side then
needs no compilers, C headers, Rust, build backends, or network access for build
dependencies. Source-distribution (sdist) mirroring is not implemented.

## Notes and limitations

- This is a production-oriented starter implementation, not a full artifact-management product.
- It does not implement sumdb mirroring. On the high side use `GOSUMDB=off` and rely on committed `go.sum`, signed bundles, and manifest hashes.
- It uses JSON state files to keep the implementation dependency-free. Use SQLite/PostgreSQL if you need multiple writers or a larger approval workflow.
- Admin endpoints are unauthenticated. Bind to localhost or protect them.
- High-side gaps and out-of-order future bundles are quarantined, not rejected. Check `/admin/missing` and re-export the requested range from the low side with `/admin/reexport`.
- Low-side fetching depends on the installed Go toolchain and Git/VCS tools, and (for Python) on `pip`.
- High side never invokes `go` or `pip` and has no upstream fetcher.
- Python support mirrors wheels only; sdists and PyPI metadata (`requires-python`, yank status) beyond the manifest are not yet surfaced.
- Re-export (`/admin/reexport`) replays any produced bundle — Go proxy, `/admin/go/collect`, or `/admin/python/collect` — from the persistent archive under `<root>/bundles/`. The archive grows over time; prune old sequences if disk is a concern (they can be re-collected).
