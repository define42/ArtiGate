# HTTP API reference

ArtiGate is a single binary with two roles that never share routes: `artigate low` (the collector/exporter — every `/admin/*/collect`, re-export, watch, and the low dashboard) and `artigate high` (a read-only mirror that serves imported bundle contents). This page documents every HTTP endpoint on both sides, with the exact request-body fields and response shapes taken from the Go structs in `cmd/artigate`.

!!! note "Two roles, two route tables"
    The low side is an **exporter only** — it has no package pull-through. Anything that is not `/admin/*`, `/healthz`, `/`, or `/ui*` returns `404`. Only the [high side](high-side.md) serves package contents to clients. See [Architecture](architecture.md) for the full model and [Low side](low-side.md) / [High side](high-side.md) for operations.

## Conventions

- **Bundle IDs** are `<stream>-bundle-%06d`, e.g. `go-bundle-000042`, `python-bundle-000007`. Each bundle is three files: `<id>.tar.gz`, `<id>.manifest.json`, `<id>.manifest.json.sig`.
- **Streams** are the seven ecosystems, each independently sequenced: `go`, `python`, `maven`, `apt`, `rpm`, `containers`, `npm`. The `go` stream keeps the legacy single-stream numbering.
- **Error codes**: collect and re-export errors are `400`; watch validation `400`, watch store failures `500`; high-side import/status failures `500`; UI `detail` not-found `404`; `repos` for a wrong ecosystem `400`. Non-read methods on serving/UI routes return `405`.
- **Auth**: only the low dashboard can require login (`ARTIGATE_LOW_AUTH`). The high side is never authenticated. See [Security & trust](security.md) and [TLS / HTTPS](tls.md).

---

## LOW side

`LowServer.ServeHTTP` tries `serveLowAdmin`, then `serveLowUI`, else `404 not found`.

| Route | Method | Purpose |
|---|---|---|
| `/admin/{eco}/collect` | POST | Collect + export a bundle for one ecosystem |
| `/admin/reexport` | POST | Re-transmit already-archived bundles |
| `/admin/watches` | GET / POST | List / create scheduled pulls |
| `/admin/watches/{run,enable,disable,delete}` | POST | Act on a watch by id |
| `/admin/bundles` | GET | Per-stream export status |
| `/healthz` | any | Liveness (`ok\n`) |
| `/`, `/ui`, `/ui/` | GET/HEAD | Dashboard HTML |
| `/ui/api/status` | GET/HEAD | Same payload as `/admin/bundles` |

### Collect endpoints

Every ecosystem exposes `POST /admin/{eco}/collect`. The dispatch is POST-only; a non-POST request falls through to UI routing. Without `?stream=1` the handler returns a single buffered JSON `ExportResult` on success, or `http.Error` at **400** on failure. An empty body is JSON-valid but every collector then rejects it for missing required fields.

#### Shared response — `ExportResult`

```json
{
  "stream": "python",
  "sequence": 7,
  "exported_modules": 12,
  "bundle_id": "python-bundle-000007",
  "skipped": false,
  "message": "",
  "skipped_modules": [
    { "module": "github.com/foo/bar", "version": "v1.2.3", "error": "..." }
  ]
}
```

| Field | Type | Notes |
|---|---|---|
| `stream` | string | omitempty |
| `sequence` | int64 | omitempty; the sequence this bundle consumed |
| `exported_modules` | int | **always emitted**; a *unit* count (Go modules, Python projects, container repos, Maven artifacts…) |
| `bundle_id` | string | omitempty |
| `skipped` | bool | omitempty; `true` when Tier-1 dedup found every resolved file already forwarded on this stream — **no bundle written, no sequence consumed** |
| `message` | string | omitempty; `"no new content since the last export"` on a dedup skip, or `"re-exported from archive"` on a replay |
| `skipped_modules` | `[]FailedModule` | omitempty; per-item fetch failures that were skipped so the rest of the batch still exports. `FailedModule` = `{module, version, error}` |

!!! warning "`skipped:true` consumes no sequence"
    A dedup skip writes no bundle and burns no sequence number. The [high side](high-side.md) must not wait on a sequence that was never produced.

!!! note "Which collectors populate `skipped_modules`"
    **Go**, **containers**, **Python** (source-only distributions that cannot be mirrored under the wheels-only policy), and **NPM** (git-URL / otherwise-unfetchable packages) report per-item failures here. **APT**, **RPM**, and **Maven** never populate the field — they either fully succeed or return a single top-level error. If *all* items fail, the whole request errors at 400 (e.g. Go `"no modules could be fetched: …"`, containers `"no images could be fetched: …"`) rather than writing an empty bundle.

---

#### Go — `POST /admin/go/collect`

`GoCollectRequest`. Body limit **8 MiB**. See [Go modules](ecosystems/go.md).

```json
{
  "modules": ["golang.org/x/text@v0.14.0", "rsc.io/quote", "example.com/m@latest"],
  "resolve_deps": false,
  "go_mod": "",
  "go_sum": ""
}
```

| Field | Type | Notes |
|---|---|---|
| `modules` | `[]string` | Each `module@version`, or bare `module` / `module@latest` (resolved to a concrete version via `go list -m -json`) |
| `resolve_deps` | bool | When true, expands the transitive module graph (`go mod download -json all`) |
| `go_mod` | string | A project's own go.mod content; **when set, `modules` and `resolve_deps` are ignored** |
| `go_sum` | string | Optional, paired with `go_mod` |

```http
POST /admin/go/collect HTTP/1.1
Content-Type: application/json

{"modules":["rsc.io/quote@v1.5.2"],"resolve_deps":true}
```

---

#### Python — `POST /admin/python/collect`

`PythonCollectRequest`. Body limit **1 MiB**. See [Python (PyPI)](ecosystems/python.md).

```json
{
  "requirements": ["requests==2.31.0", "flask>=3"],
  "target": {
    "python_version": "3.11",
    "implementation": "cp",
    "abi": "cp311",
    "platforms": ["manylinux2014_x86_64"],
    "only_binary": true
  }
}
```

| Field | Type | Notes |
|---|---|---|
| `requirements` | `[]string` | **Required** — empty → error `"no python requirements provided"`. Passed to `python -m pip download` |
| `target` | `*PythonTarget` | Optional cross-target selector |
| `target.python_version` | string | omitempty |
| `target.implementation` | string | omitempty, e.g. `cp` |
| `target.abi` | string | omitempty, e.g. `cp311` |
| `target.platforms` | `[]string` | e.g. `manylinux2014_x86_64` |
| `target.only_binary` | bool | omitempty |

!!! tip "Any target selector forces wheels"
    When any `target` selector is present, ArtiGate adds `--only-binary=:all:`, so only wheels are fetched.

---

#### Maven — `POST /admin/maven/collect`

`MavenCollectRequest`. Body limit **8 MiB**. See [Java (Maven)](ecosystems/maven.md).

```json
{ "coordinates": ["com.google.guava:guava:33.0.0-jre"], "pom_xml": "" }
```

| Field | Type | Notes |
|---|---|---|
| `coordinates` | `[]string` | Each `groupId:artifactId:version` |
| `pom_xml` | string | A full pom.xml; **when set, `coordinates` is ignored** (resolved via `mvn -B dependency:go-offline`) |

Both empty → error `"no maven coordinates or pom_xml provided"`. SNAPSHOT artifacts are rejected.

---

#### NPM — `POST /admin/npm/collect`

`NpmCollectRequest`. Body limit **8 MiB**. See [NPM](ecosystems/npm.md).

```json
{
  "packages": ["lodash@4.17.21", "react@^18.2", "@scope/pkg@latest"],
  "package_json": "",
  "package_lock": ""
}
```

| Field | Type | Notes |
|---|---|---|
| `packages` | `[]string` | npm install specs; the full dependency graph is resolved and bundled |
| `package_json` | string | A project's own package.json; **when set, `packages` is ignored** |
| `package_lock` | string | Optional; **requires `package_json`** (else error `"package_lock requires package_json"`); pins the exact resolved graph |

Both JSON blobs must be valid JSON. Packages resolving outside the registry (e.g. git URLs) or whose tarball fails are skipped/reported.

---

#### APT — `POST /admin/apt/collect`

`AptCollectRequest`. Body limit **1 MiB**. See [APT (Debian/Ubuntu)](ecosystems/apt.md).

```json
{
  "name": "debian",
  "uri": "http://deb.debian.org/debian",
  "suite": "bookworm",
  "components": ["main", "contrib"],
  "architectures": ["amd64"],
  "signed_by": "/etc/apt/keyrings/debian.gpg",
  "source_list": "",
  "newest_only": true
}
```

| Field | Type | Notes |
|---|---|---|
| `name` | string | Mirror name (URL segment on the high side) |
| `uri` | string | Archive base URI |
| `suite` | string | e.g. `bookworm` |
| `components` | `[]string` | e.g. `["main","contrib"]` |
| `architectures` | `[]string` | e.g. `["amd64"]` |
| `signed_by` | string | Local keyring path used to verify the archive |
| `source_list` | string | A deb822 stanza; an alternative to the explicit fields above |
| `newest_only` | `*bool` | **Defaults true when absent**; `false` mirrors every version in the index |

---

#### RPM — `POST /admin/rpm/collect`

`RpmCollectRequest`. Body limit **1 MiB**. See [RPM (RHEL/Fedora)](ecosystems/rpm.md).

```json
{
  "name": "baseos",
  "base_url": "https://packages.microsoft.com/rhel/9/prod/",
  "gpg_key": "/etc/pki/rpm-gpg/RPM-GPG-KEY",
  "repo_file": "",
  "newest_only": true
}
```

| Field | Type | Notes |
|---|---|---|
| `name` | string | Repo name (URL segment on the high side) |
| `base_url` | string | Repository base URL |
| `gpg_key` | string | Local keyring path for `gpgv` (optional) |
| `repo_file` | string | A full `.repo` file (one or more `[sections]`); an alternative to `name`+`base_url` |
| `newest_only` | `*bool` | **Defaults true when absent**; keeps only the highest EVR per package |

---

#### Containers — `POST /admin/containers/collect`

`ContainerCollectRequest`. Body limit **1 MiB**. See [Container images (OCI)](ecosystems/containers.md).

```json
{ "images": ["alpine:3.20", "ghcr.io/org/app@sha256:abc..."] }
```

| Field | Type | Notes |
|---|---|---|
| `images` | `[]string` | docker-style refs (tag or `@sha256:` digest) |

!!! warning "linux/amd64 only"
    Only the `linux/amd64` platform is mirrored. Unfetchable images are skipped and reported in `skipped_modules`.

---

### Streaming variant — `?stream=1`

Append `?stream=1` to any `/admin/{eco}/collect` to receive live progress as **NDJSON** (one JSON object per line). This is what the dashboard's "Collect & export" modal uses.

- Response headers: `Content-Type: application/x-ndjson`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`. HTTP **200** is sent immediately, then lines are flushed as they occur.
- The request body is buffered up to **16 MiB** before headers go out (the collect goroutine re-reads it), a cap that sits *above* each handler's own body limit.
- Exactly one terminal `done` **or** `error` event follows zero or more `log` events.

Event shapes:

```json
{"type":"log","message":"→ [3/12] rsc.io/quote@v1.5.2"}
```
```json
{"type":"done","result":{"stream":"go","sequence":42,"exported_modules":12,"bundle_id":"go-bundle-000042"}}
```
```json
{"type":"error","error":"no modules could be fetched: ..."}
```

Progress lines are human-readable, e.g. `Resolving the Go module graph…`, `Resolved 12 module(s); fetching…`, `→ [3/12] rsc.io/quote@v1.5.2`, `  ✗ example.com/x@v0.1.0: not found`, `Packing 40 file(s) into a signed bundle…`, `Running mvn dependency:go-offline…`, `Resolving 2 image reference(s) (linux/amd64)…`.

Consume it with `curl`:

```bash
curl -N -X POST 'http://localhost:8080/admin/go/collect?stream=1' \
  -H 'Content-Type: application/json' \
  -d '{"modules":["rsc.io/quote@v1.5.2"],"resolve_deps":true}'
```

!!! note
    If the `ResponseWriter` cannot flush (exotic wrappers only), the server falls back to a single buffered `ExportResult`.

---

### Re-export — `POST /admin/reexport`

Re-transmits already-produced bundles by replaying the **exact archived signed bytes** from `<root>/bundles` back into the export dir — no re-collect, no re-sign. Works for any ecosystem. Errors return **400**.

The spec can be given three ways (`stream` defaults to `"go"` when unspecified):

```bash
# 1. Query string
curl -X POST 'http://localhost:8080/admin/reexport?stream=go&sequences=42,45-47'

# 2. JSON body (ReexportHTTPBody)
curl -X POST http://localhost:8080/admin/reexport \
  -H 'Content-Type: application/json' \
  -d '{"stream":"go","sequences":"42,45-47"}'

# 3. Raw text body
curl -X POST http://localhost:8080/admin/reexport --data-binary '42,45-47'
```

`sequences` is a comma list of single numbers and inclusive `start-end` ranges; expansion is capped at **10000** sequences per request. A missing spec errors with `"missing sequence range; use ?stream=go&sequences=42,45-47 or JSON ..."`.

Response — `ReexportResult`:

```json
{
  "stream": "go",
  "requested_ranges": ["42", "45-47"],
  "sequences": [42, 45, 46, 47],
  "reexported": [
    { "stream": "go", "sequence": 42, "exported_modules": 12,
      "bundle_id": "go-bundle-000042", "message": "re-exported from archive" }
  ],
  "failed": ["43: no archived bundle for go-bundle-000043"]
}
```

| Field | Type | Notes |
|---|---|---|
| `stream` | string | |
| `requested_ranges` | `[]string` | The raw tokens, e.g. `["42","45-47"]` |
| `sequences` | `[]int64` | The expanded list |
| `reexported` | `[]ExportResult` | Successful replays (`message:"re-exported from archive"`) |
| `failed` | `[]string` | omitempty; `"<seq>: <error>"` — a sequence with no archived bundle fails with `"no archived bundle for <bundleID>"` |

!!! warning "Retention pruning is not yet built"
    Every produced bundle is currently retained under `<root>/bundles`, so re-export always works. A bundle whose archive copy is gone cannot be re-exported.

---

### Watches — `/admin/watches*`

SQLite-backed recurring collects (`<root>/watches.db`). The scheduler tick is `--watch-interval` (default `60s`; `0` disables it), and the minimum interval floor is **1 minute**. See [Scheduling (watches)](scheduling.md).

#### `GET /admin/watches` — list

Returns `WatchListResponse`:

```json
{ "watches": [
  {
    "id": 1,
    "stream": "python",
    "label": "requests hourly",
    "spec": "{\"requirements\":[\"requests\"]}",
    "interval_seconds": 3600,
    "enabled": true,
    "created_at": "2026-07-05T09:00:00Z",
    "last_run_at": "2026-07-05T10:00:00Z",
    "last_status": "ok",
    "last_message": "bundle python-bundle-000007: 12 unit(s)",
    "next_run_at": "2026-07-05T11:00:00Z"
  }
] }
```

`Watch` fields: `id`, `stream`, `label`, `spec` (the collect payload as a JSON string), `interval_seconds`, `enabled`, `created_at`, `last_run_at` (omitempty), `last_status` (omitempty, `"ok"`/`"error"`), `last_message` (omitempty, e.g. `"no new content since last export; skipped"`), `next_run_at`.

#### `POST /admin/watches` — create

Body `createWatchRequest`. Body limit **8 MiB**. Validation errors → **400**.

```json
{
  "stream": "python",
  "label": "requests hourly",
  "spec": { "requirements": ["requests"] },
  "interval_seconds": 3600
}
```

| Field | Type | Notes |
|---|---|---|
| `stream` | string | Must be a known stream |
| `label` | string | Defaults to `stream` if empty |
| `spec` | JSON | The raw collect payload for that stream; must be valid JSON |
| `interval_seconds` | int64 | Must be ≥ 60 |

Returns the created `Watch`.

#### Act on a watch by id

`POST /admin/watches/run`, `.../enable`, `.../disable`, `.../delete` all take a `watchIDRequest` body (limit 64 KiB):

```json
{ "id": 1 }
```

| Route | Response | Effect |
|---|---|---|
| `/admin/watches/run` | `{"status":"started"}` | Runs it now in the background (guarded against the scheduler) |
| `/admin/watches/enable` | `{"status":"ok"}` | Enables and makes it due promptly |
| `/admin/watches/disable` | `{"status":"ok"}` | Disables the schedule |
| `/admin/watches/delete` | `{"status":"ok"}` | Removes the watch |

---

### Bundle status — `GET /admin/bundles` and `GET /ui/api/status`

Both return the identical `LowBundleStatus` payload.

```json
{
  "streams": [
    {
      "stream": "go",
      "next_sequence": 43,
      "exported_sequences": [
        {
          "sequence": 42,
          "bundle_id": "go-bundle-000042",
          "in_archive": true,
          "in_outbound": false,
          "size_bytes": 1048576
        }
      ]
    }
  ]
}
```

| Field | Type | Notes |
|---|---|---|
| `streams[].stream` | string | Union of known streams, streams with state, and streams with bundle files on disk (sorted) |
| `streams[].next_sequence` | int64 | The next-to-allocate counter (floored at 1) |
| `exported_sequences[].sequence` | int64 | |
| `exported_sequences[].bundle_id` | string | |
| `exported_sequences[].in_archive` | bool | A retained copy exists in `<root>/bundles` (re-transmittable) |
| `exported_sequences[].in_outbound` | bool | Still staged in the export dir; **goes false once forwarded across the diode — the normal "sent" state, not an error** |
| `exported_sequences[].size_bytes` | int64 | Sum of the archive + manifest + signature |

### Health & dashboard

- `GET /healthz` → body `ok\n`, no JSON.
- `GET /`, `/ui`, `/ui/` → the self-contained HTML dashboard (tabs: Overview / Go / Python / Maven / NPM / APT / RPM / Containers). Non-read methods → **405**.

---

## HIGH side

`HighServer.ServeHTTP` tries, in order: `serveHighAdmin`, `serveGo`, `servePython`, `serveMaven`, `serveApt`, `serveRpm`, `serveContainers`, `serveNpm`, `serveUI`; unclaimed → `404`. Every ecosystem handler is **read-only** (GET/HEAD; others → `405`, or a registry error for containers). The high side never fetches upstream and never invokes toolchains — it serves imported bundle contents from disk. See [High side](high-side.md).

### Admin & health

| Route | Method | Returns |
|---|---|---|
| `/healthz` | any | `ok\n` |
| `/admin/import` | POST | `ImportResult` JSON (imports the next in-order bundle), or 500 |
| `/admin/status` | GET | `ImportStatus` JSON |
| `/admin/missing` | GET | `ImportStatus` JSON (an alias of `/admin/status`) |

`ImportResult`:

```json
{ "imported": true, "imported_bundles": ["go-bundle-000042"], "message": "all streams up to date" }
```

`ImportStatus` — also the body of `/ui/api/overview`'s `status`:

```json
{
  "streams": [
    {
      "stream": "go",
      "last_imported_sequence": 41,
      "next_expected_sequence": 42,
      "highest_seen_sequence": 47,
      "blocking_missing_sequence": 42,
      "missing_ranges": ["42-44"],
      "quarantined_sequences": [46, 47],
      "ready_to_import": false
    }
  ]
}
```

| Field | Type | Notes |
|---|---|---|
| `stream` | string | |
| `last_imported_sequence` | int64 | |
| `next_expected_sequence` | int64 | `last_imported_sequence + 1` |
| `highest_seen_sequence` | int64 | Highest complete bundle seen in landing/quarantine |
| `blocking_missing_sequence` | int64 | omitempty; set only when a *later* bundle arrived but the immediate next is absent (a real gap) |
| `missing_ranges` | `[]string` | Gaps rendered as `"42"` / `"45-47"` |
| `quarantined_sequences` | `[]int64` | Bundles that arrived out of order, held |
| `ready_to_import` | bool | The very next bundle is on disk and complete |

!!! note "Status has a side effect"
    `/admin/status`, `/admin/missing`, and `/ui/api/overview` first sort stray landing bundles into quarantine/duplicates before reporting.

---

### Serving endpoints

Each ecosystem owns a URL prefix. Point clients at the high-side base URL; see the per-ecosystem pages for full client configuration.

#### Go (GOPROXY) — prefix `/go`

Client: `GOPROXY=<base>/go,off`, `GOSUMDB=off`. Standard GOPROXY protocol. See [Go modules](ecosystems/go.md).

| URL | Returns |
|---|---|
| `/go/<module>/@v/list` | Newline list of complete, non-pseudo versions (`text/plain`) |
| `/go/<module>/@v/<version>.info` | `{"Version":"...","Time":"..."}` JSON |
| `/go/<module>/@latest` | Latest `ModuleInfo` JSON |
| `/go/<module>/@v/<version>.mod` | The `go.mod` |
| `/go/<module>/@v/<version>.zip` | The module zip |
| `/go/<module>/@v/<version>.ziphash` | The zip hash |

Only these extensions are served; anything else → `404`.

#### Python (PEP 503 simple index) — prefixes `/simple`, `/packages/`

Client: `pip install --index-url <base>/simple <pkg>`. See [Python (PyPI)](ecosystems/python.md).

| URL | Returns |
|---|---|
| `/simple` or `/simple/` | HTML anchor list of normalized project names |
| `/simple/<project>/` | HTML "Links for `<project>`" with `<a href="/packages/<file>#sha256=<hash>">` per wheel/sdist |
| `/packages/<filename>` | The file (no slashes allowed in `<filename>`) |

#### Maven — prefix `/maven`

Client: use `<base>/maven/` as a repository URL. See [Java (Maven)](ecosystems/maven.md).

Serves the Maven-2 layout directly: `/maven/<group/as/path>/<artifact>/<version>/<file>`. `maven-metadata.xml` (and its `.sha1`/`.md5`) is **computed on the fly** for the enclosing group/artifact directory.

#### APT — prefix `/apt`

Client `sources.list` URI: `<base>/apt/<mirror-name>`. See [APT (Debian/Ubuntu)](ecosystems/apt.md).

Static serving of the mirrored `dists/`, `pool/`, `Release`, `InRelease`, `Packages*`, etc.

#### RPM — prefix `/rpm`

Client `baseurl=<base>/rpm/<repo-name>`. See [RPM (RHEL/Fedora)](ecosystems/rpm.md).

Static serving of `repodata/` plus the RPMs.

#### Containers (OCI / Docker Registry v2) — prefix `/v2`

Client: `docker pull <high-side-host>/<repo>:<tag>`. See [Container images (OCI)](ecosystems/containers.md).

| URL | Returns |
|---|---|
| `/v2/` | Sets `Docker-Distribution-API-Version: registry/2.0`, body `{}` (version probe) |
| `/v2/_catalog` | `{"repositories":["...","..."]}` |
| `/v2/<name>/tags/list` | Tags list JSON (`<name>` may contain slashes) |
| `/v2/<name>/manifests/<ref>` | Image manifest (`<ref>` = tag or `sha256:...`) |
| `/v2/<name>/blobs/<digest>` | Blob (config/layer) by `sha256:...` digest |

Non-read methods reply with a registry-style error `UNSUPPORTED "read-only registry"`; invalid names → `NAME_INVALID`.

#### NPM — prefix `/npm`

Client: `npm config set registry <base>/npm/`. See [NPM](ecosystems/npm.md).

| URL | Returns |
|---|---|
| `/npm/<name>` or `/npm/@scope/pkg` | Packument (full package metadata document) |
| `/npm/<name>/<version>` or `/npm/@scope/pkg/<version>` | Single version manifest |
| `/npm/<name>/-/<file>` or `/npm/@scope/pkg/-/<file>` | Tarball (`<file>` must contain no slash) |

---

### Dashboard JSON — `/ui/api/*`

`serveUI` handles `/`, `/ui`, `/ui/` (dashboard HTML), `/ui/app.js`, and the four JSON endpoints below. All are GET/HEAD only (else **405**).

#### `GET /ui/api/overview` → `UIOverview`

```json
{ "status": { "streams": [ /* ...ImportStatus... */ ] } }
```

Just the import status; the package trees are fetched lazily.

#### `GET /ui/api/tree?eco=<eco>&path=<path>`

`eco` ∈ `go` (default), `python`, `maven`, `apt`, `rpm`, `containers`, `npm`. `path` is the parent node path (empty for root); children are returned one level at a time.

```json
{ "nodes": [
  { "label": "github.com", "path": "github.com", "kind": "dir", "expandable": true, "count": 12 }
] }
```

`UITreeNode` fields: `label`, `path`, `kind` (`dir | module | version | project | file`), `expandable` (bool), `count` (omitempty).

- Go / Maven / APT / RPM / containers use a slash-segment tree: root yields first path segments; an exact module's children are its `version` leaves (`path` = `module@version`).
- Python uses a two-level tree: root → `project` nodes; a project expands to `file` (wheel filename) leaves.
- NPM uses a flat package → versions tree (a scope is part of the name).

Inventory is memoized for **3 seconds**, so freshly imported content appears within that window.

#### `GET /ui/api/detail?eco=<eco>&path=<path>` → `UIDetail`

`path` = `module@version` for Go, a wheel filename for Python, a coordinate/ref per ecosystem. Not found → **404**.

```json
{
  "title": "golang.org/x/text",
  "subtitle": "v0.14.0",
  "fields": [ { "label": "Module", "value": "golang.org/x/text", "mono": true } ],
  "go_mod": "module golang.org/x/text\n\ngo 1.18\n",
  "copy_ref": "",
  "layers": [ { "command": "RUN ...", "size": "5.0 MiB", "digest": "sha256:...", "empty": false } ]
}
```

| Field | Type | Notes |
|---|---|---|
| `title` | string | |
| `subtitle` | string | omitempty |
| `fields` | `[]UIDetailField` | `{label, value, mono}` — Go exposes Module, Version, Published, Zip size, Zip SHA-256, and a `Proxy path` (`/go/<esc>/@v/<verEsc>.zip`); Python exposes Filename, Version, Size, Download (`/packages/<file>`), SHA-256 |
| `go_mod` | string | omitempty; the full `go.mod` |
| `copy_ref` | string | omitempty; a host-relative container pull ref the client prepends its host to |
| `layers` | `[]UIImageLayer` | omitempty; container build history — `{command, size, digest, empty}` |

#### `GET /ui/api/repos?eco=<eco>` → `UIReposResponse`

Valid only for `eco` ∈ `apt | rpm | containers`; anything else → **400** `"repos are only available for apt, rpm, and containers"`.

```json
{ "repos": [
  { "name": "debian", "suite": "bookworm", "components": ["main"],
    "architectures": ["amd64"], "tags": ["3.20"], "signed": true }
] }
```

`UIRepo` fields: `name`, `suite` (omitempty), `components` (omitempty), `architectures` (omitempty), `tags` (omitempty, containers only), `signed` (bool — true when the high side republishes with its own GPG signature). APT fields are empty for RPM.

---

## See also

- [Low side](low-side.md) and [High side](high-side.md) — operating each role.
- [Scheduling (watches)](scheduling.md) — the recurring-pull model behind `/admin/watches*`.
- [Configuration reference](configuration.md) — every flag and environment variable.
- [Ecosystems](ecosystems/index.md) — the seven ecosystem pages linked above.
- [Troubleshooting & limitations](troubleshooting.md) — error codes and known edges.
