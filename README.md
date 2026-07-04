# ArtiGate

[![codecov](https://codecov.io/gh/define42/ArtiGate/graph/badge.svg?token=RBKT8U26R8)](https://codecov.io/gh/define42/ArtiGate)

`ArtiGate` is a multi-ecosystem dependency mirror — Go modules, Python (PyPI)
wheels, Java (Maven 2) artifacts, APT (Debian/Ubuntu `.deb`) repositories, and
RPM (Fedora/RHEL `.rpm`, yum/dnf) repositories — for one-way data-diode
environments.

It contains two modes in one binary:

- `low`: internet-side exporter. On request — a `go.mod`/module list, a Python requirements list, Maven coordinates, an APT source, or a `.repo` file — it fetches the artifacts from upstream (`proxy.golang.org`, `direct` VCS/GitHub, PyPI, Maven, distro mirrors) using normal `go`/`git`/`pip`/`mvn` credentials and writes signed, numbered bundle files. It is not a module proxy; every ecosystem is driven the same way, by submitting a spec.
- `high`: air-gapped, read-only GOPROXY server. It imports signed bundles in sequence — independently per ecosystem stream — verifies all hashes, quarantines out-of-order future bundles until gaps are filled, and serves only complete module versions.

The implementation uses only the Go standard library, with a single exception: the low side stores scheduled pulls ("watches") in a SQLite database via the pure-Go [`modernc.org/sqlite`](https://pkg.go.dev/modernc.org/sqlite) driver (no cgo, so builds stay simple). Everything else — bundles, manifests, signing, per-stream sequence state — remains stdlib and JSON. The low side invokes the installed `go` command to produce canonical `.info`, `.mod`, and `.zip` files in the normal Go module cache layout.

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

# Java/Maven artifacts (release versions only)
curl -XPOST localhost:8080/admin/maven/collect \
  -d '{"coordinates":["org.slf4j:slf4j-api:2.0.16"]}'

# APT (deb) repository — full mirror of one suite/component/arch
curl -XPOST localhost:8080/admin/apt/collect -d '{"source_list":
  "Types: deb\nURIs: https://packages.microsoft.com/repos/code\nSuites: stable\nComponents: main\nArchitectures: amd64\n"}'

# RPM (yum/dnf) repository — full mirror of one .repo
curl -XPOST localhost:8080/admin/rpm/collect -d '{"repo_file":
  "[code]\nbaseurl=https://packages.microsoft.com/yumrepos/vscode\ngpgcheck=1\n"}'
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
  --gonosumdb github.com/your-org/*
```

The low side is **not** a module proxy — nothing points a `go` client at it.
Mirror Go modules by uploading a project's `go.mod` or POSTing a module list to
`/admin/go/collect` (below); `--upstream-goproxy` is only where the low side
itself fetches those modules from.

### Newer Go toolchains

Some modules declare a `go` directive newer than the toolchain installed on the
low side (e.g. a module requiring `go 1.25` while the fetcher runs `go 1.22`). By
default the low side sets `GOTOOLCHAIN=auto`, so `go` transparently downloads the
required toolchain to fetch such modules. Override with `--gotoolchain` — for
example `--gotoolchain local` to pin the installed toolchain (fetching a module
that needs a newer one then fails with `requires go >= X`), or a specific version
like `--gotoolchain go1.25.0`.

For private GitHub modules, configure the service user's `git`/SSH credentials before starting the exporter, for example:

```bash
git config --global url."ssh://git@github.com/".insteadOf "https://github.com/"
ssh-keyscan github.com >> ~/.ssh/known_hosts
```

The low side writes these three files for every export batch. Each ecosystem is
its own independently numbered **stream** (`go`, `python`, `maven`, `apt`,
`rpm`), so bundles are named `<stream>-bundle-NNNNNN` and each stream counts from
`000001` on its own. A Go export produces:

```text
go-bundle-000001.tar.gz
go-bundle-000001.manifest.json
go-bundle-000001.manifest.json.sig
```

The implementation uses `.tar.gz` because it is in the Go standard library. If you want `.tar.zst`, replace the gzip writer/reader with a zstd package such as `klauspost/compress/zstd`.

### Collecting an explicit module list

The low side fetches an explicit list of modules on demand and exports them in
one bundle — useful when you already know what an air-gapped project needs. Each
entry is `module@version`, or `module` / `module@latest` to resolve the latest
version:

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
written into a signed bundle on the **go** stream, exactly like the Python
collector (`/admin/python/collect`) writes to the **python** stream. This is the
Go equivalent of a `requirements.txt`-style manifest.

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

If the high side reports missing bundles, re-export those exact sequence numbers.
Because each ecosystem numbers its bundles independently, name the stream (it
defaults to `go` when omitted):

```bash
curl -XPOST 'http://127.0.0.1:8080/admin/reexport?stream=python&sequences=42,45-47'
```

The same endpoint also accepts a raw body or JSON body:

```bash
curl -XPOST http://127.0.0.1:8080/admin/reexport \
  -H 'Content-Type: application/json' \
  -d '{"stream":"python","sequences":"42,45-47"}'
```

Every produced bundle (`/admin/go/collect`, `/admin/python/collect`, Maven, APT, or RPM) is retained in a persistent archive under `<root>/bundles/`, grouped by stream. Re-export replays the exact archived signed files back into the export directory, so it works uniformly for **every ecosystem** — no re-signing and no dependency on the original request.

### Web dashboard

The low side serves a self-contained web UI at its root:

```text
http://low-exporter:8080/
```

The dashboard has a page per ecosystem (Go, Python, Java, APT, RPM) for one-off
collects and scheduling (below), plus a **Status** page. Status shows the next
sequence **per stream** and a table of exported bundles across all streams (with
sizes), indicating whether each bundle's files are still present in the export
directory; it also drives the **re-transmit a bundle number or range** form (pick
the stream + range, e.g. `42`, `45-47`, or `42,45-47` — the point-and-click form
of `/admin/reexport`). Status is also available as JSON at `/ui/api/status`.

### Scheduled pulls (watches)

Each ecosystem page can turn its own inputs into a **recurring pull**: below the
collect form, set an interval (hours or days) and click **Add schedule**. It uses
exactly the inputs already on that page — e.g. on the Go page, upload a `go.mod`
(and optional `go.sum`) and schedule it, so ArtiGate re-resolves and re-exports
that project's module graph every day; on the Python page, schedule a
requirements list; and so on for Maven, APT, and RPM. Each page lists its own
schedules with run-now / enable / disable / delete actions.

Watches are stored in a SQLite database and re-run on schedule. The scheduler
checks for due watches every `--watch-interval` (default `60s`; set `0` to
disable auto-running). Each watch records its last run time, status, and next
run. Watches are also managed over HTTP, where `spec` is exactly the JSON body
the matching `/admin/<eco>/collect` endpoint accepts:

```text
GET  /admin/watches          list
POST /admin/watches          create {stream, label, interval_seconds, spec}
POST /admin/watches/run      run once now, in the background {id}
POST /admin/watches/enable   {id}
POST /admin/watches/disable  {id}
POST /admin/watches/delete   {id}
```

Each run currently re-resolves and re-bundles the full spec (see Notes and limitations).

Protect the admin endpoints (and the UI) with firewall rules, a local-only listener, or a reverse proxy with authentication.

## Data diode

Transfer the three files together:

```text
<stream>-bundle-NNNNNN.tar.gz
<stream>-bundle-NNNNNN.manifest.json
<stream>-bundle-NNNNNN.manifest.json.sig
```

Each ecosystem (`go`, `python`, `maven`, `apt`, `rpm`) is its own stream with its
own counter, so a `go-bundle-000007` and a `python-bundle-000007` are unrelated.
The high side imports **each stream** strictly in sequence, but future bundles
are **not rejected**, and the streams are independent — a gap in one never blocks
another. If `go-bundle-000043` arrives while `go-bundle-000042` is missing,
`000043` is moved to the high-side quarantine directory; it stays there until
`000042` arrives and is imported, after which the importer automatically drains
any consecutive quarantined bundles of that stream. Meanwhile the `python`,
`maven`, `apt`, and `rpm` streams keep importing on their own schedules.

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

The status reports every stream independently. Example response where the `go`
stream is blocked on bundle `42` (with `43`, `44`, `47` already quarantined)
while the `python` stream is fully caught up:

```json
{
  "streams": [
    {
      "stream": "go",
      "last_imported_sequence": 41,
      "next_expected_sequence": 42,
      "highest_seen_sequence": 47,
      "blocking_missing_sequence": 42,
      "missing_ranges": ["42", "45-46"],
      "quarantined_sequences": [43, 44, 47],
      "ready_to_import": false
    },
    {
      "stream": "python",
      "last_imported_sequence": 8,
      "next_expected_sequence": 9,
      "highest_seen_sequence": 8,
      "missing_ranges": [],
      "quarantined_sequences": [],
      "ready_to_import": false
    }
  ]
}
```

After go bundle `42` is received, `/admin/import` imports it and then automatically processes the quarantined `43` and `44`. It stops again at `45` until `45-46` are received. The `python` stream (and every other stream) is unaffected throughout — each drains as far as its own contiguous bundles allow.

### Web dashboard

The high side serves a self-contained web UI at its root (no external assets, so
it works fully air-gapped):

```text
http://high-proxy:8080/
```

The front page shows the import status as a **per-stream table** — each
ecosystem's last-imported and next-expected bundle, any missing ranges it is
blocked on, and its quarantined sequences — with a banner that flags which
streams (if any) are waiting on a missing bundle. A top menu switches between
**Go modules**, **Python packages**, **Maven artifacts**, **APT packages**, and
**RPM packages**.

Below that is a **lazily loaded tree**. Go modules are grouped hierarchically by
their import path — everything under `github.com` sits beneath a single
`github.com` node, then the org, then the module, then its versions — so large
mirrors stay navigable. Each level is fetched from `/ui/api/tree` only when you
expand its parent, so the initial page transfers just the top-level nodes rather
than the whole catalog. Python projects expand to their wheels, and Maven
artifacts group by their `groupId`/`artifactId` path down to each version, the
same way.

Selecting a leaf (a Go module version or a Python wheel) opens a **detail panel**
on the right. For a Go version it shows the published time, zip size, zip
SHA-256, the GOPROXY path, and the module's `go.mod`; for a wheel it shows the
size, SHA-256, and download URL. The details come from `/ui/api/detail`.

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

`@latest` means "latest version imported into this mirror", selected as:

1. highest release version
2. else highest pre-release version
3. else newest pseudo-version by `.info` time

## Python (PyPI) support

ArtiGate mirrors Python wheels through the same numbered, signed bundle
pipeline, on its own independently numbered **python** stream (separate from the
`go` stream, so a stalled Go bundle never holds up Python imports).

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

The result is a normal signed bundle (`python-bundle-NNNNNN.*`) transferred
through the diode exactly like a Go bundle.

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

## Java (Maven) support

ArtiGate mirrors Java/JVM dependencies through the same numbered, signed bundle
pipeline and serves them as a **Maven 2 repository**. Maven, Gradle, SBT,
Kotlin, Scala, and Spring Boot all resolve from Maven-compatible repositories,
so one adapter covers the JVM ecosystem. Maven bundles ride their own
independently numbered **maven** stream, separate from `go`, `python`, `apt`,
and `rpm`.

The low side delegates to `mvn dependency:go-offline`, which resolves a
project's full dependency **and plugin** closure into an isolated local
repository; ArtiGate packs that repository (already in Maven 2 layout) into a
signed bundle. The high side serves the artifacts as static Maven 2 paths and
generates `maven-metadata.xml` on demand from the versions actually present —
never trusting a transferred metadata file.

**Release versions only.** SNAPSHOT builds and dynamic/range versions (`1.+`,
`[1.0,2.0)`, `LATEST`, `RELEASE`) are rejected: they do not resolve
reproducibly, which defeats an air-gapped mirror.

### Low side: collect artifacts

By coordinate list (`groupId:artifactId:version` each):

```bash
curl -XPOST http://127.0.0.1:8080/admin/maven/collect \
  -H 'Content-Type: application/json' \
  -d '{"coordinates":["org.slf4j:slf4j-api:2.0.16","com.google.guava:guava:33.3.1-jre"]}'
```

Or send a project's own `pom.xml` to mirror exactly what it builds (plugins
included). When `pom_xml` is set, `coordinates` is ignored:

```bash
curl -XPOST http://127.0.0.1:8080/admin/maven/collect \
  -H 'Content-Type: application/json' \
  -d "$(jq -Rs '{pom_xml: .}' < pom.xml)"
```

Set the Maven command with `--maven` (default `mvn`); the low-side Docker image
ships Maven and a JRE.

### High side: serve /maven/

After import, the high side serves a Maven 2 repository:

```text
/maven/<groupPath>/<artifactId>/<version>/<artifactId>-<version>.pom
/maven/<groupPath>/<artifactId>/<version>/<artifactId>-<version>.jar
/maven/<groupPath>/<artifactId>/maven-metadata.xml
```

`maven-metadata.xml` (and its `.sha1`/`.md5`) are computed from the mirrored
versions; the `.pom`/`.jar`/`.module` files and their upstream checksums are
served as stored. Gradle Module Metadata (`.module`) is mirrored when present.

High-side Maven clients — point at ArtiGate and mirror everything:

```xml
<!-- ~/.m2/settings.xml -->
<settings>
  <mirrors>
    <mirror>
      <id>artigate</id>
      <mirrorOf>*</mirrorOf>
      <url>https://artigate-high.local/maven/</url>
    </mirror>
  </mirrors>
</settings>
```

High-side Gradle clients:

```kotlin
repositories {
    maven { url = uri("https://artigate-high.local/maven/") }
}
```

Do not add `mavenCentral()` or other external repositories on the high side;
ArtiGate is the single source of truth. For reproducibility, pin exact versions
and use Gradle dependency locking (`gradle/verification-metadata.xml`, lockfiles).

## APT (Debian/Ubuntu) support

ArtiGate mirrors a whole upstream APT repository (one suite / components /
architectures) through the same signed bundle pipeline. This is the offline
equivalent of a normal `deb` source.

The low side downloads `dists/<suite>/InRelease`, optionally **verifies it with
`gpgv`** against a caller-supplied keyring (`Signed-By`), reads the Release
checksums, downloads and verifies the binary `Packages` index, then downloads
every referenced `.deb` and verifies each one's SHA256 against the index. The
`.deb` files are packed into a signed bundle along with their `Packages`
stanzas.

On import the high side **regenerates** `Packages`/`Packages.gz` and `Release`
from the stanzas of the `.deb` files actually present (never serving the
transferred upstream metadata as-is) and, when a signing key is configured,
clearsigns `InRelease`. That yields three layers of trust: the upstream vendor
key proves the low side fetched authentic metadata, the ArtiGate ed25519
signature proves the diode transfer was intact and approved, and the high-side
APT key proves air-gapped clients are using the approved offline mirror.

### Low side: mirror a repository

Send the exact deb822 source stanza (`.sources` format):

```bash
curl -XPOST http://127.0.0.1:8080/admin/apt/collect \
  -H 'Content-Type: application/json' \
  -d "$(jq -Rs '{source_list: .}' <<'EOF'
Types: deb
URIs: https://packages.microsoft.com/repos/code
Suites: stable
Components: main
Architectures: amd64
Signed-By: /usr/share/keyrings/microsoft.gpg
EOF
)"
```

`Signed-By` (a keyring path on the low-side host) is used with `gpgv` to verify
the upstream `InRelease`; omit it to skip upstream signature verification (the
SHA256 chain from Release to each `.deb` is always enforced). The fields can
also be sent explicitly as `{"uri","suite","components","architectures",
"signed_by","name"}`.

To mirror several repositories at once, include multiple deb822 stanzas
(blank-line separated) in `source_list`. Each is mirrored into its **own**
namespace `/apt/<mirror>/` — repositories are never merged into one index, and
each keeps its own `Release`/`Packages` and signature. Mirror names must be
distinct (they default to a slug of the URI).

### High side: serve /apt/&lt;mirror&gt;/

After import the high side serves a standard APT repository:

```text
/apt/<mirror>/dists/<suite>/InRelease            # present only when signed
/apt/<mirror>/dists/<suite>/Release
/apt/<mirror>/dists/<suite>/main/binary-amd64/Packages(.gz)
/apt/<mirror>/pool/main/c/code/code_<version>_amd64.deb
```

Sign the regenerated repository by starting the high side with a GPG key
(`--apt-gpg-key <keyid>`, with the secret key available in the process's
`GNUPGHOME`); without it the repository is published unsigned.

High-side client source — note the key is **ArtiGate's**, not the vendor's:

```text
Types: deb
URIs: https://artigate-high.local/apt/<mirror>
Suites: stable
Components: main
Architectures: amd64
Signed-By: /usr/share/keyrings/artigate-apt.gpg
```

If the mirror is published unsigned, use `[trusted=yes]` (one-line format) or an
`apt` policy that allows it instead of `Signed-By`.

## RPM (Fedora/RHEL) support

ArtiGate mirrors YUM/DNF repositories at **full metadata fidelity**, suitable
for full distro mirroring (Fedora/RHEL/EPEL), not just small vendor repos. The
low side downloads `repodata/repomd.xml`, optionally **verifies
`repomd.xml.asc`** with `gpgv` against a caller-supplied key, then downloads and
verifies **every** metadata file `repomd` references — `primary`, `filelists`,
`other`, `updateinfo` (security advisories), `comps` (groups), `modules`, and
zchunk variants — against its recorded checksum. It parses the `primary` index
to enumerate packages and downloads every `.rpm`, verifying each against the
index. All of it is packed into a signed bundle.

On import the high side serves those metadata files **verbatim** (they are
integrity-locked by the ArtiGate manifest and were signature-verified on the low
side) and **regenerates + optionally re-signs only `repomd.xml`** from the
recorded entries — so it owns the repository entry point without ever trusting a
transferred `repomd`/signature as final, while preserving every metadata type
exactly as upstream produced it (which a `createrepo_c`-only rebuild could not —
it cannot reproduce `updateinfo`/`comps`/`modules`). The repository is served
statically under `/rpm/<mirror>/`. Re-collecting publishes a newer snapshot
(metadata is replaced; `.rpm`s accumulate in the pool).

### Low side: mirror a repository

Send a yum/dnf `.repo` stanza (several `[sections]` mirror several repos, each
into its own namespace):

```bash
curl -XPOST http://127.0.0.1:8080/admin/rpm/collect \
  -H 'Content-Type: application/json' \
  -d "$(jq -Rs '{repo_file: .}' <<'EOF'
[code]
name=Visual Studio Code
baseurl=https://packages.microsoft.com/yumrepos/vscode
enabled=1
gpgcheck=1
gpgkey=https://packages.microsoft.com/keys/microsoft.asc
EOF
)"
```

`baseurl` must be concrete — `$releasever`/`$basearch` variables are rejected.
To GPG-verify the upstream `repomd.xml` on the low side, supply a **local**
keyring via the `gpg_key` field or a `gpgkey=file:///…` line (a remote
`gpgkey=https://…` is for clients and is not used for low-side verification; the
SHA256 chain is always enforced). `.zck` (zchunk) indexes are not supported;
`.gz`/`.xz` are.

### High side: serve /rpm/&lt;mirror&gt;/

After import the high side serves a standard YUM/DNF repository:

```text
/rpm/<mirror>/repodata/repomd.xml            # regenerated (+ repomd.xml.asc when signed)
/rpm/<mirror>/repodata/primary.xml.gz
/rpm/<mirror>/Packages/<name>-<version>.<arch>.rpm
```

Sign it by starting the high side with `--rpm-gpg-key <keyid>` (secret key in the
process's `GNUPGHOME`); otherwise it is published unsigned. High-side client
`.repo`:

```ini
[artigate]
name=ArtiGate mirror
baseurl=https://artigate-high.local/rpm/<mirror>
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-artigate
```

Use ArtiGate's high-side key. If the mirror is unsigned, set `repo_gpgcheck=0`
(per-package `gpgcheck` against signed `.rpm`s still applies).

## Notes and limitations

- This is a production-oriented starter implementation, not a full artifact-management product.
- It does not implement sumdb mirroring. On the high side use `GOSUMDB=off` and rely on committed `go.sum`, signed bundles, and manifest hashes.
- Sequence/bundle state is kept in JSON files; scheduled pulls ("watches") are kept in a SQLite database (`<root>/watches.db`, via pure-Go `modernc.org/sqlite`). Each watch run currently re-resolves and re-bundles its full spec — the high side dedups identical artifacts by hash on import (so repos never bloat), but a frequent watch re-sends unchanged content across the diode; a low-side content-delta index is the planned follow-up.
- Admin endpoints are unauthenticated. Bind to localhost or protect them.
- High-side gaps and out-of-order future bundles are quarantined, not rejected. Check `/admin/missing` and re-export the requested range from the low side with `/admin/reexport`.
- Low-side exports are serialized **per stream**, not globally: a long-running mirror (a large APT or RPM repo, say) does not block collects for other ecosystems (Go, Python, Maven), which run concurrently. Two collects on the *same* stream still serialize, so that stream's bundle sequence numbers stay unique and gap-free.
- Low-side fetching depends on the installed Go toolchain and Git/VCS tools, on `pip` (Python), on `mvn` + a JDK (Java/Maven), on `gpgv` (verifying upstream APT/RPM repositories), and on `xz` (some RPM indexes). APT `.deb` and RPM `.rpm` files are fetched over plain HTTP(S) with the Go standard library.
- High side never invokes `go`, `pip`, or `mvn` and has no upstream fetcher; it uses `gpg` only to sign regenerated APT/RPM repositories when `--apt-gpg-key`/`--rpm-gpg-key` is set.
- Java support mirrors release Maven artifacts only; SNAPSHOT and dynamic/range versions are rejected. SBT/Ivy-only repositories and the Gradle Plugin Portal are not specially handled beyond their Maven-compatible endpoints.
- APT support mirrors binary `deb` packages for the configured suite/components/architectures; `deb-src`, `Contents-*`, `Translation-*`, and by-hash indexes are not mirrored. The high side regenerates `Packages`/`Release`; publish signed with `--apt-gpg-key` or have clients trust the repo explicitly.
- RPM support mirrors a repository's full metadata (`primary`, `filelists`, `other`, `updateinfo`, `comps`, `modules` — carried verbatim) plus every `.rpm`; the high side regenerates and re-signs `repomd.xml`. Requirements/limits: `baseurl` must be concrete (`$releasever`/`$basearch` rejected); the `primary` index must be readable as plain/`.gz`/`.xz` to enumerate packages (a zchunk-*only* `primary` isn't parseable, though `.zck` variants are still mirrored for clients); each collect is a full re-sync (no incremental delta yet). Publish signed with `--rpm-gpg-key` or set `repo_gpgcheck=0` on clients.
- Python support mirrors wheels only; sdists and PyPI metadata (`requires-python`, yank status) beyond the manifest are not yet surfaced.
- Re-export (`/admin/reexport`) replays any produced bundle of any stream — Go proxy, `/admin/go/collect`, `/admin/python/collect`, Maven, APT, or RPM — from the persistent archive under `<root>/bundles/`; name the stream in the request (defaults to `go`). The archive grows over time; prune old sequences if disk is a concern (they can be re-collected).
