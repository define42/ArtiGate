# Ecosystems

ArtiGate mirrors **seven** package ecosystems across a one-way data diode. Each is a self-contained stream with the same lifecycle — the low side *collects* upstream artifacts, packs them into a signed *bundle*, the diode carries it, and the high side *imports* and *serves* it — but the input format and the client protocol differ per ecosystem. This page is the hub; each row links to its full page.

## The common flow

Every ecosystem follows the same **collect → bundle → import → serve** path described in [Architecture](../architecture.md):

1. **Collect** — an operator (or a [watch](../scheduling.md)) sends `POST /admin/{ecosystem}/collect` to the [low side](../low-side.md). Go, Python, Maven, and NPM shell out to their *native* CLI (`go`, `pip`, `mvn`, `npm`); APT, RPM, and containers are fetched directly over the ecosystem's own HTTP protocol (deb822 index + `.deb` files, repodata + `.rpm` files, and the OCI/Docker registry API respectively).
2. **Bundle** — the fetched files are packed into a signed three-file bundle (`<bundleID>.tar.gz`, `.manifest.json`, `.manifest.json.sig`) and written to the export directory. Each ecosystem is an independently-numbered [stream](../architecture.md), so a slow container mirror never blocks a Python collect.
3. **Import** — the [high side](../high-side.md) verifies the Ed25519 signature and every SHA-256 hash, installs the artifacts immutably, and imports strictly in sequence order per stream.
4. **Serve** — the high side **regenerates** all repository metadata from the artifacts actually present (it never trusts a transferred index) and serves clients under a per-ecosystem base path.

!!! note "One manifest, one stream per ecosystem"
    All seven streams share the same [bundle format](../architecture.md). The manifest `type` field is always the legacy string `"go-module-bundle"` regardless of ecosystem — the real ecosystem is carried by the `stream` field (`go`, `python`, `maven`, `npm`, `apt`, `rpm`, `containers`) and the populated sub-manifest.

## Comparison

| Ecosystem | Low-side input | Serves as | High-side base path | Client tool |
|---|---|---|---|---|
| [Go modules](go.md) | Module specs (`rsc.io/quote@v1.5.2`), or a project's `go.mod` + `go.sum` | GOPROXY | `/go/` | `go` |
| [Python (PyPI)](python.md) | pip requirement specifiers (`requests`, `flask==3.0.0`) | PEP 503 simple index | `/simple/` (index) + `/packages/` (wheels) | `pip` |
| [Java (Maven)](maven.md) | Maven coordinates (`com.google.guava:guava:33.0.0-jre`), or a `pom.xml` | Maven repository | `/maven/` | `mvn` |
| [NPM](npm.md) | Package specs (`lodash`), or `package.json` + `package-lock.json` | npm registry | `/npm/` | `npm` |
| [APT (Debian/Ubuntu)](apt.md) | deb822 source stanza, or explicit `uri`/`suite`/`components`/`architectures` | APT (deb822) repository | `/apt/` | `apt-get` |
| [RPM (RHEL/Fedora)](rpm.md) | A `.repo` file, or explicit `name`/`base_url` (e.g. `packages.microsoft.com`) | yum/dnf repository | `/rpm/` | `dnf` / `yum` |
| [Container images (OCI)](containers.md) | Docker-style image refs (`alpine:3.20`, `ghcr.io/org/app@sha256:…`) | OCI / Docker registry (v2) | `/v2/` | `docker` / `podman` |

!!! tip "Client base paths are stable"
    The high side claims each URL space separately (`serveGo`, `servePython`, …); anything outside these prefixes returns `404`. Point clients at `<high-base>/go`, pip at the `<high-base>/simple` index, and so on.

## The seven ecosystems

### Go modules → [go.md](go.md)

The most faithful "what this project needs to build" mode: send a project's own `go.mod` (optionally with `go.sum`) and ArtiGate mirrors exactly the module graph that project resolves. You can also list module specs directly and set `resolve_deps` to pull the **full transitive graph**. Individually unfetchable modules are skipped into `skipped_modules` rather than aborting the batch. Served as a GOPROXY under `/go/`; clients set `GOPROXY=<base>/go,off` and `GOSUMDB=off`.

### Python (PyPI) → [python.md](python.md)

Collect resolves pip **requirement specifiers** (or a target selector) and downloads **wheels only** — no sdists — so the high side never needs to build. The high side regenerates a PEP 503 simple index from the wheels present and serves it under `/simple/` (with wheel downloads under `/packages/`).

### Java (Maven) → [maven.md](maven.md)

Collect takes Maven **coordinates** or a `pom.xml` and resolves **release artifacts only** (no `-SNAPSHOT`). The high side rebuilds the Maven repository layout under `/maven/`.

### NPM → [npm.md](npm.md)

Collect takes package specs or a `package.json` + `package-lock.json` and pulls the **full package graph** of tarballs. The high side regenerates the served packument metadata from each tarball's own embedded `package.json` (never trusting a transferred packument) and recomputes the `integrity` SRI from the artifact. Served as an npm registry under `/npm/`.

### APT (Debian/Ubuntu) → [apt.md](apt.md)

Collect takes a deb822 source stanza (`source_list`) or explicit fields. By default it keeps **newest-only** — the highest version of each package — set `newest_only: false` to mirror every version in the index. The high side regenerates `Release`/`Packages` from the accumulated `.deb` stanzas (never trusting the transferred index) and optionally signs `InRelease` with `--apt-gpg-key`. Served under `/apt/`.

### RPM (RHEL/Fedora) → [rpm.md](rpm.md)

Collect takes a `.repo` file or explicit `name`/`base_url` (e.g. `packages.microsoft.com`). Like APT it is **newest-only** by default (highest EVR per package); set `newest_only: false` for every version. The high side regenerates repodata and optionally signs `repomd.xml.asc` with `--rpm-gpg-key`. Served under `/rpm/`.

### Container images (OCI) → [containers.md](containers.md)

The richest ecosystem: collect takes docker-style image references (`alpine:3.20`, or a digest pin) and mirrors the `linux/amd64` image. The high side reassembles blobs and manifests and serves an OCI/Docker v2 registry under `/v2/`. Tag constraints use `hashicorp/go-version` (ArtiGate's only non-stdlib dependency besides SQLite).

## Cross-cutting notes

Each ecosystem trades completeness for airgap-friendliness in a different way. Know these before you build a mirror:

| Ecosystem | Scope rule |
|---|---|
| Go, NPM | **Full graph** — the transitive dependency closure is mirrored |
| Python | **Wheels only** — no sdists, so the high side never compiles |
| Maven | **Release only** — `-SNAPSHOT` artifacts are not mirrored |
| APT, RPM | **Newest-only by default** — one version per package unless `newest_only: false` |

!!! warning "Content dedup is per stream"
    The low side's Tier-1 export dedup ([`exported.db`](../architecture.md)) is content-hash based and **per stream**. A re-collect of an unchanged upstream is skipped and consumes no sequence number; it does not dedup across ecosystems, and [re-export](../low-side.md) bypasses dedup entirely.

!!! tip "Live progress"
    Append `?stream=1` to any collect (e.g. `POST /admin/containers/collect?stream=1`) for NDJSON live progress instead of a single JSON result — useful for long mirrors. See the [HTTP API reference](../api.md).

For per-request bodies, exact flags, and worked examples, follow the ecosystem links above. For the trust model that makes all of this safe, read [Security & trust](../security.md).
