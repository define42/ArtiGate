# Ecosystems

ArtiGate mirrors **fourteen** ecosystems across a one-way data diode — thirteen artifact ecosystems plus the OSV vulnerability-advisory feed that lets the air-gapped side audit them. Each is a self-contained stream with the same lifecycle — the low side *collects* upstream artifacts, packs them into a signed *bundle*, the diode carries it, and the high side *imports* and *serves* it — but the input format and the client protocol differ per ecosystem. This page is the hub; each row links to its full page.

## The common flow

Every ecosystem follows the same **collect → bundle → import → serve** path described in [Architecture](../architecture.md):

1. **Collect** — an operator (or a [watch](../scheduling.md)) sends `POST /admin/{ecosystem}/collect` to the [low side](../low-side.md). Go, Python, Maven, and NPM shell out to their *native* CLI (`go`, `pip`, `mvn`, `npm`); APT, RPM, containers, AI models, crates, Terraform, Helm, NuGet, Alpine, and OSV are fetched directly over the ecosystem's own HTTP protocol (deb822 index + `.deb` files, repodata + `.rpm` files, the OCI/Docker registry API, the Hugging Face Hub's Ollama-compatible and file APIs, the cargo sparse index, the Terraform registry protocols — plus the `git` tool for `git::` module sources — Helm's `index.yaml`, the NuGet v3 flat container, `APKINDEX` + `.apk` files, and the OSV bucket's per-ecosystem `all.zip` archives respectively).
2. **Bundle** — the fetched files are packed into a signed three-file bundle (`<bundleID>.tar.gz`, `.manifest.json`, `.manifest.json.sig`) and written to the export directory. Each ecosystem is an independently-numbered [stream](../architecture.md), so a slow container mirror never blocks a Python collect.
3. **Import** — the [high side](../high-side.md) verifies the Ed25519 signature and every SHA-256 hash, installs the artifacts immutably (advisory-database snapshots being the deliberate exception — each replaces its predecessor), and imports strictly in sequence order per stream.
4. **Serve** — the high side **regenerates** all repository metadata from the artifacts actually present (it never trusts a transferred index) and serves clients under a per-ecosystem base path.

!!! note "One manifest, one stream per ecosystem"
    All fourteen streams share the same [bundle format](../architecture.md). The manifest `type` field is always the legacy string `"go-module-bundle"` regardless of ecosystem — the real ecosystem is carried by the `stream` field (`go`, `python`, `maven`, `npm`, `apt`, `rpm`, `containers`, `hf`, `crates`, `terraform`, `helm`, `nuget`, `apk`, `osv`) and the populated sub-manifest.

## Comparison

| Ecosystem | Low-side input | Serves as | High-side base path | Client tool |
|---|---|---|---|---|
| [Go modules](go.md) | Module specs (`rsc.io/quote@v1.5.2`), or a project's `go.mod` + `go.sum` | GOPROXY | `/go/` | `go` |
| [Python (PyPI)](python.md) | pip requirement specifiers (`requests`, `flask==3.0.0`) | PEP 503 simple index | `/simple/` (index) + `/packages/` (wheels) | `pip` |
| [Java (Maven)](maven.md) | Maven coordinates (`com.google.guava:guava:33.0.0-jre`), or a `pom.xml` | Maven repository | `/maven/` | `mvn` |
| [NPM](npm.md) | Package specs (`lodash`), or `package.json` + `package-lock.json` | npm registry | `/npm/` | `npm` |
| [APT (Debian/Ubuntu)](apt.md) | deb822 source stanza (several `Suites:` per mirror), or explicit `uri`/`suites`/`components`/`architectures` | APT (deb822) repository | `/apt/` | `apt-get` |
| [RPM (RHEL/Fedora)](rpm.md) | A `.repo` file, or explicit `name`/`base_url` (e.g. `packages.microsoft.com`) | yum/dnf repository | `/rpm/` | `dnf` / `yum` |
| [Container images (OCI)](containers.md) | Docker-style image refs (`alpine:3.20`, `ghcr.io/org/app@sha256:…`) | OCI / Docker registry (v2) | `/v2/` | `docker` / `podman` |
| [AI models (Hugging Face)](ai-models.md) | GGUF variant refs (`hf.co/org/model-GGUF:Q4_0`) and full repositories (`openai/gpt-oss-20b[@rev]`) | Ollama-compatible registry + Hub download API | `/v2/`, `/hf/`, `/api/models/` | `ollama`, `vllm` / `hf` via `HF_ENDPOINT` |
| [Rust crates](crates.md) | Crate specs (`serde@1.0.203`, or bare for the newest release) | cargo sparse registry | `/crates/` | `cargo` |
| [Terraform / OpenTofu](terraform.md) | Provider addresses (`hashicorp/aws@5.50.0`) and module addresses (`terraform-aws-modules/vpc/aws`), with a `platforms` list | Terraform provider + module registry protocols | `/.well-known/terraform.json`, `/terraform/` | `terraform` / `tofu` |
| [Helm charts](helm.md) | A chart repository URL plus chart specs (`nginx@21.1.0`) | Classic Helm (`index.yaml`) repository per mirror | `/helm/<mirror>` | `helm` |
| [NuGet](nuget.md) | Package specs (`Newtonsoft.Json@13.0.3`, or bare for the newest stable) | NuGet v3 feed (service index, flat container, registration, search) | `/nuget/` | `dotnet` / `nuget` |
| [Alpine (apk)](apk.md) | A mirror base + branches/repositories/architectures, or a pasted `/etc/apk/repositories` file | Alpine repository (regenerated `APKINDEX.tar.gz`) | `/apk/<mirror>` | `apk` |
| [OSV advisories](osv.md) | OSV ecosystem names (`npm`, `PyPI`, `Alpine:v3.22`, …) | OSV database feed (upstream bucket layout) + `npm audit` on the npm registry | `/osv/` | `osv-scanner --offline`, `npm audit`, `curl` |

!!! tip "Client base paths are stable"
    The high side claims each URL space separately (`serveGo`, `servePython`, …); anything outside these prefixes returns `404`. Point clients at `<high-base>/go`, pip at the `<high-base>/simple` index, and so on.

## The fourteen ecosystems

### Go modules → [go.md](go.md)

The most faithful "what this project needs to build" mode: send a project's own `go.mod` (optionally with `go.sum`) and ArtiGate mirrors exactly the module graph that project resolves. You can also list module specs directly and set `resolve_deps` to pull the **full transitive graph**. Individually unfetchable modules are skipped into `skipped_modules` rather than aborting the batch. Served as a GOPROXY under `/go/`; clients set `GOPROXY=<base>/go,off` and `GOSUMDB=off`.

### Python (PyPI) → [python.md](python.md)

Collect resolves pip **requirement specifiers** (or a target selector) and downloads **wheels only** — no sdists — so the high side never needs to build. The high side regenerates a PEP 503 simple index from the wheels present and serves it under `/simple/` (with wheel downloads under `/packages/`).

### Java (Maven) → [maven.md](maven.md)

Collect takes Maven **coordinates** or a `pom.xml` and resolves **release artifacts only** (no `-SNAPSHOT`). The high side rebuilds the Maven repository layout under `/maven/`.

### NPM → [npm.md](npm.md)

Collect takes package specs or a `package.json` + `package-lock.json` and pulls the **full package graph** of tarballs. The high side regenerates the served packument metadata from each tarball's own embedded `package.json` (never trusting a transferred packument) and recomputes the `integrity` SRI from the artifact. Served as an npm registry under `/npm/`.

### APT (Debian/Ubuntu) → [apt.md](apt.md)

Collect takes a deb822 source stanza (`source_list`) or explicit fields; one stanza's `Suites:` may list several releases (`noble noble-updates noble-security`), which share one mirror and its pool. By default it keeps **newest-only** — the highest version of each package — set `newest_only: false` to mirror every version in the index. Private mirrors authenticate with a one-time login on the collect or standing `ARTIGATE_UPSTREAM_AUTH` credentials. The high side regenerates `Release`/`Packages` per suite from the accumulated `.deb` stanzas (never trusting the transferred index) and optionally signs `InRelease` with `--apt-gpg-key`. Served under `/apt/`.

### RPM (RHEL/Fedora) → [rpm.md](rpm.md)

Collect takes a `.repo` file or explicit `name`/`base_url` (e.g. `packages.microsoft.com`). Like APT it is **newest-only** by default (highest EVR per package); set `newest_only: false` for every version. Only **x86_64 + noarch** packages are mirrored unless the `architectures` field lists others, and the mirror is named after its `baseurl`. Private repos authenticate with a one-time login on the collect or standing `ARTIGATE_UPSTREAM_AUTH` credentials. The high side regenerates repodata and optionally signs `repomd.xml.asc` with `--rpm-gpg-key`. Served under `/rpm/`.

### Container images (OCI) → [containers.md](containers.md)

The richest ecosystem: collect takes docker-style image references (`alpine:3.20`, a digest pin, or a **version constraint** like `golang:1.26.x` resolved against the upstream tag list at collect time) and mirrors the `linux/amd64` image. Private registries authenticate with a one-time login on the pull or standing `ARTIGATE_CONTAINER_AUTH` credentials. The high side reassembles blobs and manifests and serves an OCI/Docker v2 registry under `/v2/`. Tag constraints are parsed with `hashicorp/go-version`.

### AI models (Hugging Face) → [ai-models.md](ai-models.md)

Two forms on one `hf` stream. **GGUF variants** are addressed container-style (`hf.co/unsloth/gpt-oss-20b-GGUF:Q4_0` — the tag is a quantization, resolved by the Hub itself) and served back over the same registry protocol Ollama uses, so `ollama pull <high-host>/<org>/<model>:<tag>` works air-gapped; the raw GGUF also downloads from `/hf/…` for llama.cpp. **Full repository snapshots** (`openai/gpt-oss-20b`, for safetensors releases) are pinned to a commit, LFS-verified, and served over the Hub API's download subset — point `HF_ENDPOINT` at the mirror and `vllm serve`, transformers, and `hf download` work unchanged. Gated models authenticate with `ARTIGATE_HF_TOKEN` on the low side.

### Rust crates → [crates.md](crates.md)

Collect takes crate specs (`serde@1.0.203`, or bare for the newest release) and resolves the **transitive dependency graph** — normal and build dependencies, never dev, optional only when asked — against the sparse index (`https://index.crates.io` by default; `--crates-index` overrides), verifying every `.crate` against the index checksum. Each release's verbatim index line travels inside the signed manifest, and the high side serves a **cargo sparse registry** regenerated from those verified records under `/crates/`; clients use a `~/.cargo/config.toml` source replacement.

### Terraform / OpenTofu → [terraform.md](terraform.md)

Collect takes provider addresses (`hashicorp/aws@5.50.0`, mirrored for each requested platform — `linux_amd64` by default) and/or registry modules. Provider zips are verified against the registry-declared checksum and mirrored **with the upstream `SHA256SUMS`, its GPG signature, and the registry-served signing keys**, so terraform's own verification chain works unchanged against the mirror; modules are mirrored from https archives, or from `git::` sources fetched with `git` and repacked as deterministic archives. `--terraform-registry` or the request's `registry` field points at `https://registry.opentofu.org` to mirror OpenTofu. The high side serves the provider and module registry protocols under `/.well-known/terraform.json` + `/terraform/`.

### Helm charts → [helm.md](helm.md)

Collect takes a classic chart repository URL plus chart specs (`nginx@21.1.0`, or bare for the newest version), verifying archives against the repository index digest when the index declares one. Each upstream repo becomes its own mirror under `/helm/<mirror>`, its `index.yaml` **regenerated from every chart's own embedded `Chart.yaml`** with recomputed digests; clients `helm repo add` the mirror. OCI-hosted charts are out of scope — mirror those as container images.

### NuGet → [nuget.md](nuget.md)

Collect takes package specs (`Newtonsoft.Json@13.0.3`, or a bare `Serilog` for the newest stable) and resolves nuspec dependencies the way NuGet restore does — **lowest applicable version per range**, across all target-framework groups — against the v3 source (`https://api.nuget.org/v3/index.json` by default; `--nuget-source` overrides). The flat container publishes no digests, so downloads are TLS-trusted and validated against the embedded nuspec. The high side serves a **v3 feed** (service index, flat container, registration, search) under `/nuget/`, all metadata regenerated from each package's own `.nuspec`; clients use a `nuget.config` with `<clear />`.

### Alpine (apk) → [apk.md](apk.md)

Collect takes a mirror base plus branches/repositories/architectures (defaults: `main`, `x86_64`) or a pasted `/etc/apk/repositories` file, and is **newest-only by default** like APT/RPM. Private mirrors authenticate with a one-time login on the collect or standing `ARTIGATE_UPSTREAM_AUTH` credentials. Every `.apk` is verified against the `APKINDEX`-declared size and `Q1` control checksum; the verbatim stanzas travel inside the signed manifest and the high side regenerates `APKINDEX.tar.gz` under `/apk/<mirror>`, gated on the packages present — optionally RSA-signed with `--apk-rsa-key` so stock `apk` clients skip `--allow-untrusted`.

### OSV advisories → [osv.md](osv.md)

The audit companion to all of the above: collect takes **OSV ecosystem names** (`npm`, `PyPI`, `Go`, `crates.io`, `Alpine:v3.22`, `Debian:12`, …) and fetches each name's current `all.zip` advisory database from the [osv.dev](https://osv.dev) bucket. The high side serves the verified snapshots in the upstream bucket's own layout under `/osv/` (plus single advisories by id, streamed from the zip) for offline scanners — and mirroring the `npm` database makes **`npm audit` work against the mirror's npm registry**, so clients drop `audit=false`. Databases are *snapshots*: each import replaces the previous one, an unchanged database dedups to a no-op, and a daily [schedule](../scheduling.md) keeps the air-gapped advisory picture current.

## Cross-cutting notes

Each ecosystem trades completeness for airgap-friendliness in a different way. Know these before you build a mirror:

| Ecosystem | Scope rule |
|---|---|
| Go, NPM | **Full graph** — the transitive dependency closure is mirrored |
| Crates, NuGet | **Full graph per their resolvers** — crates follow normal + build dependencies (never dev; optional only with `include_optional`, highest matching version, no feature unification); NuGet picks the **lowest applicable version** per range across all target frameworks, like restore |
| Python | **Wheels only** — no sdists, so the high side never compiles |
| Maven | **Release only** — `-SNAPSHOT` artifacts are not mirrored |
| APT, RPM, Alpine | **Newest-only by default** — one version per package unless `newest_only: false` |
| Terraform | **Named providers for the selected platforms + named modules** — `platforms` defaults to `linux_amd64`; module dependencies are not auto-resolved |
| Helm | **Exactly the charts you name** — chart dependencies are not auto-resolved |
| AI models | **Exactly what you name** — one variant per reference; a repository snapshot is every file at one pinned commit (minus `repo_exclude`) |
| OSV | **Whole databases, replaced on refresh** — each named ecosystem's full `all.zip`, the one mutable mirrored subtree |

!!! warning "Content dedup is per stream"
    The low side's export dedup ([`exported.db`](../architecture.md#export-deduplication-and-delta-bundles)) is **per stream**. A re-collect of an unchanged upstream is skipped and consumes no sequence number; a partly-changed one ships a **delta bundle** carrying only the new files. APT, RPM, container, and Hugging Face LFS collects even skip *downloading* files the index says were already forwarded. It does not dedup across ecosystems, `"force": true` bypasses it per collect, and [re-export](../low-side.md) bypasses it entirely.

!!! tip "Live progress"
    Append `?stream=1` to any collect (e.g. `POST /admin/containers/collect?stream=1`) for NDJSON live progress instead of a single JSON result — useful for long mirrors. See the [HTTP API reference](../api.md).

For per-request bodies, exact flags, and worked examples, follow the ecosystem links above. For the trust model that makes all of this safe, read [Security & trust](../security.md).
