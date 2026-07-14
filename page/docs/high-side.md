# High side

The high side is ArtiGate's air-gapped, read-only mirror. It watches a landing directory for signed bundles delivered across the diode, imports them strictly in sequence order per stream, verifies every artifact, regenerates all repository metadata from the artifacts themselves, and serves clients. It never invokes `go`, `pip`, `mvn`, or `npm`, and it never reaches upstream for anything.

For the end-to-end model (streams, bundle format, signing, verification, trust) see [Architecture](architecture.md). For the raw HTTP surface see [HTTP API reference](api.md).

## Running it

The high side is the `high` subcommand of the single `artigate` binary:

```bash
artigate high \
  --public-key /etc/artigate/high.ed25519.pub \
  --root /var/lib/artigate-high \
  --landing /var/spool/diode-in \
  --listen :8080
```

`--public-key` is the only hard-required flag; startup aborts with `--public-key is required` if it is empty. The key is the base64 Ed25519 **public** key produced by `artigate keygen` on the low side — it must correspond to the private key the low side signs bundles with, or every import fails signature verification.

### Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--listen` | `:8080` | HTTP listen address |
| `--root` | `/var/lib/artigate-high` | high-side repository root |
| `--landing` | `/var/spool/diode-in` | directory where diode-delivered bundles arrive |
| `--quarantine` | `""` → `<root>/quarantine` | directory for out-of-order (future) bundles |
| `--public-key` | `""` (**required**) | base64 Ed25519 public key path |
| `--import-interval` | `10s` | bundle import scan interval; `0` disables the background importer |
| `--apt-gpg-key` | `""` | GPG key id used to sign regenerated APT repositories (`InRelease`); unset serves them unsigned |
| `--rpm-gpg-key` | `""` | GPG key id used to sign regenerated RPM repositories (`repomd.xml.asc`); unset serves them unsigned |
| `--apk-rsa-key` | `""` | PEM RSA private key path used to sign regenerated Alpine `APKINDEX` files; unset serves them unsigned |
| `--apk-key-name` | `artigate.rsa.pub` | filename Alpine clients install the APK signing public key under (`/etc/apk/keys/<name>`) |

`--import-interval` and `--quarantine` are the two that most often surprise operators: an empty `--quarantine` resolves to `<root>/quarantine` (the resolved value is printed in the startup log), and `--import-interval 0` disables the background import goroutine entirely — imports then happen only when you `POST /admin/import`.

!!! note
    TLS is configured entirely through environment variables (`ARTIGATE_TLS_MODE` and friends), shared with the low side — there is no TLS flag. The [HTTP diode ingest](deployment.md) (`ARTIGATE_DIODE_INGEST=on`) and the [UDP diode catcher](data-diode.md) (`ARTIGATE_CATCHER_INTERFACE`) are also environment-configured. For the full command-line and environment surface, see the [Configuration reference](configuration.md).

On startup `NewHighServer` makes `--root` absolute and creates `--root`, `--landing`, `--quarantine`, and `<root>/cache/download` (all mode `0755`). Import progress is persisted to `<root>/import-state.json`.

## The landing directory and the import loop

Bundles arrive in `--landing` as three files sharing a bundle ID — `<id>.tar.gz`, `<id>.manifest.json`, and `<id>.manifest.json.sig` — where the ID is `<stream>-bundle-<seq>`, e.g. `go-bundle-000042` or `python-bundle-000007`. How they arrive is up to the deployment: a folder-moving diode, an upload to the [HTTP ingest endpoint](deployment.md) (`PUT/POST /diode/<file>`, which triggers an immediate import when a bundle completes), or the [UDP catcher](data-diode.md) reassembling a fiber transmission. ArtiGate only reads what lands.

When `--import-interval > 0` a background goroutine ticks on that interval and calls the same import routine that `POST /admin/import` calls. Each pass, per stream:

1. **Sort stray bundles.** Every complete bundle in `--landing` is classified against that stream's next-expected sequence: a supported **future** bundle no more than 10,000 positions ahead moves to quarantine; an already-imported bundle moves to `<landing>/duplicates`; unsupported or excessively-future IDs move to `<root>/rejected`.
2. **Drain each stream in order.** Starting at `last-imported + 1`, the importer looks in landing and quarantine, imports it, advances, and repeats until the next sequence is missing. A gap or failure in one stream never prevents the other supported streams from draining. A bundle that fails signature, manifest, or archive verification moves to `<root>/rejected` with a bounded reason file; operational failures remain in place for retry.

Imports are **strictly consecutive within a stream**. The manifest carries a `previous_sequence` that must equal the high side's current last-imported sequence for that stream, so bundles cannot be skipped forward. A permanently missing bundle blocks its own stream forever but never the others.

!!! tip
    Quarantine is self-healing. Because the drain loop searches quarantine as well as landing, a future bundle that arrived early sits in quarantine until its predecessor imports, then gets picked up automatically on the next pass — no operator action required.

### Quarantine of out-of-order bundles

| Situation | Where the bundle goes |
|-----------|-----------------------|
| `seq == next-expected` | stays in landing, imported this pass |
| `seq > next-expected`, gap ≤ 10,000 | moved to `--quarantine` (default `<root>/quarantine`) |
| unsupported stream, larger future gap, or invalid signed content | moved to `<root>/rejected` with `<id>.reason.txt` |
| `seq <= last-imported` (replay/duplicate) | moved to `<landing>/duplicates` |
| successfully imported | its three files move to `<landing>/imported` |

!!! warning
    Import moves files into `<landing>/imported`, `<landing>/duplicates`, quarantine, and `<root>/rejected` rather than deleting them, and the low side keeps its own `<root>/bundles` archive. Account for disk growth in all of these — automatic retention/pruning is not yet built.

Every imported bundle is verified before it counts: new `ed25519ph:` signatures stream the bounded manifest through SHA-512 before Ed25519 verification (legacy raw signatures remain readable), the manifest's sequence chain and completeness are validated, and the archive is extracted into a staging area where each file's size and streaming SHA-256 must match the manifest. Installation is **write-once** — a repo path that already exists must hash identically, or the import fails with an immutable-file conflict. See [Architecture](architecture.md) for the full verification chain.

### Delta bundles and prior files

A [delta bundle](architecture.md#export-deduplication-and-delta-bundles)'s manifest lists files marked `prior` — content the low side already shipped in an earlier bundle on the same stream, deliberately left out of the archive. The importer verifies each prior file against the **accumulated repository**: it must exist at the manifest path with the manifest size (installs are immutable and were hash-verified when they first arrived, so existence + size is sufficient and keeps large delta imports cheap). If a prior file is absent — a fresh high side, or one whose earlier bundles never arrived — the import fails with:

```text
bundle references prior file <path> (sha256 <hash>) that is not in the repository:
import this stream's earlier bundles first, or run a forced (full) re-collect on the low side
```

Both remedies are low-side actions: re-export the stream's earlier bundles from the archive, or run the collect again with `"force": true` to produce a full, self-contained bundle.

## The dashboard

The high side serves a self-contained dashboard at `/` (and `/ui`). It embeds its own HTML and JavaScript — no external assets, no CDN — so it works fully air-gapped.

The dashboard shows:

- **Import status per stream** — last-imported, next-expected, and highest-seen sequence for each supported stream, plus **missing-bundle flags**. Missing ranges are derived from sorted observed sequences, so their cost is proportional to files present rather than the numeric gap size. Quarantined sequences are listed.
- **A browsable tree** — expand each ecosystem one level at a time (modules, versions, files; projects and wheels for Python; packages and versions for npm). APT mirrors expand **by suite and then component**, mirroring the repository structure. The inventory is memoized for 3 seconds, so freshly imported content appears within that window.
- **Detail** — per-item metadata: for a Go module@version, the module, version, publish time, zip size and SHA-256, the proxy path, and the full `go.mod`; for a Python wheel, filename, version, size, download path, and SHA-256; for containers, the pull reference and image layer history; for AI models, the quantization/format read from the model config, the copyable `ollama pull` reference, and the raw-GGUF download path (or a repository snapshot's pinned commit, file count, and sizes).
- **Direct downloads** — every file-backed leaf's detail panel carries download buttons for the artifact's files (the module zip, the wheel, each Maven jar/pom, each per-architecture `.deb`/`.rpm`, the npm tarball, the raw GGUF, an uploaded file), so an operator can pull a single artifact from the browser without configuring a client. Container images stay pull-only — a multi-blob image has no single file to download.
- **The "Set me up" guide** — client configuration for the repository-style ecosystems (APT, RPM, containers, AI models), including whether each repo is **signed**. A repo reports `signed: true` exactly when the high side republishes it with its own GPG signature (i.e. when `--apt-gpg-key` / `--rpm-gpg-key` is set), so the guide can tell clients whether to verify signatures. The APT guide is pinned to the tree's component nodes and offers a **release picker**: choose among the mirror's suites and tick the **components** to include, and the rendered deb822 stanza follows, exact to what is actually mirrored per suite. The AI Models guide builds its `ollama pull`, raw-GGUF, and `HF_ENDPOINT`/vLLM blocks from what is actually mirrored, and the containers guide renders the `daemon.json` `insecure-registries` block with the real host and port when serving plain HTTP.

The dashboard is backed by read-only JSON endpoints under `/ui/api/` (`overview`, `tree`, `detail`, `repos`); see [HTTP API reference](api.md).

## The serving model

`HighServer` is the sole HTTP handler. It runs a fixed, ordered dispatch chain — admin/health, diode ingest, then each ecosystem, then the UI — where the first handler that claims the request wins and anything unclaimed returns `404 not found`. Every ecosystem handler is **read-only**: only `GET` and `HEAD` are allowed (`405` otherwise; the container registry returns its own `UNSUPPORTED` error).

### Top-level URL prefixes

| Prefix | Serves |
|--------|--------|
| `/go` | Go module proxy (GOPROXY protocol) |
| `/simple` | Python (PyPI) simple index (wheel downloads live under `/packages/`) |
| `/maven` | Maven / Java artifacts |
| `/npm` | npm registry API and tarballs |
| `/apt` | APT (Debian/Ubuntu) repositories |
| `/rpm` | RPM (RHEL/Fedora) repositories |
| `/v2` | Container images (OCI / Docker Registry v2 API) — also answers Ollama pulls for mirrored GGUF models |
| `/hf`, `/api/models`, `/<org>/<repo>/resolve/…` | AI models: raw GGUF downloads and the Hugging Face Hub download API |
| `/crates` | Rust crates (cargo sparse registry: `/crates/index/…` + `/crates/dl/…`) |
| `/.well-known/terraform.json`, `/terraform` | Terraform / OpenTofu provider and module registry protocols plus the artifact files |
| `/helm` | Helm chart repositories (`/helm/<mirror>/index.yaml` + chart archives) |
| `/nuget` | NuGet v3 feed (service index at `/nuget/v3/index.json`, flat container, registration, search) |
| `/apk` | Alpine repositories (`/apk/<mirror>/<branch>/<repo>/<arch>/…`, plus `/apk/keys/<name>` when index signing is configured) |
| `/diode` | Bundle ingest (`PUT`/`POST`, only when `ARTIGATE_DIODE_INGEST=on`) |
| `/ui` | Dashboard (also served at `/`) |
| `/healthz` | Liveness check → `ok\n` |
| `/readyz` | Readiness check → `200 ok`, or `503` naming the failing checks (blocked streams, undrained backlog, stalled/failing import passes, exhausted transport quota) |
| `/metrics` | Prometheus telemetry |
| `/admin/*` | `POST /admin/import`, `GET /admin/status`, `GET /admin/missing` |

!!! note
    Two prefixes are easy to get wrong. Python's index prefix is **`/simple`** (not `/python`), with downloads under `/packages/`; containers use **`/v2`** (the Docker Registry v2 API), where a bare `/v2/` returns the API-version header and `/v2/_catalog` lists repositories. The `/v2/` space is shared: a request for a mirrored Hugging Face model (`/v2/<org>/<model>/…`) is answered by the model registry first, and everything else falls through to the container registry — which is what lets `ollama pull <host>/<org>/<model>:<tag>` and `docker pull <host>/docker.io/library/alpine:3.20` coexist on one port.

`GET /admin/status` and `GET /admin/missing` are aliases — both return the identical import-status JSON. Requesting status also has a side effect: it first sorts any stray landing bundles into quarantine/duplicates, exactly as an import pass would.

### The trust model

The high side treats the **verified artifacts themselves** as the only source of truth and **regenerates all repository metadata locally**. It never serves a transferred index, `Release`/`Packages` file, RPM `repomd`, npm packument, or Go "latest" record:

- **APT** repositories are rebuilt per suite from the `.deb` stanzas actually present; the regenerated `InRelease` is signed only if `--apt-gpg-key` is set, otherwise served unsigned.
- **RPM** repodata is rebuilt from the installed packages; `repomd.xml.asc` is signed only if `--rpm-gpg-key` is set.
- **npm** metadata is regenerated from each tarball's own embedded `package.json`.
- **Go** listings are computed by scanning the on-disk `@v` directory and filtering to **complete** versions — a version is served only once its `.complete` marker plus `.info`, `.mod`, and `.zip` are all present, so half-installed versions are never visible.
- **Crates** sparse-index files are regenerated from the manifest-carried index lines whose `cksum` equals the verified artifact's SHA-256, listing only releases whose `.crate` is present.
- **Terraform** provider metadata is rebuilt after cross-checking every zip against the mirrored `SHA256SUMS` — the document terraform verifies the GPG signature of — and lists only platforms whose zip is present.
- **Helm** `index.yaml` is regenerated per mirror from each chart's own embedded `Chart.yaml`, with digests recomputed from the artifacts.
- **NuGet** feed metadata (versions, registration, search) is regenerated from each package's own embedded `.nuspec`.
- **Alpine** `APKINDEX.tar.gz` is regenerated per branch/repo/arch from the accumulated stanzas of the `.apk` files present; signed only if `--apk-rsa-key` is set.

The high side therefore **serves only complete versions** of fully verified content. Optional repo signing (`--apt-gpg-key`, `--rpm-gpg-key`, `--apk-rsa-key`) lets you re-sign the regenerated APT/RPM/Alpine metadata with a key clients on the trusted network already trust; leaving them unset serves those repositories unsigned.

### Always unauthenticated

!!! warning
    The high side is **never authenticated**. There is no auth flag or environment variable for it — every route (the dashboard, `/admin/import`, `/admin/status`, `/admin/missing`, `/healthz`, `/readyz`, `/metrics`, and all ecosystem proxies) is open. The one exception is the optional diode ingest endpoint: enabling it requires an `ARTIGATE_DIODE_TOKEN` bearer token of at least 32 bytes. That token protects the disk from unauthenticated uploads, nothing more. Access control is expected to come from **network placement**: bind it to the trusted/isolated network, or front it with a reverse proxy. TLS (via the shared `ARTIGATE_TLS_*` variables) provides transport encryption but not authentication. See [Security & trust](security.md).

## Pointing clients here

Once the high side is serving, configure clients against its base URL. Each ecosystem page has the exact client-side setup and its "Set me up" details:

| Ecosystem | Client setup |
|-----------|--------------|
| Go modules | `GOPROXY=<base>/go,off` and `GOSUMDB=off` — see [Go modules](ecosystems/go.md) |
| Python (PyPI) | index URL `<base>/simple/` — see [Python (PyPI)](ecosystems/python.md) |
| Java (Maven) | mirror `<base>/maven/` — see [Java (Maven)](ecosystems/maven.md) |
| NPM | registry `<base>/npm/` — see [NPM](ecosystems/npm.md) |
| APT | deb822 stanza against `<base>/apt/<mirror>` — see [APT (Debian/Ubuntu)](ecosystems/apt.md) |
| RPM | `baseurl=<base>/rpm/<mirror>` — see [RPM (RHEL/Fedora)](ecosystems/rpm.md) |
| Containers | `docker pull <host>/<registry>/<repository>:<tag>` — see [Container images (OCI)](ecosystems/containers.md) |
| AI models | `ollama pull <host>/<org>/<model>:<tag>`, raw GGUF under `/hf/`, or `HF_ENDPOINT=<base>` — see [AI models (Hugging Face)](ecosystems/ai-models.md) |
| Rust crates | `~/.cargo/config.toml` source replacement with `registry = "sparse+<base>/crates/index/"` — see [Rust crates](ecosystems/crates.md) |
| Terraform / OpenTofu | `~/.terraformrc` `network_mirror` (`<base>/terraform/v1/providers/`, HTTPS required) or host-prefixed source addresses — see [Terraform / OpenTofu](ecosystems/terraform.md) |
| Helm | `helm repo add artigate <base>/helm/<mirror>` — see [Helm charts](ecosystems/helm.md) |
| NuGet | `nuget.config` source `<base>/nuget/v3/index.json` with `<clear />` — see [NuGet](ecosystems/nuget.md) |
| Alpine (apk) | `/etc/apk/repositories` line `<base>/apk/<mirror>/<branch>/<repo>`, key from `/apk/keys/<name>` — see [Alpine (apk)](ecosystems/apk.md) |

For the overview of all thirteen ecosystems see [Ecosystems](ecosystems/index.md). For production hardening and layout see [Deployment](deployment.md).
