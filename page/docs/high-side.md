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

`--import-interval` and `--quarantine` are the two that most often surprise operators: an empty `--quarantine` resolves to `<root>/quarantine` (the resolved value is printed in the startup log), and `--import-interval 0` disables the background import goroutine entirely — imports then happen only when you `POST /admin/import`.

!!! note
    TLS is configured entirely through environment variables (`ARTIGATE_TLS_MODE` and friends), shared with the low side — there is no TLS flag. See [TLS / HTTPS](tls.md). For the full command-line and environment surface, see the [Configuration reference](configuration.md).

On startup `NewHighServer` makes `--root` absolute and creates `--root`, `--landing`, `--quarantine`, and `<root>/cache/download` (all mode `0755`). Import progress is persisted to `<root>/import-state.json`.

## The landing directory and the import loop

Bundles arrive in `--landing` as three files sharing a bundle ID — `<id>.tar.gz`, `<id>.manifest.json`, and `<id>.manifest.json.sig` — where the ID is `<stream>-bundle-<seq>`, e.g. `go-bundle-000042` or `python-bundle-000007`. The diode transfer is out of ArtiGate's scope; ArtiGate only reads what lands.

When `--import-interval > 0` a background goroutine ticks on that interval and calls the same import routine that `POST /admin/import` calls. Each pass, per stream:

1. **Sort stray bundles.** Every complete bundle in `--landing` is classified against that stream's next-expected sequence: a **future** bundle (`seq` greater than next) is moved to the quarantine directory; an **already-imported** bundle (`seq` at or below the last imported) is moved to `<landing>/duplicates`; the bundle sitting at exactly the next sequence is left in place.
2. **Drain each stream in order.** Starting at `last-imported + 1`, the importer looks for that bundle in the landing dir and then the quarantine dir, imports it, advances, and repeats until the next sequence is missing. A gap in one stream blocks only that stream — the other seven drain independently.

Imports are **strictly consecutive within a stream**. The manifest carries a `previous_sequence` that must equal the high side's current last-imported sequence for that stream, so bundles cannot be skipped forward. A permanently missing bundle blocks its own stream forever but never the others.

!!! tip
    Quarantine is self-healing. Because the drain loop searches quarantine as well as landing, a future bundle that arrived early sits in quarantine until its predecessor imports, then gets picked up automatically on the next pass — no operator action required.

### Quarantine of out-of-order bundles

| Situation | Where the bundle goes |
|-----------|-----------------------|
| `seq == next-expected` | stays in landing, imported this pass |
| `seq > next-expected` (future) | moved to `--quarantine` (default `<root>/quarantine`) |
| `seq <= last-imported` (replay/duplicate) | moved to `<landing>/duplicates` |
| successfully imported | its three files move to `<landing>/imported` |

!!! warning
    Import moves files into `<landing>/imported`, `<landing>/duplicates`, and the quarantine directory rather than deleting them, and the low side keeps its own `<root>/bundles` archive. Account for disk growth in all of these — automatic retention/pruning is not yet built.

Every imported bundle is verified before it counts: the Ed25519 signature is checked over the exact on-disk manifest bytes, the manifest's sequence chain and completeness are validated, and the archive is extracted into a staging area where each file's size and streaming SHA-256 must match the manifest. Installation is **write-once** — a repo path that already exists must hash identically, or the import fails with an immutable-file conflict. See [Architecture](architecture.md) for the full verification chain.

## The dashboard

The high side serves a self-contained dashboard at `/` (and `/ui`). It embeds its own HTML and JavaScript — no external assets, no CDN — so it works fully air-gapped.

The dashboard shows:

- **Import status per stream** — last-imported, next-expected, and highest-seen sequence for each of the eight streams, plus **missing-bundle flags**. A stream is flagged as blocked only when a *later* bundle has already arrived but the immediate next one is absent (a real gap), not merely when it is waiting for the next bundle to be produced. Missing ranges are shown as e.g. `45-47`, and quarantined sequences are listed.
- **A browsable tree** — expand each ecosystem one level at a time (modules, versions, files; projects and wheels for Python; packages and versions for npm). The inventory is memoized for 3 seconds, so freshly imported content appears within that window.
- **Detail** — per-item metadata: for a Go module@version, the module, version, publish time, zip size and SHA-256, the proxy path, and the full `go.mod`; for a Python wheel, filename, version, size, download path, and SHA-256; for containers, the pull reference and image layer history; for AI models, the quantization/format read from the model config, the copyable `ollama pull` reference, and the raw-GGUF download path (or a repository snapshot's pinned commit, file count, and sizes).
- **The "Set me up" guide** — client configuration for the repository-style ecosystems (APT, RPM, containers, AI models), including whether each repo is **signed**. A repo reports `signed: true` exactly when the high side republishes it with its own GPG signature (i.e. when `--apt-gpg-key` / `--rpm-gpg-key` is set), so the guide can tell clients whether to verify signatures. The AI Models guide builds its `ollama pull`, raw-GGUF, and `HF_ENDPOINT`/vLLM blocks from what is actually mirrored.

The dashboard is backed by read-only JSON endpoints under `/ui/api/` (`overview`, `tree`, `detail`, `repos`); see [HTTP API reference](api.md).

## The serving model

`HighServer` is the sole HTTP handler. It runs a fixed, ordered dispatch chain — admin/health, then each ecosystem, then the UI — where the first handler that claims the request wins and anything unclaimed returns `404 not found`. Every ecosystem handler is **read-only**: only `GET` and `HEAD` are allowed (`405` otherwise; the container registry returns its own `UNSUPPORTED` error).

### Top-level URL prefixes

| Prefix | Serves |
|--------|--------|
| `/go` | Go module proxy (GOPROXY protocol) |
| `/simple` | Python (PyPI) simple index (wheel/sdist downloads live under `/packages/`) |
| `/maven` | Maven / Java artifacts |
| `/npm` | npm registry API and tarballs |
| `/apt` | APT (Debian/Ubuntu) repositories |
| `/rpm` | RPM (RHEL/Fedora) repositories |
| `/v2` | Container images (OCI / Docker Registry v2 API) |
| `/ui` | Dashboard (also served at `/`) |
| `/healthz` | Health check → `ok\n` |
| `/admin/*` | `POST /admin/import`, `GET /admin/status`, `GET /admin/missing` |

!!! note
    Two prefixes are easy to get wrong. Python's index prefix is **`/simple`** (not `/python`), with downloads under `/packages/`; containers use **`/v2`** (the Docker Registry v2 API), where a bare `/v2/` returns the API-version header and `/v2/_catalog` lists repositories.

`GET /admin/status` and `GET /admin/missing` are aliases — both return the identical import-status JSON. Requesting status also has a side effect: it first sorts any stray landing bundles into quarantine/duplicates, exactly as an import pass would.

### The trust model

The high side treats the **verified artifacts themselves** as the only source of truth and **regenerates all repository metadata locally**. It never serves a transferred index, `Release`/`Packages` file, RPM `repomd`, npm packument, or Go "latest" record:

- **APT** repositories are rebuilt from the `.deb` stanzas actually present; the regenerated `InRelease` is signed only if `--apt-gpg-key` is set, otherwise served unsigned.
- **RPM** repodata is rebuilt from the installed packages; `repomd.xml.asc` is signed only if `--rpm-gpg-key` is set.
- **npm** metadata is regenerated from each tarball's own embedded `package.json`.
- **Go** listings are computed by scanning the on-disk `@v` directory and filtering to **complete** versions — a version is served only once its `.complete` marker plus `.info`, `.mod`, and `.zip` are all present, so half-installed versions are never visible.

The high side therefore **serves only complete versions** of fully verified content. Optional repo signing (`--apt-gpg-key`, `--rpm-gpg-key`) lets you re-sign the regenerated APT/RPM metadata with a key clients on the trusted network already trust; leaving them unset serves those repositories unsigned.

### Always unauthenticated

!!! warning
    The high side is **never authenticated**. There is no auth flag or environment variable for it — every route (the dashboard, `/admin/import`, `/admin/status`, `/admin/missing`, `/healthz`, and all ecosystem proxies) is open. Access control is expected to come from **network placement**: bind it to the trusted/isolated network, or front it with a reverse proxy. TLS (via the shared `ARTIGATE_TLS_*` variables) provides transport encryption but not authentication. See [Security & trust](security.md).

## Pointing clients here

Once the high side is serving, configure clients against its base URL. Each ecosystem page has the exact client-side setup and its "Set me up" details:

| Ecosystem | Client setup |
|-----------|--------------|
| Go modules | `GOPROXY=<base>/go,off` and `GOSUMDB=off` — see [Go modules](ecosystems/go.md) |
| Python (PyPI) | index URL `<base>/simple/` — see [Python (PyPI)](ecosystems/python.md) |
| Java (Maven) | mirror `<base>/maven/` — see [Java (Maven)](ecosystems/maven.md) |
| NPM | registry `<base>/npm/` — see [NPM](ecosystems/npm.md) |
| APT | `deb <base>/apt/ …` — see [APT (Debian/Ubuntu)](ecosystems/apt.md) |
| RPM | `baseurl=<base>/rpm/…` — see [RPM (RHEL/Fedora)](ecosystems/rpm.md) |
| Containers | pull from `<base>/v2/…` — see [Container images (OCI)](ecosystems/containers.md) |

For the overview of all eight ecosystems see [Ecosystems](ecosystems/index.md). For production hardening and layout see [Deployment](deployment.md).
