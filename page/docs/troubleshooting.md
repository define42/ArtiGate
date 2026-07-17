# Troubleshooting & limitations

This page consolidates every deliberate limitation of ArtiGate together with the
operational issues you are most likely to hit, and how to resolve each one. The
limitations are intentional consequences of the diode design: the low side
fetches with the native toolchains, the high side *never* fetches upstream and
rebuilds all metadata from the artifacts themselves. See
[Architecture](architecture.md) and [Security & trust](security.md) for the model.

!!! note "Source of truth"
    The behaviour described here is defined in `cmd/artigate/lowside.go` /
    `highside.go` and the per-ecosystem collectors under `cmd/artigate/` (one
    file per ecosystem — `python.go`, `npm.go`, `apt.go`, `conda.go`,
    `gitmirror.go`, …), and summarised in
    the project `README.md` "Notes and limitations" section. Where this page and
    the code ever disagree, the code wins.

## Per-ecosystem limitations

Each ecosystem is its own [stream](architecture.md) with an independent sequence
counter, but each also has policy limits baked into the collector. These are by
design — they keep the mirror reproducible and keep the high side able to
regenerate everything it serves.

| Ecosystem | Limitation | Why / how to work with it |
|---|---|---|
| [Go](ecosystems/go.md) | Checksum-database records exist only for modules collected since sumdb capture was added; `--gosumdb off` disables capture. | The mirror serves the signed sumdb records and Merkle tiles captured at collect time under `/go/sumdb/…`, so clients keep `GOSUMDB` **on** (the default). Modules mirrored by pre-capture bundles have no records yet — one re-collect on the low side backfills them; until then those clients need `GOSUMDB=off`. Private modules (`GONOSUMDB`/`GOPRIVATE`) are never looked up. |
| [Python](ecosystems/python.md) | Wheels only through pip; sdists are a per-package opt-in. | Every pip run is forced to `--only-binary=:all:`, so a *requirement* with no compatible wheel fails the collect — pin a wheel-bearing version, choose the correct cross-target, exclude it, or list the package in the collect's `sdists` field. Opted-in sdists are fetched from the index JSON API (never through pip — no build hooks on the low side), verified against the API-declared SHA-256, and built by clients at install time. |
| [Maven](ecosystems/maven.md) | Release versions only. | `SNAPSHOT` and dynamic/range versions (`1.+`, `[1.0,2.0)`, `LATEST`, `RELEASE`) are rejected because they resolve differently over time and a mirror could never be reproducible. Pin exact versions. |
| [NPM](ecosystems/npm.md) | Registry tarballs only; needs npm 7+ on the low side; `dist-tags` serves only tags whose target version is mirrored; `npm audit` needs the OSV `npm` database mirrored. | Dependencies that resolve to git or file URLs are skipped and reported. Resolution uses `npm install --package-lock-only` (lockfile v2+, so npm 7 or newer). The high side rebuilds every packument from each tarball's own `package.json`; each collect snapshots the upstream `dist-tags`, and the served packument carries every mirrored tag pointing at a present version, regenerating `latest` from the versions actually served when the upstream tag is absent or unmirrored. The audit endpoint answers from the mirrored [OSV](ecosystems/osv.md) `npm` database and 404s without it — set `audit=false` only in that case. |
| [APT](ecosystems/apt.md) | Newest version of each package only (default); metadata re-syncs on each collect; signing the served repo is optional. | Untick "Newest version only" to mirror every version. Already-forwarded `.deb`s are skipped before download (delta bundles carry only the churn). A private mirror (HTTP 401/403) takes a login on the collect (`auth` field / the page's login fields) or a `host=user:password` entry in `ARTIGATE_UPSTREAM_AUTH`. Serving is signed only when `--apt-gpg-key` is set — otherwise `InRelease` is served unsigned. |
| [RPM](ecosystems/rpm.md) | Newest EVR of each package only (default); x86_64 + noarch packages only by default; no `.zck` (zchunk) indexes; signing optional. | List `architectures` explicitly to mirror more (or fewer) arches. A `.zck`-only repository cannot be parsed or rewritten — use a repo that publishes `.gz`/`.xz` metadata (or disable newest-only if the index is zchunk-only and you don't need filtering). Already-forwarded `.rpm`s are skipped before download. A private repo (HTTP 401/403) takes a login on the collect or a `host=user:password` entry in `ARTIGATE_UPSTREAM_AUTH`. Serving is signed only when `--rpm-gpg-key` is set (`repomd.xml.asc`). |
| [Containers](ecosystems/containers.md) | `linux/amd64` only; registries on non-standard ports can't be mirrored; scheduled pulls authenticate only via `ARTIGATE_CONTAINER_AUTH`; the high-side registry is read-only. | The `linux/amd64` manifest is picked out of any multi-platform index. A private image fails with "the image may be private; supply a login on the pull (auth field) or set ARTIGATE_CONTAINER_AUTH" — add a login on the pull or a standing `host=user:password` entry in `ARTIGATE_CONTAINER_AUTH`; "credentials … were not accepted" means the login itself is wrong. A registry with a port (`host:5000/…`) is rejected because the port can't appear in the high-side pull name. Use `--container-registry host=baseURL` on the low side to redirect a registry's API to a private mirror. The high side never accepts pushes. |
| [AI models](ecosystems/ai-models.md) | GGUF variants need a GGUF repository; digest pins rejected; snapshots serve only the Hub API's download subset; Ollama requires HTTPS. | Mirror a safetensors-only release as a **full repository** instead of a variant. Gated models need `ARTIGATE_HF_TOKEN` on the low side. Enable [TLS](tls.md) or pass `--insecure` to `ollama pull`. `HF_ENDPOINT`-pointed vLLM/transformers/`hf download` work; search and write APIs are not served. |
| [Rust crates](ecosystems/crates.md) | No feature unification; yanked releases skipped unless pinned; sparse indexes only. | The resolver follows normal and build dependencies (never dev; optional only with `include_optional`), picking the highest version satisfying each requirement like cargo — an unusual feature-gated dependency may need to be listed explicitly. An exact pin can still mirror a yanked release, like a lockfile. |
| [Terraform / OpenTofu](ecosystems/terraform.md) | Providers cover only the collect-time `platforms` (`linux_amd64` by default); module sources must be https archives or `git::https`; no login/publishing APIs. | Re-collect a provider version with more platforms to extend it (the high side merges platform lists). Other go-getter module schemes are skipped and reported. `network_mirror` clients need HTTPS on the high side. |
| [Helm](ecosystems/helm.md) | Classic `index.yaml` repositories only — OCI charts out of scope; `.prov` provenance files not mirrored; upstream digest checked only when the index declares one. | Mirror OCI-hosted charts as [container images](ecosystems/containers.md). Integrity comes from the regenerated index digests (recomputed from the verified artifacts). Digest-less upstream entries download TLS-trusted. |
| [NuGet](ecosystems/nuget.md) | The flat container publishes no digests, so low-side downloads are TLS-trusted; dependency resolution picks the lowest applicable version per range. | Downloads are validated against each package's embedded nuspec and hash-locked into the signed bundle from there. Lowest-applicable-version (NuGet restore behavior) applies across all target-framework groups. Use `<clear />` in `nuget.config` so nothing falls back to nuget.org. |
| [Alpine](ecosystems/apk.md) | Newest version of each package only (default); the APKINDEX carries no whole-file hash, so re-collects re-download; index signing optional. | Set `"newest_only": false` to mirror every version. Packages are verified against the index's size and `Q1` control checksum at collect time; export dedup still keeps re-sends off the diode. A private mirror (HTTP 401/403) takes a login on the collect or a `host=user:password` entry in `ARTIGATE_UPSTREAM_AUTH`. Serving is signed only when `--apk-rsa-key` is set — otherwise clients need `apk --allow-untrusted`. |
| [Conda](ecosystems/conda.md) | Greedy resolution (no SAT backtracking); a repodata entry without a SHA-256 is refused; big channels need RAM. | Pin exact versions where the greedy pick matters — the client's own solver still runs against the served repodata. Repodata is parsed fully in memory (conda-forge subdirs exceed 1 GiB plain), so budget low-side RAM. A private channel takes a login on the collect or a `host=user:password` entry in `ARTIGATE_UPSTREAM_AUTH`. |
| [RubyGems](ecosystems/rubygems.md) | Compact index only (no legacy Marshal API); greedy resolver; platform gems opt-in; no private-server auth. | Bundler and modern RubyGems use the compact index and re-resolve properly at install time. List `platforms` (e.g. `x86_64-linux`) to mirror platform variants beside the pure-Ruby gem. |
| [PHP Composer](ecosystems/composer.md) | Tagged stable releases only (no dev versions); http(s) zip dists only; constraint subset; no private-repo auth. | Dependencies resolve stable-only (Composer's default `minimum-stability`); unsupported constraint forms are reported per package, never guessed. Upstream metadata declares no usable digest, so zip downloads are TLS-trusted and hash-locked into the signed bundle. Disable packagist.org in `composer.json`. |
| [VS Code](ecosystems/vsx.md) | Open VSX only; universal builds only; gallery subset (no ratings/README assets, substring search); deps/packs pull at newest. | Extensions come from Open VSX (`--vsx-registry` overrides); the registry-published SHA-256 is verified when present. Pinning a root extension does not pin its dependencies — pin those explicitly if it matters. |
| [Ansible Galaxy](ecosystems/galaxy.md) | Collection signatures not mirrored (`signatures` is always empty); pins must be exact three-part versions; no search API. | Artifacts are verified against the API-declared SHA-256 **and** size at collect time, and the served checksums are recomputed from the verified files. Use full `namespace.name@x.y.z` pins; ranges belong in dependency constraints. |
| [CRAN](ecosystems/cran.md) | Source packages only; dependency version constraints dropped (deps mirror the index's current version); Archive downloads unverified upstream. | Clients build locally, as with `install.packages(type = "source")` against real CRAN — R build tooling required on the client. Pin `name@version` to fetch superseded releases from `Archive/`. The MD5 index checksum is a transfer check; real integrity is the signed bundle's SHA-256 chain. |
| [Git](ecosystems/git.md) | Dumb HTTP only (no push, no shallow/partial clone); full pack per collect; 2 GiB pack cap; LFS media and submodules not fetched. | Stock `git clone <base>/git/<mirror>.git` works; clients always walk one complete pack. Narrow the `refs` list for huge repositories. Mirror each submodule separately; LFS pointer blobs travel but the media does not. A private upstream takes a login on the collect or an `ARTIGATE_UPSTREAM_AUTH` entry. |
| [OSV](ecosystems/osv.md) | Whole databases per refresh (no upstream deltas); downloads TLS-trusted (the bucket publishes no digests); npm's bulk audit protocol only. | An unchanged database dedups to a no-op export, so a daily schedule costs the diode only real churn. Each snapshot *replaces* the previous one — the deliberate exception to immutable installs. yarn classic's older audit protocol is not served. |
| [Uploads](ecosystems/uploads.md) | No scheduling; no export dedup (every upload ships in full); mutable by design. | There is no upstream to re-pull — upload again when content changes. The dedup bypass is what lets a file deleted on the high side come back by re-uploading; re-uploading a name replaces the served file. Delete via `POST /admin/uploads/delete` (loopback-only unless `ARTIGATE_HIGH_ALLOW_REMOTE_ADMIN=on`). |

!!! note "Manifest `type` is always `go-module-bundle`"
    Every bundle manifest carries `"type": "go-module-bundle"` regardless of
    ecosystem — it is a legacy constant, not an ecosystem discriminator. The
    real ecosystem is the `stream` field plus the populated sub-manifest
    (`python`, `npm`, `apt`, …). Do not key tooling off `type`.

## Point clients at the high side (and only the high side)

Most "package not found" reports on the high side are actually client
misconfiguration: a fallback upstream is still configured, which both hides
gaps and reopens the dependency-confusion risk the diode exists to close.
Configure ArtiGate as the **sole** source, with no secondary registry.

```bash
# Go — ,off (not ,direct) forbids any upstream fallback
go env -w GOPROXY=https://artigate-high.local/go,off
# GOSUMDB stays on (the default): the mirror serves the checksum database's
# signed records and Merkle proofs under /go/sumdb/, so verification is
# offline too. GOSUMDB=off is only for modules mirrored by bundles from
# before sumdb capture existed (re-collect once to backfill) or when the
# low side runs --gosumdb off.
```

```ini
# Python — /etc/pip.conf
[global]
index-url = https://artigate-high.local/simple/
```

```xml
<!-- Maven — ~/.m2/settings.xml -->
<settings><mirrors><mirror>
  <id>artigate</id><mirrorOf>*</mirrorOf>
  <url>https://artigate-high.local/maven/</url>
</mirror></mirrors></settings>
```

```ini
# NPM — ~/.npmrc (or /etc/npmrc)
registry=https://artigate-high.local/npm/
fund=false
# add audit=false only while no OSV "npm" database is mirrored
```

!!! warning "Do not add extra upstreams on the high side"
    Do not add `--extra-index-url`, `mavenCentral()`, a second npm registry, or
    a `,direct` GOPROXY fallback. Any extra upstream lets an attacker get a
    same-named package pulled from elsewhere — the exact substitution attack the
    diode is meant to prevent. If the high side lacks a package, the correct fix
    is to collect it on the low side, not to add a fallback.

## Common issues

### The high side reports a missing bundle — re-transmit from Status

The high side imports strictly in sequence order per stream. If a bundle is lost
in transit (or never made it across the diode), that stream's import blocks: the
status reports `blocking_missing_sequence` and a `missing_ranges` entry once a
*later* bundle has arrived. Other streams keep importing normally.

Check the high side:

```bash
curl -s http://artigate-high.local:8080/admin/status | python3 -m json.tool
```

A blocked stream looks like this (only the next expected sequence is absent while
higher ones wait in quarantine):

```json
{
  "stream": "go",
  "last_imported_sequence": 4,
  "next_expected_sequence": 5,
  "highest_seen_sequence": 7,
  "blocking_missing_sequence": 5,
  "missing_ranges": ["5"],
  "quarantined_sequences": [6, 7],
  "ready_to_import": false
}
```

Fix it on the **low side** by re-transmitting the missing sequence(s) from the
Status page ("Re-transmit") or the re-export API. This is a byte-exact replay of
the archived bundle — it is not re-collected or re-signed, so it works for any
ecosystem:

```bash
# Re-stage sequence 5 (and, if needed, a range) back into the export dir
curl -X POST 'http://artigate-low.local:8080/admin/reexport?stream=go&sequences=5'
curl -X POST 'http://artigate-low.local:8080/admin/reexport?stream=go&sequences=5,7-9'
```

Once the missing predecessor is transferred and imported, the high side
**auto-imports the quarantined successors** on its next tick — no operator action
is needed to un-block them. See [Low side](low-side.md) for re-export and
[High side](high-side.md) for the import loop and status fields.

!!! warning "Re-export needs the archive copy"
    Re-transmit replays from the low-side bundle archive at `<root>/bundles`. If
    that copy is gone, the Status page shows `✗ not kept` and re-export fails
    with `no archived bundle for <bundle-id>`. Re-export also bypasses the export
    dedup index entirely (it never consults or updates it), so a byte-exact
    replay always works even for content the dedup index has already seen.

### An out-of-order bundle got quarantined

This is normal and self-healing. On each import tick the high side sorts the
landing directory (`--landing`, default `/var/spool/diode-in`):

- `sequence > next` → moved to `--quarantine` (default `<root>/quarantine`). A
  future bundle whose predecessor has not arrived yet.
- `sequence <= last_imported` → moved to `<landing>/duplicates`. A replay of
  something already imported; never re-processed.
- `sequence == next` → left in place and imported.

Quarantined future bundles are still found by the importer, so once the gap fills
they import automatically. You do **not** move files out of quarantine by hand.
If a bundle is stuck in quarantine forever, the predecessor is genuinely missing —
re-transmit it (see above).

!!! note "Disk growth"
    Import moves processed files to `<landing>/imported`, future ones to the
    quarantine dir, and duplicates to `<landing>/duplicates`; the low side keeps
    every produced bundle in `<root>/bundles`. Automated retention/pruning of
    these is not yet built, so account for their growth in
    [Deployment](deployment.md).

### An unsigned repo — relax the client's signature check

Republishing APT/RPM repositories with a high-side GPG signature is optional. If
you did not set `--apt-gpg-key` / `--rpm-gpg-key`, the regenerated `InRelease` /
`repomd.xml.asc` are served **unsigned**, and clients configured to verify a
signature will refuse the repo. Either sign on the high side, or relax the
client:

```ini
# APT — mark the source trusted (no signature verification)
Types: deb
URIs: https://artigate-high.local/apt/<mirror>
Suites: stable
Components: main
Architectures: amd64
Trusted: yes
```

```ini
# RPM — disable signature checks for this repo
[artigate]
baseurl=https://artigate-high.local/rpm/<mirror>
enabled=1
gpgcheck=0
repo_gpgcheck=0
```

When the repo **is** signed, point the client at ArtiGate's key (not the vendor's
original key) — the high side re-signs with its own key after regenerating the
metadata. The high-side "Set me up" guide reports whether each repo is signed.

### Docker/podman refuse the mirror — HTTPS or insecure-registries

Docker and podman require HTTPS for remote registries. The container pull name
embeds the upstream registry host:

```bash
docker pull artigate-high.local/docker.io/library/alpine:3.20
docker pull artigate-high.local/ghcr.io/org/app:v1
```

Either enable [TLS](tls.md) on the high side, or, for a plain-HTTP mirror, tell
the daemon to trust it explicitly in `/etc/docker/daemon.json` and restart:

```json
{
  "insecure-registries": [
    "artigate-high.local:8081"
  ]
}
```

```bash
systemctl restart docker
```

The high-side "Set me up" guide renders this block with your actual host and port
filled in.

### Low side: private Go modules need Git/SSH configured

The low side fetches Go modules with the host's own `go`/`git`. The simplest way
to reach a private VCS host is a login on the collect — the Go page's *Private
module host login* fields, or the `auth` field — or a standing
`ARTIGATE_GO_AUTH=gitlab.example.com=bot:token` entry (which scheduled
collects also use; `ARTIGATE_UPSTREAM_AUTH` is for the git/APT/RPM/Alpine/Conda
streams and is not read by Go collects). ArtiGate injects it into `go`/`git`
for that collect and adds
the host to `GOPRIVATE`/`GONOSUMDB` automatically, so no flags are needed for a
new host. For SSH-key auth instead, configure the service user's Git/SSH (and set
`--goprivate github.com/your-org/*` so those paths bypass the public proxy and
sumdb) **before** starting the low side:

```bash
artigate low \
  --private-key /etc/artigate/low.ed25519 \
  --upstream-goproxy https://proxy.golang.org,direct \
  --goprivate github.com/your-org/*
```

Without either, private modules fail to fetch (`GIT_TERMINAL_PROMPT=0` makes the
fetch fail fast rather than hang). A module that cannot be fetched is reported in
`skipped_modules` and skipped — one bad version never aborts the whole batch. See
[Go modules](ecosystems/go.md) and the [Configuration reference](configuration.md)
for the full flag list.

### "No new content since the last export" — this is dedup, not an error

If a collect returns `skipped: true` with the message *"no new content since the
last export"*, the [export dedup index](architecture.md) recognised that every
file's SHA-256 has already been sent across the diode for this stream. **No bundle
is written and no sequence number is consumed** — this is the intended result of
re-running a [scheduled watch](scheduling.md) against an unchanged upstream.

```json
{
  "stream": "python",
  "skipped": true,
  "message": "no new content since the last export"
}
```

If only *some* files were already sent, the collect still succeeds but writes a
**delta bundle** — the response's `prior_files` counts the manifest entries that
reference earlier content instead of carrying it. That is also intended.

If you genuinely need to re-send bytes the high side already has (for example
because the high side lost a bundle), use **re-export** from the Status page — it
replays the archived bundle and bypasses dedup entirely — or add `"force": true`
to the collect body for a fresh, full, self-contained bundle. Dedup is a
per-stream optimisation only; it fails safe (never suppresses content when a
lookup errors) and never affects correctness.

### "bundle references prior file … that is not in the repository"

A [delta bundle](architecture.md#export-deduplication-and-delta-bundles) lists
already-forwarded files as `prior` references and assumes the high side imported
this stream's earlier bundles. This error means it hasn't — typically a rebuilt
or brand-new high side, or a stream whose earlier bundles were never carried
across. The error names the exact file and both remedies:

```text
bundle references prior file <path> (sha256 <hash>) that is not in the repository:
import this stream's earlier bundles first, or run a forced (full) re-collect on the low side
```

Either **re-export the stream's earlier sequences** from the low side's archive
(Status page → Re-transmit), or run the collect again with `"force": true` so it
produces a full bundle with no prior references. Pointing a long-running low side
at a fresh high side always needs one of these two.

## Other gotchas

- **`--import-interval 0` disables the high-side background importer.** Imports
  then happen only on explicit `POST /admin/import`. See [High side](high-side.md).
- **Both dashboards are unauthenticated by default.** The low side can require a
  session login via `ARTIGATE_LOW_AUTH`; the high side is *never* authenticated.
  Bind both to localhost or a trusted network, or front them with a reverse
  proxy. See [Security & trust](security.md).
- **The manifest is signed over its exact on-disk bytes.** Any tool that
  rewrites or re-indents the manifest JSON breaks signature verification and the
  bundle will be rejected at import with "signature verification failed".
- **Immutable file conflicts.** A repo path is write-once on the high side: if a
  new bundle carries the same path with different content, import fails with
  "immutable file conflict". This is a guardrail — content already served can
  never be silently mutated.
- **Low-side collects for different ecosystems run concurrently**, but two
  collects on the *same* stream serialise on that stream's lock. The high side
  never runs `go`/`pip`/`mvn`/`npm` and does no upstream fetching at all.

## Where to look next

- [Architecture](architecture.md) — streams, sequences, the bundle format, and
  the dedup index.
- [Security & trust](security.md) — the sign-on-low / verify-and-regenerate-on-high
  trust chain.
- [HTTP API reference](api.md) — exact request/response shapes for `/admin/*`.
- [Configuration reference](configuration.md) — every flag and environment
  variable.
- [Ecosystems](ecosystems/index.md) — per-ecosystem collect and serve details.
