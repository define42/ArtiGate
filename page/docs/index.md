# ArtiGate

ArtiGate is a dependency mirror for **one-way data-diode / air-gapped networks**. It fetches Go modules, Python (PyPI) wheels and opt-in sdists, Java (Maven) artifacts, NPM packages, Rust crates, Terraform/OpenTofu providers and modules, Helm charts, NuGet packages, APT (`.deb`), RPM (`.rpm`), and Alpine (`.apk`) repositories, conda channels, Ruby gems, PHP Composer packages, VS Code extensions (from Open VSX), Ansible Galaxy collections, R packages (CRAN), Snap packages (with their store assertions), raw git repositories, container images, AI models from Hugging Face, and OSV vulnerability-advisory databases from the internet, carries them across a diode as signed numbered bundles (arbitrary operator-uploaded files ride along too), and serves them on the isolated side in each ecosystem's native format.

!!! note "One binary, two modes"
    A single `artigate` executable runs as either the internet-side exporter (`artigate low`) or the air-gapped read-only mirror (`artigate high`). The low side **delegates fetching** to the host's own `go`/`git`, `pip`, `mvn`, `npm`, and `gpgv` tools. The high side **never invokes them and never touches the network** — it only imports, verifies, and serves what already crossed the diode.

## How it works

```text
  spec ──▶ [ low ] ──▶ signed bundles ──▶ ((diode)) ──▶ [ high ] ──▶ clients
         fetch + sign        carry across          verify + serve
```

1. **Low side** — from its web dashboard you give it a spec (a `go.mod` or module list, a Python requirements list, Maven coordinates, a `package.json` or NPM package list, a crate/provider/chart/NuGet list, an APT source stanza, a `.repo`, an Alpine repositories file, a conda channel and package list, a gem/Composer/extension/collection/CRAN package list, a git clone URL, a list of container images, Hugging Face model references, or OSV ecosystem names). It fetches the closure from upstream and writes a **signed, numbered bundle** — three files per bundle: `<id>.tar.gz`, `<id>.manifest.json`, and `<id>.manifest.json.sig` — into the export directory.
2. **Diode** — a one-way transfer carries those three files into the high side's landing directory: something moves the files (ArtiGate never performs that move itself), or the optional **HTTP diode transport** does — the low side uploads each bundle to an HTTP endpoint (`ARTIGATE_DIODE_URL`) and the high side ingests uploads at `/diode/` (`ARTIGATE_DIODE_INGEST=on`) — or the [built-in UDP diode](data-diode.md) drives a one-way fiber directly.
3. **High side** — it imports each stream's bundles strictly in sequence, verifies the Ed25519 signature and every file's SHA-256 hash, installs artifacts immutably, and **regenerates** all repository metadata from the artifacts actually present. It then serves clients as a GOPROXY (checksum database included), a PyPI index, a Maven 2 repository, an NPM registry (including `npm audit` from mirrored OSV data), a cargo sparse registry, a Terraform/OpenTofu provider+module registry, Helm repositories, a NuGet v3 feed, APT/RPM/Alpine repositories, conda channels, a RubyGems compact index, a Composer repository, a VS Code extension gallery, an Ansible Galaxy v3 API, a CRAN mirror, read-only git repositories (dumb HTTP), a read-only OCI registry, an Ollama-compatible model registry plus the Hub download API for AI models, an OSV advisory feed for offline scanners, and plain downloads for uploaded files.

Each ecosystem is an independently numbered **stream**, so a stalled or missing bundle in one stream never blocks the others.

## The twenty-two streams

| Ecosystem | Low side mirrors | High side serves as | Client prefix |
|---|---|---|---|
| **Go modules** | modules by `module@version` / `module@latest`, or an uploaded `go.mod` (+`go.sum`); full dependency graph | GOPROXY | `/go/` |
| **Python (PyPI)** | a requirements list (wheels, via pip) plus opt-in **sdists** for wheel-less packages (fetched from the index JSON API, never through pip); optional cross-target for the high-side interpreter | PEP 503 simple index + downloads | `/simple/`, `/packages/` |
| **Java (Maven)** | `groupId:artifactId:version` coordinates or an uploaded `pom.xml`; release versions only | Maven 2 repository | `/maven/` |
| **NPM** | package specs or an uploaded `package.json` (+`package-lock.json`); full graph resolved with `npm`, registry tarballs only | NPM registry | `/npm/` |
| **APT (Debian/Ubuntu)** | a deb822 source stanza — several `Suites:` per mirror — with optional `Signed-By` keyring verified with `gpgv` | APT repository | `/apt/<mirror>` |
| **RPM (RHEL/Fedora)** | a yum/dnf `.repo` stanza with a concrete `baseurl`; **x86_64 + noarch** packages by default | RPM repository | `/rpm/<mirror>` |
| **Container images (OCI)** | image refs (`alpine:3.20`, `ghcr.io/org/app:v1`), optional tag version constraints; **linux/amd64 only** | read-only OCI registry (Docker Registry v2) | `/v2/` |
| **AI models (Hugging Face)** | GGUF variants (`hf.co/unsloth/gpt-oss-20b-GGUF:Q4_0`) and full repository snapshots (`openai/gpt-oss-20b`) pinned to a commit | Ollama-compatible registry + Hub download API (`HF_ENDPOINT`) | `/v2/`, `/hf/`, `/api/models/` |
| **Rust crates** | crate specs (`serde@1.0.203`, or bare for the newest release); the transitive graph resolved against the sparse index, every `.crate` verified against the index checksum | cargo sparse registry | `/crates/` |
| **Terraform / OpenTofu** | provider addresses per platform (`linux_amd64` by default) and registry modules; zips verified against the registry checksum, the upstream `SHA256SUMS`/`.sig`/signing keys mirrored too | Terraform provider + module registry protocols | `/.well-known/terraform.json`, `/terraform/` |
| **Helm charts** | a classic chart repo URL plus chart specs (`nginx@21.1.0`); archives verified against the index digest when declared | Helm (`index.yaml`) repository per mirror | `/helm/<mirror>` |
| **NuGet** | package specs (`Newtonsoft.Json@13.0.3`); nuspec dependencies resolved like NuGet restore (lowest applicable version) | NuGet v3 feed | `/nuget/` |
| **Alpine (apk)** | a mirror base + branches/repos/arches (defaults `main`, `x86_64`), or a pasted `/etc/apk/repositories` file; **newest-only by default** | Alpine repository (regenerated `APKINDEX.tar.gz`, optionally RSA-signed) | `/apk/<mirror>` |
| **Conda channels** | a channel (name or URL) + package specs and platform subdirs; files verified against the repodata SHA-256 | conda channel (regenerated per-subdir `repodata.json`) | `/conda/<mirror>` |
| **RubyGems** | gem specs (`rake@13.2.1`); runtime closure from the compact index, `.gem`s verified against the index SHA-256 | RubyGems compact index | `/rubygems/` |
| **PHP Composer** | package specs (`monolog/monolog`); require closure from p2 metadata, stable releases | Composer v2 (p2) repository | `/composer/` |
| **VS Code extensions** | extension ids (`golang.Go`), from Open VSX, dependencies and packs included | VS Code gallery API + `.vsix` downloads | `/vsx/` |
| **Ansible Galaxy** | collection specs (`ansible.posix`); artifacts verified against the API SHA-256 + size | Galaxy v3 API | `/galaxy/` |
| **R packages (CRAN)** | package specs (`jsonlite`); runtime closure as source packages | CRAN mirror (regenerated `PACKAGES`) | `/cran/` |
| **Snap packages** | snap specs (`hello`, `firefox@latest/candidate`) + one architecture; bases ride along | `.snap` + `.assert` pairs for `snap ack` + `snap install`, plus a JSON revision index | `/snap/` |
| **Git repositories** | a clone URL (+ optional name and refs); one fully verified packfile | read-only git repositories (dumb HTTP) | `/git/<mirror>.git` |
| **OSV advisories** | OSV ecosystem names (`npm`, `PyPI`, `Alpine:v3.22`, …); whole databases, replaced on refresh | OSV database feed + `npm audit` on the npm registry | `/osv/` |
| **Uploads** | a folder name + arbitrary files (multipart); no dedup, deletable on the high side | plain file downloads | `/uploads/<folder>/` |

See [Ecosystems](ecosystems/index.md) for the per-ecosystem detail pages.

## Key properties

- **Per-stream sequencing.** Every ecosystem has its own independent sequence counter. Bundles import strictly consecutively per stream — an out-of-order bundle (e.g. `go-bundle-000043` before `000042`) is quarantined, not rejected, and imported automatically once the gap fills. A gap in one stream never blocks another.
- **Signed and verified end to end.** Each bundle's manifest is signed with an Ed25519 private key held only on the low side; the high side verifies that signature over the exact manifest bytes, then re-hashes every extracted file against the manifest's SHA-256 before installing. A signature or hash mismatch aborts that bundle's import without advancing state.
- **The high side regenerates metadata, never trusts it.** Transferred `Release`/`Packages`, packuments, `latest`, and other index files are never treated as truth — the high side rebuilds all repository metadata from the verified artifacts on disk and serves only complete versions.
- **Immutable installs.** A repository path is write-once: if a later bundle carries different content for an existing path, the import fails with an immutable-file conflict rather than silently mutating it. Re-importing identical content is a no-op.
- **Only new content crosses the diode.** The low side records every forwarded file, per stream, in a small SQLite index (`<root>/exported.db`). A collect that resolves entirely to already-forwarded content writes no bundle and consumes no sequence number ("no new content"); a partly-new collect writes a **delta bundle** whose archive carries only the new files, with the rest listed as *prior* references the high side verifies against its accumulated repository. Where upstream declares hashes before the bytes (APT/RPM indexes, container digests, Hugging Face LFS), already-forwarded files are not even downloaded again. `"force": true` on any collect bypasses all of it for a full, self-contained bundle.

!!! tip "Air-gap friendly by construction"
    ArtiGate leans on the Go standard library, with six direct third-party dependencies: `caddyserver/certmagic` (automatic HTTPS/ACME), `gorilla/securecookie` (signed/encrypted session cookies), `golang.org/x/crypto` (argon2 password hashing), pure-Go `modernc.org/sqlite` (scheduled watches and the export-dedup index), `hashicorp/go-version` (container tag constraints), and `klauspost/reedsolomon` (forward error correction for the built-in UDP diode). Both dashboards are fully self-contained with no external assets.

## Where to next

- [Getting started](getting-started.md) — the fastest path to a running low + high stack.
- [Architecture](architecture.md) — the deep model: streams, bundle format, signing, delta bundles, and the import loop.
- [Low side](low-side.md) — operating the exporter: collecting, scheduling, and re-export.
- [High side](high-side.md) — operating the mirror: importing, status, and serving clients.
- [Ecosystems](ecosystems/index.md) — the twenty-two streams and their client setup.
- [Configuration reference](configuration.md) — every flag and environment variable.
- [Security & trust](security.md) — the trust story and hardening guidance.
