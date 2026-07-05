# ArtiGate

ArtiGate is a dependency mirror for **one-way data-diode / air-gapped networks**. It fetches Go modules, Python (PyPI) wheels, Java (Maven) artifacts, NPM packages, APT (`.deb`) and RPM (`.rpm`) repositories, and container images from the internet, carries them across a diode as signed numbered bundles, and serves them on the isolated side in each ecosystem's native format.

!!! note "One binary, two modes"
    A single `artigate` executable runs as either the internet-side exporter (`artigate low`) or the air-gapped read-only mirror (`artigate high`). The low side **delegates fetching** to the host's own `go`/`git`, `pip`, `mvn`, `npm`, and `gpgv` tools. The high side **never invokes them and never touches the network** — it only imports, verifies, and serves what already crossed the diode.

## How it works

```text
  spec ──▶ [ low ] ──▶ signed bundles ──▶ ((diode)) ──▶ [ high ] ──▶ clients
         fetch + sign        carry across          verify + serve
```

1. **Low side** — from its web dashboard you give it a spec (a `go.mod` or module list, a Python requirements list, Maven coordinates, a `package.json` or NPM package list, an APT source stanza, a `.repo`, or a list of container images). It fetches the closure from upstream and writes a **signed, numbered bundle** — three files per bundle: `<id>.tar.gz`, `<id>.manifest.json`, and `<id>.manifest.json.sig` — into the export directory.
2. **Diode** — a one-way transfer carries those three files into the high side's landing directory. ArtiGate never performs this move itself.
3. **High side** — it imports each stream's bundles strictly in sequence, verifies the Ed25519 signature and every file's SHA-256 hash, installs artifacts immutably, and **regenerates** all repository metadata from the artifacts actually present. It then serves clients as a GOPROXY, a PyPI index, a Maven 2 repository, an NPM registry, APT/RPM repositories, and a read-only OCI registry.

Each ecosystem is an independently numbered **stream**, so a stalled or missing bundle in one stream never blocks the others.

## The seven ecosystems

| Ecosystem | Low side mirrors | High side serves as | Client prefix |
|---|---|---|---|
| **Go modules** | modules by `module@version` / `module@latest`, or an uploaded `go.mod` (+`go.sum`); full dependency graph | GOPROXY | `/go/` |
| **Python (PyPI)** | a requirements list; **wheels only** (no sdists), optional cross-target for the high-side interpreter | PEP 503 simple index + wheel downloads | `/simple/`, `/packages/` |
| **Java (Maven)** | `groupId:artifactId:version` coordinates or an uploaded `pom.xml`; release versions only | Maven 2 repository | `/maven/` |
| **NPM** | package specs or an uploaded `package.json` (+`package-lock.json`); full graph resolved with `npm`, registry tarballs only | NPM registry | `/npm/` |
| **APT (Debian/Ubuntu)** | a deb822 source stanza, optional `Signed-By` keyring verified with `gpgv` | APT repository | `/apt/<mirror>` |
| **RPM (RHEL/Fedora)** | a yum/dnf `.repo` stanza with a concrete `baseurl` | RPM repository | `/rpm/<mirror>` |
| **Container images (OCI)** | image refs (`alpine:3.20`, `ghcr.io/org/app:v1`), optional tag version constraints; **linux/amd64 only** | read-only OCI registry (Docker Registry v2) | `/v2/` |

See [Ecosystems](ecosystems/index.md) for the per-ecosystem detail pages.

## Key properties

- **Per-stream sequencing.** Every ecosystem has its own independent sequence counter. Bundles import strictly consecutively per stream — an out-of-order bundle (e.g. `go-bundle-000043` before `000042`) is quarantined, not rejected, and imported automatically once the gap fills. A gap in one stream never blocks another.
- **Signed and verified end to end.** Each bundle's manifest is signed with an Ed25519 private key held only on the low side; the high side verifies that signature over the exact manifest bytes, then re-hashes every extracted file against the manifest's SHA-256 before installing. A signature or hash mismatch aborts that bundle's import without advancing state.
- **The high side regenerates metadata, never trusts it.** Transferred `Release`/`Packages`, packuments, `latest`, and other index files are never treated as truth — the high side rebuilds all repository metadata from the verified artifacts on disk and serves only complete versions.
- **Immutable installs.** A repository path is write-once: if a later bundle carries different content for an existing path, the import fails with an immutable-file conflict rather than silently mutating it. Re-importing identical content is a no-op.
- **Export deduplication.** The low side records the content hashes it has forwarded, per stream, in a small SQLite index (`<root>/exported.db`). When a collect resolves entirely to already-forwarded content, no bundle is written and no sequence number is consumed — a daily schedule over an unchanged upstream simply reports "no new content".

!!! tip "Air-gap friendly by construction"
    ArtiGate is stdlib-only apart from two dependencies: pure-Go SQLite (for scheduled watches and the export-dedup index) and `hashicorp/go-version` (for container tag constraints). Both dashboards are fully self-contained with no external assets.

## Where to next

- [Getting started](getting-started.md) — the fastest path to a running low + high stack.
- [Architecture](architecture.md) — the deep model: streams, bundle format, signing, and the import loop.
- [Low side](low-side.md) — operating the exporter: collecting, scheduling, and re-export.
- [High side](high-side.md) — operating the mirror: importing, status, and serving clients.
- [Ecosystems](ecosystems/index.md) — the seven ecosystems and their client setup.
- [Configuration reference](configuration.md) — every flag and environment variable.
- [Security & trust](security.md) — the trust story and hardening guidance.
