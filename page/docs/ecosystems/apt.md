# APT (Debian/Ubuntu)

ArtiGate mirrors Debian/Ubuntu-style APT repositories in **full-mirror mode** across the air gap: the low side downloads and verifies the upstream `Release` + `Packages` indexes and every referenced `.deb`, and the high side **regenerates** its own `Release`/`Packages` from the artifacts it actually holds and serves them as static files.

## How it works

| Side | Responsibility |
| --- | --- |
| **Low** (`artigate low`) | Reads a deb822 `.sources` stanza, fetches and (optionally) GPG-verifies the upstream `Release`, resolves the `Packages` index for each component × architecture, downloads and SHA-256-verifies every `.deb`, and packs everything into an Ed25519-signed bundle. Collect-only — it never proxies or pulls through. |
| **High** (`artigate high`) | On bundle import, merges the packages into a persistent per-mirror index, regenerates `Packages`/`Packages.gz` and `Release` from the stanzas of `.deb`s it actually holds, optionally clearsigns `InRelease`/`Release.gpg` with **ArtiGate's own** GPG key, and serves the result read-only under `/apt/<mirror>`. |

!!! note "The high side never trusts transferred metadata"
    The upstream `Release`/`Packages` that crossed the diode are treated as inputs only. The high side rebuilds them from the `.deb` stanzas it holds. Transfer integrity is guaranteed by ArtiGate's **Ed25519 bundle signature** plus per-file SHA-256 verification on import — independent of any APT GPG signing. See [Security & trust](../security.md).

## Low side: input

The low-side dashboard mirrors an APT repository from a **deb822 source stanza** — the modern `.sources` format. Paste a stanza (or load a `.sources` file) into the "Mirror an APT repository" card, choose whether to keep only the newest version of each package, and collect.

```text
Types: deb
URIs: https://packages.microsoft.com/repos/code
Suites: stable
Components: main
Architectures: amd64
Signed-By: /usr/share/keyrings/microsoft.gpg
```

This posts to `POST /admin/apt/collect`. The request body is capped at **1 MiB**.

### Multiple stanzas → multiple mirrors

Every `deb` stanza in the pasted text is parsed. A multi-repo `.sources` file therefore becomes **multiple mirrors in one bundle**, each published as its own repository (its own namespace) on the high side.

!!! warning "Each stanza needs a distinct name"
    Mirror names must be unique within a collect. Duplicate names are rejected with `duplicate mirror name "…"; give each source a distinct name`. When no name is supplied, one is derived from the URI (see below), so distinct URIs normally get distinct names automatically.

### deb822 fields honored

| Field | Meaning | Default if omitted |
| --- | --- | --- |
| `Types` | Only validated when present: if supplied it must contain the token `deb` (binary), and `deb-src` alone is rejected. Omitting it is allowed and the stanza is mirrored as `deb`. | none → treated as `deb` |
| `URIs` | Archive root URL (`http`/`https`). **Only the first token is used.** | required |
| `Suites` | Suite / distribution, e.g. `stable`. **Only the first token is used.** | required |
| `Components` | Space-separated components, e.g. `main contrib`. | `main` |
| `Architectures` | Space-separated arches, e.g. `amd64 arm64`. | `amd64` |
| `Signed-By` | Keyring **file path** used to verify the upstream `Release`. | none → verification skipped |

!!! warning "First-token-only for URIs and Suites"
    If a single stanza lists multiple `URIs` or multiple `Suites`, only the **first** whitespace-separated token of each is honored; the rest are silently dropped. Split them into separate stanzas to mirror all of them.

The derived default name replaces every non-alphanumeric rune with `-` (collapsed). For example `https://packages.microsoft.com/repos/code` → `packages-microsoft-com-repos-code`. Each name must be a single path segment (no `/`), and suite/component/architecture tokens must match `^[A-Za-z0-9._-]+$`.

### Optional upstream verification with `Signed-By`

`Signed-By` verification is **opt-in**. When present, ArtiGate verifies the upstream `Release` before trusting its checksums:

- It first tries `dists/<suite>/InRelease` (clearsigned) and verifies it with `gpgv --keyring <signed_by>`, then strips the PGP armor so the body matches the checksums.
- Otherwise it falls back to detached `dists/<suite>/Release` + `Release.gpg` and verifies that pair.

!!! warning "No key means no signature check"
    If `Signed-By` is empty, **no GPG signature is verified at all** — the `Release` is fetched and trusted over TLS only. Supply `Signed-By` (a keyring **file path**, not a fingerprint) whenever you want the upstream signature checked. `gpgv` and the keyring file must exist on the low-side host; verification runs with a 1-minute timeout. Only the keyring's basename is recorded in the bundle.

## What gets mirrored

For each mirror, with `distBase = <uri>/dists/<suite>`:

1. **`Release`** — fetched, optionally verified, then parsed. Only its **`SHA256:`** section is consulted to locate and verify the index files. (A `Release` with no SHA256 section fails to locate indexes.)
2. **`Packages` index** — for each component × architecture, ArtiGate looks in `<comp>/binary-<arch>/` and tries, in order, `Packages.gz` (stdlib gzip) then plain `Packages`. The candidate must be listed in the `Release` SHA256 map; it is downloaded, SHA-256-verified, and decompressed.
3. **Every referenced `.deb`** — each package stanza's `Filename` (a `pool/...` path) is path-safety-checked, downloaded, and SHA-256-verified against the index value. A mismatch is a hard failure.

!!! warning "Index format support"
    Only `Packages.gz` and plain `Packages` are supported (stdlib gzip). Repositories that publish **only** `.xz`, `.bz2`, or `.zst` indexes are not mirrorable.

Downloads use a **10-minute per-request timeout** and a **2 GiB per-file cap**. An empty result (no packages) produces no bundle: `apt mirror produced no packages`.

### "Newest version only" (default) vs every version

The **"Newest version of each package only"** checkbox is **checked by default** (`newest_only` defaults to `true`). With it on, ArtiGate keeps only the highest version per `(Package, Architecture)`, using a full dpkg-compatible version comparison (epoch → upstream → revision, with `~` sorting before everything). Uncheck it (`"newest_only": false`) to mirror **every** version present in the index.

!!! note "Newest-only is a low-side filter"
    The newest-only filter is applied at collect time on the low side. The high side **accumulates** every version and architecture it has ever imported (see below), so it never removes older versions that already crossed the diode.

## High side: regeneration and signing

On import (after Ed25519 signature + per-file SHA-256 verification), the high side publishes each mirror under `<downloadDir>/apt/<name>`:

- **Merge** — the new mirror is merged into a persistent `<name>/index.json`. `Components`/`Architectures` are unioned; packages are deduped **by `Filename`** (accumulating all versions/arches ever imported).
- **Regenerate `Packages`/`Packages.gz`** — for each merged component × architecture, ArtiGate emits the stanzas of packages where the `.deb` **actually exists on disk**. `Architecture: all` packages are emitted into every architecture's index.
- **Regenerate `Release`** — a minimal, freshly built file:

```text
Origin: ArtiGate
Label: <mirror name>
Suite: <suite>
Codename: <suite>
Components: main
Architectures: amd64
Date: Sun, 05 Jul 2026 12:00:00 UTC
MD5Sum:
 <hash> <size> main/binary-amd64/Packages
 …
SHA1:
 …
SHA256:
 …
```

!!! note "Regenerated `Release` is minimal"
    `Suite` and `Codename` are both set to the suite; there is no `Valid-Until`, no `Acquire-By-Hash`, and no `by-hash/` layout. Upstream `Release` fields other than the checksums are discarded. `MD5Sum`/`SHA1` are emitted for legacy clients only.

### Optional signing with `--apt-gpg-key`

| Flag | Default | Effect |
| --- | --- | --- |
| `-apt-gpg-key <key-id>` | `""` (unset) | When set, the high side clearsigns `InRelease` and writes a detached `Release.gpg` for each suite using **ArtiGate's own** GPG key. When unset, the repository is served **unsigned** (any stale `InRelease`/`Release.gpg` is removed). |

When a key is set, ArtiGate runs the external `gpg` binary (1-minute timeout):

```bash
gpg --batch --yes --armor --local-user <key> --clearsign   --output <distDir>/InRelease   <distDir>/Release
gpg --batch --yes --armor --local-user <key> --detach-sign --output <distDir>/Release.gpg <distDir>/Release
```

!!! warning "High-side signing uses ArtiGate's key, not the vendor's"
    The `Signed-By` keyring from the low side is **not** reused for high-side signing. High-side signatures are made with ArtiGate's own key, so clients must trust ArtiGate's high-side keyring — not the original upstream vendor keyring.

## Serving path

The high side serves the mirror as static files under `/apt` (GET/HEAD only):

```text
/apt/<mirror>/dists/<suite>/Release
/apt/<mirror>/dists/<suite>/InRelease            # only when signed
/apt/<mirror>/dists/<suite>/Release.gpg          # only when signed
/apt/<mirror>/dists/<suite>/<comp>/binary-<arch>/Packages
/apt/<mirror>/dists/<suite>/<comp>/binary-<arch>/Packages.gz
/apt/<mirror>/pool/...                           # the .deb files
```

## Client configuration

Point APT at the high side with a deb822 `.sources` file. The "Set me up" guide on the high-side dashboard generates the exact stanza for each mirrored repository:

```text
# /etc/apt/sources.list.d/artigate.sources
Types: deb
URIs: https://high-proxy:8080/apt/packages-microsoft-com-repos-code
Suites: stable
Components: main
Architectures: amd64
Signed-By: /usr/share/keyrings/artigate-apt.gpg
```

The last line depends on whether the high side signed the suite:

| High side | Client line |
| --- | --- |
| Signed (`--apt-gpg-key` set → `InRelease` present) | `Signed-By: /usr/share/keyrings/artigate-apt.gpg` — install **ArtiGate's** high-side APT public key here. |
| Unsigned (no key) | `Trusted: yes` — APT trusts the repository directly. |

!!! tip "Prefer signing over `Trusted: yes`"
    `Trusted: yes` disables APT's own signature check and relies solely on TLS plus ArtiGate's diode integrity. To get end-to-end APT verification, set `--apt-gpg-key` on the high side and distribute that key to clients as `/usr/share/keyrings/artigate-apt.gpg`.

!!! warning "No upstream fallback"
    Configure ArtiGate as the **sole** APT source with no secondary/public mirror. Any additional upstream reintroduces the dependency-confusion risk the diode exists to eliminate. See [Security & trust](../security.md).

## Example: the Microsoft VS Code repository

Mirror `packages.microsoft.com/repos/code` on the low side. Paste this deb822 stanza into the dashboard's APT card (or `POST` it directly):

```bash
curl -sS -X POST http://low-host:8080/admin/apt/collect \
  -H 'Content-Type: application/json' \
  -d '{
    "source_list": "Types: deb\nURIs: https://packages.microsoft.com/repos/code\nSuites: stable\nComponents: main\nArchitectures: amd64\nSigned-By: /usr/share/keyrings/microsoft.gpg\n",
    "newest_only": true
  }'
```

ArtiGate verifies the upstream `Release` with `microsoft.gpg`, mirrors the newest `.deb` for `stable/main` on `amd64`, and exports a signed bundle. The mirror name defaults to `packages-microsoft-com-repos-code`.

After the bundle is imported on the high side, configure a client:

```text
# /etc/apt/sources.list.d/artigate.sources
Types: deb
URIs: https://high-proxy:8080/apt/packages-microsoft-com-repos-code
Suites: stable
Components: main
Architectures: amd64
Signed-By: /usr/share/keyrings/artigate-apt.gpg
```

```bash
sudo apt-get update
sudo apt-get install code
```

## Limitations

- **Upstream verification is opt-in.** Without `Signed-By`, the upstream `Release` is trusted over TLS only — no GPG check.
- **First-token-only.** Multiple `URIs` or `Suites` in one stanza are reduced to the first; split into separate stanzas.
- **Index format.** Only `Packages.gz`/`Packages` (stdlib gzip); no `.xz`/`.bz2`/`.zst`-only repositories.
- **SHA256-only.** Only the `SHA256:` section of the upstream `Release` is used to locate indexes; a `Release` without it fails.
- **Minimal regenerated `Release`.** `Origin: ArtiGate`, `Suite == Codename`, no `Valid-Until`, no by-hash; upstream `Release` metadata is discarded.
- **High side accumulates versions.** Newest-only filtering happens only on the low side; the high side keeps every version/arch ever imported.
- **External binaries required.** `gpgv` on the low side (only when `Signed-By` is used) and `gpg` on the high side (only when `--apt-gpg-key` is set).
- **Size/time caps.** Request body 1 MiB; per-file 2 GiB; per-request 10-minute timeout.
- **Unsigned by default.** `--apt-gpg-key` is unset by default, so repositories are served unsigned and clients need `Trusted: yes` until you configure a key.

## Related pages

- [Low side](../low-side.md) — operating the exporter
- [High side](../high-side.md) — operating the read-only repository
- [Security & trust](../security.md) — the signing/verification chain and hardening
- [Scheduling (watches)](../scheduling.md) — recurring APT collects
- [HTTP API reference](../api.md) — the exact request/response contracts
- [Configuration reference](../configuration.md) — every flag and environment variable
