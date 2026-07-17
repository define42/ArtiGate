# APT (Debian/Ubuntu)

ArtiGate mirrors Debian/Ubuntu-style APT repositories in **full-mirror mode** across the air gap: the low side downloads and verifies each suite's upstream `Release` + `Packages` indexes and every referenced `.deb`, and the high side **regenerates** its own `Release`/`Packages` per suite from the artifacts it actually holds and serves them as static files.

A mirror is one **archive root** (one `URIs:` value) carrying **one or more suites**, exactly like a real APT archive — `Suites: noble noble-updates noble-security` mirrors all three under a single namespace with a shared `pool/`.

## How it works

| Side | Responsibility |
| --- | --- |
| **Low** (`artigate low`) | Reads a deb822 `.sources` stanza, and for each suite fetches and (optionally) GPG-verifies the upstream `Release`, resolves the `Packages` index for each component × architecture, downloads and SHA-256-verifies every `.deb`, and packs everything into an Ed25519-signed bundle. A `.deb` listed in several suites is downloaded and bundled once. Collect-only — it never proxies or pulls through. |
| **High** (`artigate high`) | On bundle import, merges the packages into a persistent per-mirror index, regenerates `Packages`/`Packages.gz` and `Release` under `dists/<suite>` for every suite from the stanzas of `.deb`s it actually holds, optionally clearsigns `InRelease`/`Release.gpg` with **ArtiGate's own** GPG key, and serves the result read-only under `/apt/<mirror>`. |

!!! note "The high side never trusts transferred metadata"
    The upstream `Release`/`Packages` that crossed the diode are treated as inputs only. The high side rebuilds them from the `.deb` stanzas it holds. Transfer integrity is guaranteed by ArtiGate's **Ed25519 bundle signature** plus per-file SHA-256 verification on import — independent of any APT GPG signing. See [Security & trust](../security.md).

## Low side: input

The low-side dashboard mirrors an APT repository from a **deb822 source stanza** — the modern `.sources` format. Paste a stanza (or load a `.sources` file) into the "Mirror an APT repository" card, choose whether to keep only the newest version of each package, and collect.

!!! tip "Built-in source lists"
    The APT card ships ready-made source lists for Ubuntu 26.04 LTS (resolute), 24.04 LTS (noble) and 22.04 LTS (jammy) — each as a full-archive, main-only, or security-only variant — plus Docker CE (stable) for each of those releases. Pick one under "…or start from a built-in source list" and it is pasted into the input — edit it freely (trim suites, components), then collect once or add a schedule. The built-ins set no `Signed-By`, so upstream GPG verification is skipped unless you add a keyring path yourself. The files ship in the source tree under `buildin/apt/`.

```text
Types: deb
URIs: http://archive.ubuntu.com/ubuntu
Suites: noble noble-updates noble-security
Components: main universe
Architectures: amd64
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
```

This posts to `POST /admin/apt/collect`. The request body is capped at **1 MiB**. Besides `source_list`, the body accepts `newest_only` and `force` (both booleans), or — instead of a stanza — the explicit fields `name`, `uri`, `suites`, `components`, `architectures`, and `signed_by`, which describe a single mirror; see the [HTTP API reference](../api.md).

### Multiple stanzas → multiple mirrors

Every `deb` stanza in the pasted text is parsed. A multi-repo `.sources` file therefore becomes **multiple mirrors in one bundle**, each published as its own repository (its own namespace) on the high side. Several suites of the **same** archive belong in **one** stanza, not several.

!!! warning "Each stanza needs a distinct name"
    Mirror names must be unique within a collect. Duplicate names are rejected with `duplicate mirror name "…"; combine the suites of same-URI stanzas into one stanza (Suites: a b c), or give each source a distinct name`. When no name is supplied, one is derived from the URI (see below), so distinct URIs get distinct names automatically — and two stanzas with the same URI collide by design: merge their `Suites:` instead.

### deb822 fields honored

| Field | Meaning | Default if omitted |
| --- | --- | --- |
| `Types` | Only validated when present: if supplied it must contain the token `deb` (binary), and `deb-src` alone is rejected. Omitting it is allowed and the stanza is mirrored as `deb`. | none → treated as `deb` |
| `URIs` | Archive root URL (`http`/`https`). **Only the first token is used.** | required |
| `Suites` | One or more suites, e.g. `noble noble-updates noble-security`. **Every token is mirrored.** Duplicate tokens are dropped. | required (≥ 1) |
| `Components` | Space-separated components, e.g. `main contrib`. Applies to every suite in the stanza. | `main` |
| `Architectures` | Space-separated arches, e.g. `amd64 arm64`. Applies to every suite in the stanza. | `amd64` |
| `Signed-By` | Keyring **file path** used to verify each suite's upstream `Release`. | none → verification skipped |

!!! warning "First-token-only for URIs"
    If a single stanza lists multiple `URIs` (mirror fallbacks of the same archive), only the **first** whitespace-separated token is honored; the rest are silently dropped. Use separate stanzas for genuinely different archives.

The derived default name replaces every non-alphanumeric rune with `-` (collapsed). For example `https://packages.microsoft.com/repos/code` → `packages-microsoft-com-repos-code`. Each name must be a single path segment (no `/`), and suite/component/architecture tokens must match `^[A-Za-z0-9._-]+$`.

### Optional upstream verification with `Signed-By`

`Signed-By` verification is **opt-in**. When present, ArtiGate verifies each suite's upstream `Release` before trusting its checksums:

- It first tries `dists/<suite>/InRelease` (clearsigned) and verifies it with `gpgv --keyring <signed_by>`, then strips the PGP armor so the body matches the checksums.
- Otherwise it falls back to detached `dists/<suite>/Release` + `Release.gpg` and verifies that pair.

!!! warning "No key means no signature check"
    If `Signed-By` is empty, **no GPG signature is verified at all** — the `Release` is fetched and trusted over TLS only. Supply `Signed-By` (a keyring **file path**, not a fingerprint) whenever you want the upstream signature checked. `gpgv` and the keyring file must exist on the low-side host; verification runs with a 1-minute timeout. Only the keyring's basename is recorded in the bundle.

## Private repositories

Mirrors that demand a login are fetched with HTTP Basic from one of two sources, resolved per host as *request `auth` → `ARTIGATE_UPSTREAM_AUTH` → anonymous*:

- **Per-collect login** — an optional `auth` object on the collect request, also exposed as the *Private repository login* fields on the low-side APT page: `{"host": "apt.example.com", "username": "bot", "password": "secret"}`. It is used for that one collect and never stored. `host` may be omitted when every source in the collect lives on one host; a `source_list` spanning several hosts must name the one the login is for, and a host matching none of the sources is rejected.
- **Standing credentials** — comma-separated `host=user:password` entries in `ARTIGATE_UPSTREAM_AUTH` on the low side (the key is the mirror URL's exact host, `host:port` included). Re-read on every collect, and the **only** credential source [scheduled watches](../scheduling.md) can use — specs carrying an `auth` key are rejected.

A `URIs:` value embedding `user:pass@` is rejected outright: the URI is recorded in the signed manifest and echoed in progress and error text, so a login there would leak — including across the diode. Credentials never appear in bundles, logs, progress lines, or error messages.

## What gets mirrored

For each mirror, and for **each of its suites** (`distBase = <uri>/dists/<suite>`):

1. **`Release`** — fetched, optionally verified, then parsed. Only its **`SHA256:`** section is consulted to locate and verify the index files. (A `Release` with no SHA256 section fails to locate indexes.)
2. **`Packages` index** — for each component × architecture, ArtiGate looks in `<comp>/binary-<arch>/` and tries, in order, `Packages.gz` (stdlib gzip) then plain `Packages`. The candidate must be listed in the `Release` SHA256 map; it is downloaded, SHA-256-verified, and decompressed.
3. **Every referenced `.deb`** — each package stanza's `Filename` (a `pool/...` path) is path-safety-checked, downloaded, and SHA-256-verified against the index value. A mismatch is a hard failure. Suites share the archive's `pool/`, so a `.deb` listed by more than one suite is downloaded and bundled **once**.

Because the `Packages` index declares each `.deb`'s SHA-256 *before* the bytes are fetched, APT collects get the full benefit of [export dedup](../architecture.md#export-deduplication-and-delta-bundles): a `.deb` already forwarded on the `apt` stream is **not downloaded again at all** — it rides in the manifest as a `prior` reference — and only genuinely new packages are downloaded and packed into a delta bundle. A re-collect that finds nothing new is skipped entirely (no bundle, no sequence). Add `"force": true` to the collect body to bypass the index and produce a full, self-contained bundle.

!!! warning "Index format support"
    Only `Packages.gz` and plain `Packages` are supported (stdlib gzip). Repositories that publish **only** `.xz`, `.bz2`, or `.zst` indexes are not mirrorable.

`.deb` files **stream to disk** while being hashed — a package is never buffered in memory, and its byte count must match the index-declared `Size` exactly (files without a declared size are capped at 8 GiB). Streamed downloads have a 30-minute timeout. In-memory fetches are small and capped: `Release`/`InRelease`/`Release.gpg` at 16 MiB, a `Packages` index at 1 GiB (10-minute timeout), and gzip decompression of an index refuses to expand beyond 2 GiB (decompression-bomb guard). An empty result (no packages) produces no bundle: `apt mirror produced no packages`.

### "Newest version only" (default) vs every version

The **"Newest version of each package only"** checkbox is **checked by default** (`newest_only` defaults to `true`). With it on, ArtiGate keeps only the highest version per `(Package, Architecture)`, using a full dpkg-compatible version comparison (epoch → upstream → revision, with `~` sorting before everything). Uncheck it (`"newest_only": false`) to mirror **every** version present in the index.

The filter is applied **per suite** (per component × architecture index): `noble` keeps its own newest and `noble-updates` keeps its own newest, mirroring each suite's actual shape. APT on the client then picks the overall candidate across suites, exactly as it does against the upstream archive.

!!! note "Newest-only is a low-side filter"
    The newest-only filter is applied at collect time on the low side. The high side **accumulates** every version, architecture, and suite it has ever imported (see below), so it never removes older versions that already crossed the diode.

## High side: regeneration and signing

On import (after Ed25519 signature + per-file SHA-256 verification), the high side publishes each mirror under `<downloadDir>/apt/<name>`:

- **Merge** — the new mirror is merged into a persistent `<name>/index.json`. Suites accumulate **per suite**: each suite record carries its own components/architectures (unioned when the same suite is re-imported), so suites collected with different settings never bleed into each other. Packages are deduped **by `(Suite, Filename)`** (a `.deb` listed in two suites gets one index entry per suite but one pool file). Re-collecting the same mirror with a different suite therefore **adds** a suite; it never replaces one.
- **Regenerate `Packages`/`Packages.gz`** — for each suite × **that suite's own** components × architectures, ArtiGate emits the stanzas of that suite's packages where the `.deb` **actually exists on disk**. `Architecture: all` packages are emitted into every architecture's index.
- **Prune stale `dists/` entries** — everything under `dists/` is regenerated from the index on every publish, so any `dists/<x>` not among the mirror's suites is deleted.
- **Regenerate `Release`** — one minimal, freshly built file per suite, whose `Components:`/`Architectures:` lines are the suite's own (clients are never pointed at indexes the suite doesn't have):

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
| `-apt-gpg-key <key-id>` | `""` (unset) | When set, the high side clearsigns `InRelease` and writes a detached `Release.gpg` for **each suite** using **ArtiGate's own** GPG key. When unset, the repository is served **unsigned** (any stale `InRelease`/`Release.gpg` is removed). |

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
/apt/<mirror>/dists/<suite>/Release              # one dists/<suite> tree per suite
/apt/<mirror>/dists/<suite>/InRelease            # only when signed
/apt/<mirror>/dists/<suite>/Release.gpg          # only when signed
/apt/<mirror>/dists/<suite>/<comp>/binary-<arch>/Packages
/apt/<mirror>/dists/<suite>/<comp>/binary-<arch>/Packages.gz
/apt/<mirror>/pool/...                           # the .deb files, shared by all suites
```

## Client configuration

Point APT at the high side with a deb822 `.sources` file. In the dashboard's APT tree (mirror → suite → component → package), every **component node** carries its own "Set me up" button — where you click already decides the release *and* the channel, so the guide has nothing left to ask:

- Clicking `noble/stable` on a Docker mirror generates a stanza pinned to exactly `Suites: noble` + `Components: stable`; machines that want pre-releases click `noble/test` instead. Mixing releases is never offered — a foreign release's build would sort higher and become apt's install candidate.
- The stanza's `Architectures:` is the clicked suite's own recorded list.
- When **sibling suites of the same release** also carry the clicked component (`noble-updates` and `noble-security` next to `noble`), the guide points them out — append them to `Suites:` on machines that should also pull updates and security fixes.

```text
# /etc/apt/sources.list.d/artigate.sources  (generated from the noble/main node)
Types: deb
URIs: https://high-proxy:8080/apt/archive-ubuntu-com-ubuntu
Suites: noble
Components: main
Architectures: amd64
Signed-By: /usr/share/keyrings/artigate-apt.gpg
```

Clients must use the **same suite tokens** the mirror was collected with — the regenerated `Release` sets both `Suite:` and `Codename:` to that token, so a mirror collected as `stable` is not addressable as `bookworm` (or vice versa). A machine's own codename is `lsb_release -cs` (or `VERSION_CODENAME` in `/etc/os-release`).

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
- **First-token-only for `URIs`.** Multiple `URIs` in one stanza are reduced to the first. (`Suites` has no such limit — every token is mirrored.)
- **Stanza-level `Components`/`Architectures` at collect time.** They apply to every suite in the stanza; a suite that lacks one of the listed component × architecture indexes fails the collect. (Use separate collects with different settings per suite — the high side records and publishes them per suite.)
- **Index format.** Only `Packages.gz`/`Packages` (stdlib gzip); no `.xz`/`.bz2`/`.zst`-only repositories.
- **SHA256-only.** Only the `SHA256:` section of the upstream `Release` is used to locate indexes; a `Release` without it fails.
- **Minimal regenerated `Release`.** `Origin: ArtiGate`, `Suite == Codename`, no `Valid-Until`, no by-hash; upstream `Release` metadata is discarded.
- **High side accumulates versions and suites.** Newest-only filtering happens only on the low side; the high side keeps every version/arch/suite ever imported.
- **External binaries required.** `gpgv` on the low side (only when `Signed-By` is used) and `gpg` on the high side (only when `--apt-gpg-key` is set).
- **Size/time caps.** Request body 1 MiB. `.deb` files stream to disk (never through memory): exact index-declared size enforced, 8 GiB cap without one, 30-minute timeout. In-memory metadata: Release 16 MiB, Packages index 1 GiB, decompressed index 2 GiB, 10-minute timeout.
- **Unsigned by default.** `--apt-gpg-key` is unset by default, so repositories are served unsigned and clients need `Trusted: yes` until you configure a key.

## Related pages

- [Low side](../low-side.md) — operating the exporter
- [High side](../high-side.md) — operating the read-only repository
- [Security & trust](../security.md) — the signing/verification chain and hardening
- [Scheduling (watches)](../scheduling.md) — recurring APT collects
- [HTTP API reference](../api.md) — the exact request/response contracts
- [Configuration reference](../configuration.md) — every flag and environment variable
