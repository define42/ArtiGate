# Rust crates

ArtiGate mirrors Rust crates across a data diode by resolving them against a **cargo sparse registry index** on the low side (`https://index.crates.io` by default), downloading every `.crate` archive with its index-declared checksum verified, and serving a regenerated sparse registry on the high side that `cargo` consumes through an ordinary source replacement.

The adapter has three parts: **low-side collect** (resolve against the sparse index, download and `cksum`-verify the archives, pack a signed bundle), **high-side serve** (a regenerated sparse index plus the `.crate` downloads under `/crates/`), and the **client `~/.cargo/config.toml`**. See [Architecture](../architecture.md) for the diode model, and the sibling [NPM](npm.md) page for the equivalent npm flow.

## How it works

```text
  crate specs ("serde", "serde@1.0.203")
        │
        ▼
  fetch sparse-index files ──▶ resolve versions + dependency graph
        │                      (normal + build deps; never dev)
        ▼
  download every .crate ──▶ verify against the index cksum (SHA-256)
        │
        ▼
  signed ArtiGate bundle ══ diode ══▶ high side import
   (carries each release's verbatim        │
    index line inside the manifest)        ▼
                             re-verify cksum == artifact SHA-256,
                             regenerate sparse index under /crates/index/
```

- Resolution and download use plain HTTPS against the sparse index — **no `cargo` binary is invoked** on either side.
- Like the [APT adapter](apt.md), each release's **verbatim upstream index line** travels inside the Ed25519-signed manifest. The high side never serves a line whose `cksum` does not equal the byte-verified artifact's SHA-256 — checked again at import — and regenerates every served index file from those verified records, gated on the `.crate` actually being present.

## Low side: input

`POST /admin/crates/collect` (add `?stream=1` for streamed progress). Body limit **1 MiB**.

```json
{
  "crates": ["serde@1.0.203", "tokio", "anyhow"],
  "resolve_deps": true,
  "include_optional": false
}
```

| Field | Type | Meaning |
|---|---|---|
| `crates` | `[]string` | **Required.** Crate specs: `serde` for the newest release, `serde@1.0.203` to pin (`@latest` equals the bare form). |
| `resolve_deps` | `*bool` | **Defaults true when absent** — the transitive dependency graph of the listed crates is resolved against the sparse index and bundled too. `false` mirrors only the listed crates. |
| `include_optional` | bool | Additionally follow **optional** dependencies (default `false`). |
| `force` | bool | Bypass the export-dedup index — pack every crate even if already forwarded (full, self-contained bundle). |

In the low-side dashboard (**Crates** tab), enter one spec per line.

### Validation

- Crate names must match `^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$` — crates.io enforces a stricter charset, alternative registries allow a leading digit, so both are accepted. The first character excludes `-` and `_`, so a name can never be `..` or look like a flag.
- Versions always start with a digit (`^[0-9][0-9A-Za-z.+-]*$`), so they can never be `..`, a flag, or contain a path separator.
- An empty `crates` list is rejected with `no crates provided`.

## Low side: resolution against the sparse index

The resolver first reads the upstream registry's `config.json` for the download URL template (`dl` must be an http(s) URL; explicit `{crate}`/`{version}`/`{prefix}`/`{lowerprefix}`/`{sha256-checksum}` markers are substituted, a marker-less template gets the standard `/{crate}/{version}/download` suffix). It then walks the index **breadth-first**:

| Spec / edge | Selected version |
|---|---|
| `name@1.2.3` (exact pin) | Exactly that release — an exact pin may name a **yanked** release, like a lockfile can |
| bare `name` | Highest non-yanked **stable** release; falls back to the highest pre-release if only pre-releases exist |
| dependency edge (cargo requirement: `^`, `~`, `=`, ranges, wildcards) | Highest non-yanked release satisfying the requirement — like cargo. A requirement already satisfied by a selected version resolves to it (shared dependencies resolve once) |

Dependency edges expand per the index line's `deps` array: **normal and build dependencies always, dev dependencies never, optional dependencies only with `include_optional`**. Renamed dependencies resolve under their real registry name (the `package` field). Sparse-index files are fetched per crate at the registry-defined path (`1/a`, `2/ab`, `3/a/abc`, else `se/rd/serde`), cached per collect, and capped at **64 MiB** each. A resolution is bounded at **4000 crates** so a pathological graph cannot grow without limit.

!!! note "No feature unification"
    The resolver follows dependency **edges**, not cargo's feature solver — it does no feature unification, so an unusual feature-gated dependency may need to be listed explicitly. Yanked releases are skipped unless pinned exactly.

Crates that cannot be resolved or fetched are skipped and reported in `skipped_modules` — one bad crate never blocks the rest of the batch. If **zero** crates resolve or download, the collect errors with `no crates could be resolved: …` / `no crates could be fetched: …`.

## Low side: download, verification, and the signed bundle

Every selected `.crate` is downloaded from the registry's `dl` URL and **verified against the index-declared `cksum`** (a 64-hex SHA-256) while streaming to disk. The archive is stored at the canonical path

```text
crates/files/<name>/<name>-<version>.crate      # name lowercased
```

— crate names are case-insensitively unique in a registry, so the lowercase form keeps one canonical path however a dependency spells it.

Verified crates are packed into the standard numbered, Ed25519-signed bundle on the `crates` stream (only the `crates` stream lock is held, so other ecosystems export in parallel). The manifest records one `CrateVersion` per release:

```json
{
  "name": "serde",
  "version": "1.0.203",
  "path": "crates/files/serde/serde-1.0.203.crate",
  "sha256": "…",
  "index_line": { "name": "serde", "vers": "1.0.203", "cksum": "…", "deps": ["…"] }
}
```

`index_line` is the **verbatim upstream sparse-index line**, carried inside the signed manifest. [Export dedup](../architecture.md#export-deduplication-and-delta-bundles) applies as usual: an unchanged re-collect is skipped, a partly-new one ships a delta bundle, and `"force": true` bypasses the index.

## High side: import-time verification and index regeneration

On import (after the Ed25519 signature and per-file SHA-256 checks), every crate record is validated **again**:

- name/version are path-safe and the storage path is canonical;
- the embedded index line names exactly this crate and version;
- the index line's `cksum` **equals the delivered artifact's SHA-256** (a mismatch fails the import).

Then the served sparse index is regenerated: each release's verbatim line is upserted into its crate's index file (lines from earlier bundles are kept, versions ordered oldest-first like the upstream index), and **only releases whose verified `.crate` archive is present are listed**. A record that cannot be published is logged and skipped — that version 404s rather than wedging the stream's import.

## High side: serving

The high side serves the cargo sparse-registry routes under `/crates/` (GET/HEAD only):

| Route | Response |
|---|---|
| `GET /crates/index/config.json` | `{"dl": "<base>/crates/dl"}` — cargo appends `/{crate}/{version}/download` itself |
| `GET /crates/index/<index-path>` | The regenerated sparse-index file for one crate (e.g. `/crates/index/se/rd/serde`); requested paths are lowercased |
| `GET /crates/dl/<name>/<version>/download` | The `.crate` archive |

`config.json` requires absolute URLs, so `dl` is computed from the request (scheme via `X-Forwarded-Proto`, else ArtiGate's own TLS state; host from the request `Host`) — the mirror survives being served under any host name.

## Client setup

Point cargo at the mirror with a **source replacement** in `~/.cargo/config.toml` (or a per-project `.cargo/config.toml`):

```toml
[source.crates-io]
replace-with = "artigate"

[source.artigate]
registry = "sparse+https://artigate-high.local/crates/index/"
```

Then build as usual:

```bash
cargo build
```

An alternative to replacing crates.io is a named registry (`[registries.artigate] index = "sparse+<base>/crates/index/"`) for crates addressed with `registry = "artigate"` in `Cargo.toml`.

!!! warning "No upstream fallback"
    Configure ArtiGate as the **sole** source — the `replace-with` form does exactly that. Any additional registry reintroduces the dependency-confusion risk the diode exists to eliminate. See [Security & trust](../security.md).

## Limitations

- **No feature unification.** Normal and build dependencies are followed (never dev-dependencies; optional ones only with `include_optional`), picking the highest version satisfying each requirement like cargo does — but a feature-gated dependency that only appears under an unusual feature may need to be listed explicitly.
- **Yanked releases** are excluded from newest/requirement selection; only an exact pin (`name@version`) can still mirror one — the same reach a lockfile has.
- **Sparse registries only.** The low side resolves against a sparse (HTTP) index — `--crates-index` must point at one (default `https://index.crates.io`); git-protocol indexes are not supported. The high side likewise serves the sparse protocol, which needs cargo 1.68+ on clients.
- Size and count limits: request body 1 MiB, one sparse-index file 64 MiB, at most 4000 crates per resolution.
- The dependency graph is resolved at collect time; a [scheduled](../scheduling.md) re-collect re-resolves, so bare specs track new releases through the diode automatically while dedup keeps unchanged crates off the wire.

### Low-side flag

| Flag | Default | Meaning |
|---|---|---|
| `--crates-index` | `""` (→ `https://index.crates.io`) | Sparse registry index crates are resolved from |

## Related pages

- [Low side](../low-side.md) — operating the exporter
- [High side](../high-side.md) — operating the read-only mirror
- [Security & trust](../security.md) — the signing/verification chain
- [Scheduling (watches)](../scheduling.md) — recurring crate collects
- [HTTP API reference](../api.md) — the exact request/response contracts
- [Configuration reference](../configuration.md) — every flag and environment variable
