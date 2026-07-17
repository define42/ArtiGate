# R packages (CRAN)

ArtiGate mirrors **R packages** from a CRAN mirror across a data diode. The low side resolves the runtime dependency closure (`Depends` + `Imports` + `LinkingTo`, minus R's base packages) from `src/contrib/PACKAGES` and downloads each **source package** verified against the index-declared MD5 when present. The high side regenerates `src/contrib/PACKAGES` and `PACKAGES.gz` from each tarball's **own embedded `DESCRIPTION`** and serves a CRAN-shaped mirror under `/cran`, so `install.packages("pkg", repos = "<mirror>/cran")` works air-gapped.

!!! note "Source packages only"
    Like a plain CRAN mirror used with `type = "source"`, the high side serves source tarballs; R builds them locally at install time, exactly as it would against `cloud.r-project.org`. Binary packages are not mirrored.

## How it works

```text
  package specs ("jsonlite", "data.table@1.15.4")
        │
        ▼
  fetch <mirror>/src/contrib/PACKAGES(.gz) ──▶ resolve Depends/Imports/LinkingTo
        │
        ▼
  download each <name>_<version>.tar.gz (Archive/ fallback for superseded pins)
        │
        ▼
  signed ArtiGate bundle ══ diode ══▶ high side import
                                          │
                                          ▼
                        read each tarball's own DESCRIPTION, regenerate
                        src/contrib/PACKAGES(.gz), serve under /cran
```

## Low side: input

`POST /admin/cran/collect` (add `?stream=1` for streamed progress, `?dry_run=1` for an estimate). Body limit **1 MiB**.

```json
{
  "packages": ["jsonlite", "data.table@1.15.4"]
}
```

| Field | Type | Meaning |
|---|---|---|
| `packages` | `[]string` | **Required.** Package specs: `jsonlite` for the mirror's current version, `data.table@1.15.4` to pin — a superseded pin is fetched from the mirror's `Archive/` |
| `force` | bool | Bypass the export-dedup index (full, self-contained bundle) |

`--cran-mirror` points the collector at another mirror (default `https://cloud.r-project.org`). There is no auth field. Scheduled [watches](../scheduling.md) are supported.

### Resolution and download

The index (`src/contrib/PACKAGES.gz`, falling back to plain `PACKAGES`) drives resolution: the **runtime closure** follows `Depends`, `Imports`, and `LinkingTo` — version constraints in those fields are dropped, so dependencies always mirror the index's **current** version, like a fresh `install.packages` — skipping `R` itself and the 14 base packages (`stats`, `utils`, `methods`, …). The closure is capped at 2000 packages; unresolvable dependencies are skipped into `skipped_modules`.

Each tarball downloads from `src/contrib/<name>_<version>.tar.gz`; a pinned version no longer current falls back to `src/contrib/Archive/<name>/…`, and that archived tarball's own `DESCRIPTION` supplies its dependency names. When the index declares an `MD5sum` the download is verified against it; Archive downloads (and MD5-less indexes) carry no checksum and are TLS-trusted — everything is hash-locked into the signed bundle from there.

## High side: PACKAGES regeneration

On import, each release's metadata is read from the tarball's **embedded `DESCRIPTION`** (which must name exactly the manifest's package and version — a forged identity is rejected). The index is then regenerated:

| Route | Response |
|---|---|
| `GET /cran/src/contrib/PACKAGES` | The regenerated index (`Depends`, `Imports`, `LinkingTo`, `Suggests`, `License`, `NeedsCompilation`, … plus a recomputed `MD5sum`) |
| `GET /cran/src/contrib/PACKAGES.gz` | The same, gzipped |
| `GET /cran/src/contrib/<name>_<version>.tar.gz` | The source package |
| `GET /cran/src/contrib/Archive/<name>/<name>_<version>.tar.gz` | Superseded releases, for `remotes::install_version()` |

Like real CRAN, `PACKAGES` lists **only the newest present release** of each package; superseded tarballs stay downloadable under `Archive/`.

## Client setup

```r
install.packages("jsonlite", repos = "https://artigate-high.local/cran")

# …or set the mirror once per session/profile:
options(repos = c(mirror = "https://artigate-high.local/cran"))
```

Source installs compile on the client, so R build tooling (and any system libraries a package links against) must be present there — the same requirement as installing from CRAN with `type = "source"`.

## Limitations

- **Source packages only** — no binary packages; clients build locally.
- **Dependency version constraints are dropped**: the closure always mirrors the index's current version of each dependency. Pin explicitly (and re-collect) when you need a specific dependency version.
- **MD5 is the only upstream checksum** CRAN indexes carry (and `Archive/` downloads have none) — it is treated as a transfer check, not a security control; real integrity comes from the signed bundle's SHA-256 chain, and the served `MD5sum` is recomputed from the artifact.
- **Newest-only index**: `PACKAGES` lists one version per package; older mirrored versions live under `Archive/`.
- **No private-mirror auth** on this stream.
- [Export dedup](../architecture.md#export-deduplication-and-delta-bundles) applies: an unchanged re-collect is skipped without consuming a sequence number; `"force": true` bypasses it.

## Related pages

- [Low side](../low-side.md) — operating the exporter
- [High side](../high-side.md) — operating the read-only mirror
- [Scheduling (watches)](../scheduling.md) — recurring collects
- [Security & trust](../security.md) — the signing/verification chain
- [HTTP API reference](../api.md) — the exact request/response contracts
