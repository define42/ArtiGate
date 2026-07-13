# NuGet

ArtiGate mirrors NuGet packages across a data diode by resolving package ids against a **NuGet v3 source** on the low side (`https://api.nuget.org/v3/index.json` by default), walking each package's nuspec dependencies the way NuGet restore does, downloading the `.nupkg` archives, and serving a **regenerated v3 feed** on the high side — service index, flat container, registration pages, and a minimal search — with all metadata rebuilt from each package's own embedded `.nuspec`.

## How it works

```text
  package specs ("Newtonsoft.Json@13.0.3", "Serilog")
        │
        ▼
  v3 service index ──▶ locate the flat container (PackageBaseAddress)
        │
        ▼
  resolve versions + nuspec dependency graph
  (lowest applicable version per range, like NuGet restore)
        │
        ▼
  download every .nupkg ──▶ validate the embedded .nuspec identity
        │
        ▼
  signed ArtiGate bundle ══ diode ══▶ high side import
                                          │
                                          ▼
                          regenerate all feed metadata from each
                          package's own .nuspec → v3 feed under /nuget/
```

- Resolution and download use plain HTTPS — **no `nuget`/`dotnet` binary is invoked** on either side.
- The high side **never trusts transferred metadata**: registration pages, version lists, and search results are rebuilt from each verified archive's embedded `.nuspec`.

!!! warning "The flat container publishes no digests"
    Unlike the crates or Terraform registries, NuGet's flat container declares **no per-file hash**, so low-side downloads are **TLS-trusted** to the configured source and validated against the archive's embedded `.nuspec` (a mixed-up upstream response never enters the bundle). Everything after that is hash-locked into the signed bundle: the manifest pins each `.nupkg`'s SHA-256, and the high side verifies it on import.

## Low side: input

`POST /admin/nuget/collect` (add `?stream=1` for streamed progress). Body limit **1 MiB**.

```json
{
  "packages": ["Newtonsoft.Json@13.0.3", "Serilog"],
  "resolve_deps": true
}
```

| Field | Type | Meaning |
|---|---|---|
| `packages` | `[]string` | **Required.** Package specs: `Serilog` for the newest stable release, `Newtonsoft.Json@13.0.3` to pin (`@latest` equals the bare form) |
| `resolve_deps` | `*bool` | **Defaults true when absent** — the transitive dependency graph from each package's nuspec is resolved and bundled too. `false` mirrors only the listed packages |
| `force` | bool | Bypass the export-dedup index — pack every package even if already forwarded (full, self-contained bundle) |

In the low-side dashboard (**NuGet** tab), enter one spec per line. Package ids must match `^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`; versions always start with a digit and are normalized to NuGet's SemVer2 identity form (leading zeros removed, three numeric parts — a non-zero fourth legacy part is kept — build metadata dropped).

## Low side: resolution — lowest applicable version, like restore

The resolver reads the v3 **service index** to locate the flat container (`PackageBaseAddress/3.0.0`), then walks breadth-first:

| Spec / edge | Selected version |
|---|---|
| `id@13.0.3` (exact pin) | Exactly that version (matched case-insensitively against the normalized upstream list) |
| bare `id` | Highest **stable** version; falls back to the highest pre-release if only pre-releases exist |
| dependency range (`1.0`, `[1.0]`, `[1.0,2.0)` …) | The **lowest version satisfying the range** — NuGet restore's dependency rule — preferring stable versions unless the range itself names a pre-release |

Dependency edges come from each downloaded package's embedded nuspec, collected **across all target-framework groups** and deduplicated by id + range; a range already satisfied by a selected version resolves to it. The nuspec range grammar is supported as published: a bare minimum (`1.0`), an exact pin (`[1.0]`), and interval notation with either bound optional. A resolution is bounded at **4000 packages**.

Every `.nupkg` is downloaded from the flat container (`{base}/{id}/{version}/{id}.{version}.nupkg`, all lowercase) and its **embedded `.nuspec` must identify exactly the requested id and normalized version** — the only integrity signal the flat container offers before ArtiGate's own hashing. Packages that cannot be resolved or fetched are skipped and reported in `skipped_modules`; zero fetched packages fail the collect (`no nuget packages could be fetched: …`).

## Low side: the signed bundle

Fetched packages are packed into the standard numbered, Ed25519-signed bundle on the `nuget` stream. The manifest records one `NugetPackage` per version — `id` keeps the nuspec's canonical casing, `version` is the normalized form, and `path` uses the lowercase flat-container layout:

```json
{
  "id": "Newtonsoft.Json",
  "version": "13.0.3",
  "path": "nuget/packages/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg",
  "sha256": "…"
}
```

[Export dedup](../architecture.md#export-deduplication-and-delta-bundles) applies as usual: an unchanged re-collect is skipped, a partly-new one ships a delta bundle, and `"force": true` bypasses the index.

## High side: import-time metadata regeneration

On import (after the Ed25519 signature and per-file SHA-256 checks), every package's **embedded `.nuspec`** is extracted from the `.nupkg` (a zip; the root-level `.nuspec`, 8 MiB cap) and must match the manifest record's id (case-insensitive) and normalized version. From it the high side stores, per version:

- the identity in the nuspec's canonical casing, `description`, and `authors`;
- the **dependency groups** (target framework + id/range pairs, grouped or legacy flat form);
- the raw `.nuspec` bytes, served back verbatim on the flat container's nuspec route.

A package whose archive cannot be parsed is logged and skipped — its version 404s rather than wedging the stream's import. Only versions whose archive is present are served.

## High side: the served v3 feed

The high side serves a read-only NuGet v3 feed under `/nuget/` (GET/HEAD only):

| Route | Response |
|---|---|
| `GET /nuget/v3/index.json` | Service index: `PackageBaseAddress/3.0.0`, `RegistrationsBaseUrl` (plus `/3.4.0`, `/3.6.0`), `SearchQueryService` (plus `/3.0.0-rc`) |
| `GET /nuget/v3-flatcontainer/<id>/index.json` | `{"versions": […]}` — the mirrored versions, lowercase, ascending |
| `GET /nuget/v3-flatcontainer/<id>/<ver>/<id>.<ver>.nupkg` | The package archive |
| `GET /nuget/v3-flatcontainer/<id>/<ver>/<id>.nuspec` | The verbatim embedded `.nuspec` |
| `GET /nuget/v3/registration/<id>/index.json` | Registration index: a single inlined page whose leaves carry the catalog entry (identity, dependency groups) and `packageContent` URL |
| `GET /nuget/v3/search?q=<text>` | Minimal search: case-insensitive substring match on the id |

URLs in the service index and registration pages are absolute, computed from the request host, so the feed works under any name that reaches it. Registration pages are what lets clients resolve dependencies offline; the minimal search backs `dotnet package search` and the IDE package browsers for what is actually mirrored.

## Client setup

Point NuGet at the mirror with a `nuget.config` next to the solution (or user-wide), **clearing** every other source:

```xml
<configuration>
  <packageSources>
    <clear />
    <add key="artigate" value="https://artigate-high.local/nuget/v3/index.json" protocolVersion="3" />
  </packageSources>
</configuration>
```

Then restore as usual:

```bash
dotnet restore
```

!!! warning "`<clear />` is the point"
    Without it, machine-level configs typically leave `nuget.org` configured, and a missing package would silently resolve upstream — the dependency-confusion path the diode exists to eliminate. See [Security & trust](../security.md).

## Limitations

- **TLS-trusted downloads.** The flat container publishes no digests, so the low-side download is protected by TLS plus the embedded-nuspec identity check; from the bundle onward everything is hash-verified.
- **Lowest-applicable-version resolution** across **all** target-framework groups: the mirrored graph is the union over TFMs, so a restore for any one framework finds its dependencies (a few extra packages may be mirrored for frameworks you don't use).
- **v3 sources only.** `--nuget-source` must point at a v3 service index exposing `PackageBaseAddress/3.0.0`; v2 feeds are not supported. Authenticated upstream sources are not supported.
- **Minimal search**: substring match on the package id — no relevance ranking, tags, or owner filters. Symbol packages (`.snupkg`) and README/icon endpoints are not served.
- Size and count limits: request body 1 MiB, embedded `.nuspec` 8 MiB, upstream version list 16 MiB, at most 4000 packages per resolution.

### Low-side flag

| Flag | Default | Meaning |
|---|---|---|
| `--nuget-source` | `""` (→ `https://api.nuget.org/v3/index.json`) | NuGet v3 service index packages are resolved from |

## Related pages

- [Low side](../low-side.md) — operating the exporter
- [High side](../high-side.md) — operating the read-only mirror
- [Security & trust](../security.md) — the signing/verification chain
- [Scheduling (watches)](../scheduling.md) — recurring NuGet collects
- [HTTP API reference](../api.md) — the exact request/response contracts
- [Configuration reference](../configuration.md) — every flag and environment variable
